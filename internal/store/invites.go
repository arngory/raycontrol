package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/arngory/raycontrol/internal/spa"
)

// Invite lets a client register a device itself through the API (R3-3).
type Invite struct {
	ID        string
	UserName  string
	Name      string // of the device it becomes
	Role      string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
	DeviceID  string // the device it became
	// PinProof is what Register must bring with the invite's PIN
	// (api-v1 §3), nil without one; PinTries the wrong PINs still allowed.
	PinProof []byte
	PinTries int
}

// InvitePinTries is how many wrong PINs an invite takes: the last one
// withdraws it.
const InvitePinTries = 5

// InvitePIN gives the proof an invite's PIN makes, from the invite's key:
// the store keeps the proof, never the PIN.
type InvitePIN func(key [spa.KeySize]byte) []byte

// MaxInviteTTL bounds how long an invite stays valid.
const MaxInviteTTL = 7 * 24 * time.Hour

func newID() (string, error) {
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}

// CreateInvite makes a one-time invite for a device of a user and returns
// its SPA key.
//
// With pin, the invite also needs a PIN (api-v1 §3): pin makes the proof
// from the key, and the invite takes InvitePinTries wrong ones.
func (s *Store) CreateInvite(ctx context.Context, userName, name, role string, ttl time.Duration, pin ...InvitePIN) (Invite, [spa.KeySize]byte, error) {
	var key [spa.KeySize]byte
	if err := checkName("device", name); err != nil {
		return Invite{}, key, err
	}
	if role != "user" && role != "admin" {
		return Invite{}, key, fmt.Errorf("%w role %q: use user or admin", ErrInvalid, role)
	}
	if ttl <= 0 || ttl > MaxInviteTTL {
		return Invite{}, key, fmt.Errorf("%w invite lifetime %v: up to %v", ErrInvalid, ttl, MaxInviteTTL)
	}
	u, err := s.UserByName(ctx, userName)
	if err != nil {
		return Invite{}, key, err
	}
	var taken int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM devices WHERE user_id = ? AND name = ?`, u.ID, name).Scan(&taken); err != nil {
		return Invite{}, key, err
	}
	if taken > 0 {
		return Invite{}, key, fmt.Errorf("%w device %q of %s: the name is taken", ErrInvalid, name, u.Name)
	}
	id, err := newID()
	if err != nil {
		return Invite{}, key, err
	}
	if _, err := rand.Read(key[:]); err != nil {
		return Invite{}, key, err
	}
	now := s.now().Truncate(time.Second)
	inv := Invite{ID: id, UserName: u.Name, Name: name, Role: role, CreatedAt: now, ExpiresAt: now.Add(ttl)}
	if len(pin) > 0 && pin[0] != nil {
		inv.PinProof, inv.PinTries = pin[0](key), InvitePinTries
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO invites (id, user_id, name, role, spa_key, created_at, expires_at, pin_proof, pin_tries)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		inv.ID, u.ID, inv.Name, inv.Role, key[:], now.Unix(), inv.ExpiresAt.Unix(), inv.PinProof, inv.PinTries)
	return inv, key, err
}

// FailInvitePIN counts a wrong PIN against an active invite and returns
// the tries left. The last one withdraws the invite: its row goes, as a
// revoked invite's does, and it is ErrNotFound from then on.
func (s *Store) FailInvitePIN(ctx context.Context, id string) (left int, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE invites SET pin_tries = pin_tries - 1
			WHERE id = ? AND used_at IS NULL AND pin_proof IS NOT NULL AND pin_tries > 0`, id)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return fmt.Errorf("invite %q: %w", id, ErrNotFound)
		}
		if err := tx.QueryRowContext(ctx, `SELECT pin_tries FROM invites WHERE id = ?`, id).Scan(&left); err != nil {
			return err
		}
		if left == 0 {
			_, err = tx.ExecContext(ctx, `DELETE FROM invites WHERE id = ?`, id)
		}
		return err
	})
	return left, err
}

// ListInvites returns the invites not yet used, expired ones included.
func (s *Store) ListInvites(ctx context.Context) ([]Invite, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT i.id, u.name, i.name, i.role, i.created_at, i.expires_at, i.pin_proof, i.pin_tries
		FROM invites i JOIN users u ON u.id = i.user_id WHERE i.used_at IS NULL ORDER BY u.name, i.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invite
	for rows.Next() {
		var inv Invite
		var created, expires int64
		if err := rows.Scan(&inv.ID, &inv.UserName, &inv.Name, &inv.Role, &created, &expires, &inv.PinProof, &inv.PinTries); err != nil {
			return nil, err
		}
		inv.CreatedAt, inv.ExpiresAt = time.Unix(created, 0), time.Unix(expires, 0)
		out = append(out, inv)
	}
	return out, rows.Err()
}

// DeleteInvite withdraws an unused invite.
func (s *Store) DeleteInvite(ctx context.Context, id string) error {
	return s.affectOne(ctx, "invite", id, `DELETE FROM invites WHERE id = ? AND used_at IS NULL`, id)
}

// PruneInvites removes invites used or expired before the given time.
func (s *Store) PruneInvites(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM invites WHERE expires_at < ? OR used_at < ?`, before.Unix(), before.Unix())
	return err
}

// ActiveInvite returns an invite and its SPA key if it may still be used:
// unused, unexpired, of an enabled and unexpired user.
func (s *Store) ActiveInvite(ctx context.Context, id string) (Invite, [spa.KeySize]byte, error) {
	var inv Invite
	var key [spa.KeySize]byte
	var raw []byte
	var created, expires int64
	now := s.now().Unix()
	err := s.db.QueryRowContext(ctx, `SELECT i.id, u.name, i.name, i.role, i.spa_key, i.created_at, i.expires_at, i.pin_proof, i.pin_tries
		FROM invites i JOIN users u ON u.id = i.user_id
		WHERE i.id = ? AND i.used_at IS NULL AND i.expires_at > ? AND u.enabled = 1 AND (u.expires_at IS NULL OR u.expires_at > ?)`,
		id, now, now).Scan(&inv.ID, &inv.UserName, &inv.Name, &inv.Role, &raw, &created, &expires, &inv.PinProof, &inv.PinTries)
	if errors.Is(err, sql.ErrNoRows) {
		return inv, key, fmt.Errorf("invite %q: %w", id, ErrNotFound)
	}
	if err != nil {
		return inv, key, err
	}
	copy(key[:], raw)
	inv.CreatedAt, inv.ExpiresAt = time.Unix(created, 0), time.Unix(expires, 0)
	return inv, key, nil
}

// UseInvite turns an active invite into a device known by the key of its
// TLS client certificate, once. It returns the new device and its SPA key.
func (s *Store) UseInvite(ctx context.Context, id, certPin string) (Device, [spa.KeySize]byte, error) {
	var d Device
	var key [spa.KeySize]byte
	if certPin == "" {
		return d, key, fmt.Errorf("%w: no client certificate", ErrInvalid)
	}
	inv, _, err := s.ActiveInvite(ctx, id)
	if err != nil {
		return d, key, err
	}
	devID, err := newID()
	if err != nil {
		return d, key, err
	}
	if _, err := rand.Read(key[:]); err != nil {
		return d, key, err
	}
	now := s.now().Truncate(time.Second)
	d = Device{ID: devID, UserName: inv.UserName, Name: inv.Name, Role: inv.Role, CreatedAt: now, CertPin: certPin}
	err = s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE invites SET used_at = ?, device_id = ? WHERE id = ? AND used_at IS NULL`, now.Unix(), devID, id)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return fmt.Errorf("invite %q: %w", id, ErrNotFound)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO devices (id, user_id, name, role, spa_key, created_at, cert_pin)
			SELECT ?, user_id, name, role, ?, ?, ? FROM invites WHERE id = ?`, devID, key[:], now.Unix(), certPin, id)
		return err
	})
	return d, key, err
}

// DeviceByCertPin returns the active device registered with the client
// certificate key.
func (s *Store) DeviceByCertPin(ctx context.Context, pin string) (Device, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM devices WHERE cert_pin = ?`, pin).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) || pin == "" {
		return Device{}, fmt.Errorf("device with certificate %q: %w", pin, ErrNotFound)
	}
	if err != nil {
		return Device{}, err
	}
	d, _, err := s.ActiveDevice(ctx, id)
	if err == nil {
		d.CertPin = pin
	}
	return d, err
}

// SetCertPin replaces the client certificate key of an active device that
// already has one (the device rotates its key).
func (s *Store) SetCertPin(ctx context.Context, id, oldPin, newPin string) error {
	if newPin == "" {
		return fmt.Errorf("%w: no certificate", ErrInvalid)
	}
	if _, err := s.DeviceByCertPin(ctx, oldPin); err != nil {
		return err
	}
	return s.affectOne(ctx, "device", id, `UPDATE devices SET cert_pin = ? WHERE id = ? AND cert_pin = ? AND revoked_at IS NULL`, newPin, id, oldPin)
}
