package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/arngory/raycontrol/internal/spa"
)

// ServiceKinds lists the services a node can run (docs/03-protocols.md).
var ServiceKinds = []string{
	"reality", "hy2-masq", "hy2-obfs", "naive", "doh", "yggdrasil",
	"dnstt", "masterdns", "olcrtc", "openflux", "inner",
	"subscription", "api", "ssh",
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ErrInvalid wraps validation failures.
var ErrInvalid = errors.New("store: invalid")

func checkName(kind, name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("%w %s name %q: use 1-64 of a-z 0-9 . _ - starting with a letter or digit", ErrInvalid, kind, name)
	}
	return nil
}

// User is a person who may connect through the node.
type User struct {
	ID           int64
	Name         string
	Enabled      bool
	ExpiresAt    *time.Time
	TrafficLimit *int64 // bytes
	Note         string
	CreatedAt    time.Time
	Services     []int64 // allowed service IDs
}

// CreateUser inserts u and returns it with its ID.
func (s *Store) CreateUser(ctx context.Context, u User) (User, error) {
	if err := checkName("user", u.Name); err != nil {
		return u, err
	}
	u.CreatedAt = s.now().Truncate(time.Second)
	res, err := s.db.ExecContext(ctx, `INSERT INTO users (name, enabled, expires_at, traffic_limit_bytes, note, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		u.Name, u.Enabled, nullTime(u.ExpiresAt), u.TrafficLimit, u.Note, u.CreatedAt.Unix())
	if err != nil {
		return u, err
	}
	u.ID, err = res.LastInsertId()
	return u, err
}

const userCols = `id, name, enabled, expires_at, traffic_limit_bytes, note, created_at`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	var exp, limit sql.NullInt64
	var created int64
	if err := row.Scan(&u.ID, &u.Name, &u.Enabled, &exp, &limit, &u.Note, &created); err != nil {
		return u, err
	}
	u.ExpiresAt = timePtr(exp)
	if limit.Valid {
		u.TrafficLimit = &limit.Int64
	}
	u.CreatedAt = time.Unix(created, 0)
	return u, nil
}

// UserByName returns a user with its allowed services.
func (s *Store) UserByName(ctx context.Context, name string) (User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return u, fmt.Errorf("user %q: %w", name, ErrNotFound)
	}
	if err != nil {
		return u, err
	}
	u.Services, err = s.userServices(ctx, u.ID)
	return u, err
}

// ListUsers returns all users ordered by name.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, u)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Services, err = s.userServices(ctx, out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) userServices(ctx context.Context, userID int64) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT service_id FROM user_services WHERE user_id = ? ORDER BY service_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// SetUserEnabled enables or disables a user.
func (s *Store) SetUserEnabled(ctx context.Context, name string, enabled bool) error {
	return s.affectOne(ctx, "user", name, `UPDATE users SET enabled = ? WHERE name = ?`, enabled, name)
}

// DeleteUser removes a user and, by cascade, its devices.
func (s *Store) DeleteUser(ctx context.Context, name string) error {
	return s.affectOne(ctx, "user", name, `DELETE FROM users WHERE name = ?`, name)
}

// SetUserServices replaces the services a user may reach.
func (s *Store) SetUserServices(ctx context.Context, name string, serviceIDs []int64) error {
	u, err := s.UserByName(ctx, name)
	if err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM user_services WHERE user_id = ?`, u.ID); err != nil {
			return err
		}
		for _, id := range serviceIDs {
			if _, err := tx.ExecContext(ctx, `INSERT INTO user_services (user_id, service_id) VALUES (?, ?)`, u.ID, id); err != nil {
				return fmt.Errorf("service %d: %w", id, err)
			}
		}
		return nil
	})
}

// Service is one data-plane service of the node.
type Service struct {
	ID        int64 // also the SPA scope ID
	Kind      string
	Name      string
	Enabled   bool
	Settings  string // JSON
	CreatedAt time.Time
}

// CreateService inserts svc. IDs are never reused: clients refer to them
// in SPA scopes, so a deleted ID must not start meaning another service.
func (s *Store) CreateService(ctx context.Context, svc Service) (Service, error) {
	if !slices.Contains(ServiceKinds, svc.Kind) {
		return svc, fmt.Errorf("%w service kind %q", ErrInvalid, svc.Kind)
	}
	if err := checkName("service", svc.Name); err != nil {
		return svc, err
	}
	if svc.Settings == "" {
		svc.Settings = "{}"
	}
	svc.CreatedAt = s.now().Truncate(time.Second)
	res, err := s.db.ExecContext(ctx, `INSERT INTO services (kind, name, enabled, settings_json, created_at) VALUES (?, ?, ?, ?, ?)`,
		svc.Kind, svc.Name, svc.Enabled, svc.Settings, svc.CreatedAt.Unix())
	if err != nil {
		return svc, err
	}
	svc.ID, err = res.LastInsertId()
	return svc, err
}

// ListServices returns all services ordered by ID.
func (s *Store) ListServices(ctx context.Context) ([]Service, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, name, enabled, settings_json, created_at FROM services ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Service
	for rows.Next() {
		var svc Service
		var created int64
		if err := rows.Scan(&svc.ID, &svc.Kind, &svc.Name, &svc.Enabled, &svc.Settings, &created); err != nil {
			return nil, err
		}
		svc.CreatedAt = time.Unix(created, 0)
		out = append(out, svc)
	}
	return out, rows.Err()
}

// ServiceByName looks a service up by name.
func (s *Store) ServiceByName(ctx context.Context, name string) (Service, error) {
	all, err := s.ListServices(ctx)
	if err != nil {
		return Service{}, err
	}
	for _, svc := range all {
		if svc.Name == name {
			return svc, nil
		}
	}
	return Service{}, fmt.Errorf("service %q: %w", name, ErrNotFound)
}

// SetServiceEnabled enables or disables a service.
func (s *Store) SetServiceEnabled(ctx context.Context, name string, enabled bool) error {
	return s.affectOne(ctx, "service", name, `UPDATE services SET enabled = ? WHERE name = ?`, enabled, name)
}

// DeleteService removes a service.
func (s *Store) DeleteService(ctx context.Context, name string) error {
	return s.affectOne(ctx, "service", name, `DELETE FROM services WHERE name = ?`, name)
}

// Device is an enrolled client device. Its SPA key is returned only once, by
// CreateDevice.
type Device struct {
	ID        string
	UserName  string
	Name      string
	Role      string // user | admin
	CreatedAt time.Time
	RevokedAt *time.Time
}

// CreateDevice enrolls a device for a user and returns its fresh SPA key.
func (s *Store) CreateDevice(ctx context.Context, userName, name, role string) (Device, [spa.KeySize]byte, error) {
	var key [spa.KeySize]byte
	if err := checkName("device", name); err != nil {
		return Device{}, key, err
	}
	if role != "user" && role != "admin" {
		return Device{}, key, fmt.Errorf("%w role %q: use user or admin", ErrInvalid, role)
	}
	u, err := s.UserByName(ctx, userName)
	if err != nil {
		return Device{}, key, err
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Device{}, key, err
	}
	if _, err := rand.Read(key[:]); err != nil {
		return Device{}, key, err
	}
	d := Device{ID: hex.EncodeToString(id[:]), UserName: u.Name, Name: name, Role: role, CreatedAt: s.now().Truncate(time.Second)}
	_, err = s.db.ExecContext(ctx, `INSERT INTO devices (id, user_id, name, role, spa_key, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		d.ID, u.ID, d.Name, d.Role, key[:], d.CreatedAt.Unix())
	return d, key, err
}

// ListDevices returns devices, optionally of one user.
func (s *Store) ListDevices(ctx context.Context, userName string) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT d.id, u.name, d.name, d.role, d.created_at, d.revoked_at
		FROM devices d JOIN users u ON u.id = d.user_id
		WHERE ? = '' OR u.name = ? ORDER BY u.name, d.name`, userName, userName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		var created int64
		var revoked sql.NullInt64
		if err := rows.Scan(&d.ID, &d.UserName, &d.Name, &d.Role, &created, &revoked); err != nil {
			return nil, err
		}
		d.CreatedAt, d.RevokedAt = time.Unix(created, 0), timePtr(revoked)
		out = append(out, d)
	}
	return out, rows.Err()
}

// RevokeDevice marks a device revoked. Revocation is permanent.
func (s *Store) RevokeDevice(ctx context.Context, id string) error {
	return s.affectOne(ctx, "device", id, `UPDATE devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, s.now().Unix(), id)
}

// SPADevices returns the devices that may currently pass SPA: not revoked,
// owned by an enabled and unexpired user, with that user's enabled services.
func (s *Store) SPADevices(ctx context.Context) ([]spa.Device, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.id, d.spa_key, us.service_id
		FROM devices d
		JOIN users u ON u.id = d.user_id
		JOIN user_services us ON us.user_id = u.id
		JOIN services sv ON sv.id = us.service_id
		WHERE d.revoked_at IS NULL AND u.enabled = 1 AND sv.enabled = 1
		  AND (u.expires_at IS NULL OR u.expires_at > ?)
		ORDER BY d.id, us.service_id`, s.now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []spa.Device
	for rows.Next() {
		var id string
		var key []byte
		var svc uint16
		if err := rows.Scan(&id, &key, &svc); err != nil {
			return nil, err
		}
		if len(out) == 0 || out[len(out)-1].ID != id {
			d := spa.Device{ID: id}
			copy(d.Key[:], key)
			out = append(out, d)
		}
		last := &out[len(out)-1]
		last.Allowed = append(last.Allowed, svc)
	}
	return out, rows.Err()
}

func (s *Store) affectOne(ctx context.Context, kind, ref, query string, args ...any) error {
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%s %q: %w", kind, ref, ErrNotFound)
	}
	return nil
}
