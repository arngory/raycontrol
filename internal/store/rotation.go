package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// DefaultRotation is rayd's schedule of credential rotation unless its
// flags say otherwise (-cred-period, -cred-lead, -cred-grace; R4-1).
var DefaultRotation = Rotation{Period: 30 * 24 * time.Hour, Lead: 3 * 24 * time.Hour, Grace: 2 * 24 * time.Hour}

// settingRotation is the schedule the node's rayd runs with (SetRotation):
// a revocation with overlap takes its lead and grace from it.
const settingRotation = "cred_rotation"

type rotationJSON struct {
	Period int64 `json:"period"` // seconds
	Lead   int64 `json:"lead"`
	Grace  int64 `json:"grace"`
}

// SetRotation sets the schedule rayd runs with, as its flags give it, so
// that a rotation started outside rayd's loop (a revocation with overlap,
// RevokeDeviceOverlap) has the same lead and says the same grace as the
// loop. The Store keeps it, and writes it into the database for another
// process on the same database; rayd sets it at every start. An older rayd
// does not read the setting.
func (s *Store) SetRotation(ctx context.Context, r Rotation) error {
	b, err := json.Marshal(rotationJSON{Period: int64(r.Period / time.Second), Lead: int64(r.Lead / time.Second), Grace: int64(r.Grace / time.Second)})
	if err != nil {
		return err
	}
	if err := s.SetSetting(ctx, settingRotation, b); err != nil {
		return err
	}
	s.rotation.Store(&r)
	return nil
}

// StoredRotation is the schedule a revocation with overlap goes by: the one
// SetRotation set on this Store; else the one the database holds; else,
// none there (no rayd of this version started on it yet) or one that does
// not read, DefaultRotation.
func (s *Store) StoredRotation(ctx context.Context) (Rotation, error) {
	return s.revocationRotation(ctx, s.db)
}

// revocationRotation is StoredRotation, read through q (a transaction).
func (s *Store) revocationRotation(ctx context.Context, q queryRower) (Rotation, error) {
	if r := s.rotation.Load(); r != nil {
		return *r, nil
	}
	return rotationIn(ctx, q, "main")
}

type queryRower interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// rotationIn reads the stored schedule of the database schema (main, or
// cur in a carry).
func rotationIn(ctx context.Context, q queryRower, schema string) (Rotation, error) {
	var b []byte
	err := q.QueryRowContext(ctx, `SELECT value FROM `+schema+`.settings WHERE key = ?`, settingRotation).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultRotation, nil
	}
	if err != nil {
		return Rotation{}, err
	}
	var v rotationJSON
	if json.Unmarshal(b, &v) != nil || v.Lead < 0 || v.Grace < 0 || v.Period < 0 {
		return DefaultRotation, nil
	}
	return Rotation{Period: time.Duration(v.Period) * time.Second, Lead: time.Duration(v.Lead) * time.Second,
		Grace: time.Duration(v.Grace) * time.Second}, nil
}

// RevocationChain bounds how far repeated revocations with overlap of one
// user's devices push a switch back: each restarts the lead, but the
// switch never comes later than RevocationChain leads after the first
// revocation the current credential outlived (rotateForRevocation).
const RevocationChain = 2

// rotateForRevocation is what a revocation with overlap does to its user's
// credentials (RevokeDeviceOverlap; docs/08-decisions.md, R4-43): an
// unscheduled rotation with the overlap of the scheduled one (R4-1).
// Every credential of the user but DoH's (R4-37: no device holds the
// user's DoH secret) gets a fresh next secret, accepted from now on and in
// the subscriptions of the user's other devices, with its switch a lead
// from now; at the switch the current one becomes the previous, accepted
// for the grace (RotateCredentials). A next already published, by the
// schedule or by an earlier revocation with overlap, is replaced, never
// kept: the revoked device may have fetched it. The
// current secret and a previous one in its grace stay: the user's other
// devices are on them until they move, and the revoked device knows the
// current one anyway, which outlives the previous.
//
// Each revocation restarts the lead, so revocations of the user's devices
// in a row would push the switch, and the life of what the first revoked
// device knew, further each time. The switch is therefore never later
// than RevocationChain leads after the first revocation since the current
// secret became current (the user's devices revoked after its rotated_at,
// in either mode, and now): the old secret is accepted at most
// RevocationChain×lead + grace after any revocation, at most lead + grace
// after the last one of a chain. A revocation late in a chain gives the
// other devices less notice than a lead; one that misses the new next
// goes on with its link, the previous secret now, for the grace, and
// fetches.
//
// It runs in the caller's transaction, after the device is revoked, on
// tx's main database. It returns how many credentials rotate and the
// latest switch (Unix seconds; 0 with none).
func rotateForRevocation(ctx context.Context, tx *sql.Tx, user, now int64, lead time.Duration) (int, int64, error) {
	rows, err := tx.QueryContext(ctx, `SELECT c.service_id, coalesce(c.rotated_at, c.created_at) FROM credentials c
		LEFT JOIN services s ON s.id = c.service_id
		WHERE c.user_id = ? AND coalesce(s.kind, '') != 'doh' ORDER BY c.service_id`, user)
	if err != nil {
		return 0, 0, err
	}
	type row struct{ service, rotated int64 }
	var list []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.service, &r.rotated); err != nil {
			rows.Close()
			return 0, 0, err
		}
		list = append(list, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	l := int64(lead / time.Second)
	var latest int64
	for _, r := range list {
		// After rotated_at, not at it: a revocation without overlap renews
		// the user's credentials in its own second (rotated_at is its
		// revoked_at), and so does a carry's renewal; the devices revoked
		// so know none of the current secrets.
		var first sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT min(revoked_at) FROM devices WHERE user_id = ? AND revoked_at > ?`,
			user, r.rotated).Scan(&first); err != nil {
			return 0, 0, err
		}
		chain := now
		if first.Valid && first.Int64 < chain {
			chain = first.Int64
		}
		from := max(min(now+l, chain+RevocationChain*l), now)
		secret, err := NewUUID()
		if err != nil {
			return 0, 0, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE credentials SET next_secret = ?, next_from = ? WHERE user_id = ? AND service_id = ?`,
			secret, from, user, r.service); err != nil {
			return 0, 0, err
		}
		latest = max(latest, from)
	}
	return len(list), latest, nil
}
