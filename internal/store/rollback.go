package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// RenewOverlapRotations gives new credentials at once, as a revocation
// without overlap does (R4-36), to every user of the database at path
// with a credential but DoH's in a rotation: a next secret, or a previous
// secret still accepted (prev_until ahead). Each gets a new LAN key where
// the user has one, and an audit line user.renew:<op> by actor, without a
// secret.
//
// For rayctl update -rollback, and an update going back, when the rayd
// that goes in is one before v0.31.0 and the node has no period
// (-cred-period 0): that rayd runs no rotation loop, so it would never
// switch a rotation a revocation with overlap began (R4-43) nor drop its
// previous secret, and what the revoked device knew would stay accepted.
// Without a period no rotation is scheduled: every one in flight is a
// revocation's with overlap, or one the schedule began before the period
// went to 0, whose users are renewed too (their devices reconnect after
// their next fetch: harmless). No window, no lead: no edge. The caller
// decides when (with a period the older rayd's loop finishes them). A
// database of another schema than this build's is left as it is (Open
// would migrate it): nothing renewed. The database must not be open
// elsewhere (rayd stopped). It returns the users renewed, by name.
func RenewOverlapRotations(ctx context.Context, path, actor, op string) ([]string, error) {
	return renewOverlapRotations(ctx, path, actor, op, nil)
}

// renewOverlapRotations is RenewOverlapRotations with the store's clock
// (nil: the time).
func renewOverlapRotations(ctx context.Context, path, actor, op string, clock func() time.Time) ([]string, error) {
	if v, err := Schema(ctx, path); err != nil || v != KnownSchema() {
		return nil, err
	}
	s, err := Open(ctx, path)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if clock != nil {
		s.SetClock(clock)
	}
	var names []string
	err = s.tx(ctx, func(tx *sql.Tx) error {
		now := s.now().Unix()
		rows, err := tx.QueryContext(ctx, `SELECT u.id, u.name FROM users u
			WHERE EXISTS (SELECT 1 FROM credentials c LEFT JOIN services s ON s.id = c.service_id
				WHERE c.user_id = u.id AND coalesce(s.kind, '') != 'doh'
				  AND (c.next_secret IS NOT NULL OR c.prev_secret IS NOT NULL AND c.prev_until > ?))
			ORDER BY u.name`, now)
		if err != nil {
			return err
		}
		type user struct {
			id   int64
			name string
		}
		var users []user
		for rows.Next() {
			var u user
			if err := rows.Scan(&u.id, &u.name); err != nil {
				rows.Close()
				return err
			}
			users = append(users, u)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, u := range users {
			key, err := newLANKey()
			if err != nil {
				return err
			}
			n, err := renewUser(ctx, tx, u.id, now, key, true)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log (ts, actor, action, target, result) VALUES (?, ?, ?, ?, 'ok')`,
				now, actor, "user.renew:"+op, fmt.Sprintf("%s: %d credentials new, a rotation in flight, which the rayd that goes in "+
					"(before v0.31.0, no -cred-period) would not finish", u.name, n)); err != nil {
				return err
			}
			names = append(names, u.name)
		}
		return nil
	})
	return names, err
}

// RotationAt is the schedule stored in the database at path, read only:
// what the node's rayd ran with (rotationRead: a negative period as none).
// When there is none, or it does not read, no period, with the default lead
// and grace: going back then renews (rollbackRenewsOverlap in rayctl), a
// false positive at worst, and a harmless one.
func RotationAt(ctx context.Context, path string) (Rotation, error) {
	s, err := OpenReadOnly(ctx, path)
	if err != nil {
		return Rotation{}, err
	}
	defer s.Close()
	r, ok, err := rotationRead(ctx, s.db, "main")
	if err != nil {
		return Rotation{}, err
	}
	if !ok {
		return Rotation{Lead: DefaultRotation.Lead, Grace: DefaultRotation.Grace}, nil
	}
	return r, nil
}
