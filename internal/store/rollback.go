package store

import (
	"context"
	"database/sql"
	"fmt"
)

// RenewOverlapRotations gives new credentials at once, as a revocation
// without overlap does (R4-36), to every user of the database at path
// whose credentials but DoH's are in a rotation that a revocation with
// overlap began (R4-43): a next secret with the current one no newer than
// the user's latest revocation (overlapInFlight's test, on the database
// itself), or a previous secret still accepted after a switch. Each gets
// an audit line user.renew:<op> by actor, without a secret.
//
// For rayctl update -rollback that keeps the database (the schema did not
// move) and goes back to a rayd before v0.31.0: that rayd runs no rotation
// loop without a period (-cred-period 0), so it would never switch such a
// rotation nor drop its previous secret, and what the revoked device knew
// would stay accepted. With a period its loop finishes them: the caller
// decides. The database must not be open elsewhere (rayd stopped). It
// returns the users renewed, by name.
func RenewOverlapRotations(ctx context.Context, path, actor, op string) ([]string, error) {
	s, err := Open(ctx, path)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	var names []string
	err = s.tx(ctx, func(tx *sql.Tx) error {
		now := s.now().Unix()
		rows, err := tx.QueryContext(ctx, `SELECT u.id, u.name FROM users u
			WHERE EXISTS (SELECT 1 FROM credentials c LEFT JOIN services s ON s.id = c.service_id
				WHERE c.user_id = u.id AND coalesce(s.kind, '') != 'doh'
				  AND ((c.next_secret IS NOT NULL
				        AND coalesce(c.rotated_at, c.created_at) <= (SELECT max(d.revoked_at) FROM devices d WHERE d.user_id = u.id))
				    OR (c.prev_secret IS NOT NULL AND c.prev_until > ?)))
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
				now, actor, "user.renew:"+op, fmt.Sprintf("%s: %d credentials new, a rotation a revocation with overlap began, "+
					"which the version rolled back to would not finish", u.name, n)); err != nil {
				return err
			}
			names = append(names, u.name)
		}
		return nil
	})
	return names, err
}

// RotationAt is the schedule stored in the database at path (StoredRotation
// of a Store with none set), read only: what the node's rayd ran with.
func RotationAt(ctx context.Context, path string) (Rotation, error) {
	s, err := OpenReadOnly(ctx, path)
	if err != nil {
		return Rotation{}, err
	}
	defer s.Close()
	return rotationIn(ctx, s.db, "main")
}
