package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// RenewOverlapRotations gives new credentials at once, as a revocation
// without overlap does (R4-36), to every user of the database at path
// whose credentials but DoH's are in a rotation that a revocation with
// overlap began (R4-43) and that has not ended:
//   - not switched yet: a next secret, and a device of the user revoked
//     since the current secret became current (revokedSinceCurrent, the
//     chain's rule; a revocation without overlap renews in its own second
//     and is no such device, nor is a next the schedule published). Or one
//     revoked in the second of rotated_at, the next due within
//     RevocationChain leads of it: a revocation with overlap in the second
//     of a switch whose previous secret is gone (a renewal's next comes
//     from the schedule, a period on);
//   - switched, the previous secret still accepted (prev_until ahead): a
//     device of the user revoked in the RevocationChain leads (the stored
//     lead) before the switch, a revocation with overlap switching at most
//     a lead after it; a scheduled switch has none there (any revocation
//     after the schedule published renews or replaces its next), unless
//     the period is not longer than RevocationChain leads.
//
// Each gets a new LAN key where the user has one, and an audit line
// user.renew:<op> by actor, without a secret.
//
// For rayctl update -rollback, and update -version going back, when the
// rayd that goes in is one before v0.31.0: that rayd runs no rotation loop
// without a period (-cred-period 0), so it would never switch such a
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
		rot, err := rotationIn(ctx, tx, "main")
		if err != nil {
			return err
		}
		window := int64(RevocationChain * rot.Lead / time.Second)
		rows, err := tx.QueryContext(ctx, `SELECT u.id, u.name FROM users u
			WHERE EXISTS (SELECT 1 FROM credentials c LEFT JOIN services s ON s.id = c.service_id
				WHERE c.user_id = u.id AND coalesce(s.kind, '') != 'doh'
				  AND ((c.next_secret IS NOT NULL
				        AND EXISTS (SELECT 1 FROM devices d WHERE d.user_id = u.id
				                    AND (`+revokedSinceCurrent+`
				                         OR d.revoked_at = c.rotated_at AND c.next_from <= d.revoked_at + ?2)))
				    OR (c.prev_secret IS NOT NULL AND c.prev_until > ?1
				        AND EXISTS (SELECT 1 FROM devices d WHERE d.user_id = u.id
				                    AND d.revoked_at >= c.rotated_at - ?2 AND d.revoked_at < c.rotated_at))))
			ORDER BY u.name`, now, window)
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
