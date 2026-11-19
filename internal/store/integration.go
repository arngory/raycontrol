package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// IntegrationRole reports a device role of an integration: billing or
// support (integrations-v1 §2.1).
func IntegrationRole(role string) bool { return role == "billing" || role == "support" }

// NotForIntegrationDevices reports a kind of service a device made of an
// integration's invite never reaches, whatever its user has: an
// integration gives data services only, and its user may turn into a
// service user later (integrations-v1 §2.2).
func NotForIntegrationDevices(kind string) bool {
	return kind == "ssh" || kind == "api" || kind == "site"
}

// validRole is a device role the node knows.
func validRole(role string) bool { return role == "user" || role == "admin" || IntegrationRole(role) }

// regularOnlyKey marks the context of a caller that sees regular users
// only.
type regularOnlyKey struct{}

// RegularOnly is ctx for a caller that sees regular users only: an
// integration's device (integrations-v1 §2.2). Service users are not
// listed to it, a call that names one is ErrNotFound as for an unknown
// one, and the check is in the statement or transaction that makes the
// change: a user that turns into a service user between a list and a call
// is out of reach all the same.
func RegularOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, regularOnlyKey{}, true)
}

// AllUsers is ctx for a read of the whole node by a caller of RegularOnly:
// the counts of the status and the metrics, numbers only, the same for
// every role (integrations-v1 §2.2).
func AllUsers(ctx context.Context) context.Context {
	return context.WithValue(ctx, regularOnlyKey{}, false)
}

// regularOnly reports a caller of RegularOnly: the bool argument of the
// statements below that leave out service users.
func regularOnly(ctx context.Context) bool {
	v, _ := ctx.Value(regularOnlyKey{}).(bool)
	return v
}

// serviceUserIDs selects the service users (integrations-v1 §2.2): a
// device not revoked or an invite not used of a role other than user
// (admin, billing, support), or a service of kind ssh or api. An unused
// invite counts until it is withdrawn or pruned, expired or not. The
// statements take it as `AND NOT (? AND u.id IN (serviceUserIDs))`, the
// argument regularOnly(ctx): one statement, one snapshot.
const serviceUserIDs = `SELECT sd.user_id FROM devices sd WHERE sd.revoked_at IS NULL AND sd.role != 'user'
	UNION SELECT si.user_id FROM invites si WHERE si.used_at IS NULL AND si.role != 'user'
	UNION SELECT sus.user_id FROM user_services sus JOIN services ss ON ss.id = sus.service_id WHERE ss.kind IN ('ssh', 'api')`

// hasIntegration is true for a user with a device not revoked or an
// invite not used of an integration's role: such a user has no services
// (integrations-v1 §2.1), so that a revocation of its device changes no
// person's credentials (R4-36).
const hasIntegration = `EXISTS (SELECT 1 FROM devices WHERE user_id = ?1 AND revoked_at IS NULL AND role IN ('billing', 'support'))
	OR EXISTS (SELECT 1 FROM invites WHERE user_id = ?1 AND used_at IS NULL AND role IN ('billing', 'support'))`

// ErrIntegrationUser refuses services to the user of an integration's
// device or invite, and such an invite to a user with services.
var ErrIntegrationUser = fmt.Errorf("%w: the user of an integration's device has no services (integrations-v1 §2.1)", ErrPrecondition)

// SetUserExpiry sets when a user expires: at, nil for never; a time not
// after now is now, so that the user expires at once (integrations-v1
// §10). A user expired already stays as it is for another such time, and
// a repeated call leaves the same state. It returns the user as stored.
func (s *Store) SetUserExpiry(ctx context.Context, name string, at *time.Time) (User, error) {
	now := s.now().Truncate(time.Second)
	if at != nil && at.Unix() > maxExpiry {
		return User{}, fmt.Errorf("%w expiry %d: after the year 9999", ErrInvalid, at.Unix())
	}
	var u User
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var id int64
		var exp sql.NullInt64
		err := tx.QueryRowContext(ctx, `SELECT u.id, u.expires_at FROM users u WHERE u.name = ? AND NOT (? AND u.id IN (`+serviceUserIDs+`))`,
			name, regularOnly(ctx)).Scan(&id, &exp)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("user %q: %w", name, ErrNotFound)
		}
		if err != nil {
			return err
		}
		value := nullTime(at)
		if at != nil && !at.After(now) {
			value = now.Unix()
			if exp.Valid && exp.Int64 <= now.Unix() {
				value = exp.Int64 // expired already: its time stays
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET expires_at = ? WHERE id = ?`, value, id); err != nil {
			return err
		}
		if u, err = scanUser(tx.QueryRowContext(ctx, userSelect+` WHERE u.id = ?`, id)); err != nil {
			return err
		}
		u.Services, err = userServices(ctx, tx, u.ID)
		return err
	})
	if err != nil {
		return User{}, err
	}
	return u, nil
}

// maxExpiry is the last second of the year 9999: an expiry later than any
// time a client shows.
const maxExpiry = 253402300799
