package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// settingTrafficCounting "on" keeps the node counting users' traffic with
// no limit set (integrations-v1 §2.4); absent: only while some user has a
// limit, as before (traffic-limit-v1 §5).
const settingTrafficCounting = "traffic_counting"

// TrafficCountingOn reports whether the administrator keeps the counting
// on with no limit set (rayctl traffic counting on).
func (s *Store) TrafficCountingOn(ctx context.Context) (bool, error) {
	v, err := s.GetSetting(ctx, settingTrafficCounting)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return string(v) == "on", err
}

// SetTrafficCountingOn keeps the counting on, or back to while some user
// has a limit (off: "auto").
func (s *Store) SetTrafficCountingOn(ctx context.Context, on bool) error {
	if on {
		return s.SetSetting(ctx, settingTrafficCounting, []byte("on"))
	}
	return s.DeleteSetting(ctx, settingTrafficCounting)
}

// keepCountingKey marks a caller whose change may not turn the counting on
// or off.
type keepCountingKey struct{}

// KeepCounting is ctx for a caller whose change may not turn the node's
// traffic counting on or off: billing's (integrations-v1 §2.4). The first
// limit turns it on and the last one going off, and either restarts Xray,
// whose REALITY and inner connections all drop; an administrator keeps it
// on (rayctl traffic counting on) for billing to set limits.
func KeepCounting(ctx context.Context) context.Context {
	return context.WithValue(ctx, keepCountingKey{}, true)
}

func keepCounting(ctx context.Context) bool {
	v, _ := ctx.Value(keepCountingKey{}).(bool)
	return v
}

// ErrCountingFlip refuses a KeepCounting caller a change that would turn
// the counting on or off.
var ErrCountingFlip = fmt.Errorf("%w: this would turn the node's traffic counting on or off, and Xray restarts: an administrator keeps it on first (rayctl traffic counting on)", ErrPrecondition)

// limitedUsers counts the users with a traffic limit, in tx: the counting
// is on while there is one (render's Model.Traffic).
func limitedUsers(ctx context.Context, tx *sql.Tx) (int, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE traffic_limit_bytes IS NOT NULL`).Scan(&n)
	return n, err
}

// checkCounting, in a change's transaction after the change: for a
// KeepCounting caller, ErrCountingFlip when the users with a limit went
// from none (before) to some or back, unless the counting is kept on.
func checkCounting(ctx context.Context, tx *sql.Tx, before int) error {
	if !keepCounting(ctx) {
		return nil
	}
	after, err := limitedUsers(ctx, tx)
	if err != nil || (before == 0) == (after == 0) {
		return err
	}
	var on bool
	// The value is a blob, as SetSetting stores it: compared as one.
	err = tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM settings WHERE key = ? AND value = ?)`, settingTrafficCounting, []byte("on")).Scan(&on)
	if err != nil || on {
		return err
	}
	return ErrCountingFlip
}
