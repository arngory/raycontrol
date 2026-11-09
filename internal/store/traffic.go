package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// A user's traffic limit (docs/spec/traffic-limit-v1.md): up + down at the
// destinations' side, over a period. A user at or over the limit is taken
// off every data profile, as an expired one (Active).

// The periods of a limit.
const (
	// PeriodMonthly resets each month on the user's reset day, 00:00 UTC.
	PeriodMonthly = "monthly"
	// PeriodNone is the user's whole time (a package): only a reset by
	// the administrator zeroes it.
	PeriodNone = "none"
)

// MaxResetDay is the last reset day of a month: 29 to 31 are not in every
// month.
const MaxResetDay = 28

// trafficCap bounds a stored count (up, down), and trafficStep a delta
// added to it: a count and a step, and up + down, stay below 2^63, where
// Go wraps and SQLite turns the integer into a float (a process that
// counts is not trusted to report sane numbers). 2^61 bytes is 2 EiB.
const (
	trafficCap  = int64(1) << 61
	trafficStep = int64(1) << 60
)

// CheckTrafficPeriod checks a period and its reset day.
func CheckTrafficPeriod(period string, day int) error {
	if period != PeriodMonthly && period != PeriodNone {
		return fmt.Errorf("%w traffic period: use monthly or none", ErrInvalid) // not echoed: it reaches the audit
	}
	if day < 1 || day > MaxResetDay {
		return fmt.Errorf("%w reset day %d: use 1 to %d (29 to 31 are not in every month)", ErrInvalid, day, MaxResetDay)
	}
	return nil
}

// LastReset is the latest reset of a monthly period on day at or before
// now: that day of a month, 00:00 UTC.
func LastReset(now time.Time, day int) time.Time {
	n := now.UTC()
	t := time.Date(n.Year(), n.Month(), day, 0, 0, 0, 0, time.UTC)
	if t.After(n) {
		t = time.Date(n.Year(), n.Month()-1, day, 0, 0, 0, 0, time.UTC)
	}
	return t
}

// NextReset is the first reset of a monthly period on day after now.
func NextReset(now time.Time, day int) time.Time {
	l := LastReset(now, day)
	return time.Date(l.Year(), l.Month()+1, day, 0, 0, 0, 0, time.UTC)
}

// Limited reports whether the user has a traffic limit.
func (u User) Limited() bool { return u.TrafficLimit != nil }

// ResetDue reports whether the period's count is from before its last
// reset, and the reset: the moment the current period started. rayd
// writes the reset at its next poll; until then the count reads as zero.
func (u User) ResetDue(now time.Time) (bool, time.Time) {
	if !u.Limited() || u.TrafficPeriod != PeriodMonthly {
		return false, time.Time{}
	}
	last := LastReset(now, u.TrafficResetDay)
	return last.After(u.TrafficStart), last
}

// PeriodStart is the start of the current period at now; zero without a
// limit.
func (u User) PeriodStart(now time.Time) time.Time {
	if due, last := u.ResetDue(now); due {
		return last
	}
	return u.TrafficStart
}

// Used is up + down of the current period at now, as rayd last wrote it
// (a period that has reset since reads as zero).
func (u User) Used(now time.Time) int64 {
	if due, _ := u.ResetDue(now); due || !u.Limited() {
		return 0
	}
	return clampCount(u.TrafficUp) + clampCount(u.TrafficDown)
}

// NextResetAt is when the current period ends; zero without a limit and
// for PeriodNone.
func (u User) NextResetAt(now time.Time) time.Time {
	if !u.Limited() || u.TrafficPeriod != PeriodMonthly {
		return time.Time{}
	}
	return NextReset(now, u.TrafficResetDay)
}

// OverLimit reports whether the user has used up the limit at now.
func (u User) OverLimit(now time.Time) bool {
	return u.Limited() && u.Used(now) >= *u.TrafficLimit
}

// Live reports whether the user is enabled and not expired at now: their
// devices pass SPA (to the subscription at least) and get a subscription.
func (u User) Live(now time.Time) bool {
	return u.Enabled && (u.ExpiresAt == nil || u.ExpiresAt.After(now))
}

// Active reports whether the user may use the node's data profiles at now:
// live and not over the traffic limit. It is the one condition of the
// rendered configs, the subscription's profiles, SPA's data services, DoH
// and the metrics (traffic-limit-v1 §3.1).
func (u User) Active(now time.Time) bool {
	return u.Live(now) && !u.OverLimit(now)
}

// TrafficChange is what SetUserTraffic changes; nil leaves it.
type TrafficChange struct {
	Limit      *int64 // bytes; 0 removes the limit and its count
	Period     *string
	ResetDay   *int
	ResetUsage bool // the current period starts again from zero, now
}

// SetUserTraffic changes a user's limit, period, reset day, or zeroes the
// count, in one transaction, and returns the user as now stored:
//   - a first limit counts from now (period_start = counted_from = now);
//     removing it drops the count and the user's marks;
//   - a period or reset day changed does not zero the count: a reset due
//     under the old one is done first, then the period runs to the next
//     reset of the new one, starting no earlier than its last;
//   - ResetUsage zeroes the count from now.
func (s *Store) SetUserTraffic(ctx context.Context, name string, c TrafficChange) (User, error) {
	if c.Limit == nil && c.Period == nil && c.ResetDay == nil && !c.ResetUsage {
		return User{}, fmt.Errorf("%w: nothing to change", ErrInvalid)
	}
	if c.Limit != nil && *c.Limit < 0 {
		return User{}, fmt.Errorf("%w traffic limit %d: more than 0 bytes, or 0 for none", ErrInvalid, *c.Limit)
	}
	now := s.now().Truncate(time.Second)
	err := s.tx(ctx, func(tx *sql.Tx) error {
		u, err := scanUser(tx.QueryRowContext(ctx, userSelect+` WHERE u.name = ?`, name))
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("user %q: %w", name, ErrNotFound)
		}
		if err != nil {
			return err
		}
		hadRow := u.Limited() && !u.TrafficStart.IsZero()
		// A reset due under the settings the count ran with.
		if due, last := u.ResetDue(now); due && hadRow {
			if _, err := tx.ExecContext(ctx, `UPDATE user_traffic SET up = 0, down = 0, period_start = ? WHERE user_id = ?`,
				last.Unix(), u.ID); err != nil {
				return err
			}
			u.TrafficStart, u.TrafficUp, u.TrafficDown = last, 0, 0
		}
		period, day := u.TrafficPeriod, u.TrafficResetDay
		if c.Period != nil {
			period = *c.Period
		}
		if c.ResetDay != nil {
			day = *c.ResetDay
		}
		if err := CheckTrafficPeriod(period, day); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET traffic_period = ?, traffic_reset_day = ? WHERE id = ?`, period, day, u.ID); err != nil {
			return err
		}
		limited := u.Limited()
		switch {
		case c.Limit != nil && *c.Limit == 0:
			limited = false
			if _, err := tx.ExecContext(ctx, `UPDATE users SET traffic_limit_bytes = NULL WHERE id = ?`, u.ID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM user_traffic WHERE user_id = ?`, u.ID); err != nil {
				return err
			}
			if err := deleteMarks(ctx, tx, u.ID); err != nil {
				return err
			}
		case c.Limit != nil:
			limited = true
			if _, err := tx.ExecContext(ctx, `UPDATE users SET traffic_limit_bytes = ? WHERE id = ?`, *c.Limit, u.ID); err != nil {
				return err
			}
			if !hadRow {
				// Counted from now; marks of a limit before are stale.
				if err := deleteMarks(ctx, tx, u.ID); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO user_traffic (user_id, period_start, counted_from) VALUES (?, ?, ?)
					ON CONFLICT(user_id) DO UPDATE SET period_start = excluded.period_start, counted_from = excluded.counted_from, up = 0, down = 0`,
					u.ID, now.Unix(), now.Unix()); err != nil {
					return err
				}
				u.TrafficStart = now // a fresh period: nothing below moves it (hadRow is false)
			}
		}
		if !limited {
			if c.ResetUsage {
				return fmt.Errorf("%w: user %q has no traffic limit", ErrInvalid, name)
			}
			return nil
		}
		if c.ResetUsage {
			_, err := tx.ExecContext(ctx, `UPDATE user_traffic SET up = 0, down = 0, period_start = ? WHERE user_id = ?`, now.Unix(), u.ID)
			return err
		}
		// A new period or day: the period runs on to the next reset of the
		// new one, never from before its last reset (that would reset it at
		// once), and keeps its count.
		if hadRow && period == PeriodMonthly && (period != u.TrafficPeriod || day != u.TrafficResetDay) {
			if last := LastReset(now, day); last.After(u.TrafficStart) {
				_, err := tx.ExecContext(ctx, `UPDATE user_traffic SET period_start = ? WHERE user_id = ?`, last.Unix(), u.ID)
				return err
			}
		}
		return nil
	})
	if err != nil {
		return User{}, err
	}
	return s.UserByName(ctx, name)
}

// maxTrafficName bounds a counter's name: u, an ID of up to 19 digits, a
// dash and a credential's fingerprint (CredentialName).
const maxTrafficName = 1 + 19 + 1 + 2*credentialPrint

// TrafficUser is the user a counter's name belongs to: u<id> and the
// names of the user's credentials, u<id>-<fingerprint> (CredentialName).
// u<id>-n and u<id>-p are the names rayd before v0.23.0 gave the next and
// the previous credential: a process that runs across the update counts
// under them, and under u<id>, until it restarts.
func TrafficUser(name string) (int64, bool) {
	if len(name) < 2 || len(name) > maxTrafficName || name[0] != 'u' {
		return 0, false
	}
	digits, suffix, dashed := strings.Cut(name[1:], "-")
	if dashed && suffix != "n" && suffix != "p" && !isCredentialPrint(suffix) {
		return 0, false
	}
	if digits == "" || digits[0] == '0' {
		return 0, false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	id, err := strconv.ParseInt(digits, 10, 64)
	return id, err == nil
}

// deleteMarks forgets the marks of every name of a user: u<id> and
// u<id>-<anything> (marks are kept only of names TrafficUser reads, so
// these are the user's own).
func deleteMarks(ctx context.Context, tx *sql.Tx, user int64) error {
	n := "u" + strconv.FormatInt(user, 10)
	_, err := tx.ExecContext(ctx, `DELETE FROM traffic_marks WHERE name = ? OR name GLOB ?`, n, n+"-*")
	return err
}

// TrafficCounter is a name's bytes at a process that counts.
type TrafficCounter struct{ Up, Down int64 }

// TrafficSource is what rayd last took from a process that counts: its
// start as the process gives it, when, and the counters of the names of
// users with a limit then.
type TrafficSource struct {
	Boot   string
	Polled time.Time
	Marks  map[string]TrafficCounter
}

// TrafficSources returns what rayd last wrote of each process.
func (s *Store) TrafficSources(ctx context.Context) (map[string]TrafficSource, error) {
	out := map[string]TrafficSource{}
	rows, err := s.db.QueryContext(ctx, `SELECT source, boot, polled_at FROM traffic_sources`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var key string
		var src TrafficSource
		var at int64
		if err := rows.Scan(&key, &src.Boot, &at); err != nil {
			rows.Close()
			return nil, err
		}
		src.Polled, src.Marks = time.Unix(at, 0), map[string]TrafficCounter{}
		out[key] = src
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT source, name, up, down FROM traffic_marks`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var key, name string
		var c TrafficCounter
		if err := rows.Scan(&key, &name, &c.Up, &c.Down); err != nil {
			return nil, err
		}
		if src, ok := out[key]; ok {
			src.Marks[name] = c
		}
	}
	return out, rows.Err()
}

// TrafficReset moves a user's period on: zero from To, if it still starts
// at From.
type TrafficReset struct {
	UserID   int64
	From, To time.Time
}

// TrafficAdd adds bytes to a user's period, if it still starts at Start:
// a period reset or a limit removed meanwhile drops them.
type TrafficAdd struct {
	UserID   int64
	Start    time.Time
	Up, Down int64
}

// TrafficWrite is one write of rayd's count: resets, then deltas, and the
// processes' marks they were taken against, in one transaction. A crash
// before it loses nothing that the next poll does not count again from
// the marks before; after it, nothing is counted twice.
type TrafficWrite struct {
	// Start gives users with a limit and no count one, from now.
	Start  []int64
	Resets []TrafficReset
	Adds   []TrafficAdd
	// Sources replaces each named source's start, poll time and marks.
	Sources map[string]TrafficSource
	// Drop forgets these sources (a service deleted or disabled).
	Drop []string
}

// WriteTraffic applies w.
func (s *Store) WriteTraffic(ctx context.Context, w TrafficWrite) error {
	now := s.now().Unix()
	return s.tx(ctx, func(tx *sql.Tx) error {
		for _, id := range w.Start {
			if _, err := tx.ExecContext(ctx, `INSERT INTO user_traffic (user_id, period_start, counted_from)
				SELECT id, ?, ? FROM users WHERE id = ? AND traffic_limit_bytes IS NOT NULL
				ON CONFLICT(user_id) DO NOTHING`, now, now, id); err != nil {
				return err
			}
		}
		for _, r := range w.Resets {
			if _, err := tx.ExecContext(ctx, `UPDATE user_traffic SET up = 0, down = 0, period_start = ? WHERE user_id = ? AND period_start = ?`,
				r.To.Unix(), r.UserID, r.From.Unix()); err != nil {
				return err
			}
		}
		for _, a := range w.Adds {
			up, down := clampStep(a.Up), clampStep(a.Down)
			if up == 0 && down == 0 {
				continue
			}
			if _, err := tx.ExecContext(ctx, `UPDATE user_traffic SET up = min(up + ?, ?), down = min(down + ?, ?)
				WHERE user_id = ? AND period_start = ?`, up, trafficCap, down, trafficCap, a.UserID, a.Start.Unix()); err != nil {
				return err
			}
		}
		for _, key := range w.Drop {
			if _, err := tx.ExecContext(ctx, `DELETE FROM traffic_sources WHERE source = ?`, key); err != nil {
				return err
			}
		}
		for key, src := range w.Sources {
			if _, err := tx.ExecContext(ctx, `INSERT INTO traffic_sources (source, boot, polled_at) VALUES (?, ?, ?)
				ON CONFLICT(source) DO UPDATE SET boot = excluded.boot, polled_at = excluded.polled_at`,
				key, src.Boot, src.Polled.Unix()); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM traffic_marks WHERE source = ?`, key); err != nil {
				return err
			}
			for name, c := range src.Marks {
				if _, err := tx.ExecContext(ctx, `INSERT INTO traffic_marks (source, name, up, down) VALUES (?, ?, ?, ?)`,
					key, name, clampCount(c.Up), clampCount(c.Down)); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// ClearTraffic forgets every source and mark: no user has a limit, no
// process is read.
func (s *Store) ClearTraffic(ctx context.Context) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM traffic_marks`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM traffic_sources`)
		return err
	})
}

func clampStep(n int64) int64  { return min(max(n, 0), trafficStep) }
func clampCount(n int64) int64 { return min(max(n, 0), trafficCap) }
