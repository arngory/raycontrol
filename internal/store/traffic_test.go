package store

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func utc(y int, m time.Month, d, h int) time.Time { return time.Date(y, m, d, h, 0, 0, 0, time.UTC) }

// The reset day at the ends of months and years: day 28 is in every month,
// the reset is at 00:00 UTC on the day, and that moment is already the new
// period.
func TestResetMaths(t *testing.T) {
	for _, c := range []struct {
		now        time.Time
		day        int
		last, next time.Time
	}{
		{utc(2026, 11, 8, 12), 1, utc(2026, 11, 1, 0), utc(2026, 12, 1, 0)},
		{utc(2026, 12, 31, 23), 1, utc(2026, 12, 1, 0), utc(2027, 1, 1, 0)},
		{utc(2027, 1, 1, 0), 1, utc(2027, 1, 1, 0), utc(2027, 2, 1, 0)},
		{utc(2026, 1, 10, 0), 15, utc(2025, 12, 15, 0), utc(2026, 1, 15, 0)},
		{utc(2026, 1, 31, 23), 28, utc(2026, 1, 28, 0), utc(2026, 2, 28, 0)},
		{utc(2026, 2, 28, 0), 28, utc(2026, 2, 28, 0), utc(2026, 3, 28, 0)},
		{utc(2026, 2, 27, 23), 28, utc(2026, 1, 28, 0), utc(2026, 2, 28, 0)},
		{utc(2028, 2, 29, 12), 28, utc(2028, 2, 28, 0), utc(2028, 3, 28, 0)},
		{utc(2026, 3, 1, 0).Add(-time.Second), 1, utc(2026, 2, 1, 0), utc(2026, 3, 1, 0)},
		// Another zone: the day is UTC's.
		{time.Date(2026, 12, 1, 1, 0, 0, 0, time.FixedZone("UTC+3", 3*3600)), 1, utc(2026, 11, 1, 0), utc(2026, 12, 1, 0)},
		{time.Date(2027, 3, 1, 0, 0, 0, 0, time.FixedZone("UTC+3", 3*3600)), 1, utc(2027, 2, 1, 0), utc(2027, 3, 1, 0)},
		// A year without 29 February, across a year back.
		{utc(2027, 2, 28, 0), 28, utc(2027, 2, 28, 0), utc(2027, 3, 28, 0)},
		{utc(2027, 2, 28, 0).Add(-time.Second), 28, utc(2027, 1, 28, 0), utc(2027, 2, 28, 0)},
		{utc(2027, 1, 1, 0), 1, utc(2027, 1, 1, 0), utc(2027, 2, 1, 0)},
		{utc(2027, 1, 1, 0).Add(-time.Second), 1, utc(2026, 12, 1, 0), utc(2027, 1, 1, 0)},
		{utc(2027, 1, 5, 0), 10, utc(2026, 12, 10, 0), utc(2027, 1, 10, 0)},
	} {
		if got := LastReset(c.now, c.day); !got.Equal(c.last) {
			t.Errorf("LastReset(%v, %d) = %v, want %v", c.now, c.day, got, c.last)
		}
		if got := NextReset(c.now, c.day); !got.Equal(c.next) {
			t.Errorf("NextReset(%v, %d) = %v, want %v", c.now, c.day, got, c.next)
		}
	}
	for _, day := range []int{0, 29, 31, -1} {
		if err := CheckTrafficPeriod(PeriodMonthly, day); !errors.Is(err, ErrInvalid) {
			t.Errorf("day %d: %v", day, err)
		}
	}
	if err := CheckTrafficPeriod("weekly", 1); !errors.Is(err, ErrInvalid) {
		t.Errorf("weekly: %v", err)
	}
}

func TestUserTrafficState(t *testing.T) {
	limit := int64(1000)
	now := utc(2026, 11, 20, 12)
	u := User{Enabled: true, TrafficLimit: &limit, TrafficPeriod: PeriodMonthly, TrafficResetDay: 15,
		TrafficStart: utc(2026, 11, 15, 0), TrafficUp: 600, TrafficDown: 400}
	if !u.OverLimit(now) || u.Active(now) || !u.Live(now) || u.Used(now) != 1000 {
		t.Fatalf("over %v active %v used %d", u.OverLimit(now), u.Active(now), u.Used(now))
	}
	// One byte short: active.
	u.TrafficDown = 399
	if u.OverLimit(now) || !u.Active(now) {
		t.Fatal("over at 999 of 1000")
	}
	u.TrafficDown = 400
	// The next reset passed: zero, whatever was written.
	later := utc(2026, 12, 15, 0)
	if u.OverLimit(later) || u.Used(later) != 0 || !u.PeriodStart(later).Equal(later) || !u.NextResetAt(later).Equal(utc(2027, 1, 15, 0)) {
		t.Fatalf("after the reset: used %d since %v", u.Used(later), u.PeriodStart(later))
	}
	// none: never resets.
	u.TrafficPeriod = PeriodNone
	if !u.OverLimit(later) || !u.NextResetAt(later).IsZero() {
		t.Fatal("none reset")
	}
	// Disabled and expired are not active either, whatever the count;
	// without a limit nothing is over.
	u.TrafficLimit = nil
	if u.OverLimit(now) || u.Used(now) != 0 || !u.Active(now) {
		t.Fatal("no limit")
	}
	u.Enabled = false
	if u.Active(now) || u.Live(now) {
		t.Fatal("disabled active")
	}
	past := now.Add(-time.Second)
	u.Enabled, u.ExpiresAt = true, &past
	if u.Active(now) || u.Live(now) {
		t.Fatal("expired active")
	}
}

func TestSetUserTraffic(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := utc(2026, 11, 8, 12)
	s.now = func() time.Time { return now }
	if _, err := s.CreateUser(ctx, User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetUserTraffic(ctx, "alice", TrafficChange{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an empty change: %v", err)
	}
	if _, err := s.SetUserTraffic(ctx, "alice", TrafficChange{ResetUsage: true}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a reset without a limit: %v", err)
	}
	if _, err := s.SetUserTraffic(ctx, "bob", TrafficChange{ResetUsage: true}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no such user: %v", err)
	}
	neg := int64(-1)
	if _, err := s.SetUserTraffic(ctx, "alice", TrafficChange{Limit: &neg}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a negative limit: %v", err)
	}
	day29 := 29
	if _, err := s.SetUserTraffic(ctx, "alice", TrafficChange{ResetDay: &day29}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("day 29: %v", err)
	}
	if any, err := s.HasTrafficLimits(ctx); err != nil || any {
		t.Fatalf("limits before any: %v %v", any, err)
	}
	// A first limit counts from now: the first period is shorter.
	limit := int64(1 << 30)
	u, err := s.SetUserTraffic(ctx, "alice", TrafficChange{Limit: &limit})
	if err != nil {
		t.Fatal(err)
	}
	if !u.TrafficStart.Equal(now) || !u.TrafficCountedFrom.Equal(now) || u.TrafficPeriod != PeriodMonthly || u.TrafficResetDay != 1 ||
		!u.NextResetAt(now).Equal(utc(2026, 12, 1, 0)) {
		t.Fatalf("first limit: %+v", u)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE user_traffic SET up = 100, down = 200`); err != nil {
		t.Fatal(err)
	}
	// A new day does not zero the count: the period runs to the new day.
	now = utc(2026, 11, 20, 12)
	day := 15
	if u, err = s.SetUserTraffic(ctx, "alice", TrafficChange{ResetDay: &day}); err != nil {
		t.Fatal(err)
	}
	if u.Used(now) != 300 || !u.PeriodStart(now).Equal(utc(2026, 11, 15, 0)) || !u.NextResetAt(now).Equal(utc(2026, 12, 15, 0)) {
		t.Fatalf("day 15: used %d since %v next %v", u.Used(now), u.PeriodStart(now), u.NextResetAt(now))
	}
	// Back to day 1: no reset either, the count stays.
	day = 1
	if u, err = s.SetUserTraffic(ctx, "alice", TrafficChange{ResetDay: &day}); err != nil {
		t.Fatal(err)
	}
	if u.Used(now) != 300 || !u.NextResetAt(now).Equal(utc(2026, 12, 1, 0)) {
		t.Fatalf("day 1: used %d next %v", u.Used(now), u.NextResetAt(now))
	}
	// none, and back to monthly: the count stays.
	none, monthly := PeriodNone, PeriodMonthly
	if u, err = s.SetUserTraffic(ctx, "alice", TrafficChange{Period: &none}); err != nil || u.Used(now) != 300 || !u.NextResetAt(now).IsZero() {
		t.Fatalf("none: %v, used %d", err, u.Used(now))
	}
	now = utc(2027, 2, 3, 0)
	if u, err = s.SetUserTraffic(ctx, "alice", TrafficChange{Period: &monthly}); err != nil || u.Used(now) != 300 {
		t.Fatalf("monthly again: %v, used %d", err, u.Used(now))
	}
	// A raised limit keeps the count and the start.
	limit = 1 << 31
	if u, err = s.SetUserTraffic(ctx, "alice", TrafficChange{Limit: &limit}); err != nil || u.Used(now) != 300 || !u.TrafficCountedFrom.Equal(utc(2026, 11, 8, 12)) {
		t.Fatalf("raised: %v, used %d", err, u.Used(now))
	}
	// A reset by the administrator: zero from now.
	if u, err = s.SetUserTraffic(ctx, "alice", TrafficChange{ResetUsage: true}); err != nil || u.Used(now) != 0 || !u.TrafficStart.Equal(now) {
		t.Fatalf("reset: %v, used %d since %v", err, u.Used(now), u.TrafficStart)
	}
	// Off: the count and the marks of the user's names go.
	if err := s.WriteTraffic(ctx, TrafficWrite{Sources: map[string]TrafficSource{"hy2:h": {Boot: "b", Polled: now,
		Marks: map[string]TrafficCounter{"u1": {1, 2}, "u1-n": {3, 4}, "u10": {5, 6}}}}}); err != nil {
		t.Fatal(err)
	}
	off := int64(0)
	if any, err := s.HasTrafficLimits(ctx); err != nil || !any {
		t.Fatalf("limits with one: %v %v", any, err)
	}
	if u, err = s.SetUserTraffic(ctx, "alice", TrafficChange{Limit: &off}); err != nil || u.Limited() || !u.TrafficStart.IsZero() {
		t.Fatalf("off: %v %+v", err, u)
	}
	if any, err := s.HasTrafficLimits(ctx); err != nil || any {
		t.Fatalf("limits after off: %v %v", any, err)
	}
	srcs, err := s.TrafficSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if m := srcs["hy2:h"].Marks; len(m) != 1 || m["u10"] != (TrafficCounter{5, 6}) {
		t.Fatalf("marks %v", m)
	}
	var rows int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM user_traffic`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("%d rows, %v", rows, err)
	}
}

// A reset due under the old day is done before a new day applies: the
// count of a period that ended is not carried into the new one.
func TestSetUserTrafficSettlesTheReset(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := utc(2026, 10, 15, 12)
	s.now = func() time.Time { return now }
	limit := int64(1 << 30)
	if _, err := s.CreateUser(ctx, User{Name: "alice", Enabled: true, TrafficLimit: &limit, TrafficResetDay: 15}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE user_traffic SET up = 100, down = 200`); err != nil {
		t.Fatal(err)
	}
	now = utc(2026, 11, 20, 0) // past the 15th: the count is of the period before
	day := 1
	u, err := s.SetUserTraffic(ctx, "alice", TrafficChange{ResetDay: &day})
	if err != nil {
		t.Fatal(err)
	}
	if u.TrafficUp != 0 || u.TrafficDown != 0 || !u.TrafficStart.Equal(utc(2026, 11, 15, 0)) {
		t.Fatalf("used %d/%d since %v", u.TrafficUp, u.TrafficDown, u.TrafficStart)
	}
}

func TestWriteTrafficGuards(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := utc(2026, 11, 8, 12)
	s.now = func() time.Time { return now }
	limit := int64(1 << 30)
	u, err := s.CreateUser(ctx, User{Name: "alice", Enabled: true, TrafficLimit: &limit})
	if err != nil {
		t.Fatal(err)
	}
	// Bytes of another period (a reset since) are dropped; a reset from a
	// start the period no longer has is not done.
	if err := s.WriteTraffic(ctx, TrafficWrite{
		Adds:   []TrafficAdd{{UserID: u.ID, Start: now.Add(-time.Hour), Up: 5, Down: 5}, {UserID: u.ID, Start: now, Up: 7, Down: 9}},
		Resets: []TrafficReset{{UserID: u.ID, From: now.Add(-time.Hour), To: now.Add(time.Hour)}},
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.UserByName(ctx, "alice")
	if got.TrafficUp != 7 || got.TrafficDown != 9 || !got.TrafficStart.Equal(now) {
		t.Fatalf("used %d/%d since %v", got.TrafficUp, got.TrafficDown, got.TrafficStart)
	}
	// Huge and negative deltas: capped, never wrapped.
	for range 8 {
		if err := s.WriteTraffic(ctx, TrafficWrite{Adds: []TrafficAdd{{UserID: u.ID, Start: now, Up: 1<<63 - 1, Down: -1}}}); err != nil {
			t.Fatal(err)
		}
	}
	got, _ = s.UserByName(ctx, "alice")
	if got.TrafficUp != trafficCap || got.TrafficDown != 9 || got.Used(now) != trafficCap+9 || !got.OverLimit(now) {
		t.Fatalf("used %d/%d", got.TrafficUp, got.TrafficDown)
	}
}

func TestTrafficUser(t *testing.T) {
	for name, want := range map[string]int64{"u1": 1, "u5-n": 5, "u17-p": 17, "u123456789": 123456789} {
		if id, ok := TrafficUser(name); !ok || id != want {
			t.Errorf("%s: %d %v", name, id, ok)
		}
	}
	for _, name := range []string{"", "u", "u0", "u01", "u-n", "u5-x", "u5-", "x5", "u5n", "u 5", "u+5", "u99999999999999999999", "probe", "u5-n-n"} {
		if id, ok := TrafficUser(name); ok {
			t.Errorf("%q: %d", name, id)
		}
	}
	for _, id := range []int64{1, 9, 4242} {
		for _, n := range TrafficNames(id) {
			if got, ok := TrafficUser(n); !ok || got != id {
				t.Errorf("%s: %d", n, got)
			}
		}
	}
}

// A limit recorded before v0.22.0 ("not enforced") holds after the update,
// counted from then (owner's decision 2); a limit of 0 or less is none.
func TestTrafficMigration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "rayd.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	// Back to schema 11, with users as v0.21.0 recorded them.
	for _, q := range []string{
		`DELETE FROM schema_migrations WHERE version = 12`,
		`DROP TABLE traffic_marks`, `DROP TABLE traffic_sources`, `DROP TABLE user_traffic`,
		`ALTER TABLE users DROP COLUMN traffic_period`, `ALTER TABLE users DROP COLUMN traffic_reset_day`,
		`INSERT INTO users (name, enabled, traffic_limit_bytes, created_at) VALUES ('alice', 1, 53687091200, 1), ('bob', 1, NULL, 1), ('carol', 1, -5, 1)`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	s.Close()
	before := time.Now().Add(-time.Second)
	if s, err = Open(ctx, path); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	users, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var limited []string
	for _, u := range users {
		if u.TrafficPeriod != PeriodMonthly || u.TrafficResetDay != 1 {
			t.Errorf("%s: %s %d", u.Name, u.TrafficPeriod, u.TrafficResetDay)
		}
		if u.Limited() {
			limited = append(limited, u.Name)
			if u.TrafficStart.Before(before) || !u.TrafficCountedFrom.Equal(u.TrafficStart) || u.Used(time.Now()) != 0 || !u.Active(time.Now()) {
				t.Errorf("%s: %+v", u.Name, u)
			}
		}
	}
	if !slices.Equal(limited, []string{"alice"}) {
		t.Fatalf("limited %v", limited)
	}
}

// SPA for a user over the limit: the subscription and, for an admin
// device registered through the API, the API; no data service. A disabled
// user's devices pass nowhere.
func TestSPADevicesOverLimit(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	sub, _ := s.CreateService(ctx, Service{Kind: "subscription", Name: "sub", Enabled: true})
	api, _ := s.CreateService(ctx, Service{Kind: "api", Name: "api", Enabled: true})
	hy, _ := s.CreateService(ctx, Service{Kind: "hy2-masq", Name: "hy", Enabled: true})
	dns, _ := s.CreateService(ctx, Service{Kind: "dnstt", Name: "dns", Enabled: true})
	limit := int64(1000)
	u, err := s.CreateUser(ctx, User{Name: "alice", Enabled: true, TrafficLimit: &limit})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserServices(ctx, "alice", []int64{hy.ID, dns.ID}); err != nil {
		t.Fatal(err)
	}
	phone, _, err := s.CreateDevice(ctx, "alice", "phone", "user")
	if err != nil {
		t.Fatal(err)
	}
	admin, _, err := s.CreateDevice(ctx, "alice", "laptop", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE devices SET cert_pin = 'pin' WHERE id = ?`, admin.ID); err != nil {
		t.Fatal(err)
	}
	scopes := func() map[string][]uint16 {
		t.Helper()
		ds, err := s.SPADevices(ctx)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string][]uint16{}
		for _, d := range ds {
			out[d.ID] = d.Allowed
		}
		return out
	}
	id := func(svc Service) uint16 { return uint16(svc.ID) }
	got := scopes()
	if !slices.Equal(got[phone.ID], []uint16{id(sub), id(hy), id(dns)}) || !slices.Equal(got[admin.ID], []uint16{id(sub), id(api), id(hy), id(dns)}) {
		t.Fatalf("under the limit: %v", got)
	}
	if err := s.WriteTraffic(ctx, TrafficWrite{Adds: []TrafficAdd{{UserID: u.ID, Start: u.TrafficStart, Up: 600, Down: 400}}}); err != nil {
		t.Fatal(err)
	}
	got = scopes()
	if !slices.Equal(got[phone.ID], []uint16{id(sub)}) || !slices.Equal(got[admin.ID], []uint16{id(sub), id(api)}) {
		t.Fatalf("over the limit: %v", got)
	}
	if err := s.SetUserEnabled(ctx, "alice", false); err != nil {
		t.Fatal(err)
	}
	if got = scopes(); len(got) != 0 {
		t.Fatalf("disabled: %v", got)
	}
}
