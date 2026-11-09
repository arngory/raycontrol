package traffic

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// node is a store with services and users, sources the test feeds, and a
// clock the test moves.
type node struct {
	t     *testing.T
	ctx   context.Context
	path  string
	st    *store.Store
	now   time.Time     // the wall clock: never on a whole second, as the real one
	mono  time.Duration // the monotonic clock: a step of the wall clock leaves it
	hb    *health.Board
	woken int

	mu       sync.Mutex
	readings map[string]Reading // by source key; missing: the read fails
	reads    int
	delay    time.Duration // each read takes this long
	gone     string        // this source's socket is not there
}

func newNode(t *testing.T) *node {
	t.Helper()
	n := &node{t: t, ctx: context.Background(), path: filepath.Join(t.TempDir(), "node.db"), hb: &health.Board{},
		now: time.Date(2026, 11, 8, 12, 0, 0, 123456789, time.UTC), mono: time.Hour, readings: map[string]Reading{}}
	n.open()
	for _, s := range []store.Service{{Kind: "hy2-masq", Name: "hy"}, {Kind: "naive", Name: "nv"}, {Kind: "inner", Name: "inner"}, {Kind: "dnstt", Name: "dns"}} {
		s.Enabled = true
		if _, err := n.st.CreateService(n.ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	return n
}

func (n *node) open() {
	st, err := store.Open(n.ctx, n.path)
	if err != nil {
		n.t.Fatal(err)
	}
	n.t.Cleanup(func() { st.Close() })
	st.SetClock(func() time.Time { return n.now })
	n.st = st
}

// accountant is a fresh loop over the node: what rayd has after a start.
func (n *node) accountant() *Accountant {
	return &Accountant{Store: n.st, Health: n.hb, Now: func() time.Time { return n.now }, Notify: func() { n.woken++ },
		Sources: func(services []store.Service) []Source {
			var out []Source
			for _, s := range Processes(testPaths)(services) {
				key := s.Key
				s.Read = func(context.Context, time.Time) (Reading, error) {
					time.Sleep(n.delay)
					n.mu.Lock()
					defer n.mu.Unlock()
					n.reads++
					if key == n.gone {
						return Reading{}, &fs.PathError{Op: "dial", Path: key, Err: fs.ErrNotExist}
					}
					r, ok := n.readings[key]
					if !ok {
						return Reading{}, errors.New("not running")
					}
					if !r.Start.IsZero() {
						r.Mono = n.mono // Xray's: the clock at the read
					}
					return r, nil
				}
				out = append(out, s)
			}
			return out
		}}
}

func (n *node) user(name string, limit int64, services ...string) store.User {
	n.t.Helper()
	u := store.User{Name: name, Enabled: true}
	if limit > 0 {
		u.TrafficLimit = &limit
	}
	u, err := n.st.CreateUser(n.ctx, u)
	if err != nil {
		n.t.Fatal(err)
	}
	var ids []int64
	for _, s := range services {
		svc, err := n.st.ServiceByName(n.ctx, s)
		if err != nil {
			n.t.Fatal(err)
		}
		ids = append(ids, svc.ID)
	}
	if err := n.st.SetUserServices(n.ctx, name, ids); err != nil {
		n.t.Fatal(err)
	}
	// Within one second the loop cannot tell a limit from a poll: it
	// counts from the poll after (less, never more). The tests set limits
	// a second ahead.
	n.tick(time.Second)
	return u
}

// set makes a source read these counters, name, up, down, ...
func (n *node) set(key, boot string, counters ...any) {
	n.mu.Lock()
	defer n.mu.Unlock()
	r := Reading{Boot: boot, Users: map[string]store.TrafficCounter{}}
	for i := 0; i+2 < len(counters); i += 3 {
		r.Users[counters[i].(string)] = store.TrafficCounter{Up: int64(counters[i+1].(int)), Down: int64(counters[i+2].(int))}
	}
	n.readings[key] = r
}

// setXray makes inner's Xray read these counters with this uptime, as
// ReadXray gives them: its start from the wall clock, the read's
// monotonic time.
func (n *node) setXray(uptime time.Duration, counters ...any) {
	start := n.now.Add(-uptime).Truncate(time.Second)
	n.set("xray:inner", xrayBoot+strconv.FormatInt(start.Unix(), 10), counters...)
	n.mu.Lock()
	defer n.mu.Unlock()
	r := n.readings["xray:inner"]
	r.Start, r.Uptime = start, uptime
	n.readings["xray:inner"] = r
}

func (n *node) stop(key string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.readings, key)
}

// tick moves both clocks; step only the wall clock (NTP).
func (n *node) tick(d time.Duration) { n.now, n.mono = n.now.Add(d), n.mono+d }
func (n *node) step(d time.Duration) { n.now = n.now.Add(d) }

// used is a user's count as stored.
func (n *node) used(name string) (up, down int64) {
	n.t.Helper()
	u, err := n.st.UserByName(n.ctx, name)
	if err != nil {
		n.t.Fatal(err)
	}
	return u.TrafficUp, u.TrafficDown
}

func (n *node) wantUsed(name string, up, down int64) {
	n.t.Helper()
	if gu, gd := n.used(name); gu != up || gd != down {
		n.t.Fatalf("%s used %d/%d, want %d/%d", name, gu, gd, up, down)
	}
}

func (n *node) audits() []string {
	n.t.Helper()
	es, err := n.st.ListAudit(n.ctx, 100)
	if err != nil {
		n.t.Fatal(err)
	}
	var out []string
	for i := len(es) - 1; i >= 0; i-- {
		if strings.HasPrefix(es[i].Action, "user.traffic=") {
			out = append(out, es[i].Actor+" "+es[i].Action+" "+es[i].Target)
		}
	}
	return out
}

func TestCounting(t *testing.T) {
	n := newNode(t)
	n.user("alice", 1<<30, "hy")
	a := n.accountant()

	// The limit was set before the process was first read: whatever its
	// counter holds is from before the limit, and only what grows counts.
	n.set("hy2:hy", "b1", "u1", 1000, 5000)
	n.tick(time.Second)
	a.Round(n.ctx, "", false)
	n.wantUsed("alice", 0, 0)

	n.set("hy2:hy", "b1", "u1", 1100, 5300)
	n.tick(Every)
	a.Round(n.ctx, "", false)
	// Written once a minute: not yet.
	n.wantUsed("alice", 0, 0)
	n.tick(time.Minute)
	a.Round(n.ctx, "", false)
	n.wantUsed("alice", 100, 300)

	// A new run of the process: its counters are all new, above the
	// marks of the run before or not.
	n.set("hy2:hy", "b2", "u1", 50, 6000)
	n.tick(Every)
	a.Round(n.ctx, "", true)
	n.wantUsed("alice", 150, 6300)

	// A counter that goes back within the same run is taken as new too.
	n.set("hy2:hy", "b2", "u1", 70, 10)
	n.tick(Every)
	a.Round(n.ctx, "", true)
	n.wantUsed("alice", 170, 6310)

	// A name new to the process (a credential rotating): all of it.
	n.set("hy2:hy", "b2", "u1", 70, 10, "u1-n", 7, 3)
	n.tick(Every)
	a.Round(n.ctx, "", true)
	n.wantUsed("alice", 177, 6313)

	if n.woken != 0 || len(n.audits()) != 0 {
		t.Fatalf("woken %d, audits %v", n.woken, n.audits())
	}
}

// rayd dies between a poll and its write: the next rayd counts from the
// marks it wrote last, so the bytes are counted once, neither lost nor
// twice.
func TestCrashBetweenPollAndWrite(t *testing.T) {
	n := newNode(t)
	n.user("alice", 1<<30, "hy", "nv")
	a := n.accountant()
	n.set("hy2:hy", "b1", "u1", 0, 0)
	n.set("naive:nv", "n1", "u1", 0, 0)
	a.Round(n.ctx, "", false) // baseline, written
	n.tick(time.Minute)
	n.set("hy2:hy", "b1", "u1", 100, 1000)
	n.set("naive:nv", "n1", "u1", 1, 10)
	a.Round(n.ctx, "", false) // written
	n.wantUsed("alice", 101, 1010)

	n.tick(Every)
	n.set("hy2:hy", "b1", "u1", 300, 3000)
	n.set("naive:nv", "n1", "u1", 3, 30)
	a.Round(n.ctx, "", false) // pending, not written
	n.wantUsed("alice", 101, 1010)

	// The crash: a new loop over the same database.
	n.st.Close()
	n.open()
	b := n.accountant()
	n.tick(Every)
	n.set("hy2:hy", "b1", "u1", 500, 5000)
	n.set("naive:nv", "n1", "u1", 5, 50)
	b.Round(n.ctx, "", false)
	n.wantUsed("alice", 505, 5050)

	// And after a write, nothing again.
	n.tick(time.Minute)
	b.Round(n.ctx, "", false)
	n.wantUsed("alice", 505, 5050)
}

func TestCrossingAndRestore(t *testing.T) {
	n := newNode(t)
	n.user("alice", 1000, "hy")
	n.user("bob", 0, "hy")
	a := n.accountant()
	n.set("hy2:hy", "b1", "u1", 0, 0, "u2", 0, 0)
	a.Round(n.ctx, "", false)

	n.tick(Every)
	n.set("hy2:hy", "b1", "u1", 400, 500, "u2", 1<<40, 1<<40)
	a.Round(n.ctx, "", false)
	// 900 of 1000: under, and nothing written yet.
	if u, _ := n.st.UserByName(n.ctx, "alice"); !u.Active(n.now) || n.woken != 0 {
		t.Fatalf("active %v, woken %d", u.Active(n.now), n.woken)
	}

	n.tick(Every)
	n.set("hy2:hy", "b1", "u1", 450, 550, "u2", 1<<41, 1<<41)
	a.Round(n.ctx, "", false)
	// 1000 of 1000: over, written at once, apply woken, audited.
	n.wantUsed("alice", 450, 550)
	u, _ := n.st.UserByName(n.ctx, "alice")
	if u.Active(n.now) || !u.OverLimit(n.now) || n.woken != 1 {
		t.Fatalf("active %v, woken %d", u.Active(n.now), n.woken)
	}
	if got := strings.Join(n.audits(), "; "); got != "rayd user.traffic=exhausted alice" {
		t.Fatalf("audits %q", got)
	}
	// Bob has no limit: never counted, never marked.
	n.wantUsed("bob", 0, 0)
	srcs, _ := n.st.TrafficSources(n.ctx)
	if _, ok := srcs["hy2:hy"].Marks["u2"]; ok || len(srcs["hy2:hy"].Marks) != 1 {
		t.Fatalf("marks %v", srcs["hy2:hy"].Marks)
	}

	// Still over: nothing told again.
	n.tick(Every)
	a.Round(n.ctx, "", false)
	if n.woken != 1 || len(n.audits()) != 1 {
		t.Fatalf("woken %d, audits %v", n.woken, n.audits())
	}

	// A raised limit: back at the next poll.
	limit := int64(5000)
	if _, err := n.st.SetUserTraffic(n.ctx, "alice", store.TrafficChange{Limit: &limit}); err != nil {
		t.Fatal(err)
	}
	n.tick(Every)
	a.Round(n.ctx, "", false)
	if u, _ := n.st.UserByName(n.ctx, "alice"); !u.Active(n.now) || n.woken != 2 {
		t.Fatalf("active %v, woken %d", u.Active(n.now), n.woken)
	}
	// Lowered under the count: off again.
	limit = 500
	if _, err := n.st.SetUserTraffic(n.ctx, "alice", store.TrafficChange{Limit: &limit}); err != nil {
		t.Fatal(err)
	}
	n.tick(Every)
	a.Round(n.ctx, "", false)
	// A reset by the administrator: back.
	if _, err := n.st.SetUserTraffic(n.ctx, "alice", store.TrafficChange{ResetUsage: true}); err != nil {
		t.Fatal(err)
	}
	n.tick(Every)
	a.Round(n.ctx, "", false)
	want := "rayd user.traffic=exhausted alice; rayd user.traffic=restored alice; rayd user.traffic=exhausted alice; rayd user.traffic=restored alice"
	if got := strings.Join(n.audits(), "; "); got != want || n.woken != 4 {
		t.Fatalf("audits %q, woken %d", got, n.woken)
	}
	n.wantUsed("alice", 0, 0)
}

// Bytes polled before an administrator's reset are not added after it.
func TestResetUsageDropsPending(t *testing.T) {
	n := newNode(t)
	n.user("alice", 1<<30, "hy")
	a := n.accountant()
	n.set("hy2:hy", "b1", "u1", 0, 0)
	a.Round(n.ctx, "", false)
	n.tick(Every)
	n.set("hy2:hy", "b1", "u1", 100, 100)
	a.Round(n.ctx, "", false) // pending
	n.tick(time.Second)
	if _, err := n.st.SetUserTraffic(n.ctx, "alice", store.TrafficChange{ResetUsage: true}); err != nil {
		t.Fatal(err)
	}
	n.tick(time.Minute)
	n.set("hy2:hy", "b1", "u1", 110, 120)
	a.Round(n.ctx, "", false)
	n.wantUsed("alice", 10, 20)
}

func TestMonthlyReset(t *testing.T) {
	n := newNode(t)
	n.now = time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	n.user("alice", 1000, "hy")
	a := n.accountant()
	n.set("hy2:hy", "b1", "u1", 0, 0)
	a.Round(n.ctx, "", false)
	n.tick(Every)
	n.set("hy2:hy", "b1", "u1", 600, 600)
	a.Round(n.ctx, "", false)
	if u, _ := n.st.UserByName(n.ctx, "alice"); !u.OverLimit(n.now) {
		t.Fatal("not over")
	}
	// The month turns (day 1, 00:00 UTC): over no more, even before the
	// loop writes the reset.
	n.now = time.Date(2026, 11, 1, 0, 0, 5, 0, time.UTC)
	u, _ := n.st.UserByName(n.ctx, "alice")
	if !u.Active(n.now) || u.Used(n.now) != 0 || !u.PeriodStart(n.now).Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("active %v used %d since %v", u.Active(n.now), u.Used(n.now), u.PeriodStart(n.now))
	}
	// The poll across the reset: written, its bytes dropped (less than
	// true, never more), told.
	n.set("hy2:hy", "b1", "u1", 700, 700)
	a.Round(n.ctx, "", false)
	n.wantUsed("alice", 0, 0)
	u, _ = n.st.UserByName(n.ctx, "alice")
	if !u.TrafficStart.Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("since %v", u.TrafficStart)
	}
	if got := strings.Join(n.audits(), "; "); got != "rayd user.traffic=exhausted alice; rayd user.traffic=restored alice" {
		t.Fatalf("audits %q", got)
	}
	n.tick(time.Minute)
	n.set("hy2:hy", "b1", "u1", 710, 720)
	a.Round(n.ctx, "", false)
	n.wantUsed("alice", 10, 20)
}

// A rayd down across the reset: the reset is written at its first poll,
// told as restored, and the bytes of the downtime do not land in the new
// period.
func TestResetWhileDown(t *testing.T) {
	n := newNode(t)
	n.now = time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	n.user("alice", 1000, "hy")
	a := n.accountant()
	n.set("hy2:hy", "b1", "u1", 0, 0)
	a.Round(n.ctx, "", false)
	n.tick(Every)
	n.set("hy2:hy", "b1", "u1", 2000, 0)
	a.Round(n.ctx, "", false)
	n.st.Close()
	n.open()
	n.now = time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
	n.set("hy2:hy", "b1", "u1", 9000, 0)
	b := n.accountant()
	b.Round(n.ctx, "", false)
	n.wantUsed("alice", 0, 0)
	if got := strings.Join(n.audits(), "; "); got != "rayd user.traffic=exhausted alice; rayd user.traffic=restored alice" {
		t.Fatalf("audits %q", got)
	}
}

func TestPeriodNone(t *testing.T) {
	n := newNode(t)
	none := store.PeriodNone
	n.user("alice", 1000, "hy")
	if _, err := n.st.SetUserTraffic(n.ctx, "alice", store.TrafficChange{Period: &none}); err != nil {
		t.Fatal(err)
	}
	a := n.accountant()
	n.set("hy2:hy", "b1", "u1", 0, 0)
	a.Round(n.ctx, "", false)
	n.tick(Every)
	n.set("hy2:hy", "b1", "u1", 500, 600)
	a.Round(n.ctx, "", false)
	// Months later: still over, no reset.
	n.now = n.now.AddDate(0, 3, 0)
	a.Round(n.ctx, "", false)
	u, _ := n.st.UserByName(n.ctx, "alice")
	if !u.OverLimit(n.now) || !u.NextResetAt(n.now).IsZero() {
		t.Fatalf("over %v, next reset %v", u.OverLimit(n.now), u.NextResetAt(n.now))
	}
	if _, err := n.st.SetUserTraffic(n.ctx, "alice", store.TrafficChange{ResetUsage: true}); err != nil {
		t.Fatal(err)
	}
	u, _ = n.st.UserByName(n.ctx, "alice")
	if u.OverLimit(n.now) || !u.TrafficStart.Equal(n.now.Truncate(time.Second)) {
		t.Fatalf("over %v since %v", u.OverLimit(n.now), u.TrafficStart)
	}
}

// A user given a limit while the process has long counted them: counted
// from the first poll after.
func TestLimitSetLater(t *testing.T) {
	n := newNode(t)
	n.user("alice", 0, "hy")
	n.user("bob", 1<<30, "hy")
	a := n.accountant()
	n.set("hy2:hy", "b1", "u1", 1<<30, 1<<30, "u2", 0, 0)
	a.Round(n.ctx, "", false)
	n.tick(Every)
	limit := int64(1 << 31)
	if _, err := n.st.SetUserTraffic(n.ctx, "alice", store.TrafficChange{Limit: &limit}); err != nil {
		t.Fatal(err)
	}
	n.tick(Every)
	n.set("hy2:hy", "b1", "u1", 1<<30+5, 1<<30+6, "u2", 0, 0)
	a.Round(n.ctx, "", true)
	n.wantUsed("alice", 0, 0)
	n.tick(Every)
	n.set("hy2:hy", "b1", "u1", 1<<30+10, 1<<30+20, "u2", 0, 0)
	a.Round(n.ctx, "", true)
	n.wantUsed("alice", 5, 14)

	// The limit off and on again: a new start, the old marks stale.
	off := int64(0)
	if _, err := n.st.SetUserTraffic(n.ctx, "alice", store.TrafficChange{Limit: &off}); err != nil {
		t.Fatal(err)
	}
	n.tick(Every)
	n.set("hy2:hy", "b1", "u1", 1<<31, 1<<31, "u2", 0, 0)
	a.Round(n.ctx, "", true)
	if _, err := n.st.SetUserTraffic(n.ctx, "alice", store.TrafficChange{Limit: &limit}); err != nil {
		t.Fatal(err)
	}
	n.tick(Every)
	n.set("hy2:hy", "b1", "u1", 1<<31+1, 1<<31+1, "u2", 0, 0)
	a.Round(n.ctx, "", true)
	n.wantUsed("alice", 0, 0)
}

// A deleted user's number goes to a new one: the process still counts the
// old one's name, and none of that is the new user's.
func TestReusedID(t *testing.T) {
	n := newNode(t)
	n.user("alice", 1<<30, "hy")
	a := n.accountant()
	n.set("hy2:hy", "b1", "u1", 0, 0)
	a.Round(n.ctx, "", false)
	n.tick(Every)
	n.set("hy2:hy", "b1", "u1", 1000, 1000)
	a.Round(n.ctx, "", true)
	if err := n.st.DeleteUser(n.ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	n.tick(Every)
	if u := n.user("carol", 1<<30, "hy"); u.ID != 1 {
		t.Skipf("the ID was not reused (%d)", u.ID)
	}
	n.tick(Every)
	n.set("hy2:hy", "b1", "u1", 1500, 1500)
	a.Round(n.ctx, "", true)
	n.wantUsed("carol", 0, 0)
	n.tick(Every)
	n.set("hy2:hy", "b1", "u1", 1600, 1700)
	a.Round(n.ctx, "", true)
	n.wantUsed("carol", 100, 200)
}

// A process can add bytes only to the users it carries; inner carries the
// users of the DNS tunnels, Yggdrasil and the like.
func TestOnlyTheServicesUsers(t *testing.T) {
	n := newNode(t)
	n.user("alice", 1<<30, "hy")
	n.user("bob", 1<<30, "dns")
	a := n.accountant()
	n.set("naive:nv", "n1", "u1", 0, 0, "u2", 0, 0)
	n.set("xray:inner", "xray:1", "u1", 0, 0, "u2", 0, 0)
	a.Round(n.ctx, "", false)
	n.tick(Every)
	n.set("naive:nv", "n1", "u1", 1000, 1000, "u2", 1000, 1000)
	n.set("xray:inner", "xray:1", "u1", 7, 7, "u2", 5, 6)
	a.Round(n.ctx, "", true)
	n.wantUsed("alice", 0, 0)
	n.wantUsed("bob", 5, 6)
	// Given the service later: what the process counted before is not
	// counted again.
	nv, _ := n.st.ServiceByName(n.ctx, "nv")
	hy, _ := n.st.ServiceByName(n.ctx, "hy")
	if err := n.st.SetUserServices(n.ctx, "alice", []int64{hy.ID, nv.ID}); err != nil {
		t.Fatal(err)
	}
	n.tick(Every)
	n.set("naive:nv", "n1", "u1", 1010, 1020, "u2", 1000, 1000)
	a.Round(n.ctx, "", true)
	n.wantUsed("alice", 10, 20)
}

// Xray says when it started: a process that started after the limit was
// set holds none of the bytes from before, all of it counts.
func TestXrayStart(t *testing.T) {
	n := newNode(t)
	n.user("bob", 1<<30, "dns")
	a := n.accountant()
	// Xray started 2 s after the limit (the first limit restarts it).
	n.tick(10 * time.Second)
	n.setXray(8*time.Second, "u1", 30, 40)
	a.Round(n.ctx, "", true)
	n.wantUsed("bob", 30, 40)
	// Read again, the uptime a second short of the time between (whole
	// seconds): the same run.
	n.tick(Every)
	n.setXray(8*time.Second+Every-time.Second, "u1", 35, 45)
	a.Round(n.ctx, "", true)
	n.wantUsed("bob", 35, 45)
	// A process that started before the limit: from the first poll.
	n2 := newNode(t)
	n2.user("bob", 1<<30, "dns")
	n2.setXray(time.Hour, "u1", 30, 40)
	n2.accountant().Round(n2.ctx, "", true)
	n2.wantUsed("bob", 0, 0)
}

// The wall clock steps between two reads of one Xray run (NTP): its
// uptime grew with the monotonic clock, so it is the same run, whatever
// its start reads as now. A restart is still one.
func TestXrayClockStep(t *testing.T) {
	n := newNode(t)
	n.user("alice", 1<<40, "dns")
	a := n.accountant()
	up := time.Hour
	n.setXray(up, "u1", 1000, 1000)
	a.Round(n.ctx, "", true)
	n.tick(Every)
	up += Every
	n.setXray(up, "u1", 30<<30, 30<<30)
	a.Round(n.ctx, "", true)
	u1, d1 := n.used("alice")
	val := 30 << 30
	for _, step := range []time.Duration{10 * time.Second, -40 * time.Second} {
		n.step(step)
		n.tick(Every)
		up += Every
		val += 5
		n.setXray(up, "u1", val, val)
		a.Round(n.ctx, "", true)
		if u2, d2 := n.used("alice"); u2 != u1+5 || d2 != d1+5 {
			t.Fatalf("a step of %v: +%d/+%d, want +5/+5", step, u2-u1, d2-d1)
		}
		u1, d1 = u1+5, d1+5
	}
	// Xray restarts: its uptime is less than the time since the last read.
	n.tick(Every)
	n.setXray(3*time.Second, "u1", 7, 9)
	a.Round(n.ctx, "", true)
	n.wantUsed("alice", u1+7, d1+9)

	// After rayd's restart (no reading of its own): the stored poll and
	// the uptime. The same run, though the wall clock stepped since...
	n.tick(Every)
	b := n.accountant()
	n.step(-30 * time.Second)
	n.setXray(3*time.Second+Every, "u1", 17, 19)
	b.Round(n.ctx, "", true)
	n.wantUsed("alice", u1+17, d1+19)
	// ...and a restart while rayd was away, its new counters past the
	// old marks: whole, not the difference.
	n.tick(Every)
	c := n.accountant()
	n.tick(time.Minute)
	n.setXray(20*time.Second, "u1", 40, 50)
	c.Round(n.ctx, "", true)
	n.wantUsed("alice", u1+57, d1+69)

	// A restart this rayd sees, its new counters past the old marks.
	n.tick(Every)
	n.setXray(20*time.Second+Every, "u1", 60, 70)
	c.Round(n.ctx, "", true)
	n.wantUsed("alice", u1+77, d1+89)
	n.tick(Every)
	n.setXray(4*time.Second, "u1", 100, 100)
	c.Round(n.ctx, "", true)
	n.wantUsed("alice", u1+177, d1+189)

	// A young process and a step of the wall clock longer than its
	// uptime: still one run.
	n.tick(Every)
	n.setXray(4*time.Second+Every, "u1", 110, 110)
	c.Round(n.ctx, "", true)
	n.step(2 * time.Hour)
	n.tick(Every)
	n.setXray(4*time.Second+2*Every, "u1", 111, 112)
	c.Round(n.ctx, "", true)
	n.wantUsed("alice", u1+188, d1+201)
}

// A source that fails gives nothing and keeps its marks; one whose service
// went loses them; with no limit left nothing is read and nothing kept.
func TestSourcesComeAndGo(t *testing.T) {
	n := newNode(t)
	n.user("alice", 1<<30, "hy", "nv")
	a := n.accountant()
	n.set("hy2:hy", "b1", "u1", 0, 0)
	n.set("naive:nv", "n1", "u1", 0, 0)
	a.Round(n.ctx, "", false)
	n.stop("hy2:hy")
	n.tick(Every)
	n.set("naive:nv", "n1", "u1", 1, 1)
	a.Round(n.ctx, "", true)
	failing := false
	for _, l := range n.hb.Loops() {
		failing = failing || l.Name == "traffic hy" && l.Failing()
	}
	if !failing {
		t.Fatalf("loops %+v", n.hb.Loops())
	}
	// A process that does not run (no socket) is no failure of the count.
	n.mu.Lock()
	n.gone = "naive:nv"
	n.mu.Unlock()
	n.tick(Every)
	a.Round(n.ctx, "", true)
	for _, l := range n.hb.Loops() {
		if l.Name == "traffic nv" && (l.Failing() || l.Detail != "not running") {
			t.Fatalf("not running: %+v", l)
		}
	}
	n.mu.Lock()
	n.gone = ""
	n.mu.Unlock()
	n.set("hy2:hy", "b1", "u1", 5, 5)
	n.tick(Every)
	a.Round(n.ctx, "", true)
	n.wantUsed("alice", 6, 6)

	if err := n.st.SetServiceEnabled(n.ctx, "hy", false); err != nil {
		t.Fatal(err)
	}
	n.tick(Every)
	a.Round(n.ctx, "", false)
	srcs, _ := n.st.TrafficSources(n.ctx)
	if _, ok := srcs["hy2:hy"]; ok || len(srcs) != 1 {
		t.Fatalf("sources %v", srcs)
	}

	off := int64(0)
	if _, err := n.st.SetUserTraffic(n.ctx, "alice", store.TrafficChange{Limit: &off}); err != nil {
		t.Fatal(err)
	}
	reads := n.reads
	n.tick(Every)
	a.Round(n.ctx, "", false)
	srcs, _ = n.st.TrafficSources(n.ctx)
	if n.reads != reads || len(srcs) != 0 || len(n.hb.Loops()) != 0 {
		t.Fatalf("reads %d→%d, sources %v, loops %+v", reads, n.reads, srcs, n.hb.Loops())
	}
}

// Before rayd restarts a process it reads it and writes: the counters the
// restart zeroes are kept.
func TestFlushBeforeRestart(t *testing.T) {
	n := newNode(t)
	n.user("alice", 1<<30, "hy", "nv")
	a := n.accountant()
	a.Flush(n.ctx, "hy") // never read: nothing to keep, nothing read
	if n.reads != 0 {
		t.Fatalf("%d reads", n.reads)
	}
	n.set("hy2:hy", "b1", "u1", 0, 0)
	n.set("naive:nv", "n1", "u1", 0, 0)
	a.Round(n.ctx, "", false)
	n.tick(Every)
	n.set("hy2:hy", "b1", "u1", 100, 200)
	n.set("naive:nv", "n1", "u1", 1, 2)
	reads := n.reads
	a.Flush(n.ctx, "inner") // never answered: nothing of it to keep
	if n.reads != reads {
		t.Fatalf("%d reads of a process never read", n.reads-reads)
	}
	a.Flush(n.ctx, "hy")
	n.wantUsed("alice", 100, 200)
	if n.reads != reads+1 {
		t.Fatalf("%d reads, want 1", n.reads-reads)
	}
	// The restart: a new run from zero.
	n.set("hy2:hy", "b2", "u1", 3, 4)
	n.tick(Every)
	a.Round(n.ctx, "", true)
	n.wantUsed("alice", 104, 206)

	// After rayd's own restart, before its first round: the store's marks
	// are the process's, and a restart of it is read first all the same.
	b := n.accountant()
	n.set("hy2:hy", "b2", "u1", 13, 14)
	reads = n.reads
	b.Flush(n.ctx, "hy")
	if n.reads != reads+1 {
		t.Fatalf("%d reads after rayd's restart, want 1", n.reads-reads)
	}
	n.wantUsed("alice", 114, 216)
}

// Counts from a process are not trusted: no wrap, no negative.
func TestHostileCounts(t *testing.T) {
	n := newNode(t)
	n.user("alice", 1<<30, "hy")
	a := n.accountant()
	n.set("hy2:hy", "b1", "u1", 0, 0)
	a.Round(n.ctx, "", false)
	for range 4 {
		n.tick(Every)
		n.readings["hy2:hy"] = Reading{Boot: "b" + itoa(n.now.Unix()), Users: map[string]store.TrafficCounter{
			"u1": {Up: 1<<63 - 1, Down: -5}, "u1-n": {Up: 1<<63 - 1, Down: 1<<63 - 1}, "u001": {Up: 9}, "x": {Up: 9}}}
		a.Round(n.ctx, "", true)
	}
	up, down := n.used("alice")
	if up <= 0 || down <= 0 || up > 1<<61 || down > 1<<61 {
		t.Fatalf("used %d/%d", up, down)
	}
	if u, _ := n.st.UserByName(n.ctx, "alice"); !u.OverLimit(n.now) {
		t.Fatal("not over")
	}
	// A negative count is zero: what grows from it is not more.
	m := newNode(t)
	m.user("bob", 1<<30, "hy")
	b := m.accountant()
	m.set("hy2:hy", "b1", "u1", 0, 0)
	b.Round(m.ctx, "", true)
	m.tick(Every)
	m.set("hy2:hy", "b1", "u1", 7, -5)
	b.Round(m.ctx, "", true)
	m.tick(Every)
	m.set("hy2:hy", "b1", "u1", 7, 10)
	b.Round(m.ctx, "", true)
	m.wantUsed("bob", 7, 10)
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

var testPaths = render.Paths{Rendered: "/nonexistent/rendered", Run: "/nonexistent/run"}

// A limit without its count (not a state the store makes): the count is
// made, from now, and nothing is written over and over.
func TestLimitWithoutCount(t *testing.T) {
	n := newNode(t)
	n.user("alice", 1<<30, "hy")
	db, err := sql.Open("sqlite", "file:"+n.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(n.ctx, `DELETE FROM user_traffic`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	a := n.accountant()
	n.set("hy2:hy", "b1", "u1", 500, 500)
	a.Round(n.ctx, "", false)
	u, _ := n.st.UserByName(n.ctx, "alice")
	if sec := n.now.Truncate(time.Second); !u.TrafficStart.Equal(sec) || !u.TrafficCountedFrom.Equal(sec) || u.Used(n.now) != 0 {
		t.Fatalf("count %+v", u)
	}
	n.tick(Every)
	n.set("hy2:hy", "b1", "u1", 510, 520)
	a.Round(n.ctx, "", false) // the baseline: the limit is from the round before
	n.tick(time.Minute)
	n.set("hy2:hy", "b1", "u1", 515, 530)
	a.Round(n.ctx, "", false)
	n.wantUsed("alice", 5, 10)
}

// A limit set in the same second as a poll, after it: counted_from is in
// whole seconds, so the poll's time is too, or the limit would read as set
// before the poll and the process's whole counter would count.
func TestLimitSameSecondAfterPoll(t *testing.T) {
	n := newNode(t)
	n.user("alice", 0, "hy")   // no limit yet
	n.user("bob", 1<<40, "hy") // someone has one: the loop polls
	n.now = n.now.Truncate(time.Second).Add(300 * time.Millisecond)
	a := n.accountant()
	// Hysteria2 has carried 50 GiB of alice's, before any limit.
	n.set("hy2:hy", "b1", "u2", 0, 0, "u1", 10<<30, 40<<30)
	a.Round(n.ctx, "", true) // at hh:mm:ss.300
	n.now = n.now.Add(400 * time.Millisecond)
	limit := int64(100 << 30)
	if _, err := n.st.SetUserTraffic(n.ctx, "alice", store.TrafficChange{Limit: &limit}); err != nil { // at .700
		t.Fatal(err)
	}
	n.tick(Every)
	n.set("hy2:hy", "b1", "u2", 0, 0, "u1", 10<<30+1, 40<<30+1)
	a.Round(n.ctx, "", true) // the baseline
	n.tick(Every)
	n.set("hy2:hy", "b1", "u2", 0, 0, "u1", 10<<30+3, 40<<30+4)
	a.Round(n.ctx, "", true)
	n.wantUsed("alice", 2, 3)
}

// TestLimitWithoutCount with the poll a fraction into its second.
func TestLimitWithoutCountSubSecond(t *testing.T) {
	n := newNode(t)
	n.user("alice", 1<<30, "hy")
	db, err := sql.Open("sqlite", "file:"+n.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(n.ctx, `DELETE FROM user_traffic`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	n.now = n.now.Truncate(time.Second).Add(400 * time.Millisecond)
	a := n.accountant()
	n.set("hy2:hy", "b1", "u1", 500, 500)
	a.Round(n.ctx, "", false) // makes the count, from this second
	n.tick(Every)
	n.set("hy2:hy", "b1", "u1", 510, 520)
	a.Round(n.ctx, "", false) // the baseline
	n.tick(time.Minute)
	n.set("hy2:hy", "b1", "u1", 515, 530)
	a.Round(n.ctx, "", false)
	n.wantUsed("alice", 5, 10)
}

// Processes that are slow to answer hold a round as long as the slowest,
// not their sum: apply waits for a round before a restart.
func TestSlowSources(t *testing.T) {
	n := newNode(t)
	n.user("alice", 1<<30, "hy", "nv", "dns")
	a := n.accountant()
	n.set("hy2:hy", "b1", "u1", 0, 0)
	n.set("naive:nv", "n1", "u1", 0, 0)
	n.set("xray:inner", "xray:1", "u1", 0, 0)
	n.delay = 400 * time.Millisecond
	start := time.Now()
	a.Round(n.ctx, "", true)
	if d := time.Since(start); d > 1100*time.Millisecond || n.reads != 3 {
		t.Fatalf("a round of 3 slow sources took %v (%d reads)", d, n.reads)
	}
}
