package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/store"
)

// The auto update (spec/node-update-v1.md §1): off unless root's policy
// file has it on; on, a newer patch release is asked for once in the
// window, at a moment of the node's still in it; a newer minor version is
// not; a version that rolled back is not asked for again, one that failed
// before it changed the node is, a day later.
func TestAutoUpdate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	reqFile, statFile, polFile := filepath.Join(dir, "update-request"), filepath.Join(dir, "status.json"), filepath.Join(dir, "policy.json")

	var mu sync.Mutex
	clock := time.Date(2026, 11, 8, 1, 0, 0, 0, time.Local) // before the window
	step := 15 * time.Minute
	latestV := "v0.19.1"
	now := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		clock = clock.Add(step)
		return clock
	}
	at := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	set := func(f func()) { mu.Lock(); f(); mu.Unlock() }
	latest := func(context.Context) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		return latestV, nil
	}
	var seen atomic.Value
	a := &autoUpdater{st: st, running: "v0.19.0", latest: latest, seen: &seen, request: reqFile, status: statFile, policy: polFile,
		now: now, tick: time.Millisecond, hb: &health.Board{}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	go a.run(ctx)

	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for i := 0; !cond(); i++ {
			if i == 5000 {
				t.Fatalf("no %s (clock %s)", what, at().Format("15:04"))
			}
			time.Sleep(time.Millisecond)
		}
	}
	none := func(what string) {
		t.Helper()
		start := at()
		waitFor("two days", func() bool { return at().Sub(start) > 48*time.Hour })
		if _, err := os.Stat(reqFile); !os.IsNotExist(err) {
			t.Fatal(what)
		}
	}
	// Off: no request, through days; rayd's own settings do not turn it on.
	st.SetSetting(ctx, "update_auto", []byte("patch"))
	none("a request while off")

	// On, with a window as short as it may be: asked for in it.
	set(func() { step = 2 * time.Minute })
	if err := nodeupdate.WritePolicy(polFile, nodeupdate.Policy{Remote: "off", Auto: "patch", Window: "03:00-03:30"}); err != nil {
		t.Fatal(err)
	}
	waitFor("request", func() bool { _, ok := nodeupdate.PeekRequest(reqFile); return ok })
	r, _ := nodeupdate.PeekRequest(reqFile)
	if r.Kind != nodeupdate.Auto || r.Version != "v0.19.1" || r.Check(nodeupdate.NodeKinds, "v0.19.0", nil, r.At) != nil || !nodeupdate.InWindow(r.At.In(time.Local), "03:00-03:30") {
		t.Fatalf("request %+v at %s", r, r.At.In(time.Local).Format("15:04"))
	}
	if v, _ := seen.Load().(string); v != "v0.19.1" {
		t.Errorf("seen %q", v)
	}

	// Root's unit ran it and it rolled back: not asked for again.
	set(func() { step = 15 * time.Minute })
	os.Remove(reqFile)
	nodeupdate.WriteStatus(statFile, nodeupdate.Status{ID: r.ID, State: nodeupdate.RolledBack, Target: "v0.19.1", To: "v0.19.0", Error: "x", Ended: at()})
	none("a version that rolled back asked for again")

	// It failed before it changed the node (the download): a day later.
	ended := at()
	nodeupdate.WriteStatus(statFile, nodeupdate.Status{ID: r.ID, State: nodeupdate.Failed, Untouched: true, Target: "v0.19.1", Error: "x", Ended: ended})
	waitFor("the request again", func() bool { _, ok := nodeupdate.PeekRequest(reqFile); return ok })
	if r, _ := nodeupdate.PeekRequest(reqFile); r.At.Sub(ended) < nodeupdate.RetryAfter {
		t.Fatalf("asked for again %v after it failed", r.At.Sub(ended))
	}
	os.Remove(reqFile)

	// A minor release is not a patch: not taken either.
	nodeupdate.WriteStatus(statFile, nodeupdate.Status{ID: r.ID, State: nodeupdate.Done, Target: "v0.19.1", To: "v0.19.1", Ended: at()})
	set(func() { latestV = "v0.20.0" })
	none("a minor release asked for")
}

func TestGaveUp(t *testing.T) {
	now := time.Now()
	v := "v0.19.3"
	for _, c := range []struct {
		s    nodeupdate.Status
		want bool
	}{
		{nodeupdate.Status{State: nodeupdate.Done, Target: v}, false},
		{nodeupdate.Status{State: nodeupdate.RolledBack, Target: v, Ended: now.Add(-48 * time.Hour)}, true},
		{nodeupdate.Status{State: nodeupdate.Failed, Target: v, Ended: now.Add(-48 * time.Hour)}, true},
		{nodeupdate.Status{State: nodeupdate.Failed, Target: v, Untouched: true, Ended: now.Add(-time.Hour)}, true},
		{nodeupdate.Status{State: nodeupdate.Failed, Target: v, Untouched: true, Ended: now.Add(-25 * time.Hour)}, false},
		// An admin's latest that rolled back: the release it went for.
		{nodeupdate.Status{State: nodeupdate.RolledBack, Target: "latest", Release: v}, true},
		{nodeupdate.Status{State: nodeupdate.RolledBack, Target: "latest", Release: "v0.19.2"}, false},
		// Whatever came since, a release held stays alone.
		{nodeupdate.Status{State: nodeupdate.Failed, Untouched: true, Target: "latest", Held: []string{"v0.19.1", v}}, true},
	} {
		if got := gaveUp(c.s, v, now); got != c.want {
			t.Errorf("%+v: %v", c.s, got)
		}
	}
}

// The loop sleeps a tick, but no longer than to the moment it waits for;
// past a moment it does not wait for, a whole tick (no spin).
func TestNextWait(t *testing.T) {
	now := time.Now()
	tick := 10 * time.Minute
	for _, c := range []struct {
		due  time.Time
		soon bool
		want time.Duration
	}{
		{time.Time{}, false, tick},
		{now.Add(3 * time.Minute), true, 3 * time.Minute},
		{now.Add(time.Hour), true, tick},
		{now.Add(-time.Minute), true, time.Second},
		{now.Add(-time.Hour), false, tick},
	} {
		if got := nextWait(tick, c.due, now, c.soon); got != c.want {
			t.Errorf("due %v soon %v: %v, want %v", c.due.Sub(now), c.soon, got, c.want)
		}
	}
}

// One look of the loop: it waits for its moment only while it has one in
// this window; given up, busy or past the window it waits a whole tick.
func TestAutoStep(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	reqFile, statFile, polFile := filepath.Join(dir, "update-request"), filepath.Join(dir, "status.json"), filepath.Join(dir, "policy.json")
	nodeupdate.WritePolicy(polFile, nodeupdate.Policy{Remote: "off", Auto: "patch", Window: "03:00-05:00"})
	a := &autoUpdater{st: st, running: "v0.19.0", latest: func(context.Context) (string, error) { return "v0.19.1", nil }, seen: &atomic.Value{},
		request: reqFile, status: statFile, policy: polFile, now: time.Now, tick: 10 * time.Minute, hb: &health.Board{},
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	at := func(h, m int) time.Time { return time.Date(2026, 11, 8, h, m, 0, 0, time.Local) }

	var s autoState
	if a.step(ctx, &s, at(2, 0)) || !s.due.IsZero() {
		t.Fatalf("before the window: %+v", s)
	}
	if !a.step(ctx, &s, at(3, 0)) || s.due.Before(at(3, 0)) || !s.due.Before(at(5, 0)) {
		t.Fatalf("in the window: a moment in it, waited for: %+v", s)
	}
	// Just before the moment, but in the window: the moment is t plus a
	// random span from 0 up to 30 minutes, so it falls in the window's
	// first second once in 1,800 runs, and a second before it would be
	// before the window.
	just := s.due.Add(-time.Second)
	if just.Before(at(3, 0)) {
		just = at(3, 0)
	}
	if !a.step(ctx, &s, just) {
		t.Fatal("just before the moment: not waited for")
	}
	// The moment passed while the release was given up: no wait for it.
	nodeupdate.WriteStatus(statFile, nodeupdate.Status{State: nodeupdate.RolledBack, Target: "latest", Release: "v0.19.1", Held: []string{"v0.19.1"}})
	if a.step(ctx, &s, s.due.Add(time.Minute)) || !s.due.IsZero() {
		t.Fatalf("given up: %+v", s)
	}
	if _, err := os.Stat(reqFile); !os.IsNotExist(err) {
		t.Fatal("a held release asked for")
	}
	// Busy (an update runs): likewise, and nothing asked for.
	os.Remove(statFile)
	a.step(ctx, &s, at(3, 10))
	nodeupdate.WriteStatus(statFile, nodeupdate.Status{State: nodeupdate.Running, Target: "latest", Started: s.due})
	if a.step(ctx, &s, s.due.Add(time.Minute)) || !s.due.IsZero() {
		t.Fatalf("busy: %+v", s)
	}
	if _, err := os.Stat(reqFile); !os.IsNotExist(err) {
		t.Fatal("asked for while an update runs")
	}
	// Its moment come, nothing in the way: asked for.
	os.Remove(statFile)
	a.step(ctx, &s, at(3, 20))
	if a.step(ctx, &s, s.due) || !s.due.IsZero() {
		t.Fatalf("the moment: %+v", s)
	}
	if r, ok := nodeupdate.PeekRequest(reqFile); !ok || r.Version != "v0.19.1" || r.Kind != nodeupdate.Auto {
		t.Fatalf("the request: %+v %v", r, ok)
	}
}

// A new minor version is not asked for, but said, with what takes it; no
// newer release is up to date. From the release the check fetched: no
// other call.
func TestAutoStepNewerMinor(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	reqFile, statFile, polFile := filepath.Join(dir, "update-request"), filepath.Join(dir, "status.json"), filepath.Join(dir, "policy.json")
	nodeupdate.WritePolicy(polFile, nodeupdate.Policy{Remote: "off", Auto: "patch", Window: "03:00-05:00"})
	latest, asked := "v0.20.0", 0
	hb := &health.Board{}
	a := &autoUpdater{st: st, running: "v0.19.0", latest: func(context.Context) (string, error) { asked++; return latest, nil },
		seen: &atomic.Value{}, request: reqFile, status: statFile, policy: polFile, now: time.Now, tick: 10 * time.Minute, hb: hb,
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	detail := func() string {
		for _, l := range hb.Loops() {
			if l.Name == "auto-update" {
				return l.Detail
			}
		}
		return ""
	}
	var s autoState
	at := time.Date(2026, 11, 8, 3, 10, 0, 0, time.Local)
	for i := range 3 {
		if a.step(ctx, &s, at.Add(time.Duration(i)*time.Minute)) || !s.due.IsZero() {
			t.Fatalf("waits for a minor release: %+v", s)
		}
	}
	if _, err := os.Stat(reqFile); !os.IsNotExist(err) || asked != 1 {
		t.Fatalf("a minor release asked for (%v), or the latest fetched %d times", err, asked)
	}
	want := "patch, window 03:00-05:00: v0.20.0 is out, a new minor version, which it leaves: this node runs v0.19.0; " +
		"rayctl update takes it (or an admin's phone, with remote updates on)"
	if d := detail(); d != want {
		t.Errorf("detail %q\nwant   %q", d, want)
	}
	// A major one likewise; none newer: up to date.
	for v, want := range map[string]string{
		"v1.0.0":  "v1.0.0 is out, a new major version",
		"v0.19.0": "patch, window 03:00-05:00: up to date (v0.19.0)",
	} {
		latest, s = v, autoState{}
		a.step(ctx, &s, at)
		if d := detail(); !strings.Contains(d, want) {
			t.Errorf("latest %s: %q", v, d)
		}
	}
}

// Once a newer minor version is out, the auto update takes the newest
// patch release of the running one (what patch finds), and keeps it for
// GetUpdateStatus; without one it tells of the minor version as before,
// and of why the patch releases are not known. patch is asked whenever
// latest is not a patch release of the running one, with that latest:
// after a newer minor version, and after a latest that is a backport.
func TestAutoNewestPatch(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	reqFile, statFile, polFile := filepath.Join(dir, "update-request"), filepath.Join(dir, "status.json"), filepath.Join(dir, "policy.json")
	nodeupdate.WritePolicy(polFile, nodeupdate.Policy{Remote: "off", Auto: "patch", Window: "03:00-05:00"})
	latest, patch, probed, asked := "v0.27.0", "v0.26.2", 0, ""
	var perr error
	hb := &health.Board{}
	var seen, seenPatch atomic.Value
	a := &autoUpdater{st: st, running: "v0.26.0", latest: func(context.Context) (string, error) { return latest, nil },
		patch: func(_ context.Context, l string) (string, error) { probed++; asked = l; return patch, perr }, seen: &seen, seenPatch: &seenPatch,
		request: reqFile, status: statFile, policy: polFile, now: time.Now, tick: 10 * time.Minute, hb: hb,
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	detail := func() string {
		for _, l := range hb.Loops() {
			if l.Name == "auto-update" {
				return l.Detail
			}
		}
		return ""
	}
	var s autoState
	at := time.Date(2026, 11, 8, 3, 10, 0, 0, time.Local)
	if !a.step(ctx, &s, at) || s.due.IsZero() {
		t.Fatalf("no moment for v0.26.2: %+v %q", s, detail())
	}
	if v, _ := seenPatch.Load().(string); v != "v0.26.2" || probed != 1 {
		t.Errorf("seen patch %q, probed %d", v, probed)
	}
	a.step(ctx, &s, s.due)
	r, ok := nodeupdate.PeekRequest(reqFile)
	if !ok || r.Version != "v0.26.2" || r.Kind != nodeupdate.Auto || r.Check(nodeupdate.NodeKinds, "v0.26.0", nil, r.At) != nil {
		t.Fatalf("request %+v %v: %q", r, ok, detail())
	}
	os.Remove(reqFile)

	// None found, or the search failed: the minor version is told of.
	for _, c := range []struct {
		err  error
		want string
	}{
		{nil, "patch, window 03:00-05:00: v0.27.0 is out, a new minor version, which it leaves: this node runs v0.26.0; " +
			"rayctl update takes it (or an admin's phone, with remote updates on)"},
		{errors.New("down"), "patch, window 03:00-05:00: v0.27.0 is out, a new minor version, which it leaves: this node runs v0.26.0; " +
			"rayctl update takes it (or an admin's phone, with remote updates on); newer patch releases of v0.26.0 not known: down"},
	} {
		patch, perr, s = "", c.err, autoState{}
		if a.step(ctx, &s, at) || !s.due.IsZero() {
			t.Fatalf("waits with no patch release: %+v", s)
		}
		if d := detail(); d != c.want {
			t.Errorf("detail %q\nwant   %q", d, c.want)
		}
	}
	// A patch latest: taken, no search.
	latest, probed, s = "v0.26.1", 0, autoState{}
	if !a.step(ctx, &s, at) || probed != 0 || !strings.Contains(detail(), "v0.26.1 at ") {
		t.Errorf("patch latest: probed %d, %q", probed, detail())
	}
	// A backport marked latest (v0.25.5 after v0.26.1), older than the
	// node: the search runs all the same, and v0.26.1 is taken.
	latest, patch, perr, probed, s = "v0.25.5", "v0.26.1", nil, 0, autoState{}
	if !a.step(ctx, &s, at) || probed != 1 || asked != "v0.25.5" || !strings.Contains(detail(), "v0.26.1 at ") {
		t.Errorf("backport latest: probed %d with %q, %q", probed, asked, detail())
	}
	// Latest is the running version: asked (the next number only, in
	// NewestPatch); nothing found, up to date; a failure is said.
	for _, c := range []struct {
		err  error
		want string
	}{
		{nil, "patch, window 03:00-05:00: up to date (v0.26.0)"},
		{errors.New("down"), "patch, window 03:00-05:00: no newer release known (v0.26.0; the latest is v0.26.0); newer patch releases of v0.26.0 not known: down"},
	} {
		latest, patch, perr, probed, s = "v0.26.0", "", c.err, 0, autoState{}
		if a.step(ctx, &s, at) || probed != 1 || asked != "v0.26.0" || detail() != c.want {
			t.Errorf("latest is running: probed %d with %q, %q", probed, asked, detail())
		}
	}
}
