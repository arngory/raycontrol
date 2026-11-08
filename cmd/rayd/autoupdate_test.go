package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
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
	if r.Kind != nodeupdate.Auto || r.Version != "v0.19.1" || r.Check("v0.19.0", r.At) != nil || !nodeupdate.InWindow(r.At.In(time.Local), "03:00-03:30") {
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
