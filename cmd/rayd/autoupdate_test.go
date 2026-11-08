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

// The auto update (spec/node-update-v1.md §4): off by default; on, a
// newer patch release is asked for once in the window, at a moment of the
// node's; a newer minor version is not; a version that failed is not
// asked for again.
func TestAutoUpdate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	reqFile, statFile := filepath.Join(dir, "update-request"), filepath.Join(dir, "status.json")

	var mu sync.Mutex
	clock := time.Date(2026, 11, 8, 1, 0, 0, 0, time.Local) // before the window
	latestV := "v0.19.1"
	now := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		clock = clock.Add(2 * time.Minute)
		return clock
	}
	latest := func(context.Context) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		return latestV, nil
	}
	var seen atomic.Value
	hb := &health.Board{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	go autoUpdate(ctx, st, "v0.19.0", latest, &seen, reqFile, statFile, now, time.Millisecond, hb, log)

	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for i := 0; !cond(); i++ {
			if i == 3000 {
				t.Fatalf("no %s (clock %s)", what, clock.Format("15:04"))
			}
			time.Sleep(time.Millisecond)
		}
	}
	// Off: no request, through a whole day.
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(reqFile); !os.IsNotExist(err) {
		t.Fatal("a request while off")
	}
	st.SetSetting(ctx, nodeupdate.SettingAuto, []byte("patch"))
	waitFor("request", func() bool { _, ok := nodeupdate.PeekRequest(reqFile); return ok })
	r, _ := nodeupdate.PeekRequest(reqFile)
	mu.Lock()
	at := clock
	mu.Unlock()
	if r.Kind != nodeupdate.Auto || r.Version != "v0.19.1" || r.Check("v0.19.0") != nil || !nodeupdate.InWindow(at.Add(-4*time.Minute), nodeupdate.DefaultWindow) {
		t.Fatalf("request %+v at %s", r, at)
	}
	if v, _ := seen.Load().(string); v != "v0.19.1" {
		t.Errorf("seen %q", v)
	}
	// Root's unit ran it and it rolled back: not asked for again.
	os.Remove(reqFile)
	nodeupdate.WriteStatus(statFile, nodeupdate.Status{ID: r.ID, State: nodeupdate.RolledBack, Target: "v0.19.1", To: "v0.19.0", Error: "x"})
	time.Sleep(300 * time.Millisecond)
	if _, err := os.Stat(reqFile); !os.IsNotExist(err) {
		t.Fatal("a failed version asked for again")
	}
	// A minor release is not a patch: not taken either.
	mu.Lock()
	latestV = "v0.20.0"
	mu.Unlock()
	time.Sleep(300 * time.Millisecond)
	if _, err := os.Stat(reqFile); !os.IsNotExist(err) {
		t.Fatal("a minor release asked for")
	}
}
