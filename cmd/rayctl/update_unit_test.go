package main

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// After an update, each data-plane unit that ran before must run again
// and keep running: one that crashes a moment after its start, or never
// comes up, fails the update (which rolls back).
func TestWaitDataPlane(t *testing.T) {
	running := map[string]string{"ActiveState": "active", "SubState": "running", "Result": "success", "NRestarts": "0", "Job": "0"}
	with := func(m map[string]string, kv ...string) map[string]string {
		c := map[string]string{}
		for k, v := range m {
			c[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			c[kv[i]] = kv[i+1]
		}
		return c
	}
	// Each unit's states in turn; the last one stays.
	states := func(byUnit map[string][]map[string]string) func(string) func() (map[string]string, error) {
		var mu sync.Mutex
		seen := map[string]int{}
		return func(u string) func() (map[string]string, error) {
			return func() (map[string]string, error) {
				mu.Lock()
				defer mu.Unlock()
				seq := byUnit[u]
				i := min(seen[u], len(seq)-1)
				seen[u]++
				return seq[i], nil
			}
		}
	}
	ctx := context.Background()
	wait := func(byUnit map[string][]map[string]string) error {
		var units []string
		restarts := map[string]string{}
		for u := range byUnit {
			units, restarts[u] = append(units, u), "0"
		}
		return waitDataPlane(ctx, units, restarts, states(byUnit), 5*time.Millisecond, 50*time.Millisecond, time.Millisecond)
	}
	if err := wait(map[string][]map[string]string{
		"niko-front.service": {with(running, "ActiveState", "activating", "SubState", "start"), running},
		"niko-dns.service":   {running},
	}); err != nil {
		t.Fatalf("units that come back: %v", err)
	}
	for name, c := range map[string]struct {
		seq  []map[string]string
		says string
	}{
		"crash after the start": {[]map[string]string{running, with(running, "NRestarts", "1")}, "restarted"},
		"crash loop":            {[]map[string]string{with(running, "ActiveState", "activating", "SubState", "auto-restart", "Result", "exit-code")}, "exited"},
		"refused config":        {[]map[string]string{with(running, "ActiveState", "failed", "SubState", "failed", "Result", "exit-code")}, "did not start"},
		"never up":              {[]map[string]string{with(running, "ActiveState", "activating", "SubState", "start")}, "within"},
	} {
		err := wait(map[string][]map[string]string{"niko-front.service": c.seq})
		if err == nil || !strings.Contains(err.Error(), c.says) || !strings.Contains(err.Error(), "niko-front.service") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
