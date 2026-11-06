package main

import (
	"context"
	"slices"
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

// The units an update waits for: those that ran before it (taken before
// rayd restarts them: one the new niko-server refuses is in auto-restart,
// not active, afterwards), unless the new deployment removed them, and
// those that run now (review of the update path).
func TestDataPlaneAfter(t *testing.T) {
	before := []string{"niko-front.service", "niko-dns.service"}
	now := []string{"niko-dns.service", "niko-mdns.service"}
	all := func(string) bool { return true }
	if got := dataPlaneAfter(before, now, all); !slices.Equal(got, []string{"niko-front.service", "niko-dns.service", "niko-mdns.service"}) {
		t.Fatalf("got %v", got)
	}
	// The front crash-loops after the update: still waited for.
	if got := dataPlaneAfter(before, []string{"niko-dns.service"}, all); !slices.Contains(got, "niko-front.service") {
		t.Fatalf("a unit that ran before is not waited for: %v", got)
	}
	// A unit the new deployment removed is not.
	gone := func(u string) bool { return u != "niko-front.service" }
	if got := dataPlaneAfter(before, now, gone); slices.Contains(got, "niko-front.service") {
		t.Fatalf("a removed unit is waited for: %v", got)
	}
}

// After an update: the DNS tunnels that keep modes weaker than a new one's.
func TestWeakerModes(t *testing.T) {
	for _, c := range []struct {
		kind, settings string
		n              int
	}{
		{"dnstt", `{"auth":"required","seal":"optional"}`, 0},
		{"dnstt", `{}`, 2},
		{"dnstt", `{"auth":"optional","seal":"required"}`, 1},
		{"masterdns", `{"auth":"optional","seal":"optional"}`, 0},
		{"masterdns", `{"encryption_method":5}`, 2},
		{"reality", `{}`, 0},
	} {
		if got := weakerModes(c.kind, c.settings); len(got) != c.n {
			t.Errorf("%s %s: %q", c.kind, c.settings, got)
		}
	}
}
