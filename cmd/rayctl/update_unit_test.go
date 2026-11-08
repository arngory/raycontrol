package main

import (
	"context"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/release"
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

// A unit skipped for its missing certificate is not waited for; one in
// auto-restart, failed or with its start queued is.
func TestWaitsForFile(t *testing.T) {
	for _, c := range []struct {
		st   map[string]string
		want bool
	}{
		{map[string]string{"ActiveState": "inactive", "SubState": "dead", "ConditionResult": "no", "Job": ""}, true},
		{map[string]string{"ActiveState": "inactive", "SubState": "dead", "ConditionResult": "no", "Job": "0"}, true},
		{map[string]string{"ActiveState": "inactive", "SubState": "dead", "ConditionResult": "no", "Job": "12"}, false},
		{map[string]string{"ActiveState": "activating", "SubState": "auto-restart", "ConditionResult": "yes"}, false},
		{map[string]string{"ActiveState": "failed", "SubState": "failed", "ConditionResult": "yes"}, false},
		{map[string]string{"ActiveState": "active", "SubState": "running", "ConditionResult": "yes"}, false},
	} {
		if got := waitsForFile(c.st); got != c.want {
			t.Errorf("%v: %v, want %v", c.st, got, c.want)
		}
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

// The rayctl on the node hands a newer release's update to that release's
// rayctl; not a downgrade, the same version, its own version, a child, or
// with -no-handoff.
func TestHandsOff(t *testing.T) {
	saved := version
	t.Cleanup(func() { version = saved })
	version = "v0.19.0"
	t.Setenv(handoffEnv, "")
	for _, c := range []struct {
		refused           bool
		target, installed string
		want              bool
	}{
		{false, "v0.19.1", "v0.19.0", true},
		{false, "v0.20.0", "v0.19.0", true},
		{true, "v0.19.1", "v0.19.0", false},  // -no-handoff
		{false, "v0.19.0", "v0.19.0", false}, // -force, same version
		{false, "v0.18.1", "v0.19.0", false}, // going back: this rayctl knows the newer node
		{false, "v0.19.0", "v0.18.1", false}, // the target is this rayctl
	} {
		if got := handsOff(c.refused, c.target, c.installed); got != c.want {
			t.Errorf("handsOff(%v, %s, %s) = %v", c.refused, c.target, c.installed, got)
		}
	}
	t.Setenv(handoffEnv, "1") // the child: never again
	if handsOff(false, "v0.20.0", "v0.19.0") {
		t.Error("a handed-over update handed over again")
	}
}

// The child compares with, and records for a rollback, the version it
// updates from, not its own.
func TestInstalledVersion(t *testing.T) {
	saved := version
	t.Cleanup(func() { version = saved })
	version = "v0.20.0"
	t.Setenv(handoffEnv, "")
	t.Setenv(updateFromEnv, "v0.19.0")
	if v := installedVersion(); v != "v0.20.0" {
		t.Errorf("not handed over: %s", v)
	}
	t.Setenv(handoffEnv, "1")
	if v := installedVersion(); v != "v0.19.0" {
		t.Errorf("handed over: %s", v)
	}
	for _, bad := range []string{"", "v0.19.0\nVERSION", "../../x", strings.Repeat("v", 41)} {
		t.Setenv(updateFromEnv, bad)
		if v := installedVersion(); v != "v0.20.0" {
			t.Errorf("from %q: %s", bad, v)
		}
	}
}

// No release build has the test key (testkey.go, build tag releasetest).
func TestReleaseBuildHasNoTestKey(t *testing.T) {
	wf, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wf), "releasetest") {
		t.Fatal("release.yml builds with the releasetest tag: its rayctl would take a release key from the environment")
	}
	if releaseKey != release.PubKey {
		t.Fatalf("releaseKey %s in a test without the tag", releaseKey)
	}
}
