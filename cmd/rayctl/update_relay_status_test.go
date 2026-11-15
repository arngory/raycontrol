package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/nodeupdate"
)

// fakePolicy is rayctl update status|remote on a relay on a test's own
// directories: systemctl recorded, rayd relay's unit enabled or not, the
// path unit active or not.
type fakePolicy struct {
	at     relayPolicyAt
	ran    []string
	probe  bool  // rayd relay's unit enabled
	active bool  // the path unit
	fails  error // systemctl
}

func newFakePolicy(t *testing.T, dir string) *fakePolicy {
	t.Helper()
	root := t.TempDir()
	f := &fakePolicy{probe: true}
	units := filepath.Join(root, "systemd")
	os.MkdirAll(units, 0o755)
	for _, u := range []string{deploy.RelayUpdatePath, deploy.RelayUpdateService, deploy.RelayRecover} {
		os.WriteFile(filepath.Join(units, u), []byte("unit"), 0o644)
	}
	os.MkdirAll(filepath.Join(root, "rayd-relay"), 0o700)
	f.at = relayPolicyAt{
		dir: dir, policy: filepath.Join(root, "update", "policy.json"), status: filepath.Join(root, "update", "status.json"),
		request: filepath.Join(root, "rayd-relay", "update-request"), units: units, root: func() error { return nil },
		enable: func(u string, now bool) error {
			f.ran = append(f.ran, strings.Join(systemctlEnable("enable", u, now), " "))
			f.active = f.active || u == deploy.RelayUpdatePath && now
			return f.fails
		},
		disable: func(u string, now bool) error {
			f.ran = append(f.ran, strings.Join(systemctlEnable("disable", u, now), " "))
			f.active = f.active && u != deploy.RelayUpdatePath
			return f.fails
		},
		probeEnabled: func() bool { return f.probe },
		pathActive:   func() bool { return f.active },
		rayspa:       func() string { return version },
	}
	return f
}

func (f *fakePolicy) run(t *testing.T, c *cli, args ...string) (string, error) {
	t.Helper()
	return captureStdout(t, func() error { return c.relayPolicy(args, f.at) })
}

// rayctl update remote on|off on a relay (spec/relay-update-remote-v1.md
// §9.1): root's policy, the same file a node has, written with what else
// it holds; on only with the units for it and with rayd relay, which
// takes the exit's word, and then the path unit runs and the recover unit
// is enabled for the next boot; off disables both and removes a request
// that waits. auto does not apply. Not root: nothing changes.
func TestRelayRemote(t *testing.T) {
	c := &cli{}
	f := newFakePolicy(t, t.TempDir())
	text, err := f.run(t, c, "remote", "on")
	if err != nil || nodeupdate.ReadPolicy(f.at.policy) != (nodeupdate.Policy{Remote: "on", Auto: "off", Window: nodeupdate.DefaultWindow}) ||
		!slices.Equal(f.ran, []string{"enable --now " + deploy.RelayUpdatePath, "enable " + deploy.RelayRecover}) ||
		!strings.Contains(text, "the exit may now name a release for this relay: a signed one, newer than it; the relay downloads and verifies it itself (rayctl update remote off)") {
		t.Fatalf("on: %v %q %q", err, f.ran, text)
	}
	// A request waiting goes with off; the units are disabled, recover not
	// stopped.
	nodeupdate.WriteRequest(f.at.request, nodeupdate.Request{ID: "0a", Kind: nodeupdate.Exit, Version: "v0.28.0", By: "exit", At: time.Now()}, time.Now())
	f.ran = nil
	if _, err := f.run(t, c, "remote", "off"); err != nil || nodeupdate.ReadPolicy(f.at.policy).Remote != "off" ||
		!slices.Equal(f.ran, []string{"disable --now " + deploy.RelayUpdatePath, "disable " + deploy.RelayRecover}) {
		t.Fatalf("off: %v %q", err, f.ran)
	}
	if _, err := os.Lstat(f.at.request); !os.IsNotExist(err) {
		t.Errorf("the request waiting stays: %v", err)
	}
	// Off whatever systemd says (the runner reads the policy again); on
	// says it did not start.
	f.fails = errors.New("Failed to enable unit")
	if text, err := f.run(t, c, "remote", "off"); err != nil || !strings.Contains(text, "warning: Failed to enable unit") {
		t.Errorf("off, systemctl failing: %v %q", err, text)
	}
	if _, err := f.run(t, c, "remote", "on"); err == nil || !strings.Contains(err.Error(), "did not start") {
		t.Errorf("on, systemctl failing: %v", err)
	}
	f.fails = nil

	// Without rayd relay, or the units (a relay installed before them):
	// refused, the policy as it was.
	f = newFakePolicy(t, t.TempDir())
	f.probe = false
	if _, err := f.run(t, c, "remote", "on"); err == nil || !strings.Contains(err.Error(), "the relay's probe endpoint (rayd relay) does not run: it takes the exit's word; a new bundle from the exit has one") ||
		nodeupdate.ReadPolicy(f.at.policy).Remote != "off" || len(f.ran) != 0 {
		t.Errorf("no rayd relay: %v %q", err, f.ran)
	}
	f.probe = true
	os.Remove(filepath.Join(f.at.units, deploy.RelayUpdatePath))
	if _, err := f.run(t, c, "remote", "on"); err == nil || !strings.Contains(err.Error(), "rayctl update first") || nodeupdate.ReadPolicy(f.at.policy).Remote != "off" {
		t.Errorf("no units: %v", err)
	}
	f = newFakePolicy(t, t.TempDir())
	f.at.root = func() error { return errors.New("run as root") }
	if _, err := f.run(t, c, "remote", "on"); err == nil || nodeupdate.ReadPolicy(f.at.policy).Remote != "off" || len(f.ran) != 0 {
		t.Errorf("not root: %v", err)
	}
	// auto, and what is no command.
	for _, args := range [][]string{{"auto", "patch"}, {"auto", "off"}} {
		if _, err := f.run(t, c, args...); !errors.Is(err, errRelayAuto) ||
			err.Error() != "a relay follows its exit: rayctl update remote on takes the releases the exit names" {
			t.Errorf("%v: %v", args, err)
		}
	}
	for _, args := range [][]string{{"status", "x"}, {"nope"}, {"remote"}, {"remote", "yes"}, {"remote", "on", "x"}} {
		if _, err := f.run(t, c, args...); !errors.Is(err, errUsage) {
			t.Errorf("%v: %v", args, err)
		}
	}
}

// rayctl update status on a relay: installed, what the last update kept,
// the switch (and whether its path unit runs), the last update by the
// exit's word with its code, held releases and its error; -json the same.
func TestRelayStatus(t *testing.T) {
	saved := version
	t.Cleanup(func() { version = saved })
	version = "v0.28.0"
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, relayKeptFile), []byte(`{"version":"v0.27.0"}`), 0o600)
	f := newFakePolicy(t, dir)
	text, err := f.run(t, &cli{}, "status")
	want := "host       relay\ninstalled  v0.28.0 (rayctl)\nprevious   v0.27.0 (rayctl update -rollback)\n" +
		"remote     off (default): rayctl update remote on takes the releases the exit names\nlast       none\n" +
		"latest     rayctl update -check asks GitHub\nauto       does not apply: a relay follows its exit\n"
	if err != nil || text != want {
		t.Errorf("off:\n%s\nwant\n%s", text, want)
	}

	nodeupdate.WritePolicy(f.at.policy, nodeupdate.Policy{Remote: "on", Auto: "off", Window: nodeupdate.DefaultWindow})
	ended := time.Date(2026, 11, 20, 3, 41, 12, 0, time.UTC)
	nodeupdate.WriteStatus(f.at.status, nodeupdate.Status{ID: "0a", State: nodeupdate.Done, From: "v0.27.0", To: "v0.28.0", Target: "v0.28.0",
		Release: "v0.28.0", By: "exit", Kind: nodeupdate.Exit, Ended: ended})
	f.active = true
	text, err = f.run(t, &cli{}, "status")
	if err != nil || !strings.Contains(text, "\nremote     on: the exit names the release (raycontrol-relay-update.path active); rayctl update remote off\n"+
		"last       done: v0.27.0 → v0.28.0, by exit, 2026-11-20T03:41:12Z\nlatest") || strings.Contains(text, "warning") {
		t.Errorf("on, done:\n%s", text)
	}
	// The path unit not running, a rollback with its code, held, the
	// error; the mark of an update that did not end.
	f.active = false
	nodeupdate.WriteStatus(f.at.status, nodeupdate.Status{ID: "0b", State: nodeupdate.RolledBack, From: "v0.28.0", To: "v0.28.0", Target: "v0.28.1",
		Release: "v0.28.1", By: "exit", Kind: nodeupdate.Exit, Ended: ended, Reason: nodeupdate.ReasonCheck, Error: "rayspa is inactive/dead\x1b[2J",
		Held: []string{"v0.28.1"}})
	(relayOps{dir: dir}).mark(relayMark{State: "open", From: "v0.27.0", To: "v0.28.0", By: markByExit})
	text, _ = f.run(t, &cli{}, "status")
	for _, w := range []string{
		"unfinished the last update or rollback of this relay did not bring it back",
		"remote     on: the exit names the release (raycontrol-relay-update.path not active); rayctl update remote off\n" +
			"warning: raycontrol-relay-update.path is not active: systemctl enable --now raycontrol-relay-update.path\n",
		"last       rolled_back (check): v0.28.0 → v0.28.0, by exit, 2026-11-20T03:41:12Z\n",
		"held       v0.28.1 (did not hold here",
		"error      rayspa is inactive/dead?[2J\n",
	} {
		if !strings.Contains(text, w) {
			t.Errorf("lacks %q:\n%s", w, text)
		}
	}
	// A run with no outcome for an hour: failed, as the exit sees it.
	nodeupdate.WriteStatus(f.at.status, nodeupdate.Status{ID: "0c", State: nodeupdate.Running, From: "v0.28.0", To: "v0.28.1", By: "exit",
		Kind: nodeupdate.Exit, Requested: ended, Started: time.Now().Add(-2 * time.Hour)})
	text, _ = f.run(t, &cli{}, "status")
	if !strings.Contains(text, "last       failed: v0.28.0 → v0.28.1, by exit, asked 2026-11-20T03:41:12Z\n") ||
		!strings.Contains(text, "journalctl -u "+deploy.RelayUpdateService) {
		t.Errorf("a run with no outcome:\n%s", text)
	}

	// -json: remote by the policy, the last update, held.
	nodeupdate.WriteStatus(f.at.status, nodeupdate.Status{ID: "0b", State: nodeupdate.RolledBack, From: "v0.28.0", To: "v0.28.0", Target: "v0.28.1",
		Release: "v0.28.1", By: "exit", Kind: nodeupdate.Exit, Reason: nodeupdate.ReasonCheck, Held: []string{"v0.28.1"}})
	text, err = f.run(t, &cli{json: true}, "status")
	var j struct {
		Host, Remote, Auto, Previous, Unfinished string
		Held                                     []string
		Last                                     *nodeupdate.Status
	}
	if err != nil || json.Unmarshal([]byte(text), &j) != nil || j.Host != "relay" || j.Remote != "on" || j.Auto != "n/a" || j.Previous != "v0.27.0" ||
		j.Unfinished == "" || !slices.Equal(j.Held, []string{"v0.28.1"}) || j.Last == nil || j.Last.State != nodeupdate.RolledBack || j.Last.Reason != "check" {
		t.Errorf("-json: %v %s", err, text)
	}
	f = newFakePolicy(t, t.TempDir())
	text, _ = f.run(t, &cli{json: true}, "status")
	if !strings.Contains(text, `"remote": "off"`) || !strings.Contains(text, `"last": null`) || !strings.Contains(text, `"held": []`) {
		t.Errorf("-json, nothing yet: %s", text)
	}
}

// rayctl update -check on a relay says whether the exit's word updates it,
// by root's policy.
func TestRelayCheckRemote(t *testing.T) {
	f := newFakeRelay(t)
	if text, err := f.update(updateOpts{want: "latest", check: true}); err != nil ||
		!strings.Contains(text, "this host is a relay msk: rayctl update here updates it; rayctl update remote on takes the releases its exit names\n") {
		t.Errorf("off: %v %q", err, text)
	}
	nodeupdate.WritePolicy(f.env.policy, nodeupdate.Policy{Remote: "on", Auto: "off", Window: nodeupdate.DefaultWindow})
	if text, err := f.update(updateOpts{want: "latest", check: true}); err != nil ||
		!strings.Contains(text, "this host is a relay msk: rayctl update here updates it; the releases its exit names update it too (rayctl update remote off)\n") {
		t.Errorf("on: %v %q", err, text)
	}
}
