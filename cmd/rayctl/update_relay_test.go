package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"
	"google.golang.org/protobuf/proto"

	"github.com/arngory/raycontrol/internal/deploy"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/release"
)

// A relay is told apart from a node and from nothing: by its bundle, or,
// the bundle gone, by rayspa's relay unit. Updates by request refuse it.
func TestUpdateHost(t *testing.T) {
	dir := t.TempDir()
	db, bundle, unit := filepath.Join(dir, "rayd.db"), filepath.Join(dir, "relay.bundle"), filepath.Join(dir, "rayspa.service")
	if _, err := updateHost(db, bundle, unit); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Errorf("nothing here: %v", err)
	}
	os.WriteFile(unit, []byte("[Service]\nExecStart=/usr/local/bin/rayspa run -db /var/lib/rayd/rayd.db\n"), 0o644)
	if h, err := updateHost(db, bundle, unit); err == nil || h != noHost {
		t.Errorf("a node's rayspa unit without its database: %v %v", h, err)
	}
	os.WriteFile(unit, []byte("[Service]\nExecStart=/usr/local/bin/rayspa run -relay /run/rayspa/relay.bundle -state x\n"), 0o644)
	if h, err := updateHost(db, bundle, unit); err != nil || h != relayHost {
		t.Errorf("a relay without its bundle: %v %v", h, err)
	}
	os.Remove(unit)
	os.WriteFile(bundle, nil, 0o600)
	if h, err := updateHost(db, bundle, unit); err != nil || h != relayHost {
		t.Errorf("a relay: %v %v", h, err)
	}
	os.WriteFile(db, nil, 0o600)
	if h, err := updateHost(db, bundle, unit); err != nil || h != nodeHost {
		t.Errorf("a node: %v %v", h, err)
	}
	if !strings.Contains(errRelayByHand.Error(), "rayctl update on this host") {
		t.Errorf("the refusal says nothing of what to do: %v", errRelayByHand)
	}
}

func testRelayBundle(t *testing.T) string {
	t.Helper()
	s, err := node.RelayBundle{Version: 1, Name: "msk", Exit: netip.MustParseAddr("203.0.113.7"),
		API: node.BundleSub{Port: 8443, Pin: "pin"}, Cert: "pem"}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The stored bundle is read before anything changes: missing, readable by
// others, or broken, the update refuses and says what to do.
func TestRelayBundleAt(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "relay.bundle")
	if _, err := relayBundleAt(p); err == nil || !strings.Contains(err.Error(), "missing") || !strings.Contains(err.Error(), "nothing changed") {
		t.Errorf("missing: %v", err)
	}
	os.WriteFile(p, []byte("rcrelay1:garbage"), 0o600)
	if _, err := relayBundleAt(p); err == nil || !strings.Contains(err.Error(), "rayctl relay bundle") {
		t.Errorf("broken: %v", err)
	}
	os.WriteFile(p, []byte(testRelayBundle(t)+"\n"), 0o644)
	os.Chmod(p, 0o644)
	if _, err := relayBundleAt(p); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Errorf("readable by others: %v", err)
	}
	os.Chmod(p, 0o600)
	if b, err := relayBundleAt(p); err != nil || b.Name != "msk" {
		t.Errorf("good: %+v %v", b, err)
	}
}

// rayctl update does not take a relay below the release that brought its
// update: that one's bootstrap.sh does.
func TestRelayTarget(t *testing.T) {
	if err := relayTarget("v0.25.1"); err == nil || !strings.Contains(err.Error(), "RAYCONTROL_VERSION=v0.25.1 bash bootstrap.sh -relay") {
		t.Errorf("v0.25.1: %v", err)
	}
	for _, v := range []string{relayUpdateSince, "v0.26.1", "v1.0.0", "local", "dev"} {
		if err := relayTarget(v); err != nil {
			t.Errorf("%s: %v", v, err)
		}
	}
}

// Before anything changes: sshd on one port, this session on it, and the
// relay's perimeter as it is letting this session in; if it does not,
// the refusal says what to run on the exit, then rayctl update again.
func TestRelayBefore(t *testing.T) {
	snap := &perimeterv1.Snapshot{AdminPrefixes: []string{"203.0.113.9/32"}, AdminPorts: []*perimeterv1.Port{{Proto: "tcp", Port: 22}}}
	one := func() ([]int, error) { return []int{22}, nil }
	listens := func(int) bool { return true }
	have := func() (*perimeterv1.Snapshot, error) { return snap, nil }
	if port, w, err := relayBefore(one, listens, session{"203.0.113.9", 22}, have, "msk"); err != nil || w != "" || port != 22 {
		t.Errorf("an admin's session: %d %q %v", port, w, err)
	}
	if _, w, err := relayBefore(one, listens, session{}, have, "msk"); err != nil || !strings.Contains(w, "not known") {
		t.Errorf("tmux: %q %v", w, err)
	}
	_, _, err := relayBefore(one, listens, session{"198.51.100.7", 22}, have, "msk")
	if err == nil || !strings.Contains(err.Error(), "rayctl relay set -admin 203.0.113.9/32,198.51.100.7 msk, then rayctl update again") ||
		!strings.Contains(err.Error(), "nothing changed") {
		t.Errorf("outside the admin addresses: %v", err)
	}
	two := func() ([]int, error) { return []int{22, 2222}, nil }
	if _, _, err := relayBefore(two, listens, session{"203.0.113.9", 22}, have, "msk"); err == nil || !strings.Contains(err.Error(), "keep one") {
		t.Errorf("two ports: %v", err)
	}
	none := func() (*perimeterv1.Snapshot, error) { return nil, os.ErrNotExist }
	if _, _, err := relayBefore(one, listens, session{"203.0.113.9", 22}, none, "msk"); err == nil || !strings.Contains(err.Error(), "bootstrap.sh -relay") {
		t.Errorf("no snapshot: %v", err)
	}
	broken := func() ([]int, error) { return nil, errors.New("sshd -T failed") }
	if _, _, err := relayBefore(broken, listens, session{}, have, "msk"); err == nil || !strings.Contains(err.Error(), "fix sshd") {
		t.Errorf("sshd: %v", err)
	}
}

// The update's steps and its way back: a failure to place the first binary
// changes nothing; a failing install or check brings the previous relay
// back; only a relay that does not come back is left open, and the error
// says so. The mark goes once the relay is checked, and stays when it is
// left open.
func TestRelayUpdateRun(t *testing.T) {
	boom := errors.New("boom")
	for name, c := range map[string]struct {
		fail     string // the steps that fail; "place0": before the first binary
		calls    []string
		contains string
		back     bool // rolledBack
	}{
		"done":            {"", []string{"keep", "mark", "place", "install", "check", "unmark"}, "", false},
		"keep":            {"keep", []string{"keep"}, "nothing changed", false},
		"mark":            {"mark", []string{"keep", "mark"}, "nothing changed", false},
		"nothing placed":  {"place0", []string{"keep", "mark", "place", "unmark"}, "nothing changed: the relay runs as it did", false},
		"place":           {"place", []string{"keep", "mark", "place", "restore", "checkBack", "unmark"}, "installing: boom", true},
		"install":         {"install", []string{"keep", "mark", "place", "install", "restore", "checkBack", "unmark"}, "the relay install: boom", true},
		"check":           {"check", []string{"keep", "mark", "place", "install", "check", "restore", "checkBack", "unmark"}, "after the install: boom", true},
		"restore":         {"install,restore", []string{"keep", "mark", "place", "install", "restore", "open"}, "host left open", false},
		"checkBack":       {"check,checkBack", []string{"keep", "mark", "place", "install", "check", "restore", "checkBack", "open"}, "host left open", false},
		"open fails":      {"install,checkBack,open", []string{"keep", "mark", "place", "install", "restore", "checkBack", "open"}, "could NOT be taken down", false},
		"the words stand": {"install", nil, "the previous version runs again", true},
	} {
		var calls []string
		fails := strings.Split(c.fail, ",")
		step := func(n string) func() error {
			return func() error {
				calls = append(calls, n)
				if slices.Contains(fails, n) {
					return boom
				}
				return nil
			}
		}
		u := relayUpdate{keep: step("keep"), mark: step("mark"), install: step("install"), check: step("check"),
			restore: step("restore"), checkBack: step("checkBack"), open: step("open"),
			unmark: func() { calls = append(calls, "unmark") },
			place: func() (bool, error) {
				calls = append(calls, "place")
				switch {
				case slices.Contains(fails, "place0"):
					return false, boom
				case slices.Contains(fails, "place"):
					return true, boom
				}
				return true, nil
			}}
		var err error
		_, _ = captureStdout(t, func() error { err = u.run(); return nil })
		var rb rolledBack
		switch {
		case c.fail == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case c.fail != "" && (err == nil || !strings.Contains(err.Error(), c.contains)):
			t.Errorf("%s: %v", name, err)
		case errors.As(err, &rb) != c.back:
			t.Errorf("%s: rolled back %v: %v", name, !c.back, err)
		case c.calls != nil && !slices.Equal(calls, c.calls):
			t.Errorf("%s: %v, want %v", name, calls, c.calls)
		}
	}
}

// relayTable is an nft listing of a relay's table as rayspa leaves it:
// the admin set filled, the forwarding to the exit with its ports.
const relayTable = `table inet raycontrol {
	set admin4 {
		type ipv4_addr
		flags interval
		elements = { 203.0.113.9 }
	}
	set admin6 {
		type ipv6_addr
		flags interval
	}
	set relay_fwd {
		type inet_proto . inet_service
		elements = { tcp . 443, udp . 443 }
	}
	chain relay_dnat {
		type nat hook prerouting priority dstnat - 1; policy accept;
		meta nfproto ipv4 fib daddr type local meta l4proto . th dport @relay_fwd dnat ip to 203.0.113.7
	}
}
`

// After the update and after its rollback: rayspa runs, the one started
// from the binary on disk, its table applied the perimeter of the snapshot
// it runs from: the admin addresses and, when that snapshot has services
// the relay forwards, the forwarding to the exit; the kernel forwards, SSH from the admin addresses, the version
// wanted, the probe endpoint if it ran before.
func TestRelayHealth(t *testing.T) {
	up := map[string]string{"ActiveState": "active", "SubState": "running"}
	down := map[string]string{"ActiveState": "inactive", "SubState": "dead"}
	snap := &perimeterv1.Snapshot{AdminPrefixes: []string{"203.0.113.9/32"}, AdminPorts: []*perimeterv1.Port{{Proto: "tcp", Port: 22}},
		Services: relayServices(true)}
	good := func() relayHealth {
		return relayHealth{
			rayspa: func() (map[string]string, error) { return up, nil }, probe: func() (map[string]string, error) { return up, nil },
			probeRan: true, exe: func() error { return nil },
			nft:        func(...string) (string, error) { return relayTable, nil },
			forwarding: func() ([]byte, error) { return []byte("1\n"), nil },
			snapshot:   func() (*perimeterv1.Snapshot, error) { return snap, nil },
			version:    func() string { return "v0.26.1" }, want: "v0.26.1", port: 22, client: "203.0.113.9", name: "msk",
		}
	}
	if err := good().check(); err != nil {
		t.Fatal(err)
	}
	table := func(s string) func(...string) (string, error) {
		return func(...string) (string, error) { return s, nil }
	}
	for name, c := range map[string]struct {
		break_   func(*relayHealth)
		contains string
	}{
		"rayspa down":    {func(h *relayHealth) { h.rayspa = func() (map[string]string, error) { return down, nil } }, "rayspa is inactive/dead"},
		"an old process": {func(h *relayHealth) { h.exe = func() error { return errors.New("it was not started again") } }, "not started again"},
		"no table": {func(h *relayHealth) {
			h.nft = func(...string) (string, error) { return "", errors.New("No such file or directory") }
		}, "no perimeter table"},
		"no admin set": {func(h *relayHealth) {
			h.nft = table(strings.Replace(relayTable, "elements = { 203.0.113.9 }", "", 1))
		}, "no admin address"},
		"no forwarded ports": {func(h *relayHealth) {
			h.nft = table(strings.Replace(relayTable, "elements = { tcp . 443, udp . 443 }", "", 1))
		}, "forwards no service"},
		"no DNAT": {func(h *relayHealth) {
			h.nft = table(strings.Replace(relayTable, "dnat ip to 203.0.113.7", "counter", 1))
		}, "forwards no service"},
		"no snapshot": {func(h *relayHealth) {
			h.snapshot = func() (*perimeterv1.Snapshot, error) { return nil, os.ErrNotExist }
		}, "perimeter cannot be read"},
		"no forwarding":   {func(h *relayHealth) { h.forwarding = func() ([]byte, error) { return []byte("0\n"), nil } }, "does not forward"},
		"session outside": {func(h *relayHealth) { h.client = "198.51.100.7" }, "rayctl relay set -admin"},
		"old version":     {func(h *relayHealth) { h.version = func() string { return "v0.26.0" } }, `"v0.26.0", not v0.26.1`},
		"probe down":      {func(h *relayHealth) { h.probe = func() (map[string]string, error) { return down, nil } }, "probe endpoint"},
	} {
		h := good()
		c.break_(&h)
		if err := h.check(); err == nil || !strings.Contains(err.Error(), c.contains) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A perimeter with no service to forward (none given to the relay
	// yet, or the exit's admin took them away since the update kept the
	// relay): relay_fwd is empty and must be, its own SSH and the probe
	// are served here; no probe before, a local build.
	h := good()
	h.nft = table(strings.Replace(relayTable, "elements = { tcp . 443, udp . 443 }", "", 1))
	h.snapshot = func() (*perimeterv1.Snapshot, error) {
		return &perimeterv1.Snapshot{AdminPrefixes: snap.AdminPrefixes, AdminPorts: snap.AdminPorts, Services: relayServices(false)}, nil
	}
	h.probeRan, h.probe = false, func() (map[string]string, error) { return down, nil }
	h.want, h.version = "local", func() string { return "dev" }
	if err := h.check(); err != nil {
		t.Errorf("nothing forwarded before, no probe, a local build: %v", err)
	}
	// Waiting: a rayspa that comes up passes; one that dies at once does not.
	n := 0
	coming := func() error {
		if n++; n < 3 {
			return errors.New("not yet")
		}
		return nil
	}
	ctx := context.Background()
	if err := waitHealthy(ctx, coming, time.Second, time.Millisecond, time.Millisecond); err != nil {
		t.Errorf("coming up: %v", err)
	}
	n = 0
	dies := func() error {
		if n++; n > 1 {
			return errors.New("rayspa is activating/auto-restart")
		}
		return nil
	}
	if err := waitHealthy(ctx, dies, time.Second, time.Millisecond, time.Millisecond); err == nil {
		t.Error("a rayspa that died after its start passed")
	}
}

// runningBinary: the process's binary is the file on disk, or it is not
// (renamed over since it started). This test's own process stands in.
func TestRunningBinary(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	if _, err := os.Stat("/proc/self/exe"); err != nil {
		t.Skip("no /proc")
	}
	pid := func(string) string { return fmt.Sprint(os.Getpid()) }
	if err := runningBinary("rayspa.service", self, pid)(); err != nil {
		t.Errorf("the binary it runs: %v", err)
	}
	other := filepath.Join(t.TempDir(), "rayspa")
	os.WriteFile(other, []byte("another binary"), 0o755)
	if err := runningBinary("rayspa.service", other, pid)(); err == nil || !strings.Contains(err.Error(), "not started again") {
		t.Errorf("another binary: %v", err)
	}
	if err := runningBinary("rayspa.service", self, func(string) string { return "0" })(); err == nil || !strings.Contains(err.Error(), "no main process") {
		t.Errorf("no process: %v", err)
	}
}

// fakeRelay is a relay host on a test's own directories: rayspa, rayctl
// and rayd, rayspa's unit, the sysctl files, its snapshot (with a
// service), the stored bundle; systemctl and the rest recorded, and the
// steps rayctl update cannot run here (the release, the install, the
// check of a running relay) given.
type fakeRelay struct {
	t      *testing.T
	dir    string
	ran    []string
	wants  []string         // the versions each check after a change expected
	bad    map[string]error // a check of that version fails
	before error            // relayBefore's refusal
	asked  int              // relayBefore called
	open   bool             // hostOpen
	down   bool             // the units disabled --now and not started since
	yes    bool             // the answer to the prompt
	prompt string
	inst   func() error // the install
	placeF func(src, dst string) error
	// signalled: a signal came from the point of no return on (the
	// unit's stop, a shutdown).
	signalled bool
	// early: the unit's stop came before the point of no return (an
	// update by the exit's word takes it from its start); stop ends the
	// update's context as the signal would.
	early bool
	stop  context.CancelFunc
	env   relayEnv
}

func (f *fakeRelay) at(p string) string { return filepath.Join(f.dir, p) }

func (f *fakeRelay) write(p, s string) {
	f.t.Helper()
	if err := os.WriteFile(f.at(p), []byte(s), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeRelay) read(p string) string {
	b, err := os.ReadFile(f.at(p))
	if err != nil {
		return "<none>"
	}
	return string(b)
}

func (f *fakeRelay) record(s string) { f.ran = append(f.ran, s) }

// relayServices are the services of a relay's snapshot as its exit sends
// them (api.RelaySnapshot): the relay's own SSH and the probe endpoint,
// served there (Local), and, if forwarded, a service it forwards to the
// exit on relayTable's ports.
func relayServices(forwarded bool) []*perimeterv1.Service {
	s := []*perimeterv1.Service{
		{Id: 5, Local: true, Ports: []*perimeterv1.Port{{Proto: "tcp", Port: 22}}},
		{Id: 900, Local: true, Ports: []*perimeterv1.Port{{Proto: "tcp", Port: 8443}, {Proto: "udp", Port: 8443}}},
	}
	if forwarded {
		s = append(s, &perimeterv1.Service{Id: 1, Ports: []*perimeterv1.Port{{Proto: "tcp", Port: 443}, {Proto: "udp", Port: 443}}})
	}
	return s
}

// snapshotWith is a snapshot that lets 203.0.113.9 in on port 22, with a
// service it forwards if services.
func snapshotWith(t *testing.T, services bool) string {
	t.Helper()
	snap := &perimeterv1.Snapshot{AdminPrefixes: []string{"203.0.113.9/32"}, AdminPorts: []*perimeterv1.Port{{Proto: "tcp", Port: 22}},
		Services: relayServices(services)}
	b, err := proto.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func newFakeRelay(t *testing.T) *fakeRelay {
	f := &fakeRelay{t: t, dir: t.TempDir(), bad: map[string]error{}, yes: true}
	for _, d := range []string{"bin", "etc", "etc/sysctl", "state"} {
		os.Mkdir(f.at(d), 0o755)
	}
	f.write("bin/rayspa", "rayspa v0.26.0")
	f.write("bin/rayctl", "rayctl v0.26.0")
	f.write("bin/rayd", "rayd v0.26.0")
	f.write("etc/rayspa.service", "old unit")
	f.write("etc/sysctl/90-raycontrol.conf", "hardening\n")
	f.write("etc/sysctl/91-raycontrol-relay.conf", "net.ipv4.ip_forward = 1\n")
	f.write("state/snapshot.pb", snapshotWith(t, true))
	if err := os.WriteFile(f.at("relay.bundle"), []byte(testRelayBundle(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	ops := relayOps{
		dir: f.at("previous"), bins: map[string]string{"rayspa": f.at("bin/rayspa"), "rayctl": f.at("bin/rayctl"), "rayd": f.at("bin/rayd")},
		files: []string{f.at("etc/rayspa.service"), f.at("etc/rayd-relay.service"),
			f.at("etc/sysctl/90-raycontrol.conf"), f.at("etc/sysctl/91-raycontrol-relay.conf")},
		sysctlDir: f.at("etc/sysctl") + "/", snapshot: f.at("state/snapshot.pb"),
		units:  []string{"rayspa.service", "rayd-relay.service"},
		state:  func(u string) unitWas { return unitWas{Enabled: !f.down, Active: !f.down} },
		loaded: func(string) bool { return true },
		run: func(name string, args ...string) error {
			f.record(strings.Join(append([]string{name}, args...), " "))
			switch {
			case len(args) > 1 && args[0] == "disable" && args[1] == "--now":
				f.down = true
			case len(args) > 0 && args[0] == "start":
				f.down = false
			}
			return nil
		},
		place: func(src, dst string) error {
			if f.placeF != nil {
				if err := f.placeF(src, dst); err != nil {
					return err
				}
			}
			f.record("place " + filepath.Base(dst))
			b, err := os.ReadFile(src)
			if err != nil {
				return err
			}
			return os.WriteFile(dst, b, 0o755)
		},
		disarm: func() { f.record("disarm") }, unforward: func() { f.record("unforward") },
		tableGone: func() bool { return true }, rayspa: "rayspa",
	}
	f.env = relayEnv{
		bundle: f.at("relay.bundle"), ops: ops, session: session{"203.0.113.9", 22}, policy: f.at("policy.json"),
		before: func(string) (int, string, error) {
			f.asked++
			return 22, "", f.before
		},
		sshPort:     func() int { return 22 },
		hostOpen:    func() bool { return f.open },
		lock:        func(what string) error { f.record("lock " + what); return nil },
		installLock: func() (*os.File, error) { return takeInstallLock(f.at("install.lock")) },
		newStage:    func() (string, error) { return os.MkdirTemp(f.dir, "stage-") },
		stage: func(_ context.Context, o updateOpts, stage, installed string) (staged, error) {
			if o.check {
				fmt.Printf("installed %s, release v0.26.1 available: rayctl update\n", installed)
				return staged{version: "v0.26.1", done: true}, nil
			}
			for _, n := range []string{"rayspa", "rayctl", "rayd"} {
				os.WriteFile(filepath.Join(stage, n), []byte(n+" v0.26.1"), 0o755)
			}
			return staged{version: "v0.26.1"}, nil
		},
		place: func(stage string) (bool, error) { return placeRelayBinaries(stage, ops.bins, ops.place) },
		install: func(lock *os.File) error {
			f.record("install")
			// The lock the update took goes on to the install, held.
			if lock == nil {
				return errors.New("no install lock passed on")
			}
			if _, err := lock.Stat(); err != nil {
				return fmt.Errorf("the install lock passed on is closed: %w", err)
			}
			if other, err := takeInstallLock(f.at("install.lock")); err == nil {
				other.Close()
				return errors.New("the install lock is not held through the install")
			}
			if f.inst != nil {
				return f.inst()
			}
			return nil
		},
		health: func(w healthWant) func() error {
			return func() error { f.wants = append(f.wants, w.want); return f.bad[w.want] }
		},
		confirm: func(p string) bool { f.prompt = p; return f.yes },
		signals: func() (func() bool, func()) {
			f.record("signals")
			return func() bool { return f.signalled }, func() { f.record("signals end") }
		},
		interrupt: func(ctx context.Context) (context.Context, func() bool, func()) {
			f.record("interrupt")
			ctx, f.stop = context.WithCancel(ctx)
			return ctx, func() bool { return f.early }, f.stop
		},
	}
	return f
}

func (f *fakeRelay) update(o updateOpts) (string, error) {
	return captureStdout(f.t, func() error { return f.env.update(context.Background(), o, false, "v0.26.0") })
}

func (f *fakeRelay) rollback(yes bool) (string, error) {
	return captureStdout(f.t, func() error { return f.env.update(context.Background(), updateOpts{yes: yes}, true, "v0.26.1") })
}

// keep and restore on files of a test's own: the binaries (one already as
// kept is not placed again), the files (one added by the update goes),
// rayspa's snapshot, the sysctl files forwarding first, the units stopped
// for sure, enabled and started as they were.
func TestRelayKeepRestore(t *testing.T) {
	f := newFakeRelay(t)
	ops := f.env.ops
	ops.state = func(u string) unitWas { return unitWas{Enabled: u == "rayspa.service", Active: u == "rayspa.service"} }
	k, err := ops.keep("v0.26.0")
	if err != nil {
		t.Fatal(err)
	}
	if !k.Snapshot || !k.Files[f.at("etc/rayspa.service")] || k.Files[f.at("etc/rayd-relay.service")] || !k.Units["rayspa.service"].Active {
		t.Fatalf("kept %+v", k)
	}
	// The update: new rayspa and rayd, rayctl as it was, a new unit, the
	// old one rewritten, the snapshot gone (the install removes it),
	// forwarding's file gone (a failed install's unforward).
	f.write("bin/rayspa", "rayspa v0.26.1")
	f.write("bin/rayd", "rayd v0.26.1")
	f.write("etc/rayspa.service", "new unit")
	f.write("etc/rayd-relay.service", "new probe unit")
	os.Remove(f.at("etc/sysctl/91-raycontrol-relay.conf"))
	os.Remove(f.at("state/snapshot.pb"))
	f.ran = nil
	var back relayKept
	if _, err := captureStdout(t, func() (err error) { back, err = ops.restore(true); return err }); err != nil {
		t.Fatal(err)
	}
	if back.Version != "v0.26.0" {
		t.Errorf("version %q", back.Version)
	}
	for p, want := range map[string]string{
		"bin/rayspa": "rayspa v0.26.0", "bin/rayctl": "rayctl v0.26.0", "bin/rayd": "rayd v0.26.0",
		"etc/rayspa.service": "old unit", "etc/rayd-relay.service": "<none>",
		"etc/sysctl/91-raycontrol-relay.conf": "net.ipv4.ip_forward = 1\n", "state/snapshot.pb": snapshotWith(t, true),
	} {
		if got := f.read(p); got != want {
			t.Errorf("%s: %q, want %q", p, got, want)
		}
	}
	want := []string{"disarm", "systemctl stop rayd-relay.service", "systemctl stop rayspa.service", "place rayd", "place rayspa",
		"systemctl daemon-reload",
		"sysctl -q -e -p " + f.at("etc/sysctl/91-raycontrol-relay.conf"), "sysctl -q -e -p " + f.at("etc/sysctl/90-raycontrol.conf"),
		"systemctl enable rayspa.service", "systemctl disable rayd-relay.service", "systemctl start rayspa.service"}
	if !slices.Equal(f.ran, want) {
		t.Errorf("ran %q\nwant %q", f.ran, want)
	}
	// A rollback by hand keeps rayspa's snapshot as it is now.
	f.write("state/snapshot.pb", "the exit's latest")
	if _, err := captureStdout(t, func() error { _, err := ops.restore(false); return err }); err != nil {
		t.Fatal(err)
	}
	if got := f.read("state/snapshot.pb"); got != "the exit's latest" {
		t.Errorf("snapshot %q after a rollback by hand", got)
	}
	// A unit that does not stop: no restore under a rayspa that runs on.
	run := ops.run
	ops.run = func(name string, args ...string) error {
		if len(args) > 0 && args[0] == "stop" {
			return errors.New("timed out")
		}
		return run(name, args...)
	}
	f.ran = nil
	if _, err := captureStdout(t, func() error { _, err := ops.restore(true); return err }); err == nil || !strings.Contains(err.Error(), "stopping") {
		t.Errorf("a unit that did not stop: %v", err)
	}
	if slices.ContainsFunc(f.ran, func(s string) bool { return strings.HasPrefix(s, "place") }) {
		t.Errorf("binaries placed under a running rayspa: %q", f.ran)
	}
	ops.run = run
	// Nothing kept: nothing to roll back to.
	none := ops
	none.dir = f.at("none")
	if _, err := none.restore(true); err == nil || !strings.Contains(err.Error(), "nothing to roll back to") {
		t.Errorf("no copy: %v", err)
	}
	// open: rayspa down, forwarding off, the mark says so; a table that
	// stays is said, and so is a rayspa that does not stop and puts its
	// table back a moment later: the host is not open then.
	ops.state = f.env.ops.state
	f.ran = nil
	if err := ops.open(); err != nil || !slices.Equal(f.ran, []string{"systemctl disable --now rayd-relay.service rayspa.service", "rayspa teardown", "unforward"}) {
		t.Errorf("open: %v %q", err, f.ran)
	}
	if m, ok := ops.readMark(); !ok || m.State != "open" {
		t.Errorf("open left the mark %+v %v", m, ok)
	}
	looked := 0
	ops.tableGone = func() bool { looked++; return looked == 1 }
	if err := ops.open(); err == nil || !strings.Contains(err.Error(), "the host is NOT open") || looked != 2 {
		t.Errorf("a table back a moment later: %v, looked %d", err, looked)
	}
	ops.tableGone = func() bool { return true }
	ops.state = func(string) unitWas { return unitWas{Enabled: true, Active: true} }
	if err := ops.open(); err == nil || !strings.Contains(err.Error(), "rayspa still runs") {
		t.Errorf("a rayspa that did not stop: %v", err)
	}
	ops.tableGone = func() bool { return false }
	if err := ops.open(); err == nil {
		t.Error("a table left was not said")
	}
}

// The check after a change judges the table by the snapshot rayspa runs
// from, not by the one kept before the change: a relay that forwards
// nothing (its snapshot has only its own SSH and the probe, served there)
// passes with relay_fwd empty, before and after the exit's admin took its
// services away, and so does -rollback, which keeps the snapshot as it is
// now; one whose snapshot has a service to forward and whose table has
// none does not, nor does its rollback, and only then is the host opened.
func TestRelayCheckBySnapshotRun(t *testing.T) {
	up := map[string]string{"ActiveState": "active", "SubState": "running"}
	empty := strings.Replace(relayTable, "elements = { tcp . 443, udp . 443 }", "", 1)
	checked := func(f *fakeRelay, table string) {
		f.env.health = func(w healthWant) func() error {
			h := relayHealth{
				rayspa: func() (map[string]string, error) { return up, nil }, probe: func() (map[string]string, error) { return up, nil },
				probeRan: w.probeRan, exe: func() error { return nil },
				nft:        func(...string) (string, error) { return table, nil },
				forwarding: func() ([]byte, error) { return []byte("1\n"), nil },
				snapshot:   func() (*perimeterv1.Snapshot, error) { return readSnapshot(f.at("state/snapshot.pb")) },
				version:    func() string { return w.want }, want: w.want, port: w.port, client: w.client, name: w.name,
			}
			return func() error { f.wants = append(f.wants, w.want); return h.check() }
		}
	}
	opened := func(f *fakeRelay) bool {
		return slices.ContainsFunc(f.ran, func(s string) bool { return strings.Contains(s, "disable --now") })
	}

	// Nothing to forward from the start.
	f := newFakeRelay(t)
	f.write("state/snapshot.pb", snapshotWith(t, false))
	checked(f, empty)
	if _, err := f.update(updateOpts{want: "latest", yes: true}); err != nil || opened(f) {
		t.Errorf("a relay with nothing to forward: %v %q", err, f.ran)
	}

	// Kept with a service; the exit's admin takes it away, the new version
	// takes the new snapshot: the update passes, and -rollback after it.
	f = newFakeRelay(t)
	checked(f, empty)
	f.inst = func() error { f.write("state/snapshot.pb", snapshotWith(t, false)); return nil }
	if _, err := f.update(updateOpts{want: "latest", yes: true}); err != nil || opened(f) {
		t.Fatalf("services taken away during the update: %v %q", err, f.ran)
	}
	if _, err := f.rollback(true); err != nil || opened(f) || f.read("bin/rayspa") != "rayspa v0.26.0" {
		t.Errorf("-rollback after the services were taken away: %v %q", err, f.ran)
	}

	// A service to forward and a table that forwards none.
	f = newFakeRelay(t)
	checked(f, empty)
	if _, err := f.update(updateOpts{want: "latest", yes: true}); err == nil || !strings.Contains(err.Error(), "forwards no service") || !opened(f) {
		t.Errorf("a table that does not forward: %v %q", err, f.ran)
	}
}

// A sysctl file that does not load whole (net.ipv6.* with IPv6 off, a
// container's read-only keys) is a warning in a restore, as in the install,
// never a reason to open the host: the check after, of the previous
// version, is what judges the relay (forwarding read in /proc among it).
func TestRelayRestoreSysctlWarns(t *testing.T) {
	sysctlFails := func(f *fakeRelay) {
		run := f.env.ops.run
		f.env.ops.run = func(name string, args ...string) error {
			err := run(name, args...)
			if name == "sysctl" {
				return errors.New("sysctl: cannot stat /proc/sys/net/ipv6/conf/all/accept_ra: No such file or directory")
			}
			return err
		}
	}
	opened := func(f *fakeRelay) bool {
		return slices.ContainsFunc(f.ran, func(s string) bool { return strings.Contains(s, "disable --now") })
	}

	// An update whose check fails: rolled back, the previous version checked.
	f := newFakeRelay(t)
	sysctlFails(f)
	f.bad["v0.26.1"] = errors.New("rayspa is inactive/dead")
	text, err := f.update(updateOpts{want: "latest", yes: true})
	if rb := (rolledBack{}); !errors.As(err, &rb) || opened(f) {
		t.Fatalf("not rolled back: %v %q", err, f.ran)
	}
	if !strings.Contains(text, "warning: sysctl: cannot stat") || !slices.Equal(f.wants, []string{"v0.26.1", "v0.26.0"}) {
		t.Errorf("output %q, checked %v", text, f.wants)
	}
	if !slices.Contains(f.ran, "sysctl -q -e -p "+f.at("etc/sysctl/90-raycontrol.conf")) {
		t.Errorf("sysctl not as the install runs it: %q", f.ran)
	}
	// -rollback asked for on a healthy relay.
	f.ran = nil
	if _, err := f.rollback(true); err != nil || opened(f) {
		t.Errorf("-rollback: %v %q", err, f.ran)
	}
	// The previous version does not pass its check (forwarding off, say):
	// then, and only then, the host is opened.
	f = newFakeRelay(t)
	sysctlFails(f)
	f.bad["v0.26.1"] = errors.New("rayspa is inactive/dead")
	f.bad["v0.26.0"] = errors.New(`the relay does not forward (net.ipv4.ip_forward "0")`)
	if _, err := f.update(updateOpts{want: "latest", yes: true}); err == nil || !strings.Contains(err.Error(), "host left open") || !opened(f) {
		t.Errorf("not opened: %v", err)
	}
}

// After a restore loads the sysctl files it reads them back, as the
// install does: a hardening key that did not take is said, a warning and
// no failure; one the host has not (sysctl -e skipped it) is not, nor is
// forwarding, which the check after reads.
func TestRelayRestoreSysctlReadBack(t *testing.T) {
	f := newFakeRelay(t)
	f.write("etc/sysctl/90-raycontrol.conf", "# hardening\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv6.conf.all.accept_ra = 0\n"+
		"net.ipv4.tcp_syncookies = 1\n")
	ops := f.env.ops
	if _, err := ops.keep("v0.26.0"); err != nil {
		t.Fatal(err)
	}
	var read []string
	ops.sysctlValue = func(key string) (string, error) {
		read = append(read, key)
		switch key {
		case "net.ipv4.conf.all.accept_redirects":
			return "1\n", nil
		case "net.ipv6.conf.all.accept_ra":
			return "", errors.New("sysctl: cannot stat /proc/sys/net/ipv6/conf/all/accept_ra")
		case "net.ipv4.ip_forward":
			return "0\n", nil
		}
		return "1\n", nil
	}
	text, err := captureStdout(t, func() error { _, err := ops.restore(true); return err })
	if err != nil {
		t.Fatal(err)
	}
	want := "warning: after the restore net.ipv4.conf.all.accept_redirects is 1, not 0: another sysctl file overrides " +
		f.at("etc/sysctl/90-raycontrol.conf") + ", or the host does not let it change (a container)\n"
	if strings.Count(text, "warning:") != 1 || !strings.Contains(text, want) {
		t.Errorf("output %q", text)
	}
	if !slices.Equal(read, []string{"net.ipv4.ip_forward", "net.ipv4.conf.all.accept_redirects", "net.ipv6.conf.all.accept_ra",
		"net.ipv4.tcp_syncookies"}) {
		t.Errorf("read back %q", read)
	}
}

// The copy is whole or not there: a keep that fails halfway leaves no
// relay.json to restore from.
func TestRelayKeepWholeOrNothing(t *testing.T) {
	f := newFakeRelay(t)
	os.Remove(f.at("state/snapshot.pb"))
	os.Mkdir(f.at("state/snapshot.pb"), 0o700) // not a regular file
	if _, err := f.env.ops.keep("v0.26.0"); err == nil {
		t.Fatal("kept a snapshot that is a directory")
	}
	if _, err := os.Stat(filepath.Join(f.env.ops.dir, relayKeptFile)); !os.IsNotExist(err) {
		t.Errorf("relay.json after a keep that failed: %v", err)
	}
	if _, err := f.env.ops.kept(); err == nil {
		t.Error("a rollback would restore from a copy that is not whole")
	}
	// The copy of an earlier update stays as it was when a keep fails,
	// and goes once a new one is whole; nothing is left beside it.
	f = newFakeRelay(t)
	if _, err := f.env.ops.keep("v0.25.9"); err != nil {
		t.Fatal(err)
	}
	os.Remove(f.at("state/snapshot.pb"))
	os.Mkdir(f.at("state/snapshot.pb"), 0o700)
	if _, err := f.env.ops.keep("v0.26.0"); err == nil {
		t.Fatal("kept a snapshot that is a directory")
	}
	if k, err := f.env.ops.kept(); err != nil || k.Version != "v0.25.9" {
		t.Errorf("the earlier copy after a keep that failed: %+v %v", k, err)
	}
	os.Remove(f.at("state/snapshot.pb"))
	if _, err := f.env.ops.keep("v0.26.0"); err != nil {
		t.Fatal(err)
	}
	if k, err := f.env.ops.kept(); err != nil || k.Version != "v0.26.0" || f.read("previous/VERSION") != "v0.26.0\n" {
		t.Errorf("the new copy: %+v %v", k, err)
	}
	for _, d := range []string{"previous.new", "previous.old"} {
		if _, err := os.Lstat(f.at(d)); !os.IsNotExist(err) {
			t.Errorf("%s left: %v", d, err)
		}
	}
	// Cut off between the renames: the earlier copy is taken back first.
	os.Rename(f.at("previous"), f.at("previous.old"))
	os.Mkdir(f.at("state/snapshot.pb"), 0o700)
	if _, err := f.env.ops.keep("v0.26.1"); err == nil {
		t.Fatal("kept a snapshot that is a directory")
	}
	if k, err := f.env.ops.kept(); err != nil || k.Version != "v0.26.0" {
		t.Errorf("the copy cut off between the renames: %+v %v", k, err)
	}
}

// The swap of a whole new copy for the earlier one: if the new copy cannot
// take its place, the earlier one goes back to it; if the earlier one
// cannot be moved aside, it stays. Either way the keep fails, the earlier
// copy is the one kept, and nothing is left beside it.
func TestRelayKeepRenameFails(t *testing.T) {
	for _, fails := range []string{"previous.new", "previous"} {
		f := newFakeRelay(t)
		if _, err := f.env.ops.keep("v0.25.9"); err != nil {
			t.Fatal(err)
		}
		var renamed []string
		f.env.ops.rename = func(from, to string) error {
			renamed = append(renamed, filepath.Base(from)+" "+filepath.Base(to))
			if from == f.at(fails) {
				return errors.New("no space left on device")
			}
			return os.Rename(from, to)
		}
		if _, err := f.env.ops.keep("v0.26.0"); err == nil || !strings.Contains(err.Error(), "no space") {
			t.Fatalf("%s not renamed: keep %v", fails, err)
		}
		if k, err := f.env.ops.kept(); err != nil || k.Version != "v0.25.9" || f.read("previous/VERSION") != "v0.25.9\n" {
			t.Errorf("%s not renamed: kept %+v %v", fails, k, err)
		}
		for _, d := range []string{"previous.new", "previous.old"} {
			if _, err := os.Lstat(f.at(d)); !os.IsNotExist(err) {
				t.Errorf("%s not renamed: %s left (%v)", fails, d, err)
			}
		}
		want := []string{"previous previous.old", "previous.new previous", "previous.old previous"}
		if fails == "previous" {
			want = want[:1]
		}
		if !slices.Equal(renamed, want) {
			t.Errorf("%s not renamed: renames %q", fails, renamed)
		}
	}
}

// rayctl update on a relay, the whole of it on a fake host.
func TestRelayUpdateWhole(t *testing.T) {
	// Done: the check expects the new version, the copy and nothing else
	// stays, the signals are caught from the point of no return.
	f := newFakeRelay(t)
	if _, err := f.update(updateOpts{want: "latest"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.wants, []string{"v0.26.1"}) {
		t.Errorf("checked %v", f.wants)
	}
	if f.read("bin/rayspa") != "rayspa v0.26.1" || !strings.Contains(f.prompt, "at most about 5 minutes") {
		t.Errorf("rayspa %q, prompt %q", f.read("bin/rayspa"), f.prompt)
	}
	if k, err := f.env.ops.kept(); err != nil || k.Version != "v0.26.0" || !k.Snapshot {
		t.Errorf("kept %+v %v", k, err)
	}
	if _, marked := f.env.ops.readMark(); marked {
		t.Error("a mark after an update that ended checked")
	}
	if !slices.Contains(f.ran, "lock update") || !slices.Contains(f.ran, "signals") {
		t.Errorf("ran %q", f.ran)
	}

	// The install fails having removed the snapshot and rewritten the
	// unit: the relay comes back as it ran, its snapshot too.
	f = newFakeRelay(t)
	f.inst = func() error {
		os.Remove(f.at("state/snapshot.pb"))
		f.write("etc/rayspa.service", "new unit")
		return errors.New("the relay took no perimeter from its exit")
	}
	_, err := f.update(updateOpts{want: "latest", yes: true})
	if rb := (rolledBack{}); !errors.As(err, &rb) {
		t.Fatalf("not rolled back: %v", err)
	}
	if f.read("state/snapshot.pb") != snapshotWith(t, true) || f.read("etc/rayspa.service") != "old unit" || f.read("bin/rayspa") != "rayspa v0.26.0" {
		t.Errorf("not back as it ran: %q %q %q", f.read("state/snapshot.pb"), f.read("etc/rayspa.service"), f.read("bin/rayspa"))
	}
	if !slices.Equal(f.wants, []string{"v0.26.0"}) {
		t.Errorf("checked %v", f.wants)
	}
	if _, marked := f.env.ops.readMark(); marked {
		t.Error("a mark after a rollback that ended checked")
	}

	// The previous relay does not pass its check either: the host is
	// left open, forwarding off, and the next update says how to recover.
	f = newFakeRelay(t)
	f.inst = func() error { return errors.New("boom") }
	f.bad["v0.26.0"] = errors.New("rayspa is inactive/dead")
	if _, err := f.update(updateOpts{want: "latest", yes: true}); err == nil || !strings.Contains(err.Error(), "host left open") {
		t.Fatalf("not open: %v", err)
	}
	if !slices.Contains(f.ran, "unforward") || !slices.Contains(f.ran, "systemctl disable --now rayd-relay.service rayspa.service") {
		t.Errorf("ran %q", f.ran)
	}
	text, err := f.update(updateOpts{want: "latest", yes: true, force: true})
	if err == nil || !strings.Contains(err.Error(), "rayctl update -rollback") || strings.Contains(text, "newest") {
		t.Errorf("after the host was left open: %q %v", text, err)
	}
	if text, err := f.update(updateOpts{want: "latest", check: true}); err != nil || !strings.Contains(text, "warning: the last update or rollback") {
		t.Errorf("-check: %q %v", text, err)
	}
	if text, err := captureStdout(t, func() error { return (&cli{}).relayPolicy([]string{"status"}, newFakePolicy(t, f.env.ops.dir).at) }); err != nil ||
		!strings.Contains(text, "unfinished the last update or rollback") {
		t.Errorf("status: %q %v", text, err)
	}

	// relayBefore refuses: nothing is kept, placed or marked.
	f = newFakeRelay(t)
	f.before = errors.New("this SSH session comes from 198.51.100.7, not from the relay's admin addresses")
	if _, err := f.update(updateOpts{want: "latest", yes: true}); err == nil || !strings.Contains(err.Error(), "admin addresses") {
		t.Fatalf("refusal: %v", err)
	}
	if _, err := f.env.ops.kept(); err == nil || f.read("bin/rayspa") != "rayspa v0.26.0" {
		t.Errorf("changed after a refusal: %q", f.read("bin/rayspa"))
	}

	// The first binary cannot be placed (a full disk): nothing to undo, no
	// unit stopped, no mark.
	f = newFakeRelay(t)
	f.placeF = func(string, string) error { return errors.New("no space left on device") }
	if _, err := f.update(updateOpts{want: "latest", yes: true}); err == nil || !strings.Contains(err.Error(), "nothing changed") {
		t.Fatalf("full disk: %v", err)
	}
	if slices.ContainsFunc(f.ran, func(s string) bool { return strings.Contains(s, "stop") || s == "disarm" }) {
		t.Errorf("a relay that ran was touched: %q", f.ran)
	}
	if _, marked := f.env.ops.readMark(); marked {
		t.Error("a mark after nothing changed")
	}

	// Not confirmed: nothing changes.
	f = newFakeRelay(t)
	f.yes = false
	if _, err := f.update(updateOpts{want: "latest"}); err == nil || f.read("bin/rayspa") != "rayspa v0.26.0" {
		t.Errorf("not confirmed: %v", err)
	}
}

// Under the relay's runner (spec/relay-update-remote-v1.md §4.2) the
// update writes how it ended, as a node's does: touched once the first
// binary went in, and the code of where it failed; its mark says it is
// the exit's. By hand nothing is written and the mark is a person's.
func TestRelayUpdateResult(t *testing.T) {
	boom := errors.New("boom")
	held := func(f *fakeRelay) {
		l, err := takeInstallLock(f.at("install.lock"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
	}
	for name, c := range map[string]struct {
		set  func(*fakeRelay)
		want nodeupdate.Result
	}{
		"done": {nil, nodeupdate.Result{State: nodeupdate.Done, Version: "v0.26.1", Release: "v0.26.1"}},
		"no bundle": {func(f *fakeRelay) { os.Remove(f.at("relay.bundle")) },
			nodeupdate.Result{State: nodeupdate.Failed, Version: "v0.26.0", Untouched: true, Reason: nodeupdate.ReasonBundle}},
		"an update by hand that did not end": {func(f *fakeRelay) {
			os.MkdirAll(f.env.ops.dir, 0o700)
			f.env.ops.mark(relayMark{State: "updating", From: "v0.25.9", To: "v0.26.0"})
		}, nodeupdate.Result{State: nodeupdate.Failed, Version: "v0.26.0", Untouched: true, Reason: nodeupdate.ReasonUnfinished}},
		"SSH": {func(f *fakeRelay) { f.before = errors.New("this SSH session comes from 198.51.100.7") },
			nodeupdate.Result{State: nodeupdate.Failed, Version: "v0.26.0", Untouched: true, Reason: nodeupdate.ReasonSSH}},
		"download": {func(f *fakeRelay) {
			f.env.stage = func(context.Context, updateOpts, string, string) (staged, error) {
				return staged{}, fetchReason(errors.New("downloading SHA256SUMS: timeout"))
			}
		}, nodeupdate.Result{State: nodeupdate.Failed, Version: "v0.26.0", Untouched: true, Reason: nodeupdate.ReasonDownload}},
		"another install": {held,
			nodeupdate.Result{State: nodeupdate.Failed, Version: "v0.26.0", Release: "v0.26.1", Untouched: true, Reason: nodeupdate.ReasonBusy}},
		"full disk": {func(f *fakeRelay) {
			f.placeF = func(string, string) error { return errors.New("no space left on device") }
		},
			nodeupdate.Result{State: nodeupdate.Failed, Version: "v0.26.0", Release: "v0.26.1", Untouched: true, Reason: nodeupdate.ReasonPlace}},
		"full disk, the second binary": {func(f *fakeRelay) {
			f.placeF = func(_, dst string) error { // rayctl and rayd go in first
				if filepath.Base(dst) == "rayspa" {
					return errors.New("no space left on device")
				}
				return nil
			}
		}, nodeupdate.Result{State: nodeupdate.RolledBack, Version: "v0.26.0", Release: "v0.26.1", Reason: nodeupdate.ReasonInstall}},
		"install": {func(f *fakeRelay) { f.inst = func() error { return boom } },
			nodeupdate.Result{State: nodeupdate.RolledBack, Version: "v0.26.0", Release: "v0.26.1", Reason: nodeupdate.ReasonInstall}},
		"check": {func(f *fakeRelay) { f.bad["v0.26.1"] = boom },
			nodeupdate.Result{State: nodeupdate.RolledBack, Version: "v0.26.0", Release: "v0.26.1", Reason: nodeupdate.ReasonCheck}},
		"open": {func(f *fakeRelay) { f.inst = func() error { return boom }; f.bad["v0.26.0"] = boom },
			nodeupdate.Result{State: nodeupdate.Failed, Release: "v0.26.1", Reason: nodeupdate.ReasonOpen}},
		// The unit's stop cut the install short: rolled back, interrupted.
		"interrupted": {func(f *fakeRelay) { f.signalled = true; f.inst = func() error { return errors.New("interrupted") } },
			nodeupdate.Result{State: nodeupdate.RolledBack, Version: "v0.26.0", Release: "v0.26.1", Reason: nodeupdate.ReasonInterrupted}},
		// Interrupted and not back: the host is open, which root must see.
		"interrupted, open": {func(f *fakeRelay) {
			f.signalled = true
			f.inst = func() error { return errors.New("interrupted") }
			f.bad["v0.26.0"] = boom
		}, nodeupdate.Result{State: nodeupdate.Failed, Release: "v0.26.1", Reason: nodeupdate.ReasonOpen}},
		"a signal, and done all the same": {func(f *fakeRelay) { f.signalled = true },
			nodeupdate.Result{State: nodeupdate.Done, Version: "v0.26.1", Release: "v0.26.1"}},
	} {
		f := newFakeRelay(t)
		f.env.result = f.at("result.json")
		var mark string
		f.inst = func() error { mark = f.read("previous/" + relayMarkFile); return nil }
		if c.set != nil {
			c.set(f)
		}
		_, err := f.update(updateOpts{want: "v0.26.1", yes: true})
		got, ok := nodeupdate.ReadResult(f.env.result)
		want := c.want
		if !ok || got.Error == "" != (want.State == nodeupdate.Done) {
			t.Errorf("%s: %+v %v (%v)", name, got, ok, err)
			continue
		}
		if want.State == nodeupdate.Done && err != nil || want.State != nodeupdate.Done && got.Error != strings.TrimPrefix(err.Error(), "update failed, the previous version runs again: ") {
			t.Errorf("%s: error %q, the update's %v", name, got.Error, err)
		}
		got.Error = ""
		if got != want {
			t.Errorf("%s: %+v, want %+v (%v)", name, got, want, err)
		}
		if name == "done" && !strings.Contains(mark, `"by":"exit"`) {
			t.Errorf("the mark of an update by the exit's word: %s", mark)
		}
	}

	// The release's rayctl took the update: it writes the outcome, not this
	// one.
	f := newFakeRelay(t)
	f.env.result = f.at("result.json")
	f.env.stage = func(context.Context, updateOpts, string, string) (staged, error) {
		return staged{version: "v0.26.1", done: true, handed: true}, errors.New("the update by the rayctl of v0.26.1: exit status 1")
	}
	if _, err := f.update(updateOpts{want: "v0.26.1", yes: true}); err == nil {
		t.Fatal("the handed update's error is lost")
	}
	if _, err := os.Stat(f.env.result); !os.IsNotExist(err) {
		t.Errorf("a result beside the release's rayctl's: %v", err)
	}
	// -check and -rollback write none.
	f = newFakeRelay(t)
	f.env.result = f.at("result.json")
	if _, err := f.update(updateOpts{want: "latest", check: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.rollback(true); err == nil {
		t.Fatal("rolled back with nothing kept")
	}
	if _, err := os.Stat(f.env.result); !os.IsNotExist(err) {
		t.Errorf("a result of -check or -rollback: %v", err)
	}

	// By hand: no result, and the mark names no one.
	f = newFakeRelay(t)
	var mark string
	f.inst = func() error { mark = f.read("previous/" + relayMarkFile); return nil }
	if _, err := f.update(updateOpts{want: "latest", yes: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(mark, `"by"`) || !strings.Contains(mark, `"state":"updating"`) {
		t.Errorf("the mark of an update by hand: %s", mark)
	}
	if entries, _ := filepath.Glob(f.at("*.json")); len(entries) != 0 {
		t.Errorf("an update by hand wrote %v", entries)
	}
}

// An update by the exit's word takes its unit's stop from its start (its
// timeout during a slow download, systemctl stop): the download ends, and
// the update stops before its first change, saying so in its outcome:
// failed, interrupted, untouched, which rayd relay asks for again later.
// Never killed with no word, which the runner could only guess at. Told
// to stop once the release is staged, it changes nothing either; once it
// changed something, it rolls back as ever, interrupted. By hand the
// signal is not taken before the point of no return.
func TestRelayUpdateStoppedFirst(t *testing.T) {
	stopped := func(f *fakeRelay) func(context.Context, updateOpts, string, string) (staged, error) {
		return func(ctx context.Context, _ updateOpts, stage, _ string) (staged, error) {
			f.early = true
			f.stop()
			<-ctx.Done()
			return staged{}, fetchReason(fmt.Errorf("downloading SHA256SUMS: %w", ctx.Err()))
		}
	}
	for name, c := range map[string]struct {
		set  func(*fakeRelay)
		want nodeupdate.Result
	}{
		"during the download": {func(f *fakeRelay) { f.env.stage = stopped(f) },
			nodeupdate.Result{State: nodeupdate.Failed, Version: "v0.26.0", Untouched: true, Reason: nodeupdate.ReasonInterrupted}},
		"once staged": {func(f *fakeRelay) {
			stage := f.env.stage
			f.env.stage = func(ctx context.Context, o updateOpts, st, installed string) (staged, error) {
				s, err := stage(ctx, o, st, installed)
				f.early = true
				return s, err
			}
		}, nodeupdate.Result{State: nodeupdate.Failed, Version: "v0.26.0", Release: "v0.26.1", Untouched: true, Reason: nodeupdate.ReasonInterrupted}},
		"in the install": {func(f *fakeRelay) {
			f.inst = func() error { f.early = true; return errors.New("interrupted") }
		}, nodeupdate.Result{State: nodeupdate.RolledBack, Version: "v0.26.0", Release: "v0.26.1", Reason: nodeupdate.ReasonInterrupted}},
	} {
		f := newFakeRelay(t)
		f.env.result = f.at("result.json")
		c.set(f)
		_, err := f.update(updateOpts{want: "v0.26.1", yes: true})
		got, ok := nodeupdate.ReadResult(f.env.result)
		if !ok || err == nil || got.Error == "" || !strings.Contains(err.Error(), got.Error) {
			t.Errorf("%s: %+v %v (%v)", name, got, ok, err)
			continue
		}
		if c.want.Untouched && !strings.Contains(got.Error, "stopped before any change") {
			t.Errorf("%s: %q", name, got.Error)
		}
		got.Error = ""
		if got != c.want {
			t.Errorf("%s: %+v, want %+v (%v)", name, got, c.want, err)
		}
		if c.want.Untouched {
			if _, marked := f.env.ops.readMark(); marked || f.read("bin/rayspa") != "rayspa v0.26.0" || slices.Contains(f.ran, "install") {
				t.Errorf("%s: changed: %q", name, f.ran)
			}
			if _, err := f.env.ops.kept(); err == nil {
				t.Errorf("%s: kept a copy", name)
			}
		}
	}
	// By hand: none of it.
	f := newFakeRelay(t)
	if _, err := f.update(updateOpts{want: "latest", yes: true}); err != nil || slices.Contains(f.ran, "interrupt") {
		t.Errorf("by hand: %v %q", err, f.ran)
	}

	// The real signal: SIGTERM while the download goes on (were it not
	// taken, this test's process would die here).
	f = newFakeRelay(t)
	f.env.result = f.at("result.json")
	f.env.interrupt = stopOnSignal
	f.env.stage = func(ctx context.Context, _ updateOpts, _, _ string) (staged, error) {
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
			return staged{}, errors.New("the download did not stop")
		}
		return staged{}, fetchReason(fmt.Errorf("downloading SHA256SUMS: %w", ctx.Err()))
	}
	_, err := f.update(updateOpts{want: "v0.26.1", yes: true})
	if got, ok := nodeupdate.ReadResult(f.env.result); !ok || err == nil || got.State != nodeupdate.Failed || !got.Untouched ||
		got.Reason != nodeupdate.ReasonInterrupted {
		t.Errorf("SIGTERM downloading: %+v %v (%v)", got, ok, err)
	}
}

// stopOnSignal ends its context at the first signal and says so after;
// stopped, it ends it too, but says no signal came.
func TestStopOnSignal(t *testing.T) {
	ctx, caught, stop := stopOnSignal(context.Background())
	if caught() || ctx.Err() != nil {
		t.Fatal("caught before any came")
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("SIGTERM did not end the context")
	}
	if !caught() {
		t.Error("the signal is not said to have come")
	}
	stop()
	stop()
	ctx, caught, stop = stopOnSignal(context.Background())
	stop()
	if ctx.Err() == nil || caught() {
		t.Errorf("stopped: %v %v", ctx.Err(), caught())
	}
}

// A relay's update by the exit's word handed to the release's rayctl: the
// unit's stop (SIGTERM to every process of it) does not end the rayctl
// that handed it over while the release's own rolls the relay back, or
// the runner would find it gone with no outcome. Were it not caught, this
// test's process would die here.
func TestHandoffRelayWaits(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ended")
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	body := "#!/bin/sh\nsleep 1\necho ended > " + out + "\n"
	tw.WriteHeader(&tar.Header{Name: "rayctl", Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write([]byte(body))
	tw.Close()
	zw.Close()
	r := release.Release{Version: "v0.26.1", Archive: buf.Bytes(), Sums: []byte("sums"), Sig: []byte("sig")}
	t.Setenv(nodeupdate.ResultEnv, filepath.Join(t.TempDir(), "result.json"))
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
	}()
	var handed bool
	_, err := captureStdout(t, func() (err error) { handed, err = handoff(r, t.TempDir(), "v0.26.0", "relay", true, false); return err })
	if !handed || err != nil {
		t.Fatalf("handed %v: %v", handed, err)
	}
	if b, _ := os.ReadFile(out); string(b) != "ended\n" {
		t.Errorf("returned before the release's rayctl ended: %q", b)
	}
}

// The release an update stages, its failure's code: one that does not
// verify (another key, another version signed), one that cannot be had,
// one below the relay's floor or behind the relay.
func TestStageReleaseReasons(t *testing.T) {
	k := newSigner(t)
	saved := releaseKey
	releaseKey = k.pub
	t.Cleanup(func() { releaseKey = saved })
	t.Setenv(handoffEnv, "")
	t.Setenv("RAYCONTROL_MIRRORS", "")
	c := &cli{}
	stage := func(o updateOpts, installed string) error {
		_, err := captureStdout(t, func() error {
			_, err := c.stageRelease(context.Background(), o, t.TempDir(), installed, relayBinaries, relayTarget)
			return err
		})
		return err
	}
	out := filepath.Join(t.TempDir(), "handed")
	other := releaseDir(t, signedRelease(t, newSigner(t), "v0.26.1", out))
	if err := stage(updateOpts{want: "latest", from: other}, "v0.26.0"); reasonOf(err) != nodeupdate.ReasonSignature {
		t.Errorf("another key: %q %v", reasonOf(err), err)
	}
	files := signedRelease(t, k, "v0.26.1", out)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// v0.26.2 is v0.26.1's files: the signature says v0.26.1.
		if !strings.Contains(r.URL.Path, "/v0.26.1/") && !strings.Contains(r.URL.Path, "/v0.26.2/") {
			http.NotFound(w, r)
			return
		}
		if b, ok := files[r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]]; ok {
			w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	releaseBase = srv.URL
	t.Cleanup(func() { releaseBase = "" })
	for _, c := range []struct {
		want, installed, reason string
	}{
		{"v0.26.2", "v0.26.0", nodeupdate.ReasonSignature}, // a mirror's older release under a newer name
		{"v0.26.9", "v0.26.0", nodeupdate.ReasonDownload},  // not published
	} {
		if err := stage(updateOpts{want: c.want, yes: true}, c.installed); err == nil || reasonOf(err) != c.reason {
			t.Errorf("%s: %q %v", c.want, reasonOf(err), err)
		}
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a release that did not verify ran")
	}
	// Below the relay's floor, or older than the relay: the version.
	if err := stage(updateOpts{want: "latest", from: releaseDir(t, signedRelease(t, k, "v0.25.2", out))}, "v0.25.1"); reasonOf(err) != nodeupdate.ReasonVersion {
		t.Errorf("below the floor: %q %v", reasonOf(err), err)
	}
	if err := stage(updateOpts{want: "latest", from: releaseDir(t, files)}, "v0.27.0"); reasonOf(err) != nodeupdate.ReasonVersion {
		t.Errorf("older than the relay: %q %v", reasonOf(err), err)
	}
}

// While another install has the relay install lock (bootstrap.sh -relay,
// or the install of an update that was killed), neither an update nor a
// -rollback changes anything.
func TestRelayInstallLockHeld(t *testing.T) {
	f := newFakeRelay(t)
	if _, err := f.update(updateOpts{want: "latest", yes: true}); err != nil {
		t.Fatal(err)
	}
	other, err := takeInstallLock(f.at("install.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	f.ran = nil
	if _, err := f.rollback(true); err == nil || !strings.Contains(err.Error(), "another rayctl install -relay") ||
		f.read("bin/rayspa") != "rayspa v0.26.1" || slices.ContainsFunc(f.ran, func(s string) bool { return strings.HasPrefix(s, "systemctl") }) {
		t.Errorf("-rollback: %v, rayspa %q, ran %q", err, f.read("bin/rayspa"), f.ran)
	}
	f = newFakeRelay(t)
	held, err := takeInstallLock(f.at("install.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if _, err := f.update(updateOpts{want: "latest", yes: true}); err == nil || !strings.Contains(err.Error(), "nothing changed") ||
		f.read("bin/rayspa") != "rayspa v0.26.0" {
		t.Errorf("update: %v, rayspa %q", err, f.read("bin/rayspa"))
	}
	if _, marked := f.env.ops.readMark(); marked {
		t.Error("marked")
	}
}

// A mark with no whole copy beside it (only by hand: the copy is whole
// before the mark is written) is no dead end: rayctl update, -rollback
// and status name the relay's bootstrap.sh, not -rollback.
func TestRelayMarkWithoutCopy(t *testing.T) {
	f := newFakeRelay(t)
	os.MkdirAll(f.env.ops.dir, 0o700)
	f.env.ops.mark(relayMark{State: "updating", From: "v0.26.0", To: "v0.26.1"})
	want := "bash bootstrap.sh -relay " + deploy.RelayBundle + " installs the relay anew"
	if _, err := f.update(updateOpts{want: "latest", yes: true}); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("update: %v", err)
	}
	if _, err := f.rollback(true); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("-rollback: %v", err)
	}
	if text, err := captureStdout(t, func() error { return (&cli{}).relayPolicy([]string{"status"}, newFakePolicy(t, f.env.ops.dir).at) }); err != nil ||
		!strings.Contains(text, want) {
		t.Errorf("status: %q %v", text, err)
	}
	// Unmarked, nothing kept: nothing to roll back to, as ever.
	f = newFakeRelay(t)
	if _, err := f.rollback(true); err == nil || !strings.Contains(err.Error(), "nothing to roll back to") {
		t.Errorf("-rollback unmarked: %v", err)
	}
}

// rayctl update -rollback on a relay: asked first; after an update that
// was interrupted with the host left open (the install removed the
// snapshot), it restores the kept snapshot without asking a perimeter
// there is none of to let this session in.
func TestRelayRollbackWhole(t *testing.T) {
	f := newFakeRelay(t)
	if _, err := f.update(updateOpts{want: "latest", yes: true}); err != nil {
		t.Fatal(err)
	}
	f.yes = false
	if _, err := f.rollback(false); err == nil || !strings.Contains(err.Error(), "not confirmed") || f.read("bin/rayspa") != "rayspa v0.26.1" {
		t.Errorf("not confirmed: %v, rayspa %q", err, f.read("bin/rayspa"))
	}
	// By hand after a good update: the snapshot stays the exit's latest.
	f.write("state/snapshot.pb", "the exit's latest")
	f.yes = true
	if _, err := f.rollback(false); err != nil {
		t.Fatal(err)
	}
	if f.read("bin/rayspa") != "rayspa v0.26.0" || f.read("state/snapshot.pb") != "the exit's latest" || f.asked == 0 {
		t.Errorf("rollback by hand: %q %q, asked %d", f.read("bin/rayspa"), f.read("state/snapshot.pb"), f.asked)
	}

	// Interrupted: kept and marked, the new binaries in place, the install
	// opened the host and removed the snapshot; relayBefore would refuse.
	f = newFakeRelay(t)
	if _, err := f.env.ops.keep("v0.26.0"); err != nil {
		t.Fatal(err)
	}
	f.env.ops.mark(relayMark{State: "updating", From: "v0.26.0", To: "v0.26.1"})
	f.write("bin/rayspa", "rayspa v0.26.1")
	os.Remove(f.at("state/snapshot.pb"))
	f.open = true
	f.before = errors.New("the relay's perimeter cannot be read")
	text, err := f.update(updateOpts{want: "latest", yes: true})
	if err == nil || !strings.Contains(err.Error(), "was interrupted: rayctl update -rollback puts v0.26.0 back") || strings.Contains(text, "newest") {
		t.Errorf("update after an interrupted one: %q %v", text, err)
	}
	if _, err := f.rollback(true); err != nil {
		t.Fatalf("rollback of an open host: %v", err)
	}
	if f.read("bin/rayspa") != "rayspa v0.26.0" || f.read("state/snapshot.pb") != snapshotWith(t, true) || f.asked != 0 {
		t.Errorf("after: %q %q, asked %d", f.read("bin/rayspa"), f.read("state/snapshot.pb"), f.asked)
	}
	if _, marked := f.env.ops.readMark(); marked {
		t.Error("the mark stays after a rollback that ended checked")
	}
	// Marked, the host not open (killed between place and install): the
	// kept snapshot comes back too, and this session is checked first.
	f = newFakeRelay(t)
	f.env.ops.keep("v0.26.0")
	f.env.ops.mark(relayMark{State: "updating", From: "v0.26.0", To: "v0.26.1"})
	f.write("state/snapshot.pb", "a snapshot the update's install took")
	if _, err := f.rollback(true); err != nil || f.read("state/snapshot.pb") != snapshotWith(t, true) || f.asked != 1 {
		t.Errorf("marked, not open: %v %q, asked %d", err, f.read("state/snapshot.pb"), f.asked)
	}
}

// statusGroup makes the relay's status group this test's own (rayd's is
// not here).
func statusGroup(t *testing.T) int {
	t.Helper()
	g, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Skipf("no name for gid %d: %v", os.Getgid(), err)
	}
	saved := relayStatusGroup
	t.Cleanup(func() { relayStatusGroup = saved })
	relayStatusGroup = g.Name
	return os.Getgid()
}

// statusMode is the mode and group of a status file.
func statusMode(t *testing.T, path string) (os.FileMode, int) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm(), int(fi.Sys().(*syscall.Stat_t).Gid)
}

// A rollback by hand on the relay is root's own repair, and its status
// says so (kind local, which rayd relay tells the exit as none of its
// offers): not the update by the exit's word that failed and left the
// host open, unfinished, nor done for the release rolled back from, which
// rayd relay would take for the one it runs. That release is held. Under
// the runner (its ExecStopPost, the recover unit) the runner writes the
// status, not the rollback.
func TestRelayRollbackNoted(t *testing.T) {
	gid := statusGroup(t)
	for name, c := range map[string]struct {
		last      nodeupdate.Status
		marked    bool
		installed string
	}{
		"after the exit's update, done": {last: nodeupdate.Status{ID: "0a", State: nodeupdate.Done, From: "v0.26.0", To: "v0.26.1", Target: "v0.26.1",
			Release: "v0.26.1", By: "exit", Kind: nodeupdate.Exit, Held: []string{"v0.25.9"}}, installed: "v0.26.1"},
		"after the exit's update left the host open": {last: nodeupdate.Status{ID: "0b", State: nodeupdate.Failed, From: "v0.26.0", Target: "v0.26.1",
			Release: "v0.26.1", By: "exit", Kind: nodeupdate.Exit, Reason: nodeupdate.ReasonOpen, Unfinished: true, Held: []string{"v0.25.9", "v0.26.1"}},
			marked: true, installed: "v0.26.0"},
	} {
		f := newFakeRelay(t)
		f.env.status = f.at("update/status.json")
		os.Mkdir(f.at("update"), 0o755)
		nodeupdate.WriteStatus(f.env.status, c.last)
		f.env.ops.keep("v0.26.0")
		f.write("bin/rayspa", "rayspa v0.26.1")
		if c.marked {
			f.env.ops.mark(relayMark{State: "open", From: "v0.26.0", To: "v0.26.1", By: markByExit})
			f.open = true
		}
		// The rayctl that runs it: the new one after a good update, maybe
		// still the old one after one that did not end (its mark says).
		if _, err := captureStdout(t, func() error { return f.env.update(context.Background(), updateOpts{yes: true}, true, c.installed) }); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		st := nodeupdate.ReadStatus(f.env.status)
		if st.Kind != nodeupdate.Local || st.State != nodeupdate.RolledBack || st.To != "v0.26.0" || st.Unfinished || st.ID == c.last.ID ||
			!slices.Equal(st.Held, []string{"v0.25.9", "v0.26.1"}) || !strings.HasPrefix(st.By, "root") {
			t.Errorf("%s: %+v", name, st)
		}
		if mode, g := statusMode(t, f.env.status); mode != 0o640 || g != gid {
			t.Errorf("%s: mode %v, group %d", name, mode, g)
		}
	}
	// The release rolled back from is the one that ran, by hand after a
	// good update.
	f := newFakeRelay(t)
	f.env.status = f.at("update/status.json")
	os.Mkdir(f.at("update"), 0o755)
	if _, err := f.update(updateOpts{want: "latest", yes: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.rollback(true); err != nil {
		t.Fatal(err)
	}
	if st := nodeupdate.ReadStatus(f.env.status); st.From != "v0.26.1" || st.Release != "v0.26.1" || !slices.Equal(st.Held, []string{"v0.26.1"}) {
		t.Errorf("by hand after a good update: %+v", st)
	}
	// Under the runner: nothing written.
	f = newFakeRelay(t)
	f.env.status = f.at("update/status.json")
	os.Mkdir(f.at("update"), 0o755)
	last := nodeupdate.Status{ID: "0c", State: nodeupdate.Failed, Kind: nodeupdate.Exit, Target: "v0.26.1", Reason: nodeupdate.ReasonInterrupted}
	nodeupdate.WriteStatus(f.env.status, last)
	f.env.ops.keep("v0.26.0")
	t.Setenv(rollbackByRunnerEnv, "1")
	if _, err := f.rollback(true); err != nil {
		t.Fatal(err)
	}
	if st := nodeupdate.ReadStatus(f.env.status); st.ID != "0c" {
		t.Errorf("under the runner: %+v", st)
	}
	// No update by the exit's word ever ran: no status made.
	t.Setenv(rollbackByRunnerEnv, "")
	f = newFakeRelay(t)
	f.env.status = f.at("none/status.json")
	f.env.ops.keep("v0.26.0")
	if _, err := f.rollback(true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.at("none")); !os.IsNotExist(err) {
		t.Errorf("a status made: %v", err)
	}
	// The runner's rollback says it runs it.
	dir := t.TempDir()
	rayctl := filepath.Join(dir, "rayctl")
	os.WriteFile(rayctl, []byte("#!/bin/sh\nenv > "+filepath.Join(dir, "env")+"\n"), 0o755)
	if _, err := runRollback(rayctl); err != nil {
		t.Fatal(err)
	}
	if env, _ := os.ReadFile(filepath.Join(dir, "env")); !strings.Contains(string(env), rollbackByRunnerEnv+"=1\n") {
		t.Errorf("the runner's rollback: %s", env)
	}
}

// The relay's status, as its runner writes it, is rayd relay's group's to
// read (0640), not everyone's: it holds root's whole text. A node's stays
// 0644, its rayd reads it as ever.
func TestRelayStatusMode(t *testing.T) {
	gid := statusGroup(t)
	f := newFakeRunner(t)
	f.rayctl(`echo '{"state":"failed","version":"v0.27.0","error":"this SSH session comes from 198.51.100.7","untouched":true,"reason":"ssh"}' > "$RAYCONTROL_UPDATE_RESULT"; exit 1`)
	f.request("v0.27.1")
	if st, _ := f.run(); st.Reason != nodeupdate.ReasonSSH {
		t.Fatalf("%+v", st)
	}
	if mode, g := statusMode(t, f.q.status); mode != 0o640 || g != gid {
		t.Errorf("a relay's: mode %v, group %d", mode, g)
	}
	// ExecStopPost and the recover unit write it the same.
	nodeupdate.WriteStatus(f.q.status, nodeupdate.Status{ID: "0a", State: nodeupdate.Running, From: "v0.27.0", Target: "v0.27.1", Kind: nodeupdate.Exit})
	captureStdout(t, f.q.ended)
	if mode, g := statusMode(t, f.q.status); mode != 0o640 || g != gid {
		t.Errorf("ended: mode %v, group %d", mode, g)
	}
	f.mark(relayMark{State: "open", From: "v0.27.0", To: "v0.27.1", By: markByExit})
	captureStdout(t, f.q.recover)
	if mode, g := statusMode(t, f.q.status); mode != 0o640 || g != gid {
		t.Errorf("recovered: mode %v, group %d", mode, g)
	}
	// No such group: root's alone.
	relayStatusGroup = "no-such-group-of-raycontrol"
	f.request("v0.27.1")
	f.run()
	if mode, _ := statusMode(t, f.q.status); mode != 0o600 {
		t.Errorf("no group: mode %v", mode)
	}
	// A node's.
	n := nodeRequests()
	dir := t.TempDir()
	n.request, n.status, n.policy, n.result = filepath.Join(dir, "update-request"), filepath.Join(dir, "status.json"), filepath.Join(dir, "policy.json"),
		filepath.Join(dir, "result.json")
	n.lock = func(func() bool) error { return nil }
	nodeupdate.WriteRequest(n.request, nodeupdate.Request{ID: "0a", Kind: nodeupdate.Remote, Version: "v0.27.1", By: "alice", At: time.Now()}, time.Now())
	captureStdout(t, n.take)
	if mode, _ := statusMode(t, n.status); mode != 0o644 {
		t.Errorf("a node's: mode %v", mode)
	}
}

// The install that the update runs has none of the update's own
// variables (the handoff's above all: it would take the install for an
// update), and gets the install lock as fd 3.
func TestRelayInstallCommand(t *testing.T) {
	t.Setenv(handoffEnv, "1")
	t.Setenv(updateFromEnv, "v0.26.0")
	lock, err := os.CreateTemp(t.TempDir(), "lock")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	cmd := relayInstallCommand("/usr/local/bin/rayctl", "/etc/raycontrol/relay.bundle", lock)
	if !slices.Equal(cmd.Args, []string{"/usr/local/bin/rayctl", "install", "-relay", "/etc/raycontrol/relay.bundle"}) {
		t.Errorf("args %q", cmd.Args)
	}
	if slices.ContainsFunc(cmd.Env, func(kv string) bool {
		return strings.HasPrefix(kv, handoffEnv+"=") || strings.HasPrefix(kv, updateFromEnv+"=")
	}) || !slices.Contains(cmd.Env, relayLockEnv+"=3") {
		t.Errorf("env %q", cmd.Env)
	}
	if len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0] != lock {
		t.Errorf("extra files %v", cmd.ExtraFiles)
	}
}

// minisign as the release workflow signs (internal/release's tests do the
// same).
type signer struct {
	pub  string
	priv ed25519.PrivateKey
	id   []byte
}

func newSigner(t *testing.T) signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	return signer{pub: base64.StdEncoding.EncodeToString(append(append([]byte("Ed"), id...), pub...)), priv: priv, id: id}
}

func (k signer) sign(msg []byte, trusted string) []byte {
	h := blake2b.Sum512(msg)
	sig := ed25519.Sign(k.priv, h[:])
	global := ed25519.Sign(k.priv, append(slices.Clone(sig), trusted...))
	raw := append(append([]byte("ED"), k.id...), sig...)
	return []byte(fmt.Sprintf("untrusted comment: test\n%s\ntrusted comment: %s\n%s\n",
		base64.StdEncoding.EncodeToString(raw), trusted, base64.StdEncoding.EncodeToString(global)))
}

// signedRelease is a release's three files, signed by k: its archive has
// rayctl (a script that writes how it was started to out), rayspa and
// rayd.
func signedRelease(t *testing.T, k signer, ver, out string) map[string][]byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, body := range map[string]string{
		"rayctl":   "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + out + "\nenv | grep '^RAYCONTROL_UPDATE_' > " + out + ".env\n",
		"rayspa":   "rayspa " + ver,
		"rayd":     "rayd " + ver,
		"VERSIONS": "raycontrol " + ver + "\n",
	} {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	tw.Close()
	zw.Close()
	arc := buf.Bytes()
	sum := sha256.Sum256(arc)
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + release.Archive(runtime.GOARCH) + "\n")
	return map[string][]byte{"SHA256SUMS": sums, "SHA256SUMS.minisig": k.sign(sums, "raycontrol "+ver), release.Archive(runtime.GOARCH): arc}
}

func releaseDir(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A relay's update takes its release the way a node's does (stageRelease):
// verified with the pinned key, never back unless named, -check only says,
// the relay's own floor (relayTarget) before anything, and a newer release
// handed to its own rayctl, which updates the relay.
func TestStageReleaseRelay(t *testing.T) {
	k := newSigner(t)
	saved := releaseKey
	releaseKey = k.pub
	t.Cleanup(func() { releaseKey = saved })
	t.Setenv(handoffEnv, "")
	t.Setenv("RAYCONTROL_MIRRORS", "")
	c := &cli{}
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "handed")
	stage := func(o updateOpts, installed string) (staged, string, string, error) {
		st := t.TempDir()
		var s staged
		text, err := captureStdout(t, func() (err error) {
			s, err = c.stageRelease(ctx, o, st, installed, relayBinaries, relayTarget)
			return err
		})
		return s, st, text, err
	}
	v261 := releaseDir(t, signedRelease(t, k, "v0.26.1", out))

	// Another key: refused, nothing staged.
	other := signedRelease(t, newSigner(t), "v0.26.1", out)
	if _, st, _, err := stage(updateOpts{want: "latest", from: releaseDir(t, other), yes: true}, "v0.26.0"); err == nil ||
		!strings.Contains(err.Error(), "SHA256SUMS") {
		t.Errorf("another key: %v", err)
	} else if m, _ := os.ReadDir(st); len(m) != 0 {
		t.Errorf("staged %v from a release that does not verify", m)
	}
	// The same version: nothing to do.
	if s, _, text, err := stage(updateOpts{want: "latest", from: v261}, "v0.26.1"); err != nil || !s.done || !strings.Contains(text, "is installed") {
		t.Errorf("the same: %+v %q %v", s, text, err)
	}
	// Back, not named: refused.
	if _, _, _, err := stage(updateOpts{want: "latest", from: v261}, "v0.27.0"); err == nil || !strings.Contains(err.Error(), "goes back") {
		t.Errorf("back: %v", err)
	}
	// -check says, hands nothing over.
	s, _, text, err := stage(updateOpts{want: "latest", from: v261, check: true}, "v0.26.0")
	if err != nil || !s.done || s.handed || !strings.Contains(text, "installed v0.26.0, release v0.26.1 available") {
		t.Errorf("-check: %+v %q %v", s, text, err)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("-check ran the release's rayctl")
	}
	// Below the relay's floor: refused before the handoff, with -check too.
	v252 := releaseDir(t, signedRelease(t, k, "v0.25.2", out))
	for _, check := range []bool{false, true} {
		if _, _, _, err := stage(updateOpts{want: "latest", from: v252, check: check, yes: true}, "v0.25.1"); err == nil ||
			!strings.Contains(err.Error(), "bootstrap.sh -relay") {
			t.Errorf("v0.25.2, check %v: %v", check, err)
		}
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a release below the relay's floor was handed the update")
	}
	// Newer: the release's own rayctl updates, from the verified files.
	s, _, text, err = stage(updateOpts{want: "latest", from: v261, yes: true, host: "relay"}, "v0.26.0")
	if err != nil || !s.handed || s.version != "v0.26.1" || !strings.Contains(text, "its own rayctl updates the relay") {
		t.Fatalf("handoff: %+v %q %v", s, text, err)
	}
	args, _ := os.ReadFile(out)
	env, _ := os.ReadFile(out + ".env")
	a := strings.Fields(string(args))
	if len(a) < 5 || a[0] != "update" || a[1] != "-from" || !slices.Contains(a, "-version") || !slices.Contains(a, "v0.26.1") || !slices.Contains(a, "-yes") {
		t.Errorf("handed with %q", a)
	}
	if !strings.Contains(string(env), handoffEnv+"=1") || !strings.Contains(string(env), updateFromEnv+"=v0.26.0") {
		t.Errorf("handed with the environment %q", env)
	}
	// Named back, or -no-handoff: this rayctl stages the release's files.
	os.Remove(out)
	s, st, _, err := stage(updateOpts{want: "latest", from: v261, noHandoff: true}, "v0.26.0")
	if err != nil || s.done || s.handed {
		t.Fatalf("-no-handoff: %+v %v", s, err)
	}
	if b, _ := os.ReadFile(filepath.Join(st, "rayspa")); string(b) != "rayspa v0.26.1" {
		t.Errorf("staged rayspa %q", b)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("-no-handoff ran the release's rayctl")
	}

	// From GitHub: latest is read from its signed SHA256SUMS first, and an
	// installed latest downloads no archive.
	files := signedRelease(t, k, "v0.26.1", out)
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		if b, ok := files[name]; ok {
			w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	releaseBase = srv.URL
	t.Cleanup(func() { releaseBase = "" })
	if s, _, text, err := stage(updateOpts{want: "latest"}, "v0.26.1"); err != nil || !s.done || !strings.Contains(text, "is installed, the newest") {
		t.Errorf("latest installed: %+v %q %v", s, text, err)
	}
	if slices.ContainsFunc(hits, func(p string) bool { return strings.HasSuffix(p, ".tar.gz") }) {
		t.Errorf("the archive was downloaded for nothing: %v", hits)
	}
	if s, _, text, err := stage(updateOpts{want: "latest", check: true}, "v0.26.0"); err != nil || !s.done || !strings.Contains(text, "release v0.26.1 available") {
		t.Errorf("latest, -check: %+v %q %v", s, text, err)
	}
	// The relay's floor holds on the way that reads latest first, -check too.
	files = signedRelease(t, k, "v0.25.2", out)
	if _, _, _, err := stage(updateOpts{want: "latest", check: true}, "v0.25.1"); err == nil || !strings.Contains(err.Error(), "bootstrap.sh -relay") {
		t.Errorf("latest below the floor, -check: %v", err)
	}
}

// rayspa owns the snapshot's directory: root reads the snapshot without
// following a link planted there and without waiting on a FIFO.
func TestReadSnapshotRegularOnly(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(t.TempDir(), "shadow")
	os.WriteFile(secret, []byte("root only"), 0o600)
	link := filepath.Join(dir, "snapshot.pb")
	os.Symlink(secret, link)
	if _, err := readSnapshot(link); err == nil || !strings.Contains(err.Error(), "link") {
		t.Errorf("a link: %v", err)
	}
	fifo := filepath.Join(dir, "fifo.pb")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() { _, err := readSnapshot(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a FIFO was read")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readSnapshot hangs on a FIFO")
	}
	if _, err := readSnapshot(filepath.Join(dir, "none")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
}

// -check only says: with -rollback, which changes the host, it is a usage
// error, on a node and on a relay alike, before anything else.
func TestUpdateCheckRollbackRefused(t *testing.T) {
	c := &cli{}
	for _, args := range [][]string{{"-check", "-rollback"}, {"-rollback", "-check", "-yes"}} {
		if err := c.update(context.Background(), args); !errors.Is(err, errUsage) {
			t.Errorf("%v: %v", args, err)
		}
	}
}

// From the point of no return SIGTERM (a shutdown, logind) and SIGHUP (the
// SSH connection gone) do not end the rayctl that would roll back: were
// they not caught, this test's process would die here.
func TestCatchSignals(t *testing.T) {
	caught, stop := catchSignals()
	defer stop()
	if caught() {
		t.Fatal("caught before any came")
	}
	for _, s := range []syscall.Signal{syscall.SIGTERM, syscall.SIGHUP} {
		if err := syscall.Kill(os.Getpid(), s); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(200 * time.Millisecond)
	// Said, and still said when asked again: an update cut short by the
	// unit's stop is interrupted.
	if !caught() {
		t.Error("the signals are not said to have come")
	}
	if !caught() {
		t.Error("the signals are not said to have come when asked again")
	}
}

// What a relay install writes and an update keeps: the plan's files and
// those written once the relay is up.
func TestRelayFiles(t *testing.T) {
	files := relayFiles()
	for _, f := range []string{"/etc/systemd/system/rayspa.service", "/etc/systemd/system/" + deploy.RelayProbeUnit,
		deploy.HardeningSysctl, deploy.RelaySysctl, deploy.ConntrackSysctl, deploy.ModulesLoad, deploy.PortsSysctl,
		// The update by the exit's word (relay-update-remote-v1 §4.1): a
		// rollback below it takes them away, a rollback to it back.
		"/etc/systemd/system/" + deploy.RelayUpdatePath, "/etc/systemd/system/" + deploy.RelayUpdateService,
		"/etc/systemd/system/" + deploy.RelayRecover} {
		if !slices.Contains(files, f) {
			t.Errorf("%s is not kept", f)
		}
	}
	// The recover unit's condition is the mark this rayctl writes.
	if p := filepath.Join(previousDir, relayMarkFile); p != deploy.RelayUpdateMark {
		t.Errorf("the mark is %s, the recover unit waits for %s", p, deploy.RelayUpdateMark)
	}
}

// The units of the update by the exit's word come after rayspa and the
// probe on this host: rayspa first, which open looks at, the path unit
// started after the two; the recover unit is only enabled again as it
// was, never stopped or started by a restore or open (it may be what runs
// the rollback, and must stay enabled on a host left open). A path unit
// waiting counts as active.
func TestRelayRemoteUnitsKept(t *testing.T) {
	ops := (&cli{}).relayEnvHere(context.Background()).ops
	if !slices.Equal(ops.units, []string{relayUnit, deploy.RelayProbeUnit, deploy.RelayUpdatePath, deploy.RelayRecover}) ||
		!slices.Equal(ops.enableOnly, []string{deploy.RelayRecover}) {
		t.Fatalf("units %v, enable only %v", ops.units, ops.enableOnly)
	}
	waiting := map[string]string{"ActiveState": "active", "SubState": "waiting"}
	if !unitActive(deploy.RelayUpdatePath, waiting) || unitActive(relayUnit, waiting) ||
		!unitActive(relayUnit, map[string]string{"ActiveState": "active", "SubState": "running"}) ||
		unitActive(deploy.RelayUpdatePath, map[string]string{"ActiveState": "inactive", "SubState": "dead"}) {
		t.Error("unitActive")
	}

	f := newFakeRelay(t)
	ops = f.env.ops
	ops.units = append(ops.units, deploy.RelayUpdatePath, deploy.RelayRecover)
	ops.enableOnly = []string{deploy.RelayRecover}
	// remote on before the update: the path unit enabled and waiting, the
	// recover unit enabled, not running.
	ops.state = func(u string) unitWas { return unitWas{Enabled: true, Active: u != deploy.RelayRecover} }
	if _, err := ops.keep("v0.26.0"); err != nil {
		t.Fatal(err)
	}
	f.ran = nil
	if _, err := captureStdout(t, func() error { _, err := ops.restore(true); return err }); err != nil {
		t.Fatal(err)
	}
	want := []string{"disarm", "systemctl stop --no-block " + deploy.RelayUpdatePath, "systemctl stop rayd-relay.service", "systemctl stop rayspa.service",
		"systemctl daemon-reload",
		"sysctl -q -e -p " + f.at("etc/sysctl/91-raycontrol-relay.conf"), "sysctl -q -e -p " + f.at("etc/sysctl/90-raycontrol.conf"),
		"systemctl enable rayspa.service", "systemctl enable rayd-relay.service", "systemctl enable " + deploy.RelayUpdatePath,
		"systemctl enable " + deploy.RelayRecover,
		"systemctl start rayspa.service", "systemctl start rayd-relay.service", "systemctl start --no-block " + deploy.RelayUpdatePath}
	if !slices.Equal(f.ran, want) {
		t.Errorf("restore ran %q\nwant %q", f.ran, want)
	}
	// remote off before: both disabled again.
	ops.state = func(u string) unitWas { return unitWas{Enabled: u == relayUnit, Active: u == relayUnit} }
	if _, err := ops.keep("v0.26.0"); err != nil {
		t.Fatal(err)
	}
	f.ran = nil
	if _, err := captureStdout(t, func() error { _, err := ops.restore(true); return err }); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.ran, "systemctl disable "+deploy.RelayUpdatePath) || !slices.Contains(f.ran, "systemctl disable "+deploy.RelayRecover) ||
		slices.Contains(f.ran, "systemctl start --no-block "+deploy.RelayUpdatePath) {
		t.Errorf("restore of remote off ran %q", f.ran)
	}
	// open: the path unit down, then rayspa and the probe, the recover
	// unit left for the next boot.
	ops.state = f.env.ops.state
	f.ran = nil
	if err := ops.open(); err != nil ||
		!slices.Equal(f.ran, []string{"systemctl disable --now --no-block " + deploy.RelayUpdatePath, "systemctl disable --now rayd-relay.service rayspa.service",
			"rayspa teardown", "unforward"}) {
		t.Errorf("open: %v %q", err, f.ran)
	}
	// Above: a job of the path unit is never waited for, in a restore or
	// open. The path unit is ordered before the update service
	// (systemd.path): while that stops halfway (systemctl stop,
	// test/relay/host.sh) the job waits for the stop, which waits for
	// this rollback (until TimeoutStopSec).
	if j := unitJob("stop", deploy.RelayUpdatePath); !slices.Equal(j, []string{"stop", "--no-block", deploy.RelayUpdatePath}) {
		t.Errorf("unitJob of the path unit: %q", j)
	}
	if j := unitJob("start", relayUnit); !slices.Equal(j, []string{"start", relayUnit}) {
		t.Errorf("unitJob of rayspa: %q", j)
	}
	if slices.ContainsFunc(f.ran, func(s string) bool { return strings.Contains(s, deploy.RelayRecover) }) {
		t.Errorf("open touched the recover unit: %q", f.ran)
	}
	// After a rollback to a release from before the update by the exit's
	// word (or an update by hand from one that failed): the restore took
	// the path unit's file away, and systemctl (252, 255) refuses to
	// disable a unit with no file, stopping nothing of the call. rayspa
	// and the probe go down all the same, and the host is open; the path
	// unit is not asked for.
	f = newFakeRelay(t)
	ops = f.env.ops
	ops.units = append(ops.units, deploy.RelayUpdatePath, deploy.RelayRecover)
	ops.enableOnly = []string{deploy.RelayRecover}
	ops.loaded = func(u string) bool { return u != deploy.RelayUpdatePath }
	run := ops.run
	ops.run = func(name string, args ...string) error {
		if name == "systemctl" && len(args) > 0 && args[0] == "disable" && slices.Contains(args, deploy.RelayUpdatePath) {
			f.record("refused " + strings.Join(args, " "))
			return errors.New("Failed to disable unit: Unit file " + deploy.RelayUpdatePath + " does not exist.")
		}
		return run(name, args...)
	}
	if err := ops.open(); err != nil || !f.down ||
		!slices.Equal(f.ran, []string{"systemctl disable --now rayd-relay.service rayspa.service", "rayspa teardown", "unforward"}) {
		t.Errorf("open, the path unit's file gone: %v %q", err, f.ran)
	}
	// Its file there but the disable failing all the same: no matter.
	ops.loaded = func(string) bool { return true }
	f.ran, f.down = nil, false
	if err := ops.open(); err != nil || !f.down || !slices.Contains(f.ran, "systemctl disable --now rayd-relay.service rayspa.service") {
		t.Errorf("open, the path unit refused: %v %q", err, f.ran)
	}
}

// rayctl install -relay enables the units of the update by the exit's word
// as root's policy has it: on, the path unit started and the recover unit
// for the next boot; off, both disabled, the recover unit never stopped.
func TestRelayRemoteUnits(t *testing.T) {
	var ran []string
	enable := func(u string, now bool) error {
		ran = append(ran, strings.Join(systemctlEnable("enable", u, now), " "))
		return nil
	}
	disable := func(u string, now bool) error {
		ran = append(ran, strings.Join(systemctlEnable("disable", u, now), " "))
		return nil
	}
	if err := relayRemoteUnits(true, enable, disable); err != nil ||
		!slices.Equal(ran, []string{"enable --now " + deploy.RelayUpdatePath, "enable " + deploy.RelayRecover}) {
		t.Errorf("on: %v %q", err, ran)
	}
	ran = nil
	if err := relayRemoteUnits(false, enable, disable); err != nil ||
		!slices.Equal(ran, []string{"disable --now " + deploy.RelayUpdatePath, "disable " + deploy.RelayRecover}) {
		t.Errorf("off: %v %q", err, ran)
	}
	// One that fails does not keep the other from its turn, and is said.
	ran = nil
	failing := func(u string, now bool) error {
		ran = append(ran, u)
		return errors.New("Unit file " + u + " does not exist")
	}
	if err := relayRemoteUnits(true, failing, disable); err == nil || len(ran) != 2 {
		t.Errorf("failing: %v %q", err, ran)
	}
}
