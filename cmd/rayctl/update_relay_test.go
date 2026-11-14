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
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/node"
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

// The update's steps and its way back: a failing install or check brings
// the previous relay back; only a relay that does not come back is left
// open, and the error says so.
func TestRelayUpdateRun(t *testing.T) {
	boom := errors.New("boom")
	for name, c := range map[string]struct {
		fail     string // the step that fails
		calls    []string
		contains string
		back     bool // rolledBack
	}{
		"done":            {"", []string{"keep", "place", "install", "check"}, "", false},
		"keep":            {"keep", []string{"keep"}, "nothing changed", false},
		"place":           {"place", []string{"keep", "place", "restore", "checkBack"}, "installing: boom", true},
		"install":         {"install", []string{"keep", "place", "install", "restore", "checkBack"}, "the relay install: boom", true},
		"check":           {"check", []string{"keep", "place", "install", "check", "restore", "checkBack"}, "after the install: boom", true},
		"restore":         {"install,restore", []string{"keep", "place", "install", "restore", "open"}, "host left open", false},
		"checkBack":       {"check,checkBack", []string{"keep", "place", "install", "check", "restore", "checkBack", "open"}, "host left open", false},
		"open fails":      {"install,checkBack,open", []string{"keep", "place", "install", "restore", "checkBack", "open"}, "could NOT be taken down", false},
		"the words stand": {"install", nil, "the previous version runs again", true},
	} {
		var calls []string
		step := func(n string) func() error {
			return func() error {
				calls = append(calls, n)
				if slices.Contains(strings.Split(c.fail, ","), n) {
					return boom
				}
				return nil
			}
		}
		u := relayUpdate{keep: step("keep"), place: step("place"), install: step("install"), check: step("check"),
			restore: step("restore"), checkBack: step("checkBack"), open: step("open")}
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

// After the update and after its rollback: rayspa runs and holds its
// table, the kernel forwards, SSH from the admin addresses, the version
// wanted, the probe endpoint if it ran before.
func TestRelayHealth(t *testing.T) {
	up := map[string]string{"ActiveState": "active", "SubState": "running"}
	down := map[string]string{"ActiveState": "inactive", "SubState": "dead"}
	snap := &perimeterv1.Snapshot{AdminPrefixes: []string{"203.0.113.9/32"}, AdminPorts: []*perimeterv1.Port{{Proto: "tcp", Port: 22}}}
	good := func() relayHealth {
		return relayHealth{
			rayspa: func() (map[string]string, error) { return up, nil }, probe: func() (map[string]string, error) { return up, nil },
			probeRan: true, tableGone: func() bool { return false },
			forwarding: func() ([]byte, error) { return []byte("1\n"), nil },
			snapshot:   func() (*perimeterv1.Snapshot, error) { return snap, nil },
			version:    func() string { return "v0.26.1" }, want: "v0.26.1", port: 22, client: "203.0.113.9", name: "msk",
		}
	}
	if err := good().check(); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		break_   func(*relayHealth)
		contains string
	}{
		"rayspa down":     {func(h *relayHealth) { h.rayspa = func() (map[string]string, error) { return down, nil } }, "rayspa is inactive/dead"},
		"no table":        {func(h *relayHealth) { h.tableGone = func() bool { return true } }, "no perimeter table"},
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
	h := good()
	h.probeRan, h.probe = false, func() (map[string]string, error) { return down, nil }
	h.want = "local"
	h.version = func() string { return "dev" }
	if err := h.check(); err != nil {
		t.Errorf("no probe before, a local build: %v", err)
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

// keep and restore on files of a test's own: the binaries, the plan's
// files (one added by the update goes again), rayspa's snapshot, the units
// enabled and started as they were.
func TestRelayKeepRestore(t *testing.T) {
	dir := t.TempDir()
	at := func(p string) string { return filepath.Join(dir, p) }
	for _, d := range []string{"bin", "etc", "state"} {
		os.Mkdir(at(d), 0o755)
	}
	write := func(p, s string) {
		if err := os.WriteFile(at(p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	read := func(p string) string {
		b, err := os.ReadFile(at(p))
		if err != nil {
			return "<none>"
		}
		return string(b)
	}
	write("bin/rayspa", "old rayspa")
	write("bin/rayctl", "old rayctl")
	write("etc/rayspa.service", "old unit")
	write("etc/91-relay.conf", "net.ipv4.ip_forward = 1\n")
	write("state/snapshot.pb", "old snapshot")
	var ran []string
	ops := relayOps{
		dir: at("previous"), bins: map[string]string{"rayspa": at("bin/rayspa"), "rayctl": at("bin/rayctl"), "rayd": at("bin/rayd")},
		files: []string{at("etc/rayspa.service"), at("etc/rayd-relay.service"), at("etc/91-relay.conf")}, snapshot: at("state/snapshot.pb"),
		units: []string{"rayspa.service", "rayd-relay.service"},
		state: func(u string) unitWas { return unitWas{Enabled: u == "rayspa.service", Active: u == "rayspa.service"} },
		run: func(name string, args ...string) error {
			ran = append(ran, strings.Join(append([]string{name}, args...), " "))
			return nil
		},
		place: func(src, dst string) error {
			b, err := os.ReadFile(src)
			if err != nil {
				return err
			}
			return os.WriteFile(dst, b, 0o755)
		},
		disarm: func() { ran = append(ran, "disarm") }, unforward: func() {}, tableGone: func() bool { return true },
	}
	k, err := ops.keep("v0.26.0")
	if err != nil {
		t.Fatal(err)
	}
	if !k.Snapshot || !k.Files[at("etc/rayspa.service")] || k.Files[at("etc/rayd-relay.service")] || !k.Units["rayspa.service"].Active {
		t.Fatalf("kept %+v", k)
	}
	// The update: new binaries, a new unit, the old one rewritten, rayd
	// added, the snapshot gone (the install removes it), forwarding off.
	write("bin/rayspa", "new rayspa")
	write("bin/rayctl", "new rayctl")
	write("bin/rayd", "new rayd")
	write("etc/rayspa.service", "new unit")
	write("etc/rayd-relay.service", "new probe unit")
	os.Remove(at("etc/91-relay.conf"))
	os.Remove(at("state/snapshot.pb"))
	ran = nil
	var back relayKept
	if _, err := captureStdout(t, func() (err error) { back, err = ops.restore(true); return err }); err != nil {
		t.Fatal(err)
	}
	if back.Version != "v0.26.0" {
		t.Errorf("version %q", back.Version)
	}
	for p, want := range map[string]string{
		"bin/rayspa": "old rayspa", "bin/rayctl": "old rayctl", "bin/rayd": "new rayd", // none before: none kept
		"etc/rayspa.service": "old unit", "etc/rayd-relay.service": "<none>", "etc/91-relay.conf": "net.ipv4.ip_forward = 1\n",
		"state/snapshot.pb": "old snapshot",
	} {
		if got := read(p); got != want {
			t.Errorf("%s: %q, want %q", p, got, want)
		}
	}
	want := []string{"disarm", "systemctl stop rayd-relay.service rayspa.service", "systemctl daemon-reload",
		"systemctl enable rayspa.service", "systemctl disable rayd-relay.service", "systemctl start rayspa.service"}
	if !slices.Equal(ran, want) {
		t.Errorf("ran %q\nwant %q", ran, want)
	}
	// A manual rollback keeps rayspa's snapshot as it is now.
	write("state/snapshot.pb", "the exit's latest")
	if _, err := captureStdout(t, func() error { _, err := ops.restore(false); return err }); err != nil {
		t.Fatal(err)
	}
	if got := read("state/snapshot.pb"); got != "the exit's latest" {
		t.Errorf("snapshot %q after a rollback by hand", got)
	}
	// Nothing kept: nothing to roll back to.
	ops.dir = at("none")
	if _, err := ops.restore(true); err == nil || !strings.Contains(err.Error(), "nothing to roll back to") {
		t.Errorf("no copy: %v", err)
	}
	// open: rayspa down; a table that stays is said.
	ran = nil
	ops.rayspa = "rayspa"
	if err := ops.open(); err != nil || !slices.Equal(ran, []string{"systemctl disable --now rayd-relay.service rayspa.service", "rayspa teardown"}) {
		t.Errorf("open: %v %q", err, ran)
	}
	ops.tableGone = func() bool { return false }
	if err := ops.open(); err == nil {
		t.Error("a table left was not said")
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
}

// rayctl update status|remote|auto on a relay: no policy to set, status
// says what is installed and what the last update kept.
func TestRelayPolicy(t *testing.T) {
	c := &cli{}
	dir := t.TempDir()
	for _, args := range [][]string{{"remote", "on"}, {"auto", "patch"}} {
		if err := c.relayPolicy(args, dir); !errors.Is(err, errRelayByHand) {
			t.Errorf("%v: %v", args, err)
		}
	}
	for _, args := range [][]string{{"status", "x"}, {"nope"}} {
		if err := c.relayPolicy(args, dir); !errors.Is(err, errUsage) {
			t.Errorf("%v: %v", args, err)
		}
	}
	os.WriteFile(filepath.Join(dir, relayKeptFile), []byte(`{"version":"v0.26.0"}`), 0o600)
	text, err := captureStdout(t, func() error { return c.relayPolicy([]string{"status"}, dir) })
	if err != nil || !strings.Contains(text, "host       relay") || !strings.Contains(text, "previous   v0.26.0") ||
		!strings.Contains(text, "remote     does not apply") || !strings.Contains(text, "rayctl update -check") {
		t.Errorf("status: %q %v", text, err)
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
