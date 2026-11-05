package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/deploy"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
)

// A relay opens one SSH port: sshd's, from its listen addresses, which
// carry the ports of Port too.
func TestSSHDPorts(t *testing.T) {
	for out, want := range map[string][]int{
		"port 22\nlistenaddress [::]:22\nlistenaddress 0.0.0.0:22\n":                 {22},
		"port 2222\naddressfamily any\n":                                             {2222},
		"port 22\nport 2222\nlistenaddress 0.0.0.0:22\nlistenaddress 0.0.0.0:2222\n": {22, 2222},
		// ListenAddress with its own port: Port is not where sshd is.
		"port 22\nlistenaddress 198.51.100.1:2200\n":      {2200},
		"port 22\nlistenaddress 0.0.0.0:22 rdomain red\n": {22},
	} {
		got, err := parseSSHDPorts(out)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%q: %v %v, want %v", out, got, err, want)
		}
	}
	if _, err := parseSSHDPorts("port x\n"); err == nil {
		t.Error("a port that is no number")
	}
}

func TestAdminIncludes(t *testing.T) {
	admin := []string{"203.0.113.9/32", "2001:db8:1::/48"}
	for addr, want := range map[string]bool{
		"203.0.113.9": true, "::ffff:203.0.113.9": true, "2001:db8:1::5": true, "fe80::1%eth0": false,
		"203.0.113.10": false, "": false, "garbage": false,
	} {
		if got := adminIncludes(admin, addr); got != want {
			t.Errorf("%q: %v", addr, got)
		}
	}
}

// The one port the relay opens: configured, listened on, and the one this
// session came in on.
func TestRelaySSHPort(t *testing.T) {
	on := func(ports ...int) func(int) bool { return func(p int) bool { return slices.Contains(ports, p) } }
	for name, c := range map[string]struct {
		sshd    []int
		listen  func(int) bool
		session int
		ok      bool
	}{
		"one":                       {[]int{22}, on(22), 22, true},
		"session not known":         {[]int{2200}, on(2200), 0, true},
		"two":                       {[]int{22, 2200}, on(22, 2200), 22, false},
		"none":                      {nil, on(22), 22, false},
		"configured, not restarted": {[]int{2200}, on(22), 22, false},
		"ssh.socket on 22 only":     {[]int{2200}, on(22), 0, false},
	} {
		port, err := relaySSHPort(c.sshd, c.listen, c.session)
		if (err == nil) != c.ok || c.ok && port != c.sshd[0] {
			t.Errorf("%s: %d %v", name, port, err)
		}
	}
}

func TestListensOn(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0
   1: 0100007F:0898 0100007F:B5E2 01 00000000:00000000 00:00000000 00000000     0        0 2 1 0 20 4 30 10 -1
`
	tcp6 := `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A
`
	for port, want := range map[int]bool{22: true, 8080: true, 2200: false, 0x16 << 8: false} {
		if got := listensOn([]string{tcp, tcp6}, port); got != want {
			t.Errorf("port %d: %v", port, got)
		}
	}
}

// The relay's perimeter must let this session's next connection in.
func TestCheckRelaySSH(t *testing.T) {
	snap := &perimeterv1.Snapshot{AdminPrefixes: []string{"203.0.113.9/32"}, AdminPorts: []*perimeterv1.Port{{Proto: "tcp", Port: 22}}}
	for name, c := range map[string]struct {
		port            int
		client          string
		ok, warn        bool
		suggestContains string
	}{
		"inside":           {22, "203.0.113.9", true, false, ""},
		"another port":     {2200, "203.0.113.9", false, false, "-ssh-port 2200"},
		"outside":          {22, "198.51.100.7", false, false, "-admin 203.0.113.9/32,198.51.100.7 r1"},
		"not known":        {22, "", true, true, ""},
		"through a tunnel": {22, "127.0.0.1", true, true, ""},
	} {
		warning, err := checkRelaySSH(snap, c.port, c.client, "r1")
		if (err == nil) != c.ok || (warning != "") != c.warn || err != nil && !strings.Contains(err.Error(), c.suggestContains) {
			t.Errorf("%s: %q %v", name, warning, err)
		}
	}
	if _, err := checkRelaySSH(&perimeterv1.Snapshot{AdminPorts: snap.AdminPorts}, 22, "203.0.113.9", "r1"); err == nil {
		t.Error("no admin addresses")
	}
}

// fakeRelayHost follows the steps of a relay install, with rayspa's state.
type fakeRelayHost struct {
	calls                 []string
	unit, enabled, active bool   // rayspa's unit file, enabled, running
	table, guarded        bool   // the perimeter's table, the guard timer armed
	stuckEnabled          bool   // disable fails (read-only /etc): nothing changes
	stuckActive           bool   // systemd does not answer: rayspa runs on, teardown goes ahead
	crashAt, guardOffAt   string // rayspa dies, or the guard goes off, at that call
	forwarding            bool   // net.ipv4.ip_forward on, and our file there
	fails                 []string
	panicAt, cancelAt     string
	cancel                func()
	snap                  *perimeterv1.Snapshot
}

func (f *fakeRelayHost) call(name string, then func()) error {
	f.calls = append(f.calls, name)
	defer func() {
		if name == f.cancelAt {
			f.cancel()
		}
		if name == f.crashAt {
			f.active = false
		}
		if name == f.guardOffAt {
			f.guarded = false
		}
	}()
	if name == f.panicAt {
		panic(name)
	}
	if slices.Contains(f.fails, name) {
		return errors.New(name + " failed")
	}
	if then != nil {
		then()
	}
	return nil
}

func (f *fakeRelayHost) steps() relaySteps {
	f.snap = &perimeterv1.Snapshot{Revision: 7}
	return relaySteps{
		unitExists: func() bool { return f.unit },
		enabled:    func() bool { return f.enabled || f.stuckActive }, // no answer: maybe
		active:     func() bool { return f.active || f.stuckActive },  // no answer: maybe
		systemctl: func(args ...string) error {
			verb := strings.Join(args[:len(args)-1], " ")
			if verb == "disable --now" && f.stuckEnabled {
				f.calls = append(f.calls, strings.Join(args, " "))
				return errors.New("read-only /etc")
			}
			if verb == "disable --now" && f.stuckActive {
				f.calls = append(f.calls, strings.Join(args, " "))
				return errors.New("timed out")
			}
			return f.call(strings.Join(args, " "), func() {
				switch verb {
				case "disable":
					f.enabled = false
				case "disable --now":
					f.enabled, f.active = false, false
				case "stop":
					f.active = false
				case "start":
					f.active, f.table = true, true
				}
			})
		},
		teardown: func() error {
			if f.active && !f.stuckActive {
				f.calls = append(f.calls, "teardown")
				return errors.New("rayspa.service is running")
			}
			return f.call("teardown", func() { f.table = false })
		},
		tableGone:      func() bool { return !f.table },
		write:          func() error { return f.call("write", func() { f.unit = true }) },
		removeSnapshot: func() error { return f.call("rm snapshot", nil) },
		guard:          func() error { return f.call("guard", func() { f.guarded = true }) },
		start: func() error {
			if !f.guarded {
				f.calls = append(f.calls, "start "+relayUnit)
				return errors.New("the guard went off")
			}
			return f.call("start "+relayUnit, func() { f.active, f.table = true, true })
		},
		unguard: func() error {
			if !f.guarded {
				f.calls = append(f.calls, "unguard")
				return fmt.Errorf("%w (went off, or never armed)", errGuardOff)
			}
			return f.call("unguard", func() { f.guarded = false })
		},
		waitSnapshot: func(context.Context) error { return f.call("wait", nil) },
		readSnapshot: func() (*perimeterv1.Snapshot, error) { return f.snap, f.call("read", nil) },
		check: func(s *perimeterv1.Snapshot) (string, error) {
			if s != f.snap {
				return "", f.call("check another snapshot", nil)
			}
			return "", f.call("check", nil)
		},
		forward:   func() error { return f.call("forward", func() { f.forwarding = true }) },
		unforward: func() { f.calls = append(f.calls, "unforward"); f.forwarding = false },
		settle:    func(context.Context) error { return f.call("settle", nil) },
		enable:    func() error { return f.call("enable", func() { f.enabled, f.active = true, true }) },
	}
}

func (f *fakeRelayHost) run() (*perimeterv1.Snapshot, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.cancel = cancel
	snap, _, err := f.steps().run(ctx)
	return snap, err
}

// rayspa is enabled, and forwarding on, only after the check; an earlier
// install's is disabled before the first write; a guard timer, armed before
// anything changes and disarmed once checked, covers what rayctl cannot;
// every other way out takes rayspa down, and says when that failed.
func TestRelaySteps(t *testing.T) {
	const u = relayUnit
	happy := []string{"guard", "write", "stop " + u, "rm snapshot", "start " + u, "wait", "read", "check", "unguard", "enable", "forward", "settle"}
	down := []string{"unforward", "disable --now " + u, "teardown", "unguard"}
	open := func(f *fakeRelayHost) bool { return !f.enabled && !f.active && !f.table && !f.guarded && !f.forwarding }
	// What a failure (or a step done, then a signal) at step i leaves: what
	// ran, then down; on a new host without a unit, nothing to disable.
	after := func(i int, done bool) []string {
		w := slices.Index(happy, "write")
		if i < w || i == w && !done {
			return append(slices.Clone(happy[:i+1]), "unforward", "teardown", "unguard")
		}
		return append(slices.Clone(happy[:i+1]), down...)
	}

	f := &fakeRelayHost{}
	if snap, err := f.run(); err != nil || !slices.Equal(f.calls, happy) || !f.enabled || !f.active || f.guarded || !f.forwarding || snap != f.snap {
		t.Fatalf("a new relay: %v %+v %v", f.calls, f, err)
	}
	f = &fakeRelayHost{unit: true, enabled: true, active: true, table: true}
	if _, err := f.run(); err != nil || !slices.Equal(f.calls, append([]string{"disable " + u}, happy...)) || !f.enabled {
		t.Fatalf("again: %v %v", f.calls, err)
	}
	f = &fakeRelayHost{unit: true, enabled: true, active: true, table: true, fails: []string{"disable " + u}}
	if _, err := f.run(); err == nil || !slices.Equal(f.calls, []string{"disable " + u}) || !strings.Contains(err.Error(), "nothing changed") {
		t.Fatalf("an earlier rayspa that stays enabled: %v %v", f.calls, err)
	}

	// A re-install of a forwarding relay that fails early: its forwarding
	// goes with it.
	f = &fakeRelayHost{unit: true, enabled: true, active: true, table: true, forwarding: true, fails: []string{"wait"}}
	if _, err := f.run(); err == nil || f.forwarding {
		t.Errorf("a failed re-install still forwards: %+v %v", f, err)
	}
	// A failure at any step: nothing after it, rayspa down, the host open.
	for i, at := range happy {
		f := &fakeRelayHost{fails: []string{at}}
		_, err := f.run()
		if at == "unguard" {
			f.guarded = false // still armed: it only takes down again what is down
		}
		if err == nil || !slices.Equal(f.calls, after(i, false)) || !strings.Contains(err.Error(), "left open") || !open(f) {
			t.Errorf("%s fails: %v %+v %v", at, f.calls, f, err)
		}
	}
	// A signal at any step: the same, from the next step on; at the last,
	// the install is complete.
	for i, at := range happy[:len(happy)-1] {
		f := &fakeRelayHost{cancelAt: at}
		_, err := f.run()
		if err == nil || !strings.Contains(err.Error(), "interrupted") || !slices.Equal(f.calls, after(i, true)) || !open(f) {
			t.Errorf("a signal at %s: %v %+v %v", at, f.calls, f, err)
		}
	}
	f = &fakeRelayHost{cancelAt: happy[len(happy)-1]}
	if _, err := f.run(); err != nil || !f.enabled || !f.active {
		t.Errorf("a signal at the last step: %+v %v", f, err)
	}
	// A panic too.
	f = &fakeRelayHost{panicAt: "check"}
	func() {
		defer func() { _ = recover() }()
		_, _ = f.run()
	}()
	if !slices.Equal(f.calls, after(slices.Index(happy, "check"), false)) || !open(f) {
		t.Errorf("a panic: %v %+v", f.calls, f)
	}

	// rayspa that cannot be disabled keeps its table: said so, and the
	// guard stays armed to try again.
	f = &fakeRelayHost{fails: []string{"disable --now " + u}, cancelAt: "check"}
	if _, err := f.run(); err == nil || !strings.Contains(err.Error(), "could NOT") || !f.guarded || !f.table {
		t.Errorf("a table left: %+v %v", f, err)
	}
	// Open now (rayspa died), but still enabled for the next boot: said so.
	f = &fakeRelayHost{fails: []string{"forward"}, stuckEnabled: true, crashAt: "forward"}
	if _, err := f.run(); err == nil || !strings.Contains(err.Error(), "at boot") || f.calls[len(f.calls)-1] != "teardown" {
		t.Errorf("enabled at boot: %v %v", f.calls, err)
	}
	// systemd that does not answer: rayspa may run on and put its table
	// back. Not said to be open, and the guard stays armed.
	f = &fakeRelayHost{stuckActive: true, fails: []string{"wait"}}
	if _, err := f.run(); err == nil || !strings.Contains(err.Error(), "could not be seen to stop") || strings.Contains(err.Error(), "open") || !f.guarded {
		t.Errorf("still running: %+v %v", f, err)
	}
	// The guard that went off is said, not only the step that failed;
	// once disarmed, or never armed, nothing is said about it.
	f = &fakeRelayHost{guardOffAt: "start " + u, fails: []string{"wait"}}
	if _, err := f.run(); err == nil || !strings.Contains(err.Error(), "went off") {
		t.Errorf("the guard went off: %v", err)
	}
	// Once only, when the disarm itself found it gone.
	f = &fakeRelayHost{guardOffAt: "check"}
	if _, err := f.run(); err == nil || strings.Count(err.Error(), errGuardOff.Error()) != 1 {
		t.Errorf("the guard went off, said: %v", err)
	}
	for _, at := range []string{"enable", "forward", "write", "guard"} {
		f = &fakeRelayHost{fails: []string{at}}
		if _, err := f.run(); err == nil || strings.Contains(err.Error(), "went off") {
			t.Errorf("%s fails: %v", at, err)
		}
	}
	// No unit yet (a new host): systemd not answering says nothing of a
	// rayspa that was never there.
	f = &fakeRelayHost{stuckActive: true, fails: []string{"write"}}
	if _, err := f.run(); err == nil || !strings.Contains(err.Error(), "left open") {
		t.Errorf("no unit: %v", err)
	}
	// The guard that went off before rayspa starts: it does not start.
	f = &fakeRelayHost{}
	g := f.steps()
	guard := g.guard
	g.guard = func() error { err := guard(); f.guarded = false; return err }
	if _, _, err := g.run(context.Background()); err == nil || slices.Contains(f.calls, "wait") || f.active {
		t.Errorf("started without a guard: %v %v", f.calls, err)
	}
	// Not enabled, only not disabled: open, and nothing about the boot.
	f = &fakeRelayHost{fails: []string{"start " + u, "disable --now " + u}}
	if _, err := f.run(); err == nil || strings.Contains(err.Error(), "at boot") || !strings.Contains(err.Error(), "left open") {
		t.Errorf("not enabled: %v", err)
	}
}

// The guard goes off only while armed, under its lock, and takes rayspa
// down; disarming it says whether it went off; rayspa starts only while it
// is armed.
func TestGuard(t *testing.T) {
	cmd := strings.Join(guardCommand("/usr/bin/flock", "/usr/local/bin/rayspa"), " ")
	for _, want := range []string{
		"systemd-run --unit=" + relayGuard + " --on-active=300 --timer-property=AccuracySec=1s --collect /usr/bin/flock " + guardLock + " /bin/sh -c ",
		"test -e " + guardArmed + " || exit 0; rm -f " + guardArmed + "; systemctl disable --now rayspa.service; exec /usr/local/bin/rayspa teardown",
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("guard command %q lacks %q", cmd, want)
		}
	}
	dir := t.TempDir()
	lock, armed := dir+"/lock", dir+"/armed"
	var calls []string
	run := func(name string, args ...string) error {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil
	}

	// Armed: one left before goes, timer and service; the token is there.
	if err := armGuard(armed, run, "/usr/bin/flock", "/usr/local/bin/rayspa"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(armed); err != nil || len(calls) != 2 ||
		calls[0] != "systemctl stop "+relayGuard+".timer "+relayGuard+".service" || !strings.HasPrefix(calls[1], "systemd-run ") {
		t.Fatalf("arming: %v %v", calls, err)
	}
	calls = nil
	// Under the lock: the guard cannot go off while the start is queued.
	inLock := func(name string, args ...string) error {
		f, err := os.OpenFile(lock, os.O_RDWR, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
			return errors.New("ran outside the guard's lock")
		}
		return run(name, args...)
	}
	if err := startGuarded(lock, armed, inLock); err != nil || !slices.Equal(calls, []string{"systemctl start --no-block " + relayUnit}) {
		t.Fatalf("start while armed: %v %v", calls, err)
	}
	calls = nil
	if err := unguardAt(lock, armed, run); err != nil || !slices.Equal(calls, []string{"systemctl stop " + relayGuard + ".timer"}) {
		t.Fatalf("disarming: %v %v", calls, err)
	}
	if _, err := os.Stat(armed); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("still armed")
	}
	calls = nil
	if err := unguardAt(lock, armed, run); err == nil || !strings.Contains(err.Error(), "took rayspa down") {
		t.Fatalf("went off: %v", err)
	}
	if err := startGuarded(lock, armed, run); err == nil || len(calls) != 0 {
		t.Fatalf("start after the guard went off: %v %v", calls, err)
	}

	// With util-linux flock, as the guard holds it: disarming waits for a
	// guard going off and says so, whether the guard's lock is exclusive or
	// shared (so rayctl's must be exclusive).
	path, err := exec.LookPath("flock")
	if err != nil {
		t.Skip("no flock here")
	}
	for _, mode := range []string{"-x", "-s"} {
		if err := os.WriteFile(armed, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		guard := exec.Command(path, mode, lock, "/bin/sh", "-c", "sleep 0.5; test -e "+armed+" || exit 0; rm -f "+armed)
		if err := guard.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond) // the guard holds the lock
		err := unguardAt(lock, armed, run)
		_ = guard.Wait()
		if err == nil {
			t.Errorf("flock %s: disarmed while the guard went off", mode)
		}
	}
}

// One install at a time.
func TestInstallLock(t *testing.T) {
	path := t.TempDir() + "/lock"
	first, err := takeInstallLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := takeInstallLock(path); err == nil || !strings.Contains(err.Error(), "another") {
		t.Fatalf("a second install: %v", err)
	}
	first.Close()
	again, err := takeInstallLock(path)
	if err != nil {
		t.Fatalf("after the first: %v", err)
	}
	again.Close()
	if _, err := takeInstallLock(t.TempDir() + "/no/such/dir/lock"); err == nil || strings.Contains(err.Error(), "another") {
		t.Fatalf("an error that is no other install: %v", err)
	}
}

// What systemctl says, or does not: rayspa counts as enabled and running
// unless systemd says it is not.
func TestSystemctlAnswers(t *testing.T) {
	for out, want := range map[string]bool{"enabled\n": true, "disabled\n": false, "not-found\n": false, "masked": false, "": true, "static": true} {
		if maybeEnabled(out) != want {
			t.Errorf("is-enabled %q: %v", out, !want)
		}
	}
	for out, want := range map[string]bool{"active\n": true, "inactive\n": false, "failed": false, "activating": true, "": true} {
		if maybeActive(out) != want {
			t.Errorf("is-active %q: %v", out, !want)
		}
	}
}

// Forwarding: on now, and on at boot as all of sysctl.d gives it.
func TestCheckForwarding(t *testing.T) {
	read := func(v string, err error) func() ([]byte, error) {
		return func() ([]byte, error) { return []byte(v), err }
	}
	if err := checkForwarding(read("1\n", nil), "1", deploy.RelaySysctl); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		read       func() ([]byte, error)
		boot, says string
	}{
		"off now":        {read("0\n", nil), "1", "stays off (0)"},
		"off at boot":    {read("1\n", nil), "0", "from /etc/sysctl.d/99-hardening.conf"},
		"cannot be read": {read("", os.ErrPermission), "1", "cannot be read"},
	} {
		err := checkForwarding(c.read, c.boot, "/etc/sysctl.d/99-hardening.conf")
		if err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Forwarding at boot, as systemd-sysctl and udev leave it: files by name
// across the directories, an earlier directory hiding a file of the same
// name; a key set again to another value moves last, to the same value
// keeps its place; one variable under two names; a glob only for keys not
// set by name; interfaces' own settings, globs and the default as udev
// applies them; sysctl.conf not read.
func TestForwardingAtBoot(t *testing.T) {
	root := t.TempDir()
	etc, lib := root+"/etc/sysctl.d", root+"/usr/lib/sysctl.d"
	dirs := []string{etc, root + "/run/sysctl.d", lib}
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	base := map[string]string{
		lib + "/05-default.conf":          "net.ipv4.ip_forward = 0\n",
		etc + "/91-raycontrol-relay.conf": "# relay\nnet.ipv4.ip_forward = 1\n",
		lib + "/99-hardening.conf":        "net/ipv4/ip_forward=0\n",
		etc + "/99-hardening.conf":        "; hides the lib file\nkernel.foo = 1\n",
		root + "/etc/sysctl.conf":         "net.ipv4.ip_forward = 0\n",
		etc + "/90-other.conf.disabled":   "net.ipv4.ip_forward = 0\n",
	}
	for name, c := range map[string]struct {
		extra      map[string]string
		value, why string
	}{
		"ours last":                   {nil, "1", "91-raycontrol-relay.conf"},
		"a later file":                {map[string]string{etc + "/99-zz.conf": "-net.ipv4.ip_forward = 0\r\n"}, "0", "99-zz.conf"},
		"the other name":              {map[string]string{etc + "/99-stig.conf": "net.ipv4.conf.all.forwarding = 0\n"}, "0", "99-stig.conf"},
		"a glob":                      {map[string]string{etc + "/99-glob.conf": "net/ipv4/conf/*/forwarding=0\n"}, "0", "99-glob.conf"},
		"a glob before ours, by udev": {map[string]string{etc + "/10-glob.conf": "net.ipv4.conf.*.forwarding = 0\n"}, "0", "10-glob.conf"},
		"the default":                 {map[string]string{etc + "/10-def.conf": "net.ipv4.conf.default.forwarding = 0\n"}, "0", "10-def.conf"},
		"one interface":               {map[string]string{etc + "/10-eth.conf": "net.ipv4.conf.eth0.forwarding = 0\n"}, "0", "10-eth.conf"},
		// The same value keeps its earlier place: the other name, between,
		// has the last word.
		"same value keeps its place": {map[string]string{etc + "/10-x.conf": "net.ipv4.ip_forward = 1\n", etc + "/50-y.conf": "net.ipv4.conf.all.forwarding = 0\n"}, "0", "50-y.conf"},
		// A glob does not override a key set by name, whatever the order.
		"by name beats a glob": {map[string]string{etc + "/99-g.conf": "net.ipv4.ip_*=0\n"}, "1", "91-raycontrol-relay.conf"},
		"another key":          {map[string]string{etc + "/99-o.conf": "net.ipv4.conf.all.rp_filter = 0\nnet.ipv6.conf.*.forwarding = 0\nnet.ipv4.conf.lo.forwarding = 0\n"}, "1", "91-raycontrol-relay.conf"},
	} {
		os.RemoveAll(root)
		for p, b := range base {
			write(p, b)
		}
		for p, b := range c.extra {
			write(p, b)
		}
		if v, f := forwardingAtBoot(dirs); v != c.value || !strings.HasSuffix(f, "/"+c.why) {
			t.Errorf("%s: %q from %s", name, v, f)
		}
	}
}

// Forwarding goes on only if it stays on at boot, and a failure leaves the
// kernel as it was, without our file.
func TestTurnForwardingOn(t *testing.T) {
	dir := t.TempDir()
	proc := dir + "/ip_forward"
	setup := func() (written, removed, applied *bool) {
		t.Helper()
		if err := os.WriteFile(proc, []byte("0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		var w, r, a bool
		return &w, &r, &a
	}
	read := func() string { b, _ := os.ReadFile(proc); return strings.TrimSpace(string(b)) }
	run := func(boot string, takes bool) (written, removed, applied bool, err error) {
		w, r, a := setup()
		err = turnForwardingOn(proc,
			func() error { *w = true; return nil },
			func() error { *r = true; return nil },
			func() {
				*a = true
				if takes {
					os.WriteFile(proc, []byte("1\n"), 0o644)
				}
			},
			func() (string, string) { return boot, "/etc/sysctl.d/99-zz.conf" })
		return *w, *r, *a, err
	}
	if w, r, a, err := run("1", true); err != nil || !w || r || !a || read() != "1" {
		t.Fatalf("on: %v written %v removed %v applied %v now %s", err, w, r, a, read())
	}
	if _, r, a, err := run("0", true); err == nil || !strings.Contains(err.Error(), "99-zz.conf") || !r || a || read() != "0" {
		t.Fatalf("off at boot: %v removed %v applied %v now %s", err, r, a, read())
	}
	if _, r, _, err := run("1", false); err == nil || !r || read() != "0" {
		t.Fatalf("does not take: %v removed %v now %s", err, r, read())
	}
}

// Waiting for rayspa: running, or a restart, a failed result, the limit.
func TestWaitActive(t *testing.T) {
	seq := func(states ...map[string]string) func() (map[string]string, error) {
		i := 0
		return func() (map[string]string, error) {
			st := states[min(i, len(states)-1)]
			i++
			return st, nil
		}
	}
	activating := map[string]string{"ActiveState": "activating", "SubState": "start-pre", "Result": "success", "NRestarts": "0", "Job": "1"}
	running := map[string]string{"ActiveState": "active", "SubState": "running", "Result": "success", "NRestarts": "0"}
	ctx := context.Background()
	if err := waitActive(ctx, seq(activating, activating, running), "0", time.Second, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	// Queued behind network-online.target: the last run's Result and
	// restarts are not this one's.
	stale := map[string]string{"ActiveState": "inactive", "SubState": "dead", "Result": "exit-code", "NRestarts": "4", "Job": "112"}
	if err := waitActive(ctx, seq(stale, stale, running), "0", time.Second, time.Millisecond); err != nil {
		t.Fatalf("queued: %v", err)
	}
	// Restarts counted from before the start.
	again := map[string]string{"ActiveState": "active", "SubState": "running", "Result": "success", "NRestarts": "3"}
	if err := waitActive(ctx, seq(again), "3", time.Second, time.Millisecond); err != nil {
		t.Fatalf("restarts before: %v", err)
	}
	if err := stillRunning(seq(again), "3"); err != nil {
		t.Fatalf("still running: %v", err)
	}
	for name, st := range map[string]map[string]string{
		"restarted since": {"ActiveState": "active", "SubState": "running", "NRestarts": "4"},
		"stopped":         {"ActiveState": "activating", "SubState": "auto-restart", "NRestarts": "3"},
	} {
		if err := stillRunning(seq(st), "3"); err == nil {
			t.Errorf("still running, %s", name)
		}
	}
	for name, c := range map[string]struct {
		show func() (map[string]string, error)
		says string
	}{
		"a crash loop":   {seq(activating, map[string]string{"ActiveState": "active", "SubState": "running", "Result": "success", "NRestarts": "2"}), "restarted (2 times)"},
		"a failed start": {seq(map[string]string{"ActiveState": "inactive", "SubState": "dead", "Result": "exit-code", "NRestarts": "0"}), "did not start (exit-code)"},
		"never":          {seq(activating), "did not start within"},
	} {
		if err := waitActive(ctx, c.show, "0", 20*time.Millisecond, time.Millisecond); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Exited and to be started again: a failure, even with the start job
	// still queued (systemd before 254).
	restart := map[string]string{"ActiveState": "activating", "SubState": "auto-restart", "Result": "exit-code", "NRestarts": "0", "Job": "9"}
	if err := waitActive(ctx, seq(activating, restart), "0", time.Second, time.Millisecond); err == nil || !strings.Contains(err.Error(), "exited") {
		t.Errorf("auto-restart: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := waitActive(cancelled, seq(activating), "0", time.Second, time.Millisecond); !errors.Is(err, errInterrupted) {
		t.Errorf("interrupted: %v", err)
	}
}
