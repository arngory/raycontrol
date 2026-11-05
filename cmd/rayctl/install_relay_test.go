package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

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
	calls                   []string
	unit, enabled, active   bool // rayspa's unit file, enabled, running
	table, guarded          bool // the perimeter's table, the guard timer armed
	fail, panicAt, cancelAt string
	cancel                  func()
}

func (f *fakeRelayHost) call(name string, then func()) error {
	f.calls = append(f.calls, name)
	defer func() {
		if name == f.cancelAt {
			f.cancel()
		}
	}()
	if name == f.panicAt {
		panic(name)
	}
	if name == f.fail {
		return errors.New(name + " failed")
	}
	if then != nil {
		then()
	}
	return nil
}

func (f *fakeRelayHost) steps() relaySteps {
	return relaySteps{
		unitExists: func() bool { return f.unit },
		systemctl: func(args ...string) error {
			return f.call(strings.Join(args, " "), func() {
				switch strings.Join(args[:len(args)-1], " ") {
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
			if f.active {
				f.calls = append(f.calls, "teardown")
				return errors.New("rayspa.service is running")
			}
			return f.call("teardown", func() { f.table = false })
		},
		tableGone:      func() bool { return !f.table },
		write:          func() error { return f.call("write", func() { f.unit = true }) },
		removeSnapshot: func() error { return f.call("rm snapshot", nil) },
		guard:          func() error { return f.call("guard", func() { f.guarded = true }) },
		unguard: func() error {
			if !f.guarded {
				f.calls = append(f.calls, "unguard")
				return errors.New("not loaded")
			}
			return f.call("unguard", func() { f.guarded = false })
		},
		waitSnapshot: func(context.Context) error { return f.call("wait", nil) },
		readSnapshot: func() (*perimeterv1.Snapshot, error) { return &perimeterv1.Snapshot{}, f.call("read", nil) },
		check:        func(*perimeterv1.Snapshot) (string, error) { return "", f.call("check", nil) },
		forward:      func() error { return f.call("forward", nil) },
		enable:       func() error { return f.call("enable", func() { f.enabled, f.active = true, true }) },
	}
}

func (f *fakeRelayHost) run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.cancel = cancel
	_, _, err := f.steps().run(ctx)
	return err
}

// rayspa is enabled, and forwarding on, only after the check; an earlier
// install's is disabled before the first write; a guard timer covers what
// rayctl cannot; every other way out takes rayspa down, and says when that
// failed.
func TestRelaySteps(t *testing.T) {
	const u = relayUnit
	happy := []string{"write", "stop " + u, "rm snapshot", "guard", "start " + u, "wait", "read", "check", "forward", "enable", "unguard"}
	down := []string{"disable --now " + u, "teardown", "unguard"}
	open := func(f *fakeRelayHost) bool { return !f.enabled && !f.active && !f.table && !f.guarded }

	f := &fakeRelayHost{}
	if err := f.run(); err != nil || !slices.Equal(f.calls, happy) || !f.enabled || !f.active || f.guarded {
		t.Fatalf("a new relay: %v %+v %v", f.calls, f, err)
	}
	f = &fakeRelayHost{unit: true, enabled: true, active: true, table: true}
	if err := f.run(); err != nil || !slices.Equal(f.calls, append([]string{"disable " + u}, happy...)) || !f.enabled {
		t.Fatalf("again: %v %v", f.calls, err)
	}
	f = &fakeRelayHost{unit: true, enabled: true, active: true, table: true, fail: "disable " + u}
	if err := f.run(); err == nil || !slices.Equal(f.calls, []string{"disable " + u}) || !strings.Contains(err.Error(), "nothing changed") {
		t.Fatalf("an earlier rayspa that stays enabled: %v %v", f.calls, err)
	}

	// A failure at any step: nothing after it, rayspa down, the host open.
	for i, at := range happy {
		f := &fakeRelayHost{fail: at}
		err := f.run()
		want := append(slices.Clone(happy[:i+1]), down...)
		if at == "write" {
			want = []string{"write", "teardown", "unguard"} // no unit yet
		}
		if at == "unguard" {
			f.guarded = false // armed still: it only takes down again what is down
		}
		if err == nil || !slices.Equal(f.calls, want) || !strings.Contains(err.Error(), "left open") || !open(f) {
			t.Errorf("%s fails: %v %+v %v", at, f.calls, f, err)
		}
	}
	// A signal at any step: the same, from the next step on.
	for i, at := range happy {
		f := &fakeRelayHost{cancelAt: at}
		err := f.run()
		want := append(slices.Clone(happy[:i+1]), down...)
		if err == nil || !strings.Contains(err.Error(), "interrupted") || !slices.Equal(f.calls, want) || !open(f) {
			t.Errorf("a signal at %s: %v %+v %v", at, f.calls, f, err)
		}
	}
	// A panic too.
	f = &fakeRelayHost{panicAt: "check"}
	func() {
		defer func() { _ = recover() }()
		_ = f.run()
	}()
	if !slices.Equal(f.calls, append(slices.Clone(happy[:8]), down...)) || !open(f) {
		t.Errorf("a panic: %v %+v", f.calls, f)
	}

	// rayspa that cannot be disabled keeps its table: said so, and the
	// guard stays armed to try again.
	f = &fakeRelayHost{fail: "disable --now " + u, cancelAt: "check"}
	if err := f.run(); err == nil || !strings.Contains(err.Error(), "could NOT") || !f.guarded || !f.table {
		t.Errorf("a table left: %+v %v", f, err)
	}
	// Open now, but enabled for the next boot: said so.
	g := (&fakeRelayHost{}).steps()
	g.systemctl = func(args ...string) error {
		if args[0] == "disable" || args[0] == "start" {
			return errors.New("failed")
		}
		return nil
	}
	if _, _, err := g.run(context.Background()); err == nil || !strings.Contains(err.Error(), "at boot") {
		t.Errorf("enabled at boot: %v", err)
	}
}
