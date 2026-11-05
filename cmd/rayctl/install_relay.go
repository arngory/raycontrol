package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/arngory/raycontrol/internal/deploy"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/perimeter"
)

// relaySnapshot is where rayspa keeps the last snapshot it applied.
const relaySnapshot = deploy.RayspaState

// The guard: a transient systemd timer that takes rayspa down if rayctl
// dies (kill -9, out of memory) before rayspa passed its checks. It acts
// only while guardArmed is there, under guardLock, so that disarming it and
// its going off cannot cross: one of them happens, and rayctl knows which.
const (
	relayGuard = "raycontrol-relay-guard"
	guardLock  = "/run/" + relayGuard + ".lock"
	guardArmed = "/run/" + relayGuard + ".armed"
	// guardAfter covers starting rayspa (network-online.target may take two
	// minutes) and its first snapshot (45 s).
	guardAfter = 5 * time.Minute
)

// guardCommand is the systemd-run command line that arms the guard.
func guardCommand(flock, rayspa string) []string {
	return []string{"systemd-run", "--unit=" + relayGuard, fmt.Sprintf("--on-active=%d", int(guardAfter/time.Second)),
		"--timer-property=AccuracySec=1s", "--collect", flock, guardLock, "/bin/sh", "-c",
		"test -e " + guardArmed + " || exit 0; rm -f " + guardArmed + "; systemctl disable --now " + relayUnit + "; exec " + rayspa + " teardown"}
}

// installRelay makes this host a relay (spec/relay-v1.md §3.1): the bundle,
// rayspa taking its perimeter from the exit, forwarding on. rayspa closes
// everything but what its perimeter opens, the relay host's SSH included.
// So everything that can be checked is checked before anything changes;
// rayspa is started, not enabled, until its first snapshot admits this
// host's sshd from the relay's admin addresses, this session's included;
// and every other way out, a signal too, stops it, disables it and removes
// its table, so that a relay that cannot reach its exit does not lock its
// admin out, now or at the next boot.
func installRelay(bundlePath, packages string) error {
	// Before the journal: a node's records are its own.
	if _, err := os.Stat(deploy.DB); err == nil {
		return fmt.Errorf("this host is a node (%s): a relay goes on a host of its own", deploy.DB)
	}
	raw, err := os.ReadFile(bundlePath) //nolint:gosec // G304: the operator's file
	if err != nil {
		return err
	}
	b, err := node.DecodeRelayBundle(string(raw))
	if err != nil {
		return fmt.Errorf("%s: %w", bundlePath, err)
	}
	for _, tool := range []string{"nft", "systemctl", "systemd-run", "install"} {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("%s is missing: a relay needs nftables and systemd", tool)
		}
	}
	flock, err := exec.LookPath("flock")
	if err != nil {
		return errors.New("flock is missing (util-linux): the install's guard timer needs it")
	}
	if _, err := os.Stat(deploy.DefaultBinaries.Rayspa); err != nil {
		return fmt.Errorf("%s is missing: install/bootstrap.sh -relay installs it", deploy.DefaultBinaries.Rayspa)
	}
	// One install at a time: two would share the guard.
	installLock, err := takeInstallLock(relayInstallLock)
	if err != nil {
		return err
	}
	defer installLock.Close()
	sshd, err := sshdPorts()
	if err != nil {
		return fmt.Errorf("a relay closes all but its SSH port, and sshd's cannot be told (%w): fix sshd first", err)
	}
	sess := sshSession()
	port, err := relaySSHPort(sshd, listening, sess.port)
	if err != nil {
		return err
	}

	h, err := journaledHost()
	if err != nil {
		return err
	}
	// Recorded first, before anything can fail: rayctl uninstall takes all
	// of it back, the binaries the bootstrap put in place too.
	for _, bin := range []string{deploy.DefaultBinaries.Rayspa, "/usr/local/bin/rayctl"} {
		if _, err := os.Stat(bin); err == nil {
			if err := h.Journal.Record(deploy.Change{Kind: deploy.ChangeBinary, Path: bin}); err != nil {
				return err
			}
		}
	}
	if manager, names, ok := strings.Cut(packages, ":"); ok {
		for _, name := range splitList(names) {
			if err := h.Journal.Record(deploy.Change{Kind: deploy.ChangePackage, Name: name, Value: manager}); err != nil {
				return err
			}
		}
	}

	// Ctrl-C, Ctrl-\ (SIGQUIT), a closed SSH connection (SIGHUP, unless nohup ignores
	// it), systemd: the install stops at its next step, the way any failure
	// does.
	sigs := []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT}
	if !signal.Ignored(syscall.SIGHUP) {
		sigs = append(sigs, syscall.SIGHUP)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), sigs...)
	defer cancel()
	// Ctrl-Z would leave rayctl stopped with rayspa started and the guard
	// waiting on rayctl.
	signal.Ignore(syscall.SIGTSTP)
	defer signal.Reset(syscall.SIGTSTP)
	// The host's commands too run apart from the terminal's Ctrl-C.
	h.Run = func(name string, args ...string) ([]byte, error) { return commandApart(name, args...).CombinedOutput() }
	plan := deploy.RelayPlan(deploy.DefaultBinaries)
	unitFile := "/etc/systemd/system/" + relayUnit
	var forwardFile deploy.File
	var files []deploy.File
	for _, f := range plan.Files {
		if f.Path == deploy.RelaySysctl {
			forwardFile = f
		} else {
			files = append(files, f)
		}
	}
	rayspa := deploy.DefaultBinaries.Rayspa
	steps := relaySteps{
		unitExists: func() bool { _, err := os.Stat(unitFile); return err == nil },
		// Unless systemd says otherwise: one that does not answer may still
		// have rayspa enabled and running.
		enabled: func() bool {
			out, _ := commandApart("systemctl", "is-enabled", relayUnit).Output()
			return maybeEnabled(string(out))
		},
		active: func() bool {
			out, _ := commandApart("systemctl", "is-active", relayUnit).Output()
			return maybeActive(string(out))
		},
		systemctl: func(args ...string) error { return runApart("systemctl", args...) },
		teardown:  func() error { return runApart(rayspa, "teardown") },
		tableGone: tableGone,
		write: func() error {
			for _, u := range plan.Users {
				if err := h.EnsureUser(u); err != nil {
					return err
				}
			}
			files := append([]deploy.File{{Path: deploy.RelayBundle, Mode: 0o600, Content: []byte(strings.TrimSpace(string(raw)) + "\n")}}, files...)
			var sysctl []deploy.File
			for _, f := range files {
				changed, err := h.WriteFile(f)
				if err != nil {
					return err
				}
				if changed && strings.HasPrefix(f.Path, "/etc/sysctl.d/") {
					sysctl = append(sysctl, f)
				}
			}
			h.ApplySysctl(sysctl)
			return runApart("systemctl", "daemon-reload")
		},
		removeSnapshot: func() error {
			if err := os.Remove(relaySnapshot); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("the snapshot of an earlier install stays (%w): it would be checked instead of this one's", err)
			}
			return nil
		},
		guard:   func() error { return armGuard(guardArmed, runApart, flock, rayspa) },
		start:   func() error { return startGuarded(guardLock, guardArmed, runApart) },
		unguard: func() error { return unguardAt(guardLock, guardArmed, runApart) },
		waitSnapshot: func(ctx context.Context) error {
			// Started without blocking (under the guard's lock): it may
			// wait for network-online.target first.
			deadline := time.Now().Add(2 * time.Minute)
			for {
				out, _ := commandApart("systemctl", "is-active", relayUnit).Output()
				v := strings.TrimSpace(string(out))
				if v == "active" {
					break
				}
				if v == "failed" || time.Now().After(deadline) {
					return fmt.Errorf("rayspa did not start (%s): journalctl -u rayspa says why", v)
				}
				select {
				case <-ctx.Done():
					return errInterrupted
				case <-time.After(500 * time.Millisecond):
				}
			}
			err := waitFile(ctx, relaySnapshot, 45*time.Second)
			if err != nil && ctx.Err() == nil {
				return fmt.Errorf("the relay took no perimeter from its exit %s (API port %d) within 45 s: does the exit "+
					"know this host's address (rayctl relay list), is its api service on, and is this the newest bundle? "+
					"journalctl -u rayspa says more", b.Exit, b.API.Port)
			}
			return err
		},
		readSnapshot: func() (*perimeterv1.Snapshot, error) { return readSnapshot(relaySnapshot) },
		check: func(snap *perimeterv1.Snapshot) (string, error) {
			return checkRelaySSH(snap, port, sess.addr, b.Name)
		},
		forward: func() error {
			if _, err := h.WriteFile(forwardFile); err != nil {
				return err
			}
			// All of sysctl.d in order, as at boot: a file after ours that
			// turns it off (99-sysctl.conf, a hardening profile) shows now.
			applied := commandApart("sysctl", "-q", "--system").Run()
			return checkForwarding(func() ([]byte, error) { return os.ReadFile("/proc/sys/net/ipv4/ip_forward") }, applied)
		},
		enable: func() error { return h.EnableNow(relayUnit) },
	}
	snap, warning, err := steps.run(ctx)
	if err != nil {
		return err
	}
	if warning != "" {
		fmt.Fprintln(os.Stderr, "warning:", warning)
	}
	fmt.Printf("relay %s up: knocks with K_relay open the exit's services through here (exit %s).\n"+
		"This host's SSH (port %d) is reachable from %s, the relay's own admin addresses (rayctl relay set on the exit).\n",
		b.Name, b.Exit, port, strings.Join(snap.AdminPrefixes, ", "))
	return nil
}

// armGuard arms the guard: one left from an earlier install goes first,
// timer and service, or systemd-run refuses the name.
func armGuard(armed string, run func(string, ...string) error, flock, rayspa string) error {
	_ = run("systemctl", "stop", relayGuard+".timer", relayGuard+".service")
	if err := os.WriteFile(armed, nil, 0o600); err != nil {
		return err
	}
	args := guardCommand(flock, rayspa)
	return run(args[0], args[1:]...)
}

// underGuard runs f holding the guard's lock, the guard still armed: the
// guard cannot go off meanwhile, and if it went off before, f does not run.
func underGuard(lock, armed string, f func() error) error {
	l, err := os.OpenFile(lock, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: a fixed path
	if err != nil {
		return err
	}
	defer l.Close()
	if err := syscall.Flock(int(l.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(l.Fd()), syscall.LOCK_UN) //nolint:errcheck // closing unlocks too
	if _, err := os.Stat(armed); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("the guard timer took rayspa down: the install took over %v", guardAfter)
	} else if err != nil {
		return err
	}
	return f()
}

// startGuarded starts rayspa only while the guard is armed: the guard that
// went off before would leave it running unchecked.
//
// The start job is only queued under the lock (--no-block): starting may
// wait minutes for the network, and the guard must not wait on rayctl meanwhile.
func startGuarded(lock, armed string, run func(string, ...string) error) error {
	return underGuard(lock, armed, func() error { return run("systemctl", "start", "--no-block", relayUnit) })
}

// relayInstallLock keeps two relay installs from running at once.
const relayInstallLock = "/run/raycontrol-relay-install.lock"

// takeInstallLock takes the install lock or says another install has it.
func takeInstallLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: a fixed path
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("another rayctl install -relay is running on this host")
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// maybeEnabled reads systemctl is-enabled: enabled unless it says it is
// not; no answer may hide an enabled rayspa.
func maybeEnabled(out string) bool {
	v := strings.TrimSpace(out)
	return v != "disabled" && v != "not-found" && v != "masked"
}

// maybeActive reads systemctl is-active: running unless it says it is not.
func maybeActive(out string) bool {
	v := strings.TrimSpace(out)
	return v != "inactive" && v != "failed"
}

// checkForwarding reads net.ipv4.ip_forward after sysctl --system (applied:
// its error) and says what keeps it off.
func checkForwarding(read func() ([]byte, error), applied error) error {
	v, err := read()
	switch {
	case err != nil:
		return fmt.Errorf("net.ipv4.ip_forward cannot be read: %w", err)
	case strings.TrimSpace(string(v)) == "1":
		return nil
	case applied != nil:
		return fmt.Errorf("net.ipv4.ip_forward stays off: sysctl --system failed (%w)", applied)
	}
	return fmt.Errorf("net.ipv4.ip_forward stays off: a sysctl file after %s turns it off (sysctl --system shows which)", deploy.RelaySysctl)
}

// unguardAt disarms the guard, under its lock: an error if it went off.
func unguardAt(lock, armed string, run func(string, ...string) error) error {
	return underGuard(lock, armed, func() error {
		if err := os.Remove(armed); err != nil {
			return err
		}
		_ = run("systemctl", "stop", relayGuard+".timer")
		return nil
	})
}

// tableGone tells whether the perimeter's table is gone (nft list tables,
// apart from the terminal).
func tableGone() bool {
	out, err := commandApart("nft", "list", "tables").Output()
	if err != nil {
		return false
	}
	return !slices.ContainsFunc(strings.Split(string(out), "\n"), func(l string) bool {
		return strings.TrimSpace(l) == "table inet "+perimeter.Table
	})
}

// relayUnit is rayspa's unit, the one RelayPlan installs.
const relayUnit = "rayspa.service"

// relaySteps is the part of a relay install that can lock the operator
// out, with the host's operations given so that a test can follow it.
type relaySteps struct {
	unitExists     func() bool
	enabled        func() bool // systemctl is-enabled, or no answer
	active         func() bool // systemctl is-active, or no answer
	systemctl      func(args ...string) error
	teardown       func() error // rayspa teardown
	tableGone      func() bool
	write          func() error // users, files, sysctl but forwarding, daemon-reload
	removeSnapshot func() error
	guard          func() error // arms relayGuard
	start          func() error // starts rayspa while the guard is armed
	unguard        func() error // disarms it, or says it went off
	waitSnapshot   func(context.Context) error
	readSnapshot   func() (*perimeterv1.Snapshot, error)
	check          func(*perimeterv1.Snapshot) (string, error)
	forward        func() error // net.ipv4.ip_forward on
	enable         func() error // journaled, enable --now
}

var errInterrupted = errors.New("interrupted")

// run writes the relay, starts rayspa without enabling it, and enables it,
// with forwarding, once its first snapshot passes the check.
//
//   - An earlier install's rayspa is disabled before the first write, and
//     rayspa is only started until the check: a reboot opens the host,
//     whatever happened to rayctl.
//   - Before anything changes, a timer is armed that takes rayspa down
//     after guardAfter unless the install disarms it, once the check has
//     passed: kill -9 or running out of memory leave no rayspa running on
//     an unchecked perimeter either. If it went off, the install fails.
//   - Every other way out, a cancelled ctx (a signal) and a panic included,
//     takes rayspa down at once; if that fails, the error says so and the
//     timer is left to try again.
func (r relaySteps) run(ctx context.Context) (snap *perimeterv1.Snapshot, warning string, err error) {
	if r.unitExists() {
		if err := r.systemctl("disable", relayUnit); err != nil {
			return nil, "", fmt.Errorf("an earlier install's rayspa stays enabled, nothing changed: %w", err)
		}
	}
	ok, armed := false, false
	defer func() {
		if !ok {
			err = r.stop(err, armed)
		}
	}()
	step := func(f func() error) error {
		if ctx.Err() != nil {
			return errInterrupted
		}
		return f()
	}
	// Stopped before its snapshot goes: a rayspa still running would save
	// the earlier bundle's perimeter, and that would be checked instead.
	for _, f := range []func() error{
		// Before anything changes: the earlier rayspa still runs.
		func() error { err := r.guard(); armed = err == nil; return err },
		r.write,
		func() error { return r.systemctl("stop", relayUnit) },
		r.removeSnapshot,
		r.start,
		func() error { return r.waitSnapshot(ctx) },
		func() (err error) { snap, err = r.readSnapshot(); return err },
		func() (err error) { warning, err = r.check(snap); return err },
		// Checked: rayspa may run now, whatever happens to rayctl.
		func() error { err := r.unguard(); armed = armed && err != nil; return err },
		r.enable,
		r.forward,
	} {
		if err := step(f); err != nil {
			return nil, "", err
		}
	}
	if ctx.Err() != nil {
		return nil, "", errInterrupted
	}
	ok = true
	return snap, warning, nil
}

// stop takes rayspa down after why, and says whether the host is open.
func (r relaySteps) stop(why error, armed bool) error {
	unit := r.unitExists()
	var disable error
	if unit {
		disable = r.systemctl("disable", "--now", relayUnit)
	}
	tear := r.teardown()
	fix := fmt.Sprintf("run systemctl disable --now %s && %s teardown before you leave this session", relayUnit, deploy.DefaultBinaries.Rayspa)
	switch {
	case !r.tableGone():
		// The guard, if armed, tries again.
		return fmt.Errorf("%w; rayspa could NOT be taken down%s: %s", why, paren(disable, tear, errors.New("its table is still there")), fix)
	case unit && r.active():
		// Perhaps running still, and putting its table back within seconds.
		return fmt.Errorf("%w; rayspa could not be seen to stop%s: %s", why, paren(disable, tear), fix)
	case disable != nil && r.enabled():
		return fmt.Errorf("%w; the host is open now, but rayspa is still enabled and closes it again at boot%s: run systemctl disable %s",
			why, paren(disable), relayUnit)
	}
	if err := r.unguard(); armed && err != nil {
		return fmt.Errorf("%w; rayspa is stopped and disabled and the host left open (%s)", why, joined(err))
	}
	return fmt.Errorf("%w; rayspa is stopped and disabled and the host left open", why)
}

// paren is joined in parentheses after a space, or nothing.
func paren(errs ...error) string {
	if s := joined(errs...); s != "" {
		return " (" + s + ")"
	}
	return ""
}

// joined puts errors on one line.
func joined(errs ...error) string {
	var s []string
	for _, err := range errs {
		if err != nil {
			s = append(s, strings.Join(strings.Fields(err.Error()), " "))
		}
	}
	return strings.Join(s, "; ")
}

// commandApart is a command in a process group of its own: a second
// Ctrl-C at the terminal does not reach it halfway.
func commandApart(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

func runApart(name string, args ...string) error {
	out, err := commandApart(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// relaySSHPort is the one port a relay host's sshd must listen on, since
// the relay opens one: configured (sshd -T), really listened on (sshd, or
// ssh.socket, may not have been restarted since), and the one this SSH
// session came in on (session, 0: not known).
func relaySSHPort(sshd []int, listening func(int) bool, session int) (int, error) {
	if len(sshd) != 1 {
		return 0, fmt.Errorf("sshd is configured for %v: a relay opens one SSH port; keep one (Port, ListenAddress in sshd_config)", sshd)
	}
	port := sshd[0]
	if session != 0 && session != port {
		return 0, fmt.Errorf("this SSH session came in on port %d, sshd's configuration says %d (sshd -T): restart sshd, "+
			"or ssh.socket, so that they agree", session, port)
	}
	if !listening(port) {
		return 0, fmt.Errorf("nothing listens on tcp/%d, sshd's port in its configuration (sshd -T): restart sshd, or ssh.socket", port)
	}
	return port, nil
}

// checkRelaySSH tells whether the relay's perimeter lets SSH in: on sshd's
// port, from the relay's admin addresses, this session's address among
// them (client, empty: not known). What it cannot check comes back as a
// warning.
func checkRelaySSH(snap *perimeterv1.Snapshot, port int, client, relay string) (string, error) {
	if len(snap.AdminPrefixes) == 0 || !slices.ContainsFunc(snap.AdminPorts, func(p *perimeterv1.Port) bool { return p.Proto == "tcp" && int(p.Port) == port }) {
		return "", fmt.Errorf("the relay's perimeter would not let SSH in here: sshd listens on %d, the relay's SSH port is %v, "+
			"its admin addresses %v; on the exit: rayctl relay set -ssh-port %d -admin <your address> %s",
			port, snap.AdminPorts, snap.AdminPrefixes, port, relay)
	}
	a, err := netip.ParseAddr(client)
	switch {
	case client == "":
		return fmt.Sprintf("this session's address is not known (tmux, screen, a console?): SSH to this host opens only from %s",
			strings.Join(snap.AdminPrefixes, ", ")), nil
	case err == nil && a.Unmap().IsLoopback():
		return fmt.Sprintf("this session comes from %s, through a tunnel: SSH to this host opens only from %s",
			client, strings.Join(snap.AdminPrefixes, ", ")), nil
	case !adminIncludes(snap.AdminPrefixes, client):
		// The next connection would be refused. relay set replaces the
		// list: the one it has, and this address.
		return "", fmt.Errorf("this SSH session comes from %s, not from the relay's admin addresses %v: the next one would be "+
			"refused; on the exit: rayctl relay set -admin %s %s, then install again",
			client, snap.AdminPrefixes, strings.Join(append(slices.Clone(snap.AdminPrefixes), client), ","), relay)
	}
	return "", nil
}

// adminIncludes tells whether an address is inside one of the prefixes.
func adminIncludes(prefixes []string, addr string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	a = a.Unmap().WithZone("")
	return slices.ContainsFunc(prefixes, func(s string) bool {
		p, err := netip.ParsePrefix(s)
		return err == nil && p.Contains(a)
	})
}

// readSnapshot reads the perimeter rayspa saved.
func readSnapshot(path string) (*perimeterv1.Snapshot, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: rayspa's state
	if err != nil {
		return nil, err
	}
	snap := &perimeterv1.Snapshot{}
	return snap, proto.Unmarshal(raw, snap)
}

// waitFile waits until a file exists.
func waitFile(ctx context.Context, path string, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if time.Now().After(deadline) {
			return errors.New("timed out")
		}
		select {
		case <-ctx.Done():
			return errors.New("interrupted")
		case <-time.After(500 * time.Millisecond):
		}
	}
}
