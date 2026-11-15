package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/arngory/raycontrol/internal/deploy"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/perimeter"
	"github.com/arngory/raycontrol/internal/release"
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
func installRelay(bundlePath, packages string) (err error) {
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
	flock, err := relayTools()
	if err != nil {
		return err
	}
	if _, err := os.Stat(deploy.DefaultBinaries.Rayspa); err != nil {
		return fmt.Errorf("%s is missing: install/bootstrap.sh -relay installs it", deploy.DefaultBinaries.Rayspa)
	}
	// Not only for the probe endpoint: rayspa's unit copies the bundle in
	// with rayd's credential command (spec/apply-plan-v1.md §6, 3).
	if _, err := os.Stat(deploy.DefaultBinaries.Rayd); err != nil {
		return fmt.Errorf("%s is missing: install/bootstrap.sh -relay installs it (rayspa's unit copies the bundle in with it)",
			deploy.DefaultBinaries.Rayd)
	}
	// One install at a time: two would share the guard. Under rayctl
	// update, the update's own lock, held from before its first change.
	_, done, err := relayInstallBegin(relayInstallLock, previousDir, nodeupdate.StatusFile)
	if err != nil {
		return err
	}
	defer func() { done(err) }()
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
	for _, bin := range []string{deploy.DefaultBinaries.Rayspa, "/usr/local/bin/rayctl", deploy.DefaultBinaries.Rayd} {
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
	if err := plan.Check(); err != nil {
		return err
	}
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
	var restarts string // rayspa's NRestarts before this start
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
		guard: func() error { return armGuard(guardArmed, runApart, flock, rayspa) },
		start: func() error {
			// The last run's state goes: its Result and restart count would
			// read as this run's.
			_ = runApart("systemctl", "reset-failed", relayUnit)
			st, _ := showUnit()
			restarts = st["NRestarts"]
			return startGuarded(guardLock, guardArmed, runApart)
		},
		unguard: func() error { return unguardAt(guardLock, guardArmed, runApart) },
		waitSnapshot: func(ctx context.Context) error {
			// Started without blocking (under the guard's lock): it may
			// wait for network-online.target first (up to 2 min).
			if err := waitActive(ctx, showUnit, restarts, 150*time.Second, 500*time.Millisecond); err != nil {
				return err
			}
			err := waitFile(ctx, relaySnapshot, 45*time.Second)
			if err == nil {
				return stillRunning(showUnit, restarts)
			}
			if ctx.Err() == nil {
				if st, _ := showUnit(); restartedSince(st, restarts) {
					return fmt.Errorf("rayspa restarted (%s times): journalctl -u rayspa says why", st["NRestarts"])
				}
				return fmt.Errorf("the relay took no perimeter from its exit %s (API port %d) within 45 s: does the exit "+
					"know this host's address (rayctl relay list), is its api service on, and is this the newest bundle? "+
					"journalctl -u rayspa says more", b.Exit, b.API.Port)
			}
			return err
		},
		readSnapshot: func() (*perimeterv1.Snapshot, error) { return readSnapshot(relaySnapshot) },
		check: func(snap *perimeterv1.Snapshot) (string, error) {
			return checkRelaySSH(snap, port, sess.addr, b.Name, "install again")
		},
		forward: func() error {
			// The value before raycontrol first: once our file is there, a
			// reboot would turn forwarding on with nothing to undo it by.
			if err := recordForwarding(h.Journal, procForward); err != nil {
				return err
			}
			return turnForwardingOn(procForward,
				func() error { _, err := h.WriteFile(forwardFile); return err },
				func() error { return os.Remove(forwardFile.Path) },
				// Our file only, its old value journaled for uninstall.
				func() { h.ApplySysctl([]deploy.File{forwardFile}) },
				func() (string, string) { return forwardingAtBoot(sysctlDirs) })
		},
		enable: func() error {
			if err := stillRunning(showUnit, restarts); err != nil {
				return err
			}
			return h.EnableNow(relayUnit)
		},
		unforward: func() {
			unforwardAt(forwardFile.Path, procForward,
				func() (string, bool) {
					c, ok := h.Journal.Original(deploy.ChangeSysctl, "", forwardKey)
					return c.Value, ok
				},
				// -e, as ApplySysctl loads it: a key this host has not
				// (net.ipv6.* with IPv6 off) is skipped, not an error.
				func() { _ = runApart("sysctl", "-q", "-e", "-p", deploy.HardeningSysctl) })
		},
		// Past RestartSec (2 s): a rayspa that dies after its snapshot has
		// restarted by then.
		settle: func(ctx context.Context) error {
			return settleFor(ctx, 3*time.Second, func() error { return stillRunning(showUnit, restarts) })
		},
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
	var probePort uint16
	if b.Probe != nil {
		probePort = b.Probe.Port
	}
	// The ports this relay listens on, now that its snapshot says which
	// are SPA's: rayspa's TCP carrier and the probe endpoint. rayspa
	// listens again each second, so a slot an outgoing connection held
	// comes back once it is reserved.
	h.ReservePorts(deploy.RelayPorts(snap.GetSpa().GetPortBase(), snap.GetSpa().GetPortRange(), probePort))
	// Every forwarded flow is an entry of this host's conntrack table
	// (spec/conn-limit-v1.md §6.1): sized by memory, shorter times.
	h.Conntrack()
	// The relay's probe endpoint (relay-v1 §9.1), once the relay is up: it
	// is the relay's extra, and the relay works without it.
	probe := relayProbe{
		bundle: b,
		hasRayd: func() bool {
			_, err := os.Stat(deploy.DefaultBinaries.Rayd)
			return err == nil
		},
		enable:  func() error { return h.EnableNow(deploy.RelayProbeUnit) },
		restart: func() error { return runApart("systemctl", "restart", deploy.RelayProbeUnit) },
		stop:    func() error { return runApart("systemctl", "disable", "--now", deploy.RelayProbeUnit) },
		settle: func() error {
			return settleFor(ctx, 3*time.Second, func() error {
				out, _ := commandApart("systemctl", "is-active", deploy.RelayProbeUnit).Output()
				if s := strings.TrimSpace(string(out)); s != "active" {
					return fmt.Errorf("rayd relay is %s", s)
				}
				return nil
			})
		},
	}
	if note, err := probe.start(); err != nil {
		fmt.Fprintln(os.Stderr, "warning:", err)
	} else if note != "" {
		fmt.Println(note)
	}
	// The update by the exit's word, on as root's policy has it: what
	// stays through an update (this install runs under it) and a
	// bootstrap.sh -relay again. The relay works without it.
	remote := nodeupdate.ReadPolicy(nodeupdate.PolicyFile).Remote == "on"
	if err := relayRemoteUnits(remote, func(u string, now bool) error { return enableUnit(h, u, now) }, disableUnit); err != nil {
		fmt.Fprintf(os.Stderr, "warning: the units of the update by the exit's word: %v (rayctl update remote on|off sets them again)\n", err)
	}
	h.WarnRelayDropChains(probePort)
	return nil
}

// relayRemoteUnits enables the units of the relay's update by its exit's
// word (spec/relay-update-remote-v1.md §4.1), the path unit started and
// the recover unit for the next boot, when on (root's policy has remote
// on), and disables them when not; recover is never started or stopped
// here (it may be what runs).
func relayRemoteUnits(on bool, enable, disable func(unit string, now bool) error) error {
	if on {
		return errors.Join(enable(deploy.RelayUpdatePath, true), enable(deploy.RelayRecover, false))
	}
	return errors.Join(disable(deploy.RelayUpdatePath, true), disable(deploy.RelayRecover, false))
}

// enableUnit enables unit, and starts it when now; journaled first, so
// that rayctl uninstall takes it down (a path unit's file alone it would
// remove, its link left behind).
func enableUnit(h *deploy.Host, unit string, now bool) error {
	if err := h.Journal.Record(deploy.Change{Kind: deploy.ChangeUnit, Name: unit}); err != nil {
		return err
	}
	return runApart("systemctl", systemctlEnable("enable", unit, now)...)
}

// disableUnit disables unit, and stops it when now.
func disableUnit(unit string, now bool) error {
	return runApart("systemctl", systemctlEnable("disable", unit, now)...)
}

// systemctlEnable is systemctl's arguments to enable or disable unit, with
// --now when now.
func systemctlEnable(verb, unit string, now bool) []string {
	if now {
		return []string{verb, "--now", unit}
	}
	return []string{verb, unit}
}

// relayTools checks the commands a relay install runs, and finds flock
// for its guard timer.
func relayTools() (flock string, err error) {
	for _, tool := range []string{"nft", "systemctl", "systemd-run", "install"} {
		if _, err := exec.LookPath(tool); err != nil {
			return "", fmt.Errorf("%s is missing: a relay needs nftables and systemd", tool)
		}
	}
	flock, err = exec.LookPath("flock")
	if err != nil {
		return "", errors.New("flock is missing (util-linux): the install's guard timer needs it")
	}
	return flock, nil
}

// relayProbe starts rayd relay, the relay's probe endpoint, on a relay that
// is up.
type relayProbe struct {
	bundle                        node.RelayBundle
	hasRayd                       func() bool
	enable, restart, stop, settle func() error
}

// start runs rayd relay with this bundle (restarted: an earlier one may run
// with the bundle before), or stops it for a bundle without an endpoint.
// An error is a warning: the relay forwards all the same.
func (p relayProbe) start() (string, error) {
	if p.bundle.Probe == nil {
		_ = p.stop()
		return "", errors.New("the bundle has no probe endpoint (one from before v0.11): the relay works without it; " +
			"a new bundle from the exit (rayctl relay bundle) has one")
	}
	if !p.hasRayd() {
		return "", fmt.Errorf("%s is missing (install/bootstrap.sh -relay installs it): the relay works without its probe endpoint",
			deploy.DefaultBinaries.Rayd)
	}
	err := p.enable()
	if err == nil {
		err = p.restart()
	}
	if err == nil {
		err = p.settle()
	}
	if err != nil {
		return "", fmt.Errorf("the relay's probe endpoint did not start (%w): journalctl -u %s says why; the relay works without it",
			err, deploy.RelayProbeUnit)
	}
	return fmt.Sprintf("Its probe endpoint (rayd relay) is on tcp/%d and udp/%d: a provider's firewall in front of this host "+
		"lets both through.", p.bundle.Probe.Port, p.bundle.Probe.Port), nil
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
		return fmt.Errorf("%w: the install took over %v", errGuardOff, guardAfter)
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

// relayLockEnv tells rayctl install -relay that rayctl update, its parent,
// holds the install lock and passes it on as fd 3: the lock stays held
// from the update's first change through the install, so a bootstrap.sh
// -relay cannot slip in between.
const relayLockEnv = "RAYCONTROL_RELAY_LOCK_FD"

// relayMarkFile, in previousDir, says that an update or a rollback of the
// relay did not end well (update_relay.go). A relay installed anew and
// checked by rayctl install -relay outside an update has no such past.
const relayMarkFile = "relay.unfinished"

// relayInstallBegin takes the install lock (relayInstallLockFor); done,
// given the install's outcome, lets it go. A relay installed anew and
// checked outside an update has no past: an update that did not end is
// over (relayMarkFile), and what an earlier update kept of the relay
// would roll it back to a version from before this install (dropRelayCopy),
// and the status of the relay's updates (status, "": none) says so
// (noteRelayInstalled). Under an update, the update keeps and says.
func relayInstallBegin(path, dir, status string) (lock *os.File, done func(error), err error) {
	lock, underUpdate, err := relayInstallLockFor(path)
	if err != nil {
		return nil, nil, err
	}
	return lock, func(err error) {
		if err == nil && !underUpdate {
			m, marked := dropRelayCopy(dir)
			noteRelayInstalled(status, m, marked)
		}
		_ = lock.Close()
	}, nil
}

// noteRelayInstalled: a relay installed anew and checked by root while an
// update of it had not ended (m, its mark, gone now; or the last status
// still says unfinished) is root's own repair, a status of kind local,
// which rayd relay tells the exit as none of its offers. Without it the
// last status would go on saying failed (open) and unfinished, a relay
// that needs root. The release that update went to is held, unless it is
// the one installed: only a newer one moves the relay on.
func noteRelayInstalled(status string, m relayMark, marked bool) {
	if status == "" {
		return
	}
	last := nodeupdate.ReadStatus(status)
	if !marked && (!last.Unfinished || last.State == nodeupdate.Running) {
		return
	}
	if _, err := os.Stat(filepath.Dir(status)); err != nil {
		return
	}
	held := last.Holding()
	if m.To != version {
		held = nodeupdate.Hold(held, m.To)
	}
	now := time.Now().UTC()
	st := nodeupdate.Status{ID: nodeupdate.NewID(), State: nodeupdate.Done, From: cmp.Or(m.From, last.From), To: version, Target: version,
		By: "root (rayctl install -relay)", Kind: nodeupdate.Local, Requested: now, Started: now, Ended: now, Held: held}
	if release.IsRelease(version) {
		st.Release = version
	}
	if err := writeRelayStatus(status, st); err != nil {
		fmt.Println("warning: the status of the relay's updates:", err)
	}
}

// dropRelayCopy removes what an earlier update kept of the relay in dir
// (previousDir), its mark with it, and says what the mark was. Only a
// relay's copy, the one with relay.json: a node's has none (and
// installRelay refuses a node's host); without one, the mark alone goes.
// The copies keep swaps through (dir.new, dir.old) go too when they hold
// relay.json: one left by a crash between keep's renames would come back
// as dir at the next update.
func dropRelayCopy(dir string) (relayMark, bool) {
	m, marked := relayOps{dir: dir}.readMark()
	for _, d := range []string{dir + ".new", dir + ".old"} {
		if _, err := os.Lstat(filepath.Join(d, relayKeptFile)); err == nil {
			_ = os.RemoveAll(d)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, relayKeptFile)); err == nil {
		_ = os.RemoveAll(dir)
		return m, marked
	}
	_ = os.Remove(filepath.Join(dir, relayMarkFile))
	return m, marked
}

// relayInstallLockFor takes the install lock, or the one an update passed
// on (underUpdate): fd 3 must be that very file and hold its lock.
func relayInstallLockFor(path string) (f *os.File, underUpdate bool, err error) {
	if os.Getenv(relayLockEnv) == "3" {
		_ = os.Unsetenv(relayLockEnv)
		if inheritedLock(path, 3) {
			return os.NewFile(3, path), true, nil
		}
	}
	f, err = takeInstallLock(path)
	return f, false, err
}

// inheritedLock tells whether fd is the lock file at path and its lock
// this process's: an open file description shared with the parent that
// took it, on which taking it again succeeds at once. fd is looked at, not
// wrapped, until it is known to be that file.
func inheritedLock(path string, fd int) bool {
	var st, pt syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || syscall.Stat(path, &pt) != nil || st.Dev != pt.Dev || st.Ino != pt.Ino {
		return false
	}
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return false
	}
	// Not passed on further: the install's own commands do not hold it.
	syscall.CloseOnExec(fd)
	return true
}

// takeInstallLock takes the install lock or says another install has it.
func takeInstallLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: a fixed path
	if err != nil {
		return nil, err
	}
	// Root's alone: anyone who could open it could hold it.
	if err := f.Chmod(0o600); err != nil {
		f.Close()
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

// checkForwarding says what keeps net.ipv4.ip_forward off: now (read), or
// at boot (the value sysctl.d gives, from file).
func checkForwarding(read func() ([]byte, error), boot, file string) error {
	v, err := read()
	switch {
	case err != nil:
		return fmt.Errorf("net.ipv4.ip_forward cannot be read: %w", err)
	case strings.TrimSpace(string(v)) != "1":
		return fmt.Errorf("net.ipv4.ip_forward stays off (%s)", strings.TrimSpace(string(v)))
	case boot != "1":
		return fmt.Errorf("net.ipv4.ip_forward would be %q at boot, from %s (systemd-sysctl and udev read it after %s)",
			boot, file, deploy.RelaySysctl)
	}
	return nil
}

// procForward is the kernel's forwarding switch, forwardKey its sysctl name.
const (
	procForward = "/proc/sys/net/ipv4/ip_forward"
	forwardKey  = "net.ipv4.ip_forward"
)

// recordForwarding journals the forwarding value from before raycontrol,
// unless it is there already: the first record holds it.
func recordForwarding(j *deploy.Journal, proc string) error {
	if j.Has(deploy.ChangeSysctl, "", forwardKey) {
		return nil
	}
	v, err := os.ReadFile(proc) //nolint:gosec // G304: /proc
	if err != nil {
		return err
	}
	return j.Record(deploy.Change{Kind: deploy.ChangeSysctl, Name: forwardKey, Value: strings.TrimSpace(string(v))})
}

// unforwardAt removes our sysctl file and writes back the forwarding value
// from before raycontrol, if raycontrol ever set it: a failed install's
// host, a re-install's too, does not forward without its relay's table.
// Writing it resets accept_redirects in the kernel: the hardening goes on
// again (reapply).
func unforwardAt(file, proc string, original func() (string, bool), reapply func()) {
	_ = os.Remove(file)
	if v, ok := original(); ok && v != "" {
		_ = os.WriteFile(proc, []byte(v+"\n"), 0o644) //nolint:gosec // G306: /proc
		reapply()
	}
}

// settleFor waits d, then checks.
func settleFor(ctx context.Context, d time.Duration, check func() error) error {
	select {
	case <-ctx.Done():
		return errInterrupted
	case <-time.After(d):
	}
	return check()
}

// turnForwardingOn writes our sysctl file and applies it, once all of
// sysctl.d is known to keep forwarding on at boot; on a failure the file
// goes (the kernel's value is stop's: it knows the one before raycontrol).
func turnForwardingOn(proc string, write, remove func() error, apply func(), boot func() (string, string)) error {
	if err := write(); err != nil {
		return err
	}
	undo := func() { _ = remove() }
	if v, file := boot(); v != "1" {
		undo()
		return checkForwarding(func() ([]byte, error) { return []byte("1"), nil }, v, file)
	}
	apply()
	if err := checkForwarding(func() ([]byte, error) { return os.ReadFile(proc) }, "1", ""); err != nil { //nolint:gosec // G304: /proc
		undo()
		return err
	}
	return nil
}

// sysctlDirs are where systemd-sysctl reads, first wins for a file name.
var sysctlDirs = []string{"/etc/sysctl.d", "/run/sysctl.d", "/usr/local/lib/sysctl.d", "/usr/lib/sysctl.d", "/lib/sysctl.d"}

// sysctlEntry is one setting of sysctl.d, its key in /proc/sys form.
type sysctlEntry struct{ key, value, file string }

// sysctlEntries reads sysctl.d as systemd-sysctl does: files by name across
// dirs (a name in an earlier dir hides it in later ones), in name order; a
// key set again to another value moves to the end, to the same value keeps
// its place. /etc/sysctl.conf only through a file there (Debian's
// 99-sysctl.conf link).
func sysctlEntries(dirs []string) []sysctlEntry {
	byName := map[string]string{}
	for i := len(dirs) - 1; i >= 0; i-- {
		paths, _ := filepath.Glob(filepath.Join(dirs[i], "*.conf"))
		for _, p := range paths {
			byName[filepath.Base(p)] = p
		}
	}
	var entries []sysctlEntry
	for _, name := range slices.Sorted(maps.Keys(byName)) {
		f := byName[name]
		b, err := os.ReadFile(f) //nolint:gosec // G304: sysctl's own files
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || line[0] == '#' || line[0] == ';' {
				continue
			}
			k, v, ok := strings.Cut(strings.TrimPrefix(line, "-"), "=")
			if !ok {
				continue
			}
			e := sysctlEntry{strings.ReplaceAll(strings.TrimSpace(k), ".", "/"), strings.TrimSpace(v), f}
			if i := slices.IndexFunc(entries, func(o sysctlEntry) bool { return o.key == e.key }); i >= 0 {
				if entries[i].value == e.value {
					continue
				}
				entries = slices.Delete(entries, i, i+1)
			}
			entries = append(entries, e)
		}
	}
	return entries
}

// forwardingAtBoot is IPv4 forwarding as sysctl.d leaves it at boot, and the
// file that decides: net.ipv4.ip_forward and net.ipv4.conf.all.forwarding
// are one variable; a glob applies only to keys not set by name. udev runs
// systemd-sysctl again for each interface that comes, so a glob over
// conf/*/forwarding, the default for new interfaces or one interface's own
// that turn it off turn it off where packets come in, wherever they are.
func forwardingAtBoot(dirs []string) (value, file string) {
	entries := sysctlEntries(dirs)
	glob := func(k string) bool { return strings.ContainsAny(k, "*?[") }
	byName := func(n string) bool {
		return slices.ContainsFunc(entries, func(e sysctlEntry) bool { return e.key == n })
	}
	for _, e := range entries {
		for _, n := range []string{"net/ipv4/ip_forward", "net/ipv4/conf/all/forwarding"} {
			if m, _ := path.Match(e.key, n); m && (!glob(e.key) || !byName(n)) {
				value, file = e.value, e.file
			}
		}
	}
	for _, e := range entries {
		iface, ok := strings.CutPrefix(e.key, "net/ipv4/conf/")
		iface, ok2 := strings.CutSuffix(iface, "/forwarding")
		if ok && ok2 && iface != "all" && iface != "lo" && e.value != "1" {
			return e.value, e.file
		}
	}
	return value, file
}

// showUnit reads rayspa's unit state from systemd.
func showUnit() (map[string]string, error) { return unitState(relayUnit)() }

// waitActive waits for rayspa to run: active, not restarted since base
// restarts, the start result a success. With Restart=always it is never
// "failed": a crash loop shows as restarts. While the start job is queued
// (network-online.target), Result and NRestarts are the last run's.
func waitActive(ctx context.Context, show func() (map[string]string, error), base string, limit, every time.Duration) error {
	return waitUnit(ctx, "rayspa", show, base, limit, every)
}

// waitUnit is waitActive for any unit, named in the errors.
func waitUnit(ctx context.Context, unit string, show func() (map[string]string, error), base string, limit, every time.Duration) error {
	deadline := time.Now().Add(limit)
	for {
		st, _ := show()
		queued := st["Job"] != "" && st["Job"] != "0"
		switch {
		case strings.HasPrefix(st["SubState"], "auto-restart"):
			// Exited, to be started again: before systemd 254 the start
			// job stays queued through it.
			return fmt.Errorf("%s exited (%s, %s): journalctl -u %s says why", unit, st["SubState"], st["Result"], unit)
		case !queued && restartedSince(st, base):
			return fmt.Errorf("%s restarted (%s times): journalctl -u %s says why", unit, st["NRestarts"], unit)
		case !queued && st["Result"] != "" && st["Result"] != "success":
			return fmt.Errorf("%s did not start (%s): journalctl -u %s says why", unit, st["Result"], unit)
		case !queued && st["ActiveState"] == "active" && st["SubState"] == "running":
			return nil
		case time.Now().After(deadline):
			return fmt.Errorf("%s did not start within %v (%s/%s): journalctl -u %s says why", unit, limit, st["ActiveState"], st["SubState"], unit)
		}
		select {
		case <-ctx.Done():
			return errInterrupted
		case <-time.After(every):
		}
	}
}

// unitState reads a unit's state as waitUnit wants it.
func unitState(unit string) func() (map[string]string, error) {
	return func() (map[string]string, error) {
		out, err := commandApart("systemctl", "show", "-p", "ActiveState,SubState,Result,NRestarts,Job,ConditionResult", unit).Output()
		st := map[string]string{}
		for _, line := range strings.Split(string(out), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				st[k] = strings.TrimSpace(v)
			}
		}
		return st, err
	}
}

// restartedSince tells whether rayspa restarted since it had base restarts.
func restartedSince(st map[string]string, base string) bool {
	n, err := strconv.Atoi(st["NRestarts"])
	b, _ := strconv.Atoi(base)
	return err == nil && n > b
}

// stillRunning checks rayspa once more, its snapshot written: running, and
// not restarted since base (Type=simple is "running" from the fork).
func stillRunning(show func() (map[string]string, error), base string) error {
	st, err := show()
	if err != nil {
		return fmt.Errorf("rayspa's state: %w", err)
	}
	if restartedSince(st, base) || st["ActiveState"] != "active" || st["SubState"] != "running" {
		return fmt.Errorf("rayspa stopped after its first snapshot (%s/%s, %s restarts): journalctl -u rayspa says why",
			st["ActiveState"], st["SubState"], st["NRestarts"])
	}
	return nil
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
	forward        func() error                // net.ipv4.ip_forward on
	unforward      func()                      // our sysctl file gone, the value before raycontrol back
	settle         func(context.Context) error // rayspa still running a while after
	enable         func() error                // journaled, enable --now
}

var (
	errInterrupted = errors.New("interrupted")
	errGuardOff    = errors.New("the guard timer took rayspa down")
)

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
		func() error { return r.settle(ctx) },
	} {
		if err := step(f); err != nil {
			return nil, "", err
		}
	}
	// The last step is done: a signal now finds the install complete, not
	// something to take down.
	ok = true
	return snap, warning, nil
}

// stop takes rayspa down after why, and says whether the host is open.
func (r relaySteps) stop(why error, armed bool) error {
	// No forwarding without the relay's table, whatever else happens.
	r.unforward()
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
	if err := r.unguard(); armed && err != nil && !errors.Is(why, errGuardOff) {
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
// warning. again is what the operator runs once the exit lets them in.
func checkRelaySSH(snap *perimeterv1.Snapshot, port int, client, relay, again string) (string, error) {
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
			"refused; on the exit: rayctl relay set -admin %s %s, then %s",
			client, snap.AdminPrefixes, strings.Join(append(slices.Clone(snap.AdminPrefixes), client), ","), relay, again)
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

// readSnapshot reads the perimeter rayspa saved. rayspa owns its
// directory: root reads the file without following a link and does not
// wait on a FIFO there (readRegular).
func readSnapshot(path string) (*perimeterv1.Snapshot, error) {
	raw, err := readRegular(path)
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
