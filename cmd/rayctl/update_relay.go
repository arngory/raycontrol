package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/arngory/raycontrol/internal/deploy"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/release"
)

// A relay's update (spec/node-update-v1.md §5): rayctl update on the relay
// host, as root. The release is chosen, verified and handed to its own
// rayctl as a node's is (stageRelease); what differs is the install, which
// is the relay install's (rayctl install -relay with the stored bundle, by
// the rayctl the update put in place), and the rollback, which puts the
// relay back as it ran before: binaries, unit and sysctl files, rayspa's
// last snapshot, its units' states.

// relayUnitFile is rayspa's unit as the relay install writes it: on a
// relay its ExecStart runs rayspa -relay.
var relayUnitFile = "/etc/systemd/system/" + relayUnit

// hostKind is what rayctl update finds on this host.
type hostKind int

const (
	noHost hostKind = iota
	nodeHost
	relayHost
)

// updateHost says what this host is for rayctl update: a node (its
// database), a relay (its bundle, or rayspa's unit run with -relay: a
// relay whose bundle is gone is still a relay, and is told so), or
// neither.
func updateHost(db, bundle, unit string) (hostKind, error) {
	if _, err := os.Stat(db); err == nil {
		return nodeHost, nil
	}
	if _, err := os.Stat(bundle); err == nil {
		return relayHost, nil
	}
	if b, err := os.ReadFile(unit); err == nil && strings.Contains(string(b), " run -relay ") { //nolint:gosec // G304: a fixed path
		return relayHost, nil
	}
	return noHost, errors.New("raycontrol is not installed here (install/bootstrap.sh)")
}

// errRelayByHand refuses what a relay does not have: updates by request
// and automatic ones need rayd's API for devices, which a relay has not.
var errRelayByHand = errors.New("this host is a relay: remote and automatic updates do not apply to it " +
	"(a relay has no rayd API for devices); rayctl update on this host updates it")

// relayUpdateSince is the first release whose rayctl updates a relay; an
// older one is installed on a relay by its own bootstrap.sh -relay.
const relayUpdateSince = "v0.26.0"

// relayBinaries are a relay's binaries by archive name: rayspa (perimeter,
// SPA, forwarding), rayd (rayspa's unit copies the bundle in with it, and
// rayd relay is the probe endpoint) and rayctl. The release's others are a
// node's.
var relayBinaries = map[string]string{
	"rayspa": deploy.DefaultBinaries.Rayspa,
	"rayd":   deploy.DefaultBinaries.Rayd,
	"rayctl": "/usr/local/bin/rayctl",
}

// relayTarget refuses a release whose rayctl cannot update a relay: going
// back below relayUpdateSince takes that release's bootstrap.sh.
func relayTarget(to string) error {
	if release.IsRelease(to) && release.Newer(relayUpdateSince, to) {
		return fmt.Errorf("%s cannot be installed on a relay by rayctl update (it can from %s): "+
			"RAYCONTROL_VERSION=%s bash bootstrap.sh -relay %s installs it", to, relayUpdateSince, to, deploy.RelayBundle)
	}
	return nil
}

// relayBundleAt reads the relay's stored bundle before anything changes:
// the install that the update runs takes it from there.
func relayBundleAt(path string) (node.RelayBundle, error) {
	b, err := node.ReadRelayBundle(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return b, fmt.Errorf("this host is a relay, but its bundle %s is missing: nothing changed; put the relay's bundle "+
			"there (0600), or a new one from rayctl relay bundle on the exit (it replaces the old one)", path)
	case err != nil:
		return b, fmt.Errorf("the relay's bundle %s: %w: nothing changed; a new one comes from rayctl relay bundle on the exit", path, err)
	}
	return b, nil
}

// relayBefore checks, before anything changes, what the relay install the
// update runs checks after it: sshd on one port, this session on it, and
// the relay's perimeter as it is now letting this session in. The admin
// addresses come from the exit, not from the release: if they do not let
// this session in now, the update's install would fail on them and leave
// the host open, so the update refuses. port is sshd's.
func relayBefore(sshd func() ([]int, error), listening func(int) bool, sess session,
	snapshot func() (*perimeterv1.Snapshot, error), name string) (port int, warning string, err error) {
	ports, err := sshd()
	if err != nil {
		return 0, "", fmt.Errorf("a relay closes all but its SSH port, and sshd's cannot be told (%w): fix sshd first; nothing changed", err)
	}
	if port, err = relaySSHPort(ports, listening, sess.port); err != nil {
		return 0, "", fmt.Errorf("%w; nothing changed", err)
	}
	snap, err := snapshot()
	if err != nil {
		return 0, "", fmt.Errorf("the relay's perimeter cannot be read (%w): nothing changed; is rayspa running (systemctl status rayspa)? "+
			"bash bootstrap.sh -relay %s installs the relay again", err, deploy.RelayBundle)
	}
	warning, err = checkRelaySSH(snap, port, sess.addr, name, "rayctl update again")
	if err != nil {
		return 0, "", fmt.Errorf("%w (nothing changed)", err)
	}
	return port, warning, nil
}

// relayKept is what an update keeps of the relay before it changes it, in
// previousDir beside the binaries: the files of the relay's plan (or that
// one was not there), whether rayspa's last snapshot was kept, and its
// units' states. Written last: its presence says the copy is whole.
type relayKept struct {
	Version  string             `json:"version"`
	Files    map[string]bool    `json:"files"`
	Snapshot bool               `json:"snapshot"`
	Units    map[string]unitWas `json:"units"`
}

// unitWas is a unit's state before the update.
type unitWas struct {
	Enabled bool `json:"enabled"`
	Active  bool `json:"active"`
}

const relayKeptFile = "relay.json"

// relayOps are the relay host's parts an update keeps and puts back, with
// the host's operations given so that a test can follow them.
type relayOps struct {
	dir       string            // previousDir
	bins      map[string]string // relayBinaries
	files     []string          // the relay plan's files
	snapshot  string            // rayspa's last snapshot
	units     []string          // rayspa's unit, then the probe's (Requisite on rayspa)
	state     func(unit string) unitWas
	run       func(name string, args ...string) error
	place     func(src, dst string) error // placeBinary
	disarm    func()                      // the install's guard timer off, if one is left
	unforward func()                      // our forwarding file gone, the value before raycontrol back
	tableGone func() bool
	rayspa    string // its binary, for teardown
}

// savedName is a file's name among the kept ones.
func savedName(path string) string {
	return strings.ReplaceAll(strings.TrimPrefix(path, "/"), "/", "_")
}

// keep puts the relay as it runs aside, version being the one installed;
// the copy of an earlier update goes.
func (o relayOps) keep(version string) (relayKept, error) {
	k := relayKept{Version: version, Files: map[string]bool{}, Units: map[string]unitWas{}}
	if err := os.RemoveAll(o.dir); err != nil {
		return k, err
	}
	if err := os.MkdirAll(filepath.Join(o.dir, "files"), 0o700); err != nil {
		return k, err
	}
	for name, p := range o.bins {
		if b, err := os.ReadFile(p); err == nil { //nolint:gosec // G304: fixed paths
			if err := os.WriteFile(filepath.Join(o.dir, name), b, 0o600); err != nil {
				return k, err
			}
		}
	}
	for _, f := range o.files {
		b, err := os.ReadFile(f) //nolint:gosec // G304: the relay plan's files
		switch {
		case errors.Is(err, os.ErrNotExist):
			k.Files[f] = false
			continue
		case err != nil:
			return k, err
		}
		if err := os.WriteFile(filepath.Join(o.dir, "files", savedName(f)), b, 0o600); err != nil {
			return k, err
		}
		k.Files[f] = true
	}
	// rayspa's directory: read without following a link.
	switch b, err := readRegular(o.snapshot); {
	case err == nil:
		if err := os.WriteFile(filepath.Join(o.dir, "snapshot.pb"), b, 0o600); err != nil {
			return k, err
		}
		k.Snapshot = true
	case !errors.Is(err, os.ErrNotExist):
		return k, fmt.Errorf("rayspa's snapshot: %w", err)
	}
	for _, u := range o.units {
		k.Units[u] = o.state(u)
	}
	if err := os.WriteFile(filepath.Join(o.dir, "VERSION"), []byte(version+"\n"), 0o600); err != nil {
		return k, err
	}
	j, err := json.Marshal(k)
	if err != nil {
		return k, err
	}
	return k, os.WriteFile(filepath.Join(o.dir, relayKeptFile), j, 0o600)
}

// kept reads what the last update kept.
func (o relayOps) kept() (relayKept, error) {
	var k relayKept
	b, err := os.ReadFile(filepath.Join(o.dir, relayKeptFile)) //nolint:gosec // G304: root's directory
	if err != nil {
		return k, errors.New("no copy of the relay from before an update: nothing to roll back to")
	}
	return k, json.Unmarshal(b, &k)
}

// restore puts the kept relay back: binaries, files (one that was not
// there goes), rayspa's snapshot when withSnapshot, and the units enabled
// and started as they were. rayspa starts from the snapshot it had, so the
// relay comes back with the perimeter it had, the exit reachable or not.
func (o relayOps) restore(withSnapshot bool) (relayKept, error) {
	k, err := o.kept()
	if err != nil {
		return k, err
	}
	fmt.Printf("putting the relay back as it ran on %s\n", k.Version)
	o.disarm()
	stop := slices.Clone(o.units)
	slices.Reverse(stop)
	_ = o.run("systemctl", append([]string{"stop"}, stop...)...)
	for _, name := range sortedKeys(o.bins) {
		src := filepath.Join(o.dir, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := o.place(src, o.bins[name]); err != nil {
			return k, err
		}
	}
	var sysctl []string
	for _, f := range sortedKeys(k.Files) {
		if !k.Files[f] {
			if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
				return k, err
			}
			continue
		}
		b, err := os.ReadFile(filepath.Join(o.dir, "files", savedName(f))) //nolint:gosec // G304: root's directory
		if err != nil {
			return k, err
		}
		if err := writeAtomic(f, b, 0o644); err != nil {
			return k, err
		}
		if strings.HasPrefix(f, "/etc/sysctl.d/") {
			sysctl = append(sysctl, f)
		}
	}
	if withSnapshot && k.Snapshot {
		b, err := os.ReadFile(filepath.Join(o.dir, "snapshot.pb")) //nolint:gosec // G304: root's directory
		if err != nil {
			return k, err
		}
		// rayspa's directory, as rayspa's: placeDB neither follows a link
		// there nor gives one away. Gone (a fresh StateDirectory comes with
		// the start), rayspa asks its exit.
		if _, err := os.Lstat(filepath.Dir(o.snapshot)); err == nil {
			if err := placeDB(o.snapshot, b); err != nil {
				return k, fmt.Errorf("rayspa's snapshot: %w", err)
			}
		}
	}
	if err := o.run("systemctl", "daemon-reload"); err != nil {
		return k, err
	}
	// Forwarding first, the hardening after: writing net.ipv4.ip_forward
	// resets accept_redirects (unforwardAt).
	slices.Reverse(sysctl)
	for _, f := range sysctl {
		if err := o.run("sysctl", "-q", "-p", f); err != nil {
			return k, err
		}
	}
	for _, u := range o.units {
		w := k.Units[u]
		switch {
		case w.Enabled:
			if err := o.run("systemctl", "enable", u); err != nil {
				return k, err
			}
		default:
			_ = o.run("systemctl", "disable", u) // perhaps no such unit
		}
	}
	for _, u := range o.units {
		if k.Units[u].Active {
			if err := o.run("systemctl", "start", u); err != nil {
				return k, err
			}
		}
	}
	return k, nil
}

// open takes rayspa down and its table off: the relay forwards nothing,
// and its host is open. The last way to keep the admin in, when the relay
// does not come back at all.
func (o relayOps) open() error {
	stop := slices.Clone(o.units)
	slices.Reverse(stop)
	disable := o.run("systemctl", append([]string{"disable", "--now"}, stop...)...)
	tear := o.run(o.rayspa, "teardown")
	o.unforward()
	if !o.tableGone() {
		return fmt.Errorf("its table is still there%s", paren(disable, tear))
	}
	return nil
}

// sortedKeys are a map's keys in order.
func sortedKeys[V any](m map[string]V) []string { return slices.Sorted(maps.Keys(m)) }

// writeAtomic writes a root file: a new file beside it, renamed over it.
func writeAtomic(path string, b []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(mode)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// relayHealth is the check of a relay after its update or its rollback:
// rayspa runs and holds its table, the kernel forwards, the perimeter
// lets SSH in from the admin addresses (this session among them, when it
// is known), rayspa is the version wanted, and the probe endpoint runs if
// it ran before.
type relayHealth struct {
	rayspa, probe func() (map[string]string, error)
	probeRan      bool
	tableGone     func() bool
	forwarding    func() ([]byte, error)
	snapshot      func() (*perimeterv1.Snapshot, error)
	version       func() string // rayspa version
	want          string        // a release, or anything (not a release)
	port          int
	client, name  string
}

func running(st map[string]string) bool {
	return st["ActiveState"] == "active" && st["SubState"] == "running"
}

func (h relayHealth) check() error {
	if st, err := h.rayspa(); err != nil || !running(st) {
		return fmt.Errorf("rayspa is %s/%s: journalctl -u rayspa says why", st["ActiveState"], st["SubState"])
	}
	if h.tableGone() {
		return errors.New("rayspa holds no perimeter table: journalctl -u rayspa says why")
	}
	if v, err := h.forwarding(); err != nil || strings.TrimSpace(string(v)) != "1" {
		return fmt.Errorf("the relay does not forward (net.ipv4.ip_forward %q)", strings.TrimSpace(string(v)))
	}
	snap, err := h.snapshot()
	if err != nil {
		return fmt.Errorf("rayspa's perimeter cannot be read: %w", err)
	}
	if _, err := checkRelaySSH(snap, h.port, h.client, h.name, "rayctl update again"); err != nil {
		return err
	}
	if release.IsRelease(h.want) {
		if v := h.version(); v != h.want {
			return fmt.Errorf("rayspa reports %q, not %s", v, h.want)
		}
	}
	if h.probeRan {
		if st, err := h.probe(); err != nil || !running(st) {
			return fmt.Errorf("rayd relay (the probe endpoint) ran before and is %s/%s now: journalctl -u %s says why",
				st["ActiveState"], st["SubState"], deploy.RelayProbeUnit)
		}
	}
	return nil
}

// waitHealthy waits until check passes, within limit, and checks again a
// moment later (settle, past rayspa's RestartSec): a rayspa that dies once
// started fails it.
func waitHealthy(ctx context.Context, check func() error, limit, settle, every time.Duration) error {
	deadline := time.Now().Add(limit)
	for {
		err := check()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return errInterrupted
		case <-time.After(every):
		}
	}
	return settleFor(ctx, settle, check)
}

// relayUpdate is a relay's update once the release is staged, its steps
// given so that a test can follow them.
type relayUpdate struct {
	keep      func() error // the relay as it runs, aside
	place     func() error // the release's binaries in place
	install   func() error // rayctl install -relay with the stored bundle, by the rayctl now in place
	check     func() error // relayHealth, of the new version
	restore   func() error // the kept relay back
	checkBack func() error // relayHealth, of the previous version
	open      func() error // rayspa down, table off
}

// run updates the relay. Nothing changes before the copy is whole. Once
// anything changed, a failure brings the relay back as it ran; only if it
// does not come back is the host left open (rayspa stopped and disabled,
// its table off, no forwarding), so that its admin is never shut out.
func (u relayUpdate) run() error {
	if err := u.keep(); err != nil {
		return fmt.Errorf("keeping the relay as it runs: %w (nothing changed)", err)
	}
	var err error
	if err = u.place(); err != nil {
		err = fmt.Errorf("installing: %w", err)
	} else if err = u.install(); err != nil {
		err = fmt.Errorf("the relay install: %w", err)
	} else if err = u.check(); err != nil {
		err = fmt.Errorf("after the install: %w", err)
	}
	if err == nil {
		return nil
	}
	fmt.Println("update failed:", err)
	return backOrOpen(err, u.restore, u.checkBack, u.open)
}

// backOrOpen brings the previous relay back after cause; if it does not
// come back, it opens the host and says so.
func backOrOpen(cause error, restore, checkBack, open func() error) error {
	berr := restore()
	if berr == nil {
		berr = checkBack()
	}
	if berr == nil {
		return rolledBack{cause}
	}
	if oerr := open(); oerr != nil {
		return fmt.Errorf("%w; the previous relay did not come back either (%v), and rayspa could NOT be taken down (%v): "+
			"run systemctl disable --now %s && %s teardown before you leave this session",
			cause, berr, oerr, relayUnit, deploy.DefaultBinaries.Rayspa)
	}
	return fmt.Errorf("%w; the previous relay did not come back either (%v): rayspa is stopped and disabled, the host "+
		"left open and not forwarding; bash bootstrap.sh -relay %s installs the relay again", cause, berr, deploy.RelayBundle)
}

// realRelayOps are relayOps on this host.
func realRelayOps() relayOps {
	var files []string
	for _, f := range deploy.RelayPlan(deploy.DefaultBinaries).Files {
		files = append(files, f.Path)
	}
	return relayOps{
		dir: previousDir, bins: relayBinaries, files: files, snapshot: relaySnapshot,
		units: []string{relayUnit, deploy.RelayProbeUnit},
		state: func(u string) unitWas {
			en, _ := commandApart("systemctl", "is-enabled", u).Output()
			st, _ := unitState(u)()
			return unitWas{Enabled: strings.TrimSpace(string(en)) == "enabled", Active: running(st)}
		},
		run:   runApart,
		place: placeBinary,
		disarm: func() {
			if l, err := os.OpenFile(guardLock, os.O_RDWR|os.O_CREATE, 0o600); err == nil { //nolint:gosec // G304: a fixed path
				// Under the guard's lock: it has gone off, or it never will.
				_ = syscall.Flock(int(l.Fd()), syscall.LOCK_EX)
				_ = os.Remove(guardArmed)
				_ = l.Close()
			}
			_ = runApart("systemctl", "stop", relayGuard+".timer")
		},
		unforward: func() {
			h, err := journaledHost()
			if err != nil {
				_ = os.Remove(deploy.RelaySysctl)
				return
			}
			unforwardAt(deploy.RelaySysctl, procForward,
				func() (string, bool) {
					c, ok := h.Journal.Original(deploy.ChangeSysctl, "", forwardKey)
					return c.Value, ok
				},
				func() { _ = runApart("sysctl", "-q", "-p", deploy.HardeningSysctl) })
		},
		tableGone: tableGone,
		rayspa:    deploy.DefaultBinaries.Rayspa,
	}
}

// realHealth is relayHealth on this host.
func realHealth(want string, probeRan bool, port int, client, name string) relayHealth {
	return relayHealth{
		rayspa: showUnit, probe: unitState(deploy.RelayProbeUnit), probeRan: probeRan,
		tableGone:  tableGone,
		forwarding: func() ([]byte, error) { return os.ReadFile(procForward) },
		snapshot:   func() (*perimeterv1.Snapshot, error) { return readSnapshot(relaySnapshot) },
		version: func() string {
			out, _ := exec.Command(deploy.DefaultBinaries.Rayspa, "version").Output() //nolint:gosec // G204: a fixed path
			return strings.TrimSpace(string(out))
		},
		want: want, port: port, client: client, name: name,
	}
}

// updateRelay is rayctl update on a relay host.
func (c *cli) updateRelay(ctx context.Context, o updateOpts, rollback bool, installed string) error {
	o.host = "relay"
	b, err := relayBundleAt(deploy.RelayBundle)
	if err != nil {
		return err
	}
	if !o.check {
		what := "update"
		if rollback {
			what = "rollback"
		}
		if err := takeUpdateLock(what, 0); err != nil {
			return err
		}
	}
	sess := sshSession()
	port, warning, err := relayBefore(sshdPorts, listening, sess, func() (*perimeterv1.Snapshot, error) { return readSnapshot(relaySnapshot) }, b.Name)
	switch {
	case err != nil && o.check:
		fmt.Println("warning: the update would refuse:", err)
	case err != nil:
		return err
	case warning != "":
		fmt.Fprintln(os.Stderr, "warning:", warning)
	}
	ops := realRelayOps()
	// The checks after a change have their own time, whatever the download
	// took.
	hctx := context.WithoutCancel(ctx)
	health := func(want string, probeRan bool) func() error {
		h := realHealth(want, probeRan, port, sess.addr, b.Name)
		return func() error { return waitHealthy(hctx, h.check, 30*time.Second, 3*time.Second, time.Second) }
	}
	if rollback {
		return rollbackRelay(o.yes, ops, health)
	}
	if os.Getenv(handoffEnv) == "1" {
		fmt.Printf("rayctl %s updates the relay, handed over by the rayctl of %s\n", version, installed)
	}
	stage, err := newStage()
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stage) }()
	s, err := c.stageRelease(ctx, o, stage, installed, relayBinaries, relayTarget)
	if o.check && !s.handed {
		fmt.Println("this host is a relay " + b.Name + ": rayctl update here updates it; remote and automatic updates do not apply to a relay")
	}
	if err != nil || s.done {
		return err
	}
	if !o.yes {
		fmt.Printf("Update relay %s from %s to %s? rayspa restarts: forwarding stops for up to a minute, clients reconnect. Type yes to go on: ",
			b.Name, installed, s.version)
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(answer) != "yes" {
			return errors.New("not confirmed")
		}
	}
	// From here the update goes to its end: Ctrl-C or a closed SSH
	// connection reach the install (its process group is the terminal's),
	// which stops as on any failure, and this rayctl takes the relay back.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(sigs)

	var k relayKept
	u := relayUpdate{
		keep: func() (err error) { k, err = ops.keep(installed); return err },
		place: func() error {
			// Not under a relay install running (bootstrap.sh -relay):
			// the lock is the install's again once the binaries are in.
			l, err := takeInstallLock(relayInstallLock)
			if err != nil {
				return err
			}
			defer l.Close()
			for _, name := range sortedKeys(relayBinaries) {
				src := filepath.Join(stage, name)
				if _, err := os.Stat(src); err != nil {
					continue
				}
				if err := placeBinary(src, relayBinaries[name]); err != nil {
					return err
				}
			}
			return nil
		},
		install: func() error {
			cmd := exec.Command("/usr/local/bin/rayctl", "install", "-relay", deploy.RelayBundle) //nolint:gosec // G204: the rayctl the update put in place
			cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
			cmd.Env = applyEnv("")
			return cmd.Run()
		},
		check:     func() error { return health(s.version, k.Units[deploy.RelayProbeUnit].Active)() },
		restore:   func() error { _, err := ops.restore(true); return err },
		checkBack: func() error { return relayBack(k, health) },
		open:      ops.open,
	}
	if err := u.run(); err != nil {
		return err
	}
	fmt.Printf("relay %s runs raycontrol %s; the previous binaries are kept for rayctl update -rollback\n", b.Name, s.version)
	return nil
}

// relayBack checks the relay put back as kept: as relayHealth if rayspa
// ran before, else nothing (it was not running, and is not).
func relayBack(k relayKept, health func(string, bool) func() error) error {
	if !k.Units[relayUnit].Active {
		return nil
	}
	return health(k.Version, k.Units[deploy.RelayProbeUnit].Active)()
}

// rollbackRelay is rayctl update -rollback on a relay: the binaries and
// files the last update replaced come back; rayspa's snapshot stays the
// one it has now (the exit's latest perimeter, which let this session in).
func rollbackRelay(yes bool, ops relayOps, health func(string, bool) func() error) error {
	k, err := ops.kept()
	if err != nil {
		return err
	}
	if !yes {
		fmt.Printf("Roll the relay back to %s? rayspa restarts: forwarding stops for a moment. Type yes to go on: ", k.Version)
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(answer) != "yes" {
			return errors.New("not confirmed")
		}
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(sigs)
	err = backOrOpen(errors.New("asked for"), func() error { _, err := ops.restore(false); return err },
		func() error { return relayBack(k, health) }, ops.open)
	var rb rolledBack
	if errors.As(err, &rb) {
		fmt.Printf("the relay runs %s again\n", k.Version)
		return nil
	}
	return err
}

// relayPolicy is rayctl update status|remote|auto on a relay: no policy,
// since a relay has no rayd API for devices; status says what is
// installed and what the last update kept.
func (c *cli) relayPolicy(args []string, dir string) error {
	switch {
	case args[0] == "status" && len(args) == 1:
	case args[0] == "status":
		return errUsage
	case args[0] == "remote" || args[0] == "auto":
		return errRelayByHand
	default:
		return errUsage
	}
	out, _ := exec.Command(deploy.DefaultBinaries.Rayspa, "version").Output() //nolint:gosec // G204: a fixed path
	rayspa := strings.TrimSpace(string(out))
	var previous string
	if b, err := os.ReadFile(filepath.Join(dir, relayKeptFile)); err == nil { //nolint:gosec // G304: root's directory
		var k relayKept
		if json.Unmarshal(b, &k) == nil {
			previous = k.Version
		}
	}
	if c.json {
		j, err := json.MarshalIndent(map[string]any{"host": "relay", "installed": version, "rayspa": rayspa, "previous": previous,
			"remote": "n/a", "auto": "n/a"}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(j))
		return nil
	}
	fmt.Printf("host       relay\ninstalled  %s (rayctl)\n", version)
	if rayspa != "" && rayspa != version {
		fmt.Printf("rayspa     %s\n", rayspa)
	}
	if previous != "" {
		fmt.Printf("previous   %s (rayctl update -rollback)\n", previous)
	}
	fmt.Println("latest     rayctl update -check asks GitHub")
	fmt.Println("remote     does not apply to a relay (no rayd API for devices)")
	fmt.Println("auto       does not apply to a relay: rayctl update on this host")
	return nil
}
