package main

import (
	"bufio"
	"bytes"
	"cmp"
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
	"github.com/arngory/raycontrol/internal/perimeter"
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
// previousDir beside the binaries: the files the relay install writes (or
// that one was not there), whether rayspa's last snapshot was kept, and
// its units' states. Written last: its presence says the copy is whole.
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

// relayMark is relayMarkFile: an update from From to To that has changed
// the relay and not ended checked ("updating"), or a relay that an update
// or a rollback left open ("open"). rayctl update refuses while it is
// there and says how to recover (advice).
type relayMark struct {
	State string `json:"state"`
	From  string `json:"from,omitempty"`
	To    string `json:"to,omitempty"`
}

func (m relayMark) advice() string {
	if m.State == "open" {
		return fmt.Sprintf("the last update or rollback of this relay left it open and not forwarding: rayctl update -rollback "+
			"tries %s again, or bash bootstrap.sh -relay %s installs the relay anew", cmp.Or(m.From, "the kept version"), deploy.RelayBundle)
	}
	return fmt.Sprintf("an update of this relay from %s to %s was interrupted: rayctl update -rollback puts %s back",
		m.From, m.To, m.From)
}

// relayFiles are the files a relay install writes: its plan's (units,
// sysctl), and those it writes once the relay is up (deploy.Host's
// Conntrack and ReservePorts). The install's journal is not among them:
// it only grows, and rayctl uninstall takes back what it records.
func relayFiles() []string {
	var files []string
	for _, f := range deploy.RelayPlan(deploy.DefaultBinaries).Files {
		files = append(files, f.Path)
	}
	return append(files, deploy.ConntrackSysctl, deploy.ModulesLoad, deploy.PortsSysctl)
}

// relayOps are the relay host's parts an update keeps and puts back, with
// the host's operations given so that a test can follow them.
type relayOps struct {
	dir       string            // previousDir
	bins      map[string]string // relayBinaries
	files     []string          // relayFiles
	sysctlDir string            // where of them are sysctl's, applied again after a restore
	snapshot  string            // rayspa's last snapshot
	units     []string          // rayspa's unit, then the probe's (Requisite on rayspa)
	state     func(unit string) unitWas
	loaded    func(unit string) bool
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
		b, err := os.ReadFile(f) //nolint:gosec // G304: the relay's files
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

// mark writes relayMarkFile; unmark removes it; readMark reads it.
func (o relayOps) mark(m relayMark) error {
	j, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(o.dir, relayMarkFile), j, 0o600)
}

func (o relayOps) unmark() { _ = os.Remove(filepath.Join(o.dir, relayMarkFile)) }

func (o relayOps) readMark() (relayMark, bool) {
	var m relayMark
	b, err := os.ReadFile(filepath.Join(o.dir, relayMarkFile)) //nolint:gosec // G304: root's directory
	if err != nil {
		return m, false
	}
	if json.Unmarshal(b, &m) != nil || m.State == "" {
		m.State = "updating" // there, whatever it says
	}
	return m, true
}

// restore puts the kept relay back: binaries (one already as kept stays),
// files (one that was not there goes), rayspa's snapshot when
// withSnapshot, and the units enabled and started as they were. rayspa
// starts from the snapshot it had, so the relay comes back with the
// perimeter it had, the exit reachable or not.
func (o relayOps) restore(withSnapshot bool) (relayKept, error) {
	k, err := o.kept()
	if err != nil {
		return k, err
	}
	fmt.Printf("putting the relay back as it ran on %s\n", k.Version)
	o.disarm()
	// Stopped for sure: a rayspa that runs on would keep the new binary
	// and its table, and the check after would look at it.
	stop := slices.Clone(o.units)
	slices.Reverse(stop)
	for _, u := range stop {
		if !o.loaded(u) {
			continue
		}
		if err := o.run("systemctl", "stop", u); err != nil {
			return k, fmt.Errorf("stopping %s: %w", u, err)
		}
	}
	for _, name := range sortedKeys(o.bins) {
		src := filepath.Join(o.dir, name)
		b, err := os.ReadFile(src) //nolint:gosec // G304: root's directory
		if err != nil {
			continue
		}
		if now, err := os.ReadFile(o.bins[name]); err == nil && bytes.Equal(now, b) {
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
		if strings.HasPrefix(f, o.sysctlDir) {
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
	// Forwarding first (91-), the hardening after (90-raycontrol.conf):
	// writing net.ipv4.ip_forward resets accept_redirects (unforwardAt).
	// As the install loads them (deploy.Host.ApplySysctl): -e, so that keys
	// this host does not have (net.ipv6.* with IPv6 off, a kernel without
	// bbr) are skipped, and a failure is only a warning. What the relay
	// needs of them, forwarding, the check after reads in /proc.
	slices.Reverse(sysctl)
	for _, f := range sysctl {
		if err := o.run("sysctl", "-q", "-e", "-p", f); err != nil {
			fmt.Println("warning:", err)
		}
	}
	for _, u := range o.units {
		if k.Units[u].Enabled {
			if err := o.run("systemctl", "enable", u); err != nil {
				return k, err
			}
		} else {
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
// does not come back at all. The mark says so to the next rayctl update.
func (o relayOps) open() error {
	m, _ := o.readMark()
	m.State = "open"
	_ = o.mark(m)
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

// placeRelayBinaries puts the staged relay binaries in place; renamed
// says whether any was, so that a failure before the first changes
// nothing to undo.
func placeRelayBinaries(stage string, bins map[string]string, place func(src, dst string) error) (renamed bool, err error) {
	for _, name := range sortedKeys(bins) {
		src := filepath.Join(stage, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := place(src, bins[name]); err != nil {
			return renamed, err
		}
		renamed = true
	}
	return renamed, nil
}

// relayInstallCommand is rayctl install -relay with the stored bundle, by
// the rayctl the update put in place: the update's own variables stay
// with the update, and the install lock it holds goes on as fd 3.
func relayInstallCommand(rayctl, bundle string, lock *os.File) *exec.Cmd {
	cmd := exec.Command(rayctl, "install", "-relay", bundle) //nolint:gosec // G204: the rayctl the update put in place
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = applyEnv("")
	if lock != nil {
		cmd.ExtraFiles = []*os.File{lock}
		cmd.Env = append(cmd.Env, relayLockEnv+"=3")
	}
	return cmd
}

// relayHealth is the check of a relay after its update or its rollback:
//   - rayspa runs, and the rayspa that runs is the binary on disk (started
//     again since it was placed: a process left running from before is not
//     the version checked);
//   - its table has applied the perimeter rayspa runs from (its snapshot,
//     the exit's latest or the one a rollback put back, not the one from
//     before the change: the exit's admin may have changed it since):
//     admin addresses, and, when that snapshot has services the relay
//     forwards (perimeter.Forwarded), the forwarding to the exit
//     (relay_dnat's DNAT, relay_fwd's ports);
//   - the kernel forwards;
//   - the perimeter lets SSH in from the admin addresses (this session
//     among them, when it is known);
//   - rayspa is the version wanted, and the probe endpoint runs if it ran
//     before.
type relayHealth struct {
	rayspa, probe func() (map[string]string, error)
	probeRan      bool
	exe           func() error                         // the running rayspa is the binary on disk
	nft           func(args ...string) (string, error) // nft's output
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

// nftBlock is the lines of one set or chain ("set admin4") of an nft
// listing, trimmed; nil if it is not there.
func nftBlock(listing, head string) []string {
	var block []string
	in := false
	for _, l := range strings.Split(listing, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case !in && l == head+" {":
			in, block = true, []string{}
		case in && l == "}":
			return block
		case in:
			block = append(block, l)
		}
	}
	return block
}

// hasElements tells whether a set of a listing has elements.
func hasElements(listing, set string) bool {
	return slices.ContainsFunc(nftBlock(listing, "set "+set), func(l string) bool { return strings.HasPrefix(l, "elements = ") })
}

func (h relayHealth) check() error {
	if st, err := h.rayspa(); err != nil || !running(st) {
		return fmt.Errorf("rayspa is %s/%s: journalctl -u rayspa says why", st["ActiveState"], st["SubState"])
	}
	if err := h.exe(); err != nil {
		return err
	}
	snap, err := h.snapshot()
	if err != nil {
		return fmt.Errorf("rayspa's perimeter cannot be read: %w", err)
	}
	table, err := h.nft("list", "table", "inet", perimeter.Table)
	if err != nil {
		return fmt.Errorf("rayspa holds no perimeter table (%v): journalctl -u rayspa says why", strings.TrimSpace(err.Error()))
	}
	if !hasElements(table, "admin4") && !hasElements(table, "admin6") {
		return errors.New("rayspa's table lets no admin address in: it has applied no perimeter (journalctl -u rayspa)")
	}
	// relay_fwd's elements are there from the snapshot on, not from a
	// client's knock; none to forward, none there (relay_dnat's rule is).
	if len(perimeter.Forwarded(snap.Services)) > 0 {
		dnat := slices.ContainsFunc(nftBlock(table, "chain relay_dnat"), func(l string) bool { return strings.Contains(l, " dnat ") })
		if !dnat || !hasElements(table, "relay_fwd") {
			return errors.New("rayspa's table forwards no service to the exit (relay_dnat, relay_fwd), its perimeter has some: " +
				"journalctl -u rayspa says why")
		}
	}
	if v, err := h.forwarding(); err != nil || strings.TrimSpace(string(v)) != "1" {
		return fmt.Errorf("the relay does not forward (net.ipv4.ip_forward %q)", strings.TrimSpace(string(v)))
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

// runningBinary checks that the unit's main process runs bin as it is on
// disk now (/proc/PID/exe is the file it was started from, renamed over
// or not). mainPID is systemd's MainPID of the unit.
func runningBinary(unit, bin string, mainPID func(unit string) string) func() error {
	return func() error {
		pid := mainPID(unit)
		if pid == "" || pid == "0" {
			return fmt.Errorf("%s has no main process", unit)
		}
		run, rerr := os.Stat("/proc/" + pid + "/exe")
		disk, derr := os.Stat(bin)
		if rerr != nil || derr != nil {
			return fmt.Errorf("which binary %s runs cannot be told: %w", unit, errors.Join(rerr, derr))
		}
		if !os.SameFile(run, disk) {
			return fmt.Errorf("the %s that runs (pid %s) is not %s as it is now: it was not started again", unit, pid, bin)
		}
		return nil
	}
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
	keep      func() error         // the relay as it runs, aside
	mark      func() error         // relayMarkFile: changes begin
	place     func() (bool, error) // the release's binaries in place; whether any was
	install   func() error         // rayctl install -relay with the stored bundle, by the rayctl now in place
	check     func() error         // relayHealth, of the new version
	restore   func() error         // the kept relay back
	checkBack func() error         // relayHealth, of the previous version
	open      func() error         // rayspa down, table off
	unmark    func()               // the relay is checked: the mark goes
}

// run updates the relay. Nothing changes before the copy is whole and the
// mark is written; a failure to place the first binary changes nothing
// either. Once anything changed, a failure brings the relay back as it
// ran; only if it does not come back is the host left open (rayspa
// stopped and disabled, its table off, no forwarding), so that its admin
// is never shut out. The mark goes once the relay is checked, updated or
// back.
func (u relayUpdate) run() error {
	if err := u.keep(); err != nil {
		return fmt.Errorf("keeping the relay as it runs: %w (nothing changed)", err)
	}
	if err := u.mark(); err != nil {
		return fmt.Errorf("marking the update as begun: %w (nothing changed)", err)
	}
	renamed, err := u.place()
	if err != nil && !renamed {
		u.unmark()
		return fmt.Errorf("installing: %w (nothing changed: the relay runs as it did)", err)
	}
	if err != nil {
		err = fmt.Errorf("installing: %w", err)
	} else if err = u.install(); err != nil {
		err = fmt.Errorf("the relay install: %w", err)
	} else if err = u.check(); err != nil {
		err = fmt.Errorf("after the install: %w", err)
	}
	if err == nil {
		u.unmark()
		return nil
	}
	fmt.Println("update failed:", err)
	err = backOrOpen(err, u.restore, u.checkBack, u.open)
	if rb := (rolledBack{}); errors.As(err, &rb) {
		u.unmark()
	}
	return err
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

// healthWant is what a check after a change expects: the version, the
// probe endpoint if it ran, sshd's port, this session's address, the
// relay's name.
type healthWant struct {
	want         string
	probeRan     bool
	port         int
	client, name string
}

// relayEnv is rayctl update on a relay with its host given: its paths and
// commands, so that a test runs the whole of it on directories of its
// own.
type relayEnv struct {
	bundle      string
	ops         relayOps
	session     session
	before      func(name string) (port int, warning string, err error) // relayBefore
	sshPort     func() int                                              // sshd's one port, 0 if it cannot be told
	hostOpen    func() bool                                             // rayspa not running, or its table gone
	lock        func(what string) error                                 // the update lock
	installLock func() (*os.File, error)                                // the relay install's
	newStage    func() (string, error)
	stage       func(ctx context.Context, o updateOpts, stage, installed string) (staged, error)
	place       func(stage string) (bool, error)
	install     func(lock *os.File) error
	health      func(healthWant) func() error
	confirm     func(prompt string) bool
	signals     func() (stop func()) // from the point of no return
}

// updateRelay is rayctl update on this relay host.
func (c *cli) updateRelay(ctx context.Context, o updateOpts, rollback bool, installed string) error {
	return c.relayEnvHere(ctx).update(ctx, o, rollback, installed)
}

func (e relayEnv) update(ctx context.Context, o updateOpts, rollback bool, installed string) error {
	o.host = "relay"
	b, err := relayBundleAt(e.bundle)
	if err != nil {
		return err
	}
	if rollback {
		return e.rollback(o.yes, b.Name)
	}
	if !o.check {
		if err := e.lock("update"); err != nil {
			return err
		}
	}
	// An update that did not end: one way back, said before anything
	// else, never "installed, the newest release".
	if m, marked := e.ops.readMark(); marked {
		if !o.check {
			return errors.New(m.advice())
		}
		fmt.Println("warning:", m.advice())
	}
	port, warning, err := e.before(b.Name)
	switch {
	case err != nil && o.check:
		fmt.Println("warning: the update would refuse:", err)
	case err != nil:
		return err
	case warning != "":
		fmt.Fprintln(os.Stderr, "warning:", warning)
	}
	if os.Getenv(handoffEnv) == "1" {
		fmt.Printf("rayctl %s updates the relay, handed over by the rayctl of %s\n", version, installed)
	}
	st, err := e.newStage()
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(st) }()
	s, err := e.stage(ctx, o, st, installed)
	if o.check && !s.handed {
		fmt.Println("this host is a relay " + b.Name + ": rayctl update here updates it; remote and automatic updates do not apply to a relay")
	}
	if err != nil || s.done {
		return err
	}
	// Here, not before the handoff: the release's rayctl takes it. Held
	// from the first change through the install, which takes it on.
	il, err := e.installLock()
	if err != nil {
		return fmt.Errorf("%w (nothing changed)", err)
	}
	defer il.Close()
	if !o.yes && !e.confirm(fmt.Sprintf("Update relay %s from %s to %s? rayspa restarts: forwarding stops, usually for under a minute, "+
		"at most about 5 minutes (the exit's first snapshot, then a rollback if it fails); clients reconnect. Type yes to go on: ",
		b.Name, installed, s.version)) {
		return errors.New("not confirmed")
	}
	// From here the update goes to its end: Ctrl-C, a closed SSH
	// connection or SIGTERM reach the install (its process group is the
	// terminal's), which stops as on any failure, and this rayctl takes the
	// relay back; a reader of its output gone does not stop it either.
	defer e.signals()()

	var k relayKept
	u := relayUpdate{
		keep:    func() (err error) { k, err = e.ops.keep(installed); return err },
		mark:    func() error { return e.ops.mark(relayMark{State: "updating", From: installed, To: s.version}) },
		place:   func() (bool, error) { return e.place(st) },
		install: func() error { return e.install(il) },
		check: func() error {
			return e.health(healthWant{want: s.version, probeRan: k.Units[deploy.RelayProbeUnit].Active, port: port, client: e.session.addr, name: b.Name})()
		},
		restore:   func() error { _, err := e.ops.restore(true); return err },
		checkBack: func() error { return relayBack(k, e.health, port, e.session.addr, b.Name) },
		open:      e.ops.open,
		unmark:    e.ops.unmark,
	}
	if err := u.run(); err != nil {
		return err
	}
	fmt.Printf("relay %s runs raycontrol %s; the previous binaries are kept for rayctl update -rollback\n", b.Name, s.version)
	return nil
}

// relayBack checks the relay put back as kept: as relayHealth if rayspa
// ran before, else nothing (it was not running, and is not).
func relayBack(k relayKept, health func(healthWant) func() error, port int, client, name string) error {
	if !k.Units[relayUnit].Active {
		return nil
	}
	return health(healthWant{want: k.Version, probeRan: k.Units[deploy.RelayProbeUnit].Active, port: port, client: client, name: name})()
}

// rollback is rayctl update -rollback on a relay: the kept relay back.
// rayspa's snapshot comes back too after an update that did not end, or
// when the host is open (the install removes it); else it stays the one
// rayspa has now (the exit's latest perimeter, which let this session
// in). A host that is open is not checked against its perimeter first:
// there is none, and nothing to lose by restoring one.
func (e relayEnv) rollback(yes bool, name string) error {
	if err := e.lock("rollback"); err != nil {
		return err
	}
	il, err := e.installLock()
	if err != nil {
		return fmt.Errorf("%w: once it has ended, rayctl update -rollback (nothing changed)", err)
	}
	defer il.Close()
	k, err := e.ops.kept()
	if err != nil {
		return err
	}
	_, marked := e.ops.readMark()
	open := e.hostOpen()
	var port int
	if open {
		port = e.sshPort()
		fmt.Println("the relay is open now (rayspa is not running or holds no table): this session is not checked against a perimeter first")
	} else {
		p, warning, err := e.before(name)
		if err != nil {
			return err
		}
		if warning != "" {
			fmt.Fprintln(os.Stderr, "warning:", warning)
		}
		port = p
	}
	if !yes && !e.confirm(fmt.Sprintf("Roll the relay back to %s? rayspa restarts: forwarding stops for a moment. Type yes to go on: ", k.Version)) {
		return errors.New("not confirmed")
	}
	defer e.signals()()
	err = backOrOpen(errors.New("asked for"), func() error { _, err := e.ops.restore(marked || open); return err },
		func() error { return relayBack(k, e.health, port, e.session.addr, name) }, e.ops.open)
	if rb := (rolledBack{}); errors.As(err, &rb) {
		e.ops.unmark()
		fmt.Printf("the relay runs %s again\n", k.Version)
		return nil
	}
	return err
}

// catchSignals takes, until stop, what would end rayctl halfway: Ctrl-C,
// Ctrl-\, SIGHUP, SIGTERM, and SIGPIPE (a write to a reader gone, such as
// tee after the SSH connection dropped, fails instead). Caught, not
// ignored: the install it starts gets them as usual.
func catchSignals() (stop func()) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGQUIT, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGPIPE)
	return func() { signal.Stop(sigs) }
}

// askYes asks prompt on the terminal; yes is the only yes.
func askYes(prompt string) bool {
	fmt.Print(prompt)
	answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(answer) == "yes"
}

// relayEnvHere is relayEnv on this host.
func (c *cli) relayEnvHere(ctx context.Context) relayEnv {
	sess := sshSession()
	hctx := context.WithoutCancel(ctx) // the checks after a change have their own time
	ops := relayOps{
		dir: previousDir, bins: relayBinaries, files: relayFiles(), sysctlDir: "/etc/sysctl.d/", snapshot: relaySnapshot,
		units: []string{relayUnit, deploy.RelayProbeUnit},
		state: func(u string) unitWas {
			en, _ := commandApart("systemctl", "is-enabled", u).Output()
			st, _ := unitState(u)()
			return unitWas{Enabled: strings.TrimSpace(string(en)) == "enabled", Active: running(st)}
		},
		loaded: unitLoaded,
		run:    runApart,
		place:  placeBinary,
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
				func() { _ = runApart("sysctl", "-q", "-e", "-p", deploy.HardeningSysctl) })
		},
		tableGone: tableGone,
		rayspa:    deploy.DefaultBinaries.Rayspa,
	}
	return relayEnv{
		bundle: deploy.RelayBundle, ops: ops, session: sess,
		before: func(name string) (int, string, error) {
			return relayBefore(sshdPorts, listening, sess, func() (*perimeterv1.Snapshot, error) { return readSnapshot(relaySnapshot) }, name)
		},
		sshPort: func() int {
			if p, err := sshdPorts(); err == nil && len(p) == 1 {
				return p[0]
			}
			return 0
		},
		hostOpen: func() bool {
			st, _ := showUnit()
			return !running(st) || tableGone()
		},
		lock:        func(what string) error { return takeUpdateLock(what, 0) },
		installLock: func() (*os.File, error) { return takeInstallLock(relayInstallLock) },
		newStage:    newStage,
		stage: func(ctx context.Context, o updateOpts, stage, installed string) (staged, error) {
			return c.stageRelease(ctx, o, stage, installed, relayBinaries, relayTarget)
		},
		place: func(stage string) (bool, error) { return placeRelayBinaries(stage, relayBinaries, placeBinary) },
		install: func(lock *os.File) error {
			return relayInstallCommand("/usr/local/bin/rayctl", deploy.RelayBundle, lock).Run()
		},
		health: func(w healthWant) func() error {
			h := realHealth(w)
			return func() error { return waitHealthy(hctx, h.check, 30*time.Second, 3*time.Second, time.Second) }
		},
		confirm: askYes,
		signals: catchSignals,
	}
}

// realHealth is relayHealth on this host.
func realHealth(w healthWant) relayHealth {
	return relayHealth{
		rayspa: showUnit, probe: unitState(deploy.RelayProbeUnit), probeRan: w.probeRan,
		exe: runningBinary(relayUnit, deploy.DefaultBinaries.Rayspa, func(unit string) string {
			out, _ := commandApart("systemctl", "show", "-p", "MainPID", "--value", unit).Output()
			return strings.TrimSpace(string(out))
		}),
		nft: func(args ...string) (string, error) {
			out, err := commandApart("nft", args...).Output()
			return string(out), err
		},
		forwarding: func() ([]byte, error) { return os.ReadFile(procForward) },
		snapshot:   func() (*perimeterv1.Snapshot, error) { return readSnapshot(relaySnapshot) },
		version: func() string {
			out, _ := commandApart(deploy.DefaultBinaries.Rayspa, "version").Output()
			return strings.TrimSpace(string(out))
		},
		want: w.want, port: w.port, client: w.client, name: w.name,
	}
}

// relayPolicy is rayctl update status|remote|auto on a relay: no policy,
// since a relay has no rayd API for devices; status says what is
// installed, what the last update kept, and whether one did not end.
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
	m, marked := relayOps{dir: dir}.readMark()
	if c.json {
		st := map[string]any{"host": "relay", "installed": version, "rayspa": rayspa, "previous": previous, "remote": "n/a", "auto": "n/a"}
		if marked {
			st["unfinished"] = m.advice()
		}
		j, err := json.MarshalIndent(st, "", "  ")
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
	if marked {
		fmt.Printf("unfinished %s\n", m.advice())
	}
	fmt.Println("latest     rayctl update -check asks GitHub")
	fmt.Println("remote     does not apply to a relay (no rayd API for devices)")
	fmt.Println("auto       does not apply to a relay: rayctl update on this host")
	return nil
}
