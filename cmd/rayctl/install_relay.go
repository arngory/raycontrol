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
const relaySnapshot = "/var/lib/rayspa/snapshot.pb"

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
	for _, tool := range []string{"nft", "systemctl", "install"} {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("%s is missing: a relay needs nftables and systemd", tool)
		}
	}
	if _, err := os.Stat(deploy.DefaultBinaries.Rayspa); err != nil {
		return fmt.Errorf("%s is missing: install/bootstrap.sh -relay installs it", deploy.DefaultBinaries.Rayspa)
	}
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

	// Ctrl-C, a closed SSH connection (SIGHUP, unless nohup ignores it),
	// systemd: the install stops at its next step, the way any failure does.
	sigs := []os.Signal{os.Interrupt, syscall.SIGTERM}
	if !signal.Ignored(syscall.SIGHUP) {
		sigs = append(sigs, syscall.SIGHUP)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), sigs...)
	defer cancel()
	plan := deploy.RelayPlan(deploy.DefaultBinaries)
	unitFile := "/etc/systemd/system/" + relayUnit
	steps := relaySteps{
		unitExists: func() bool { _, err := os.Stat(unitFile); return err == nil },
		systemctl:  func(args ...string) error { return runApart("systemctl", args...) },
		teardown:   func() error { return runApart(deploy.DefaultBinaries.Rayspa, "teardown") },
		tableGone: func() bool {
			present, err := (&perimeter.NFT{}).Present()
			return err == nil && !present
		},
		write: func() error {
			for _, u := range plan.Users {
				if err := h.EnsureUser(u); err != nil {
					return err
				}
			}
			files := append([]deploy.File{{Path: deploy.RelayBundle, Mode: 0o600, Content: []byte(strings.TrimSpace(string(raw)) + "\n")}}, plan.Files...)
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
		removeSnapshot: func() { _ = os.Remove(relaySnapshot) },
		waitSnapshot: func(ctx context.Context) error {
			if err := waitFile(ctx, relaySnapshot, 45*time.Second); err != nil {
				return fmt.Errorf("the relay took no perimeter from its exit %s (API port %d) within 45 s (%w): does the exit "+
					"know this host's address (rayctl relay list), is its api service on, and is this the newest bundle? "+
					"journalctl -u rayspa says more", b.Exit, b.API.Port, err)
			}
			return nil
		},
		readSnapshot: func() (*perimeterv1.Snapshot, error) { return readSnapshot(relaySnapshot) },
		check: func(snap *perimeterv1.Snapshot) (string, error) {
			return checkRelaySSH(snap, port, sess.addr, b.Name)
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

// relayUnit is rayspa's unit, the one RelayPlan installs.
const relayUnit = "rayspa.service"

// relaySteps is the part of a relay install that can lock the operator
// out, with the host's operations given so that a test can follow it.
type relaySteps struct {
	unitExists     func() bool
	systemctl      func(args ...string) error
	teardown       func() error // rayspa teardown
	tableGone      func() bool
	write          func() error // users, files, sysctl, daemon-reload
	removeSnapshot func()
	waitSnapshot   func(context.Context) error
	readSnapshot   func() (*perimeterv1.Snapshot, error)
	check          func(*perimeterv1.Snapshot) (string, error)
	enable         func() error // journaled, enable --now
}

// run writes the relay, starts rayspa without enabling it, and enables it
// once its first snapshot passes the check. An earlier install's rayspa is
// disabled before the first write: rayctl killed at any point leaves no
// rayspa enabled with a bundle nobody checked, so a reboot opens the host.
// Every other way out, a cancelled ctx (a signal) and a panic included,
// stops and disables rayspa and removes its table; if that fails, the error
// says so.
func (r relaySteps) run(ctx context.Context) (snap *perimeterv1.Snapshot, warning string, err error) {
	if r.unitExists() {
		if err := r.systemctl("disable", relayUnit); err != nil {
			return nil, "", fmt.Errorf("an earlier install's rayspa stays enabled, nothing changed: %w", err)
		}
	}
	ok := false
	defer func() {
		if ok {
			return
		}
		if serr := r.stop(); serr != nil {
			err = fmt.Errorf("%w; rayspa could NOT be taken down (%w): run %s teardown before you leave this session",
				err, serr, deploy.DefaultBinaries.Rayspa)
		} else {
			err = fmt.Errorf("%w; rayspa is stopped and disabled and the host left open", err)
		}
	}()
	step := func(f func() error) error {
		if ctx.Err() != nil {
			return errors.New("interrupted")
		}
		return f()
	}
	if err := step(r.write); err != nil {
		return nil, "", err
	}
	// Stopped before its snapshot goes: a rayspa still running would save
	// the earlier bundle's perimeter, and that would be checked instead.
	if err := step(func() error { return r.systemctl("stop", relayUnit) }); err != nil {
		return nil, "", err
	}
	r.removeSnapshot()
	if err := step(func() error { return r.systemctl("start", relayUnit) }); err != nil {
		return nil, "", err
	}
	if err := step(func() error { return r.waitSnapshot(ctx) }); err != nil {
		return nil, "", err
	}
	if snap, err = r.readSnapshot(); err != nil {
		return nil, "", err
	}
	if warning, err = r.check(snap); err != nil {
		return nil, "", err
	}
	if err := step(r.enable); err != nil {
		return nil, "", err
	}
	if ctx.Err() != nil {
		return nil, "", errors.New("interrupted")
	}
	ok = true
	return snap, warning, nil
}

// stop takes rayspa down and tells whether the host is really open.
func (r relaySteps) stop() error {
	var disable error
	if r.unitExists() {
		disable = r.systemctl("disable", "--now", relayUnit)
	}
	tear := r.teardown()
	if !r.tableGone() {
		return errors.Join(disable, tear, errors.New("the perimeter's table is still there"))
	}
	// Open now; rayspa left enabled would close the host again at boot.
	return disable
}

// runApart runs a command in a process group of its own: a second Ctrl-C
// at the terminal does not reach it halfway.
func runApart(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.CombinedOutput()
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
