package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/arngory/raycontrol/internal/deploy"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/node"
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

	// From the first write on, a rayspa from an earlier install would start
	// at boot with a bundle nobody checked: every way out but success stops
	// rayspa, disables it and removes its table.
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = run("systemctl", "disable", "--now", "rayspa.service")
			_ = run(deploy.DefaultBinaries.Rayspa, "teardown")
		})
	}
	fail := func(why error) error {
		stop()
		return fmt.Errorf("%w; rayspa is stopped and disabled and the host left open", why)
	}
	// Ctrl-C, a closed SSH connection (SIGHUP), systemd: the same.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	done := make(chan struct{})
	defer func() {
		signal.Stop(sig)
		close(done)
	}()
	go func() {
		select {
		case s := <-sig:
			stop()
			fmt.Fprintf(os.Stderr, "rayctl: %v: rayspa is stopped and disabled and the host left open\n", s)
			os.Exit(1)
		case <-done:
		}
	}()

	plan := deploy.RelayPlan(deploy.DefaultBinaries)
	for _, u := range plan.Users {
		if err := h.EnsureUser(u); err != nil {
			return fail(err)
		}
	}
	files := append([]deploy.File{{Path: deploy.RelayBundle, Mode: 0o600, Content: []byte(strings.TrimSpace(string(raw)) + "\n")}}, plan.Files...)
	var sysctl []deploy.File
	for _, f := range files {
		changed, err := h.WriteFile(f)
		if err != nil {
			return fail(err)
		}
		if changed && strings.HasPrefix(f.Path, "/etc/sysctl.d/") {
			sysctl = append(sysctl, f)
		}
	}
	h.ApplySysctl(sysctl)
	// A snapshot from an earlier install is not proof of this one.
	_ = os.Remove(relaySnapshot)
	if err := run("systemctl", "daemon-reload"); err != nil {
		return fail(err)
	}
	// Started, not enabled: if rayctl dies before the checks, a reboot
	// opens the host again. An earlier install's rayspa is disabled until
	// this one is checked, and restarted with the new bundle.
	for _, u := range plan.Units {
		_ = run("systemctl", "disable", u)
		if err := run("systemctl", "restart", u); err != nil {
			return fail(err)
		}
	}
	if err := waitFile(relaySnapshot, 45*time.Second); err != nil {
		return fail(fmt.Errorf("the relay took no perimeter from its exit %s (API port %d) within 45 s: does the exit know this "+
			"host's address (rayctl relay list), is its api service on, and is this the newest bundle? journalctl -u rayspa says more",
			b.Exit, b.API.Port))
	}
	snap, err := readSnapshot(relaySnapshot)
	if err != nil {
		return fail(err)
	}
	warning, err := checkRelaySSH(snap, port, sess.addr, b.Name)
	if err != nil {
		return fail(err)
	}
	for _, u := range plan.Units {
		if err := h.EnableNow(u); err != nil {
			return fail(err)
		}
	}
	if warning != "" {
		fmt.Fprintln(os.Stderr, "warning:", warning)
	}
	fmt.Printf("relay %s up: knocks with K_relay open the exit's services through here (exit %s).\n"+
		"This host's SSH (port %d) is reachable from %s, the relay's own admin addresses (rayctl relay set on the exit).\n",
		b.Name, b.Exit, port, strings.Join(snap.AdminPrefixes, ", "))
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
func waitFile(path string, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if time.Now().After(deadline) {
			return errors.New("timed out")
		}
		time.Sleep(500 * time.Millisecond)
	}
}
