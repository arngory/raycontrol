package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
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
// everything but what its perimeter opens, the relay host's SSH included:
// unless the first snapshot arrives and admits this host's sshd from the
// relay's admin addresses, rayspa is stopped, disabled and its table
// removed, so a relay that cannot reach its exit does not lock its admin
// out, now or at the next boot.
func installRelay(bundlePath, packages string) error {
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
	plan := deploy.RelayPlan(deploy.DefaultBinaries)
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
	// A snapshot from an earlier install is not proof of this one.
	_ = os.Remove(relaySnapshot)
	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	for _, u := range plan.Units {
		if err := h.EnableNow(u); err != nil {
			return err
		}
		// A rayspa already running keeps the bundle before: restart it.
		if err := run("systemctl", "restart", u); err != nil {
			return err
		}
	}
	fail := func(why error) error {
		_ = run("systemctl", "disable", "--now", "rayspa.service")
		_ = run(deploy.DefaultBinaries.Rayspa, "teardown")
		return fmt.Errorf("%w; rayspa is stopped and disabled and the host left open", why)
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
	port := sshPort()
	if len(snap.AdminPrefixes) == 0 || !slices.ContainsFunc(snap.AdminPorts, func(p *perimeterv1.Port) bool { return p.Proto == "tcp" && int(p.Port) == port }) {
		return fail(fmt.Errorf("the relay's perimeter would not let SSH in here: sshd listens on %d, the relay's SSH port is %v, "+
			"its admin addresses %v; on the exit: rayctl relay set -ssh-port %d -admin <your address> %s",
			port, snap.AdminPorts, snap.AdminPrefixes, port, b.Name))
	}
	fmt.Printf("relay %s up: knocks with K_relay open the exit's services through here (exit %s).\n"+
		"This host's SSH (port %d) is reachable from %s, the relay's own admin addresses (rayctl relay set on the exit).\n",
		b.Name, b.Exit, port, strings.Join(snap.AdminPrefixes, ", "))
	return nil
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
