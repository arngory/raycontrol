package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/node"
)

// relaySnapshot is where rayspa keeps the last snapshot it applied.
const relaySnapshot = "/var/lib/rayspa/snapshot.pb"

// installRelay makes this host a relay (spec/relay-v1.md §3.1): the bundle,
// rayspa taking its perimeter from the exit, forwarding on. rayspa closes
// everything but what its perimeter opens, the relay host's SSH included:
// unless the first snapshot arrives, rayspa is stopped again and its table
// removed, so a relay that cannot reach its exit does not lock its admin out.
func installRelay(bundlePath, packages string) error {
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
	h, err := journaledHost()
	if err != nil {
		return err
	}
	// Recorded first: rayctl uninstall takes all of it back.
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
	}
	if err := waitFile(relaySnapshot, 45*time.Second); err != nil {
		_ = run("systemctl", "stop", "rayspa.service")
		_ = run(deploy.DefaultBinaries.Rayspa, "teardown")
		return fmt.Errorf("the relay took no perimeter from its exit %s (API port %d) within 45 s, so rayspa is stopped and "+
			"the host left open: does the exit know this host's address (rayctl relay list), and is its api service on? "+
			"journalctl -u rayspa says more: %w", b.Exit, b.API.Port, err)
	}
	fmt.Printf("relay %s up: knocks with K_relay open the exit's services through here (exit %s).\n"+
		"This host's SSH is reachable from the exit's admin addresses only (rayctl admin on the exit).\n", b.Name, b.Exit)
	return nil
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
