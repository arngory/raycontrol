package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/api"
	"github.com/arngory/raycontrol/internal/backup"
	"github.com/arngory/raycontrol/internal/deploy"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/perimeter"
	"github.com/arngory/raycontrol/internal/store"
)

const passphrasePrompt = "Backup passphrase (12 characters at least; without it the backup cannot be opened): " //nolint:gosec // G101: a prompt, not a credential

// backup writes the node's state, sealed with a passphrase (R4-13).
func (c *cli) backup(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	out := fs.String("o", "", "the backup file (default: raycontrol-DATE.rcbak here)")
	passFile := fs.String("passphrase-file", "", "file with the passphrase (default: asked for twice, not echoed)")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return errUsage
	}
	if err := needRoot(); err != nil {
		return err
	}
	client := c.c
	if c.backupClient != nil {
		client = c.backupClient
	}
	resp, err := client.Backup(ctx, connect.NewRequest(&nodev1.BackupRequest{}))
	if connect.CodeOf(err) == connect.CodeResourceExhausted {
		return fmt.Errorf("the database is unusually large, more than rayctl takes (%d MiB): %w", api.MaxBackupAnswer>>20, err)
	}
	if err != nil {
		return err
	}
	pass, err := readSecret(passphrasePrompt, *passFile, true)
	if err != nil {
		return err
	}
	created := time.Unix(resp.Msg.CreatedAt, 0).UTC()
	sealed, err := backup.Pack(backup.Meta{NodeID: resp.Msg.NodeId, Version: resp.Msg.Version, CreatedAt: created},
		resp.Msg.Database, pass)
	if err != nil {
		return err
	}
	path := *out
	if path == "" {
		path = "raycontrol-" + created.Format("20060102-150405") + ".rcbak"
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the operator's file
	if err != nil {
		return err
	}
	if _, err := f.Write(sealed); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes): every key of the node, sealed with the passphrase.\n", path, len(sealed))
	fmt.Println("Keep it off the node and the passphrase apart from it; rayctl restore puts it back.")
	return nil
}

// restore replaces the node's state with a backup and brings the node up
// on it, here or on a new host after rayctl install.
func (c *cli) restore(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	in := fs.String("i", "", "the backup file")
	passFile := fs.String("passphrase-file", "", "file with the passphrase (default: asked for, not echoed)")
	host := fs.String("host", "", "the node's public address, when it moved (devices then need new bundles)")
	yes := fs.Bool("yes", false, "do not ask")
	noCarry := fs.Bool("no-carry", false, "do not keep the revocations made here since the backup: the devices come back with their "+
		"users' credentials of then (when this node's database cannot be read)")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *in == "" {
		return errUsage
	}
	if err := needRoot(); err != nil {
		return err
	}
	// Before anything changes: it stops rayd, swaps the database and
	// restarts the node, as an update does (its rayctl apply inherits the
	// lock).
	if err := takeUpdateLock("restore", 0); err != nil {
		return err
	}
	if _, err := os.Stat(deploy.DB); err != nil {
		return fmt.Errorf("no node here (%w): rayctl install first, then restore", err)
	}
	sealed, err := os.ReadFile(*in) //nolint:gosec // G304: the operator's file
	if err != nil {
		return err
	}
	pass, err := readSecret("Backup passphrase: ", *passFile, false)
	if err != nil {
		return err
	}
	meta, db, err := backup.Unpack(sealed, pass)
	if err != nil {
		return err
	}
	fmt.Printf("backup of node %s, made %s by raycontrol %s\n", meta.NodeID, meta.CreatedAt.Format(time.RFC3339), meta.Version)
	if !*yes {
		fmt.Print("This replaces the node's users, keys and services with the backup; the current state is kept aside. Type yes to go on: ")
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(answer) != "yes" {
			return errors.New("not confirmed")
		}
	}

	// The copy goes next to the database, checked by the installed rayd
	// (migrations, the new address) before anything is replaced. The
	// directory is rayd's: written as copyDB writes, never through a link
	// rayd put at that name, and rayd's through the descriptor.
	tmp := deploy.DB + ".restore"
	if err := placeDB(tmp, db); err != nil {
		return err
	}
	defer removeDB(tmp)
	// -seq-clock: the backup's seq is of the day it was made, below what
	// clients have seen since, and they drop answers with a lower one. rayd
	// keeps to the stored seq for its first ten minutes (an update that
	// rolls back needs that), so the restored one is moved to the clock
	// here, before rayd starts on it.
	initArgs := []string{"-u", "rayd", "--", deploy.DefaultBinaries.Rayd, "init", "-db", tmp, "-seq-clock"}
	if *host != "" {
		initArgs = append(initArgs, "-host", *host)
	}
	got, err := exec.CommandContext(ctx, "runuser", initArgs...).CombinedOutput() //nolint:gosec // G204: fixed binary, the operator's address
	if err != nil {
		return fmt.Errorf("the installed rayd cannot use the backup: %w: %s", err, strings.TrimSpace(string(got)))
	}
	if !strings.Contains(string(got), "node "+meta.NodeID+" ") {
		return fmt.Errorf("the backup's database does not hold node %s: %s", meta.NodeID, strings.TrimSpace(string(got)))
	}

	before := activeDataPlane() // those the restored state still has must run again
	if err := run("systemctl", "stop", "rayd.service"); err != nil {
		return err
	}
	// A revocation is for good, and changed its user's credentials (R4-36):
	// the devices revoked here since the backup stay revoked in it, with
	// new credentials for their users. With rayd stopped, so that none is
	// missed.
	if *noCarry {
		fmt.Println("-no-carry: devices revoked since the backup come back, and with them their users' credentials of then;\n" +
			"a newer backup restored here later carries nothing from this database")
	} else {
		carried, err := carryRestore(ctx, tmp, db)
		if err != nil {
			_ = run("systemctl", "start", "rayd.service")
			return fmt.Errorf("keeping the revocations made since the backup: %w; nothing changed "+
				"(rayctl restore -no-carry restores the backup as it is, revoked devices and old credentials included)", err)
		}
		fmt.Print(restoreCarryText(carried, meta.CreatedAt))
	}
	aside := deploy.DB + ".before-restore"
	if err := swapDB(tmp, deploy.DB, aside); err != nil {
		_ = run("systemctl", "start", "rayd.service")
		return err
	}
	fmt.Println("restored", deploy.DB, "- the previous state is in", aside, "until you remove it")
	if err := c.restartNode(ctx, "", "", before); err != nil {
		return fmt.Errorf("%w; to go back: systemctl stop rayd; mv %s %s; rayctl apply", err, aside, deploy.DB)
	}
	if *host != "" {
		if dns, err := c.c.GetDNS(ctx, connect.NewRequest(&nodev1.GetDNSRequest{})); err == nil && dns.Msg.Status.GetProvider() != "" {
			if _, err := c.c.SyncDNS(ctx, connect.NewRequest(&nodev1.SyncDNSRequest{})); err != nil {
				fmt.Println("warning: DNS records not updated (rayctl dns sync):", err)
			} else {
				fmt.Println("DNS records point to", *host)
			}
		}
		fmt.Println("The address changed: enrolled devices need new bundles (rayctl device add).")
	}
	return c.status(ctx)
}

// carryRestore brings into the restored copy at tmp (rayd's, checked by
// rayd init) the revocations and renewals of the node's database since the
// backup (store.CarryRestore): on root's copies of both, then the result
// back over tmp as copyDB writes. made is the backup's database as it
// came out of the backup, before rayd init migrated tmp: whether the node's
// database is a later state of the backup is read from it.
func carryRestore(ctx context.Context, tmp string, made []byte) (store.Restored, error) {
	current, doneCur, err := rootCopy(deploy.DB)
	if err != nil {
		return store.Restored{}, err
	}
	defer doneCur()
	work, doneWork, err := rootCopy(tmp)
	if err != nil {
		return store.Restored{}, err
	}
	defer doneWork()
	dir, err := os.MkdirTemp("", "rayctl-db-")
	if err != nil {
		return store.Restored{}, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	asMade := filepath.Join(dir, "backup.db")
	if err := os.WriteFile(asMade, made, 0o600); err != nil {
		return store.Restored{}, err
	}
	r, err := store.CarryRestore(ctx, work, current, asMade)
	if err != nil {
		return store.Restored{}, err
	}
	if !r.Foreign {
		if err := copyDB(work, tmp); err != nil {
			return store.Restored{}, err
		}
	}
	return r, nil
}

// restoreCarryText says what the restore did to credentials and what it
// cannot know: on this node the clients hold its current secrets, so the
// backup's do not come back; a device this node's database has no record
// of (a new host, a user deleted here since) may have been revoked after
// the backup, and the audit log is in the backup too. A database of this
// node that is no later state of the backup (store.Restored.Newer) says
// nothing of any device: nothing is carried, and why is said first.
func restoreCarryText(r store.Restored, made time.Time) string {
	var b strings.Builder
	if r.Newer != "" {
		fmt.Fprintf(&b, "the backup is newer than this node's database: nothing carried (%s)\n", r.Newer)
	}
	if r.Kept > 0 {
		fmt.Fprintf(&b, "credentials and LAN keys stay as they are on this node now for %d users: the backup's older ones do not come back\n", r.Kept)
	}
	if len(r.Carried) > 0 {
		fmt.Fprintf(&b, "revoked here since the backup, so revoked in it too; their users' credentials are new, and the users'\n"+
			"other devices reconnect after their next subscription fetch:\n")
		for _, d := range r.Carried {
			fmt.Fprintf(&b, "  %s  %s/%s\n", d.ID, d.User, d.Name)
		}
	}
	if len(r.Added) > 0 {
		fmt.Fprintf(&b, "added here since the backup, so not in it: gone with the restore. Each fetched its user's credentials,\n"+
			"which are new, so what it holds works no more:\n")
		for _, d := range r.Added {
			state := ""
			if d.Revoked {
				state = " (revoked here already)"
			}
			fmt.Fprintf(&b, "  %s  %s/%s%s\n", d.ID, d.User, d.Name, state)
		}
	}
	if len(r.New) > 0 {
		fmt.Fprintf(&b, "new credentials, their devices reconnect after their next subscription fetch:\n")
		for _, n := range r.New {
			fmt.Fprintf(&b, "  %s: %s\n", n.User, n.Why)
		}
	}
	if len(r.Unknown) > 0 {
		why := "(users deleted here since)"
		head := "has no record of %d devices the backup has active"
		switch {
		case r.Newer != "":
			why = "(a new host with this node's identity,\na cloned disk, or an older copy restored here)"
			head = "is no later state of the backup " + why + ": it says nothing of the %d devices the backup has active"
		case r.Foreign:
			why = "(this database is another node's: a new host)"
		}
		if r.Newer == "" {
			head += " " + why
		}
		fmt.Fprintf(&b, "warning: this node's database "+head+":\n"+
			"whether any of them was revoked, or its user renewed, after %s cannot be known here. Revoke again\n"+
			"those that must stay out (rayctl device revoke ID: their users' credentials change with it), and\n"+
			"rayctl user renew NAME the users renewed elsewhere since:\n",
			len(r.Unknown), made.Format(time.RFC3339))
		for _, d := range r.Unknown {
			fmt.Fprintf(&b, "  %s  %s/%s\n", d.ID, d.User, d.Name)
		}
	}
	return b.String()
}

// swapDB puts the database next in place of db, which moves to aside with
// its journal files; on failure db is put back.
func swapDB(next, db, aside string) error {
	removeDB(aside)
	moved := []string{}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Rename(db+suffix, aside+suffix); err == nil {
			moved = append(moved, suffix)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(next, db); err != nil {
		for _, suffix := range moved {
			_ = os.Rename(aside+suffix, db+suffix)
		}
		return err
	}
	return nil
}

// removeDB removes an SQLite database with its journal files.
func removeDB(path string) {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(path + suffix)
	}
}

// metrics prints the node's metrics in the Prometheus text format, or
// writes them for a collector's textfile directory (R4-14).
func (c *cli) metrics(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("metrics", flag.ContinueOnError)
	out := fs.String("o", "", "write to this file (atomically, mode 0644) instead of printing")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return errUsage
	}
	resp, err := c.c.GetMetrics(ctx, connect.NewRequest(&nodev1.GetMetricsRequest{}))
	if err != nil {
		return err
	}
	text := resp.Msg.Text
	// The early chain's counters (R4-9): what the kernel was spared. Only
	// on the node itself, not through -remote.
	if os.Geteuid() == 0 && c.identity == nil {
		if drops, err := (&perimeter.NFT{}).EarlyDrops(); err == nil {
			var m api.Metrics
			for _, reason := range slices.Sorted(maps.Keys(drops)) {
				m.Add("raycontrol_early_drops_packets_total", "Packets to the node dropped before reassembly and conntrack.",
					float64(drops[reason].Packets), "reason", reason)
				m.Add("raycontrol_early_drops_bytes_total", "Bytes of those packets.", float64(drops[reason].Bytes), "reason", reason)
			}
			text += m.String()
		}
		// The egress policy's counters (spec/egress-policy-v1.md §6): by
		// rule, never where to or whose; a rule not in force has none.
		if blocks, err := (&perimeter.NFT{}).EgressBlocks(); err == nil {
			var m api.Metrics
			for _, rule := range perimeter.EgressRules {
				d, ok := blocks[rule]
				if !ok {
					continue
				}
				m.Add("raycontrol_egress_blocked_packets_total",
					"Packets of the data plane the egress policy blocked (rayctl egress): about one a try over TCP, a datagram over UDP.",
					float64(d.Packets), "rule", rule)
				m.Add("raycontrol_egress_blocked_bytes_total", "Bytes of those packets.", float64(d.Bytes), "rule", rule)
			}
			text += m.String()
		}
		// The per-address limit on new inbound connections
		// (spec/conn-limit-v1.md §7): by protocol, never from where.
		if drops, err := (&perimeter.NFT{}).InboundDrops(); err == nil {
			var m api.Metrics
			for _, proto := range []string{"tcp", "udp"} {
				m.Add("raycontrol_conn_inbound_dropped_packets_total",
					"New inbound connections dropped over the per-address limit (SYNs, first UDP packets).",
					float64(drops[proto].Packets), "proto", proto)
			}
			text += m.String()
		}
	}
	if *out == "" {
		fmt.Print(text)
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(*out), ".raycontrol-metrics-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(text); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil { //nolint:gosec // G302: counts only, for the collector
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), *out)
}
