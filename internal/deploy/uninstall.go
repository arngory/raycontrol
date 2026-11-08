package deploy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// UninstallOptions tune rayctl uninstall.
type UninstallOptions struct {
	// KeepState leaves /var/lib/raycontrol (the database with users, keys
	// and certificates) for a later install.
	KeepState bool
	// PurgePackages removes the packages the bootstrap installed (curl,
	// openssl, nftables, polkit); by default they stay, other software may
	// use them by now.
	PurgePackages bool
}

// Runtime directories, gone at reboot anyway.
// /var/lib/rayspa holds the perimeter's copy of its last snapshot, and
// /var/lib/rayd-relay a relay's probe endpoint's devices: nothing that is
// not the exit's, and gone with them.
var runtimeDirs = []string{"/run/niko", "/run/raycontrol", "/var/lib/rayspa", "/var/lib/rayd-relay", "/var/lib/raycontrol-update"}

// Uninstall reverts what the journal records, newest first within each
// step: units off, perimeter table gone, sysctl values back, files restored
// or removed, resolv.conf as it was, host firewalls reloaded with their
// own files, users and groups removed, state and binaries deleted. Without
// a journal (installs before it existed) it removes what raycontrol is
// known to create. Errors of single steps are reported and the rest goes
// on: a half-removed node is worse than a warning.
func (h *Host) Uninstall(j *Journal, opts UninstallOptions) error {
	if !j.Exists() {
		fmt.Fprintln(h.Out, "no install journal: removing what raycontrol is known to create")
		h.synthesize(j)
	}
	var errs []error
	note := func(err error) {
		if err != nil {
			errs = append(errs, err)
			fmt.Fprintln(h.Out, "warning:", err)
		}
	}
	changes := slices.Clone(j.Changes)
	slices.Reverse(changes)
	of := func(kind string) []Change {
		var out []Change
		for _, c := range changes {
			if c.Kind == kind {
				out = append(out, c)
			}
		}
		return out
	}

	// Units: every one enabled or whose file raycontrol created (rayd may
	// have started it without apply enabling it); rayspa first, so the
	// perimeter goes with it.
	units := of(ChangeUnit)
	for _, c := range of(ChangeFile) {
		if dir, name := filepath.Split(c.Path); dir == "/etc/systemd/system/" && strings.HasSuffix(name, ".service") && c.Backup == "" &&
			!slices.ContainsFunc(units, func(u Change) bool { return u.Name == name }) {
			units = append(units, Change{Kind: ChangeUnit, Name: name})
		}
	}
	slices.SortStableFunc(units, func(a, b Change) int {
		return boolInt(b.Name == "rayspa.service") - boolInt(a.Name == "rayspa.service")
	})
	for _, c := range units {
		if _, err := h.Run("systemctl", "disable", "--now", c.Name); err == nil {
			fmt.Fprintln(h.Out, "stopped", c.Name)
		}
	}
	_, _ = h.Run("nft", "delete", "table", "inet", rayspaTable)

	// Only values that differ now: a container may not let raycontrol set
	// global keys (net.core.*) in the first place, nor set them back.
	for _, c := range of(ChangeSysctl) {
		if c.Value == "" {
			continue
		}
		if out, err := h.Run("sysctl", "-n", c.Name); err == nil && strings.Join(strings.Fields(string(out)), " ") == strings.Join(strings.Fields(c.Value), " ") {
			continue
		}
		note(h.run("sysctl", "-q", "-w", c.Name+"="+c.Value))
	}

	var resolved, firewalld, ufw bool
	for _, c := range of(ChangeFile) {
		p := h.path(c.Path)
		if c.Backup == "" {
			if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
				note(err)
			}
		} else {
			b, err := j.backup(c)
			if err == nil {
				err = os.WriteFile(p, b, c.Mode)
			}
			if err == nil {
				err = os.Chmod(p, c.Mode) // WriteFile keeps the mode of a file that is there
			}
			note(err)
		}
		resolved = resolved || strings.HasPrefix(c.Path, "/etc/systemd/resolved.conf.d/")
		firewalld = firewalld || strings.HasPrefix(c.Path, "/etc/firewalld/")
		ufw = ufw || strings.HasPrefix(c.Path, "/etc/ufw/")
		fmt.Fprintln(h.Out, map[bool]string{true: "removed", false: "restored"}[c.Backup == ""], c.Path)
	}
	for _, c := range of(ChangeSymlink) {
		p := h.path(c.Path)
		note(os.Remove(p))
		note(os.Symlink(c.Target, p))
		fmt.Fprintln(h.Out, c.Path, "points to", c.Target, "again")
	}
	for _, c := range of(ChangeDir) {
		_ = os.Remove(h.path(c.Path)) // only if empty
	}

	_, _ = h.Run("systemctl", "daemon-reload")
	// A stub given back only halfway (giveBackStub): its mark goes too,
	// and v0.11.0's, the drop-in moved aside.
	if was, err := h.unmarkStub(); was {
		resolved = true
	} else {
		note(err)
	}
	if resolved {
		_, _ = h.Run("systemctl", "try-restart", "systemd-resolved.service")
	}
	if firewalld {
		if _, err := h.Run("systemctl", "is-active", "--quiet", "firewalld.service"); err == nil {
			note(h.run("firewall-cmd", "--reload"))
		}
	}
	if ufw {
		// Loaded the way the host loads ufw at boot (ufw-init), so its chains
		// come back exactly as they were: ufw reload adds runtime rules of its
		// own (the rate-limit chains) that the boot does not.
		if _, err := h.Run("systemctl", "is-active", "--quiet", "ufw.service"); err == nil {
			note(h.run("systemctl", "restart", "ufw.service"))
		} else if out, _ := h.Run("ufw", "status"); bytes.Contains(out, []byte("Status: active")) {
			note(h.run("ufw", "reload"))
		}
	}
	h.fallbackFirewalls(j)

	for _, c := range of(ChangeUser) {
		if _, err := h.LookupUser(c.Name); err == nil {
			note(h.run("userdel", c.Name))
		}
	}
	for _, c := range of(ChangeGroup) {
		if _, err := h.LookupGroup(c.Name); err == nil {
			note(h.run("groupdel", c.Name))
		}
	}

	for _, d := range runtimeDirs {
		note(os.RemoveAll(h.path(d)))
	}
	for _, c := range of(ChangeState) {
		if opts.KeepState {
			fmt.Fprintln(h.Out, "kept", c.Path)
			continue
		}
		note(os.RemoveAll(h.path(c.Path)))
		fmt.Fprintln(h.Out, "removed", c.Path)
	}
	for _, c := range of(ChangeBinary) {
		if err := os.Remove(h.path(c.Path)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			note(err)
		}
	}

	pkgs := map[string][]string{}
	for _, c := range of(ChangePackage) {
		pkgs[c.Value] = append(pkgs[c.Value], c.Name)
	}
	for manager, names := range pkgs {
		if !opts.PurgePackages {
			fmt.Fprintf(h.Out, "kept packages the bootstrap installed (%s): %s; -purge-packages removes them\n", manager, strings.Join(names, " "))
			continue
		}
		note(h.removePackages(manager, names))
	}

	note(j.Remove())
	return errors.Join(errs...)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (h *Host) removePackages(manager string, names []string) error {
	switch manager {
	case "apt":
		return h.run("apt-get", append([]string{"remove", "-y", "-q"}, names...)...)
	case "dnf":
		return h.run("dnf", append([]string{"remove", "-y", "-q"}, names...)...)
	case "zypper":
		return h.run("zypper", append([]string{"--non-interactive", "remove"}, names...)...)
	case "pacman":
		return h.run("pacman", append([]string{"-R", "--noconfirm"}, names...)...)
	}
	return fmt.Errorf("unknown package manager %q", manager)
}

// Paths raycontrol is known to create, for installs without a journal.
var knownFiles = []string{
	"/etc/tmpfiles.d/raycontrol.conf",
	"/etc/polkit-1/rules.d/50-raycontrol.rules",
	"/etc/sysctl.d/90-raycontrol.conf",
	ResolvedDropIn,
	FirewalldService,
	UFWProfile,
}

// synthesize fills an empty journal with what an install without one left
// behind: generated files and units, raycontrol's users and groups, state
// and binaries. Replaced files and old sysctl values are unknown then.
func (h *Host) synthesize(j *Journal) {
	add := func(c Change) { j.Changes = append(j.Changes, c) }
	for _, b := range []string{DefaultBinaries.Rayd, DefaultBinaries.Rayspa, "/usr/local/bin/rayctl"} {
		add(Change{Kind: ChangeBinary, Path: b})
	}
	add(Change{Kind: ChangeState, Path: StateDir})
	units, _ := filepath.Glob(h.path("/etc/systemd/system/niko-*.service"))
	for _, u := range []string{"rayd.service", "rayspa.service"} {
		units = append(units, h.path("/etc/systemd/system/"+u))
	}
	for _, u := range units {
		if generated(u) {
			add(Change{Kind: ChangeFile, Path: strings.TrimPrefix(u, h.Root)})
			add(Change{Kind: ChangeUnit, Name: filepath.Base(u)})
		}
	}
	for _, f := range knownFiles {
		if generated(h.path(f)) {
			add(Change{Kind: ChangeFile, Path: f})
		}
	}
	add(Change{Kind: ChangeGroup, Name: AdminGroup})
	for _, name := range systemUsers(h.path("/etc/passwd")) {
		add(Change{Kind: ChangeUser, Name: name})
		add(Change{Kind: ChangeGroup, Name: name})
	}
}

// generated reports whether a file carries raycontrol's header.
func generated(path string) bool {
	b, err := os.ReadFile(path) //nolint:gosec // G304: known raycontrol paths
	return err == nil && bytes.Contains(b, []byte("Generated by raycontrol"))
}

// systemUsers lists raycontrol's users in a passwd file: rayd, rayspa and
// niko-* in the fixed UID range.
func systemUsers(passwd string) []string {
	f, err := os.Open(passwd) //nolint:gosec // G304: /etc/passwd
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 3 {
			continue
		}
		name, uid := fields[0], fields[2]
		if (name == "rayd" || name == "rayspa" || strings.HasPrefix(name, "niko-")) && len(uid) == 4 && strings.HasPrefix(uid, "91") {
			out = append(out, name)
		}
	}
	return out
}

// fallbackFirewalls takes the raycontrol service and rule out of firewalld
// and ufw when no journal recorded their files.
func (h *Host) fallbackFirewalls(j *Journal) {
	if slices.ContainsFunc(j.Changes, func(c Change) bool {
		return c.Kind == ChangeFile && (strings.HasPrefix(c.Path, "/etc/firewalld/zones/") || strings.HasPrefix(c.Path, "/etc/ufw/user"))
	}) {
		return
	}
	if h.lookPath("firewall-cmd") {
		if out, err := h.Run("firewall-cmd", "--get-zones"); err == nil {
			removed := false
			for _, z := range strings.Fields(string(out)) {
				if _, err := h.Run("firewall-cmd", "--permanent", "--zone="+z, "--query-service="+firewallName); err == nil {
					_, _ = h.Run("firewall-cmd", "--permanent", "--zone="+z, "--remove-service="+firewallName)
					removed = true
				}
			}
			if removed {
				_, _ = h.Run("firewall-cmd", "--reload")
			}
		}
	}
	if h.lookPath("ufw") {
		_, _ = h.Run("ufw", "delete", "allow", firewallName)
	}
}
