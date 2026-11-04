package deploy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/arngory/raycontrol/internal/render"
)

// Host applies a plan to the machine. Root and Run are seams for tests:
// Root prefixes every path, Run executes commands.
type Host struct {
	Root string
	Run  func(name string, args ...string) ([]byte, error)
	Out  io.Writer
	// LookupUser and LookupGroup default to os/user.
	LookupUser  func(name string) (uid int, err error)
	LookupGroup func(name string) (gid int, err error)
	// LookPath finds a command; nil means none is installed.
	LookPath func(name string) (string, error)
	// Ready, if set, is called after each unit is enabled (and restarted if
	// its file changed) and before the next one starts: rayd must render
	// the files the data-plane units read.
	Ready func(unit string) error
	// Journal, if set, gets every change before it is made (rayctl
	// uninstall reverts them).
	Journal *Journal
}

// NewHost returns a host that acts on this machine.
func NewHost(out io.Writer) *Host {
	return &Host{
		Run: func(name string, args ...string) ([]byte, error) {
			return exec.Command(name, args...).CombinedOutput()
		},
		Out:      out,
		LookPath: exec.LookPath,
		LookupUser: func(name string) (int, error) {
			u, err := user.Lookup(name)
			if err != nil {
				return 0, err
			}
			return strconv.Atoi(u.Uid)
		},
		LookupGroup: func(name string) (int, error) {
			g, err := user.LookupGroup(name)
			if err != nil {
				return 0, err
			}
			return strconv.Atoi(g.Gid)
		},
	}
}

func (h *Host) path(p string) string { return filepath.Join(h.Root, p) }

func (h *Host) run(name string, args ...string) error {
	out, err := h.Run(name, args...)
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}

// EnsureGroup creates a system group if it does not exist.
func (h *Host) EnsureGroup(name string, gid int) error {
	if got, err := h.LookupGroup(name); err == nil {
		if gid > 0 && got != gid {
			return fmt.Errorf("group %s exists with gid %d, want %d", name, got, gid)
		}
		return nil
	}
	args := []string{"--system"}
	if gid > 0 {
		args = append(args, "--gid", strconv.Itoa(gid))
	}
	if err := h.Journal.Record(Change{Kind: ChangeGroup, Name: name}); err != nil {
		return err
	}
	return h.run("groupadd", append(args, name)...)
}

// EnsureUser creates a system user with its own group and the given UID.
// An existing user with another UID is an error: nftables rules and
// SO_PEERCRED checks rely on the UID.
func (h *Host) EnsureUser(u SystemUser) error {
	if err := h.EnsureGroup(u.Name, u.UID); err != nil {
		return err
	}
	if got, err := h.LookupUser(u.Name); err == nil {
		if got != u.UID {
			return fmt.Errorf("user %s exists with uid %d, want %d", u.Name, got, u.UID)
		}
		return nil
	}
	if err := h.Journal.Record(Change{Kind: ChangeUser, Name: u.Name}); err != nil {
		return err
	}
	return h.run("useradd", "--system", "--uid", strconv.Itoa(u.UID), "--gid", u.Name,
		"--no-create-home", "--home-dir", "/nonexistent", "--shell", h.nologin(), u.Name)
}

// nologin finds the no-login shell: /usr/sbin on Debian and RHEL, /usr/bin
// on Arch; /bin/false where neither exists.
func (h *Host) nologin() string {
	for _, p := range []string{"/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/nologin"} {
		if _, err := os.Stat(h.path(p)); err == nil {
			return p
		}
	}
	return "/bin/false"
}

// WriteFile writes a file if its content differs and reports whether it did.
func (h *Host) WriteFile(f File) (bool, error) {
	p := h.path(f.Path)
	old, err := os.ReadFile(p) //nolint:gosec // G304: paths come from the deployment plan
	if err == nil && bytes.Equal(old, f.Content) {
		return false, nil
	}
	if err := h.Journal.RecordFile(f.Path); err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec // G301: system directories
		return false, err
	}
	tmp := p + ".raycontrol-new"
	if err := os.WriteFile(tmp, f.Content, os.FileMode(f.Mode)); err != nil {
		return false, err
	}
	if err := os.Chmod(tmp, os.FileMode(f.Mode)); err != nil {
		return false, err
	}
	return true, os.Rename(tmp, p)
}

// InstallBinary puts an executable in place like any file: journaled, so a
// file that was there comes back at uninstall, and labelled for SELinux.
func (h *Host) InstallBinary(src, dst string) (bool, error) {
	b, err := os.ReadFile(src) //nolint:gosec // G304: a binary the bootstrap verified
	if err != nil {
		return false, err
	}
	changed, err := h.WriteFile(File{Path: dst, Mode: 0o755, Content: b})
	if changed {
		h.relabel(dst)
	}
	return changed, err
}

// stubResolv is the systemd-resolved stub that stops working once its
// listener is off; resolvConf is the file with the real upstream servers.
const (
	stubResolv = "/run/systemd/resolve/stub-resolv.conf"
	resolvConf = "/run/systemd/resolve/resolv.conf"
)

// Apply installs the plan: users, files, units. It enables the units whose
// executables exist, in plan order, and restarts those whose files changed.
// Units listed in keep are left alone (rayctl install starts rayspa last).
func (h *Host) Apply(plan Plan, keep ...string) error {
	for _, u := range plan.Users {
		if err := h.EnsureUser(u); err != nil {
			return err
		}
	}
	// Exactly these groups: systemd starts a unit with the user's groups
	// from /etc/group, so one the plan no longer lists must go (the front
	// left the backends' groups, S-1). These users are raycontrol's own.
	for _, u := range plan.Users {
		if err := h.run("usermod", "--groups", strings.Join(u.ExtraGroups, ","), u.Name); err != nil {
			return err
		}
	}

	changedUnits := map[string]bool{}
	changedFiles := map[string]bool{}
	var written []string
	var resolvedChanged, sysctlChanged, tmpfilesChanged bool
	for _, f := range plan.Files {
		if h.skipFile(f.Path) {
			continue
		}
		changed, err := h.WriteFile(f)
		if err != nil {
			return fmt.Errorf("writing %s: %w", f.Path, err)
		}
		if !changed {
			continue
		}
		fmt.Fprintln(h.Out, "wrote", f.Path)
		changedFiles[f.Path] = true
		written = append(written, f.Path)
		switch {
		case strings.HasPrefix(f.Path, "/etc/systemd/system/"):
			changedUnits[filepath.Base(f.Path)] = true
		case strings.HasPrefix(f.Path, "/etc/systemd/resolved.conf.d/"):
			resolvedChanged = true
		case strings.HasPrefix(f.Path, "/etc/sysctl.d/"):
			sysctlChanged = true
		case strings.HasPrefix(f.Path, "/etc/tmpfiles.d/"):
			tmpfilesChanged = true
		}
	}

	h.relabel(written...)
	if tmpfilesChanged {
		if err := h.run("systemd-tmpfiles", "--create", "/etc/tmpfiles.d/raycontrol.conf"); err != nil {
			return err
		}
	}
	if sysctlChanged {
		h.ApplySysctl(plan.Files)
	}
	if resolvedChanged {
		if err := h.freePort53(); err != nil {
			return err
		}
	}
	if err := h.run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := h.hostFirewalls(plan, changedFiles); err != nil {
		return err
	}
	if slices.Contains(plan.Units, "niko-front.service") {
		h.warnPort53(render.FrontUID)
	}

	if err := h.removeStale(plan); err != nil {
		return err
	}
	for _, unit := range plan.Units {
		if slices.Contains(keep, unit) {
			continue
		}
		exe := execOf(plan, unit)
		if exe != "" {
			if _, err := os.Stat(h.path(exe)); err != nil {
				fmt.Fprintf(h.Out, "warning: %s not enabled: %s is missing\n", unit, exe)
				continue
			}
		}
		if err := h.EnableNow(unit); err != nil {
			return err
		}
		if changedUnits[unit] {
			if err := h.run("systemctl", "try-restart", unit); err != nil {
				return err
			}
		}
		if h.Ready != nil {
			if err := h.Ready(unit); err != nil {
				return err
			}
		}
	}
	for _, w := range plan.Warnings {
		fmt.Fprintln(h.Out, "warning:", w)
	}
	return nil
}

// EnableNow enables and starts a unit, noting it for uninstall.
func (h *Host) EnableNow(unit string) error {
	if err := h.Journal.Record(Change{Kind: ChangeUnit, Name: unit}); err != nil {
		return err
	}
	return h.run("systemctl", "enable", "--now", unit)
}

// ApplySysctl loads the sysctl files among files now, not at the next
// boot, noting first the values they change (for uninstall).
func (h *Host) ApplySysctl(files []File) {
	h.recordSysctl(files)
	for _, f := range files {
		if strings.HasPrefix(f.Path, "/etc/sysctl.d/") {
			// -e: keys this host does not have (net.ipv6.* with IPv6 off)
			// are skipped, not errors.
			if err := h.run("sysctl", "-q", "-e", "-p", f.Path); err != nil {
				fmt.Fprintln(h.Out, "warning:", err)
			}
		}
	}
	h.checkSysctl(files)
}

// recordSysctl notes the values the sysctl files are about to change.
func (h *Host) recordSysctl(files []File) {
	if h.Journal == nil {
		return
	}
	for _, f := range files {
		if !strings.HasPrefix(f.Path, "/etc/sysctl.d/") {
			continue
		}
		for _, line := range strings.Split(string(f.Content), "\n") {
			key, _, ok := strings.Cut(line, "=")
			key = strings.TrimSpace(key)
			if !ok || key == "" || strings.HasPrefix(key, "#") || h.Journal.Has(ChangeSysctl, "", key) {
				continue
			}
			if out, err := h.Run("sysctl", "-n", key); err == nil && len(bytes.TrimSpace(out)) > 0 {
				_ = h.Journal.Record(Change{Kind: ChangeSysctl, Name: key, Value: strings.TrimSpace(string(out))})
			}
		}
	}
}

// checkSysctl warns about values another file sets differently: at boot
// files sort by name, and a provider's 99-*.conf comes after raycontrol's.
func (h *Host) checkSysctl(files []File) {
	for _, f := range files {
		if !strings.HasPrefix(f.Path, "/etc/sysctl.d/") {
			continue
		}
		for _, line := range strings.Split(string(f.Content), "\n") {
			key, want, ok := strings.Cut(line, "=")
			key, want = strings.TrimSpace(key), strings.TrimSpace(want)
			if !ok || key == "" || strings.HasPrefix(key, "#") {
				continue
			}
			out, err := h.Run("sysctl", "-n", key)
			if got := strings.Join(strings.Fields(string(out)), " "); err == nil && got != want {
				fmt.Fprintf(h.Out, "warning: %s is %s, not %s: another sysctl file overrides %s, or the host does not let it change (a container)\n",
					key, got, want, f.Path)
			}
		}
	}
}

// relabel restores the SELinux labels of written files (RHEL family), so
// that systemd and polkit may read them whatever created them.
func (h *Host) relabel(paths ...string) {
	if len(paths) == 0 || !h.lookPath("restorecon") {
		return
	}
	if _, err := os.Stat(h.path("/sys/fs/selinux/enforce")); err != nil {
		return
	}
	if out, err := h.Run("restorecon", paths...); err != nil {
		fmt.Fprintf(h.Out, "warning: restorecon: %v: %s\n", err, bytes.TrimSpace(out))
	}
}

// execOf returns the executable of a unit in the plan.
func execOf(plan Plan, unit string) string {
	for _, f := range plan.Files {
		if f.Path != "/etc/systemd/system/"+unit {
			continue
		}
		for _, line := range strings.Split(string(f.Content), "\n") {
			if rest, ok := strings.CutPrefix(line, "ExecStart="); ok {
				return strings.Fields(rest)[0]
			}
		}
	}
	return ""
}

// removeStale stops and removes niko-* units the plan no longer has.
func (h *Host) removeStale(plan Plan) error {
	matches, err := filepath.Glob(h.path("/etc/systemd/system/niko-*.service"))
	if err != nil {
		return err
	}
	for _, m := range matches {
		unit := filepath.Base(m)
		if slices.Contains(plan.Units, unit) {
			continue
		}
		_ = h.run("systemctl", "disable", "--now", unit)
		if err := os.Remove(m); err != nil {
			return err
		}
		fmt.Fprintln(h.Out, "removed", unit)
	}
	return nil
}

// freePort53 turns off the systemd-resolved stub listener. If resolv.conf
// points at the stub, it is pointed at the upstream list first, so that the
// host keeps resolving.
func (h *Host) freePort53() error {
	rc := h.path("/etc/resolv.conf")
	if target, err := os.Readlink(rc); err == nil && strings.HasSuffix(target, "stub-resolv.conf") {
		if err := h.Journal.Record(Change{Kind: ChangeSymlink, Path: "/etc/resolv.conf", Target: target}); err != nil {
			return err
		}
		if err := os.Remove(rc); err != nil {
			return err
		}
		if err := os.Symlink(resolvConf, rc); err != nil {
			return err
		}
		fmt.Fprintln(h.Out, "/etc/resolv.conf now points to", resolvConf, "instead of", stubResolv)
	}
	// Debian and RHEL servers often run without systemd-resolved: nothing to free.
	if out, _ := h.Run("systemctl", "show", "-P", "LoadState", "systemd-resolved.service"); strings.TrimSpace(string(out)) == "not-found" {
		return nil
	}
	if err := h.run("systemctl", "try-restart", "systemd-resolved.service"); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return err
		}
		fmt.Fprintln(h.Out, "warning:", err)
	}
	return nil
}
