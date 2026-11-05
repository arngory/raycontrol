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
	if err := mkdirAll(filepath.Dir(p), 0o755); err != nil {
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

// mkdirAll makes dir and its missing parents with mode, whatever the umask:
// the services, under their own users, go through them.
func mkdirAll(dir string, mode os.FileMode) error {
	if fi, err := os.Stat(dir); err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("%s is not a directory", dir)
		}
		return nil
	}
	if parent := filepath.Dir(dir); parent != dir {
		if err := mkdirAll(parent, mode); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return os.Chmod(dir, mode)
}

// openDirs are directories the services go through (to their binaries,
// the release's data) or, for the state, into:
// before v0.11 an install under a umask of 027 or 077 left them closed to
// everyone but root. repairModes opens them again; nothing is taken away.
var openDirs = []struct {
	path string
	bits os.FileMode
}{
	{filepath.Dir(DataPlaneDir), 0o055}, {DataPlaneDir, 0o055},
	{DataDir, 0o055},
	{StateDir, 0o011},
}

// repairModes gives the directories of openDirs the bits the services need,
// and the data-plane binaries theirs, saying what it changed.
func (h *Host) repairModes() {
	fix := func(p string, bits os.FileMode, dir bool) {
		fi, err := os.Lstat(h.path(p))
		if err != nil || fi.IsDir() != dir || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm()&bits == bits {
			return
		}
		mode := fi.Mode().Perm() | bits
		if err := os.Chmod(h.path(p), mode); err != nil {
			fmt.Fprintf(h.Out, "warning: %s is mode %v, closed to the services: %v\n", p, fi.Mode().Perm(), err)
			return
		}
		fmt.Fprintf(h.Out, "%s was mode %v, closed to the services: now %v\n", p, fi.Mode().Perm(), mode)
	}
	for _, d := range openDirs {
		fix(d.path, d.bits, true)
	}
	for _, b := range []string{DefaultBinaries.Xray, DefaultBinaries.NikoServer, DefaultBinaries.Rayd, DefaultBinaries.Rayspa} {
		fix(b, 0o055, false)
	}
	// The services resolve names themselves (rayd: ACME, Cloudflare): a
	// resolv.conf they cannot read leaves Go asking localhost. Through
	// one link, as /etc/resolv.conf to resolved's stub file.
	fix(resolvTarget(h.path, ResolvConf), 0o044, false)
}

// ResolvConf is the host's resolver configuration.
const ResolvConf = "/etc/resolv.conf"

// ResolverProblem says why the services could not resolve names with the
// host's resolv.conf, or "" when they can: they run under their own users,
// so it must be readable by others, and it must name a server (without
// one Go asks localhost). root is the host's root, "" for this host.
func ResolverProblem(root string) string {
	at := func(p string) string { return filepath.Join(root, p) }
	p := at(resolvTarget(at, ResolvConf))
	fi, err := os.Stat(p)
	if err != nil {
		return fmt.Sprintf("%s: %v", ResolvConf, err)
	}
	if fi.Mode().Perm()&0o004 == 0 {
		return fmt.Sprintf("%s is mode %v: the services cannot read it", ResolvConf, fi.Mode().Perm())
	}
	b, err := os.ReadFile(p) //nolint:gosec // G304: the host's resolv.conf
	if err != nil {
		return fmt.Sprintf("%s: %v", ResolvConf, err)
	}
	for line := range strings.Lines(string(b)) {
		if f := strings.Fields(line); len(f) > 1 && f[0] == "nameserver" {
			return ""
		}
	}
	return ResolvConf + " names no nameserver: Go asks localhost:53"
}

// resolvTarget is the file a resolv.conf link points to (one link deep,
// within the host's root), or the path itself.
func resolvTarget(at func(string) string, p string) string {
	t, err := os.Readlink(at(p))
	if err != nil {
		return p
	}
	if !filepath.IsAbs(t) {
		t = filepath.Join(filepath.Dir(p), t)
	}
	return t
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
	h.repairModes()
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
	var sysctlChanged, tmpfilesChanged bool
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
	if err := h.giveBackStub(); err != nil {
		return err
	}
	if err := h.run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := h.hostFirewalls(plan, changedFiles); err != nil {
		return err
	}
	if plan.FrontDNS && slices.Contains(plan.Units, "niko-front.service") {
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

// stubPending marks a stub being given back: the drop-in is out of
// resolved's sight (it reads *.conf only), the stub not yet seen back.
const stubPending = ResolvedDropIn + ".gone"

// SharesDNSFrom is the first niko-server whose front shares UDP 53 with
// systemd-resolved's stub (SO_REUSEADDR).
var SharesDNSFrom = [3]int{0, 8, 2}

// giveBackStub undoes what installs before v0.11 did for the DNS tunnels:
// they turned systemd-resolved's stub off and pointed /etc/resolv.conf at
// the uplink servers, which left a host whose resolved has only its
// fallback servers without a resolver. The front shares UDP 53 with the
// stub from niko-server v0.8.2; with an older one installed, nothing
// changes yet.
//
// The front restarts first: an older one holds 53 without SO_REUSEADDR,
// and the stub, which resolved does not retry, could not bind beside it.
// Then resolved, and resolv.conf goes back to what the journal says it was
// only once the stub is seen on 127.0.0.53; until then it stays on the
// uplink list, and the next apply tries again (resolved only). A stub up
// already is not restarted. A drop-in that is not ours, and a resolv.conf
// the journal does not say raycontrol changed, stay.
func (h *Host) giveBackStub() error {
	dropIn := false
	if b, err := os.ReadFile(h.path(ResolvedDropIn)); err == nil {
		dropIn = bytes.HasPrefix(b, []byte("# Generated by raycontrol"))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_, err := os.Stat(h.path(stubPending))
	pending := err == nil
	rc := h.path("/etc/resolv.conf")
	target, _ := os.Readlink(rc)
	orig, journaled := h.Journal.Original(ChangeSymlink, "/etc/resolv.conf", "")
	pointed := target == resolvConf && journaled && orig.Target != "" && orig.Target != resolvConf
	if !dropIn && !pending && !pointed {
		return nil
	}
	if ok, why := h.frontSharesDNS(); !ok {
		fmt.Fprintf(h.Out, "warning: %s: systemd-resolved's stub stays off for now\n", why)
		return nil
	}
	if dropIn {
		// Another DNS server on 53 (with the stub off for it, since the
		// DNS tunnels went perhaps): the stub would take 127.0.0.53 from
		// it at the next boot.
		if others := h.OthersOn53(render.FrontUID); len(others) > 0 {
			fmt.Fprintf(h.Out, "warning: UDP 53 is held by %s %s: systemd-resolved's stub stays off (%s stays)\n",
				others[0].Owner, others[0].Addr, ResolvedDropIn)
			return nil
		}
		// The front first, while the drop-in is still in place: an older
		// one holds 53 alone, and a run stopped after this starts again
		// here.
		if !h.stubOn53() && h.loadState("niko-front.service") == "loaded" {
			if err := h.tryRestart("niko-front.service"); err != nil {
				return err
			}
		}
		if err := os.Rename(h.path(ResolvedDropIn), h.path(stubPending)); err != nil {
			return err
		}
		fmt.Fprintln(h.Out, "removed", ResolvedDropIn+": the DNS tunnels share UDP 53 with systemd-resolved's stub")
	}
	if h.loadState("systemd-resolved.service") == "not-found" {
		if err := os.Remove(h.path(stubPending)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if !h.stubOn53() {
		if err := h.tryRestart("systemd-resolved.service"); err != nil {
			return err
		}
	}
	if !h.stubOn53() {
		fmt.Fprintf(h.Out, "warning: systemd-resolved's stub is not on 127.0.0.53: /etc/resolv.conf stays where it is, "+
			"and the next rayctl apply tries again (journalctl -u systemd-resolved says why)\n")
		return nil
	}
	if err := os.Remove(h.path(stubPending)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !pointed {
		return nil
	}
	tmp := rc + ".raycontrol-new"
	_ = os.Remove(tmp)
	if err := os.Symlink(orig.Target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, rc); err != nil {
		return err
	}
	fmt.Fprintln(h.Out, "/etc/resolv.conf points to", orig.Target, "again")
	return nil
}

// loadState is a unit's LoadState: "loaded", "not-found", or "" when
// systemctl does not say (--value, not -P: systemd 245 has no -P).
func (h *Host) loadState(unit string) string {
	out, _ := h.Run("systemctl", "show", "--property=LoadState", "--value", unit)
	return strings.TrimSpace(string(out))
}

// tryRestart restarts a unit if it runs; its failure is a warning.
func (h *Host) tryRestart(unit string) error {
	if err := h.run("systemctl", "try-restart", unit); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return err
		}
		fmt.Fprintln(h.Out, "warning:", err)
	}
	return nil
}

// frontSharesDNS reports whether the installed niko-server shares UDP 53
// with systemd-resolved's stub (SharesDNSFrom or newer), or why not. With
// no niko-server there is no front to hold 53.
func (h *Host) frontSharesDNS() (bool, string) {
	if _, err := os.Stat(h.path(DefaultBinaries.NikoServer)); errors.Is(err, os.ErrNotExist) {
		return true, ""
	}
	out, err := h.Run(DefaultBinaries.NikoServer, "version")
	f := strings.Fields(string(out))
	var v [3]int
	if err != nil || len(f) < 2 {
		return false, fmt.Sprintf("cannot tell niko-server's version (%q)", strings.TrimSpace(string(out)))
	}
	if _, err := fmt.Sscanf(strings.TrimPrefix(f[1], "v"), "%d.%d.%d", &v[0], &v[1], &v[2]); err != nil {
		return false, fmt.Sprintf("cannot tell niko-server's version (%q)", f[1])
	}
	if slices.Compare(v[:], SharesDNSFrom[:]) < 0 {
		return false, fmt.Sprintf("niko-server %s is older than v%d.%d.%d, which shares UDP 53 with the stub", f[1],
			SharesDNSFrom[0], SharesDNSFrom[1], SharesDNSFrom[2])
	}
	return true, ""
}
