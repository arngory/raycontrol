package main

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/deploy"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/release"
	"github.com/arngory/raycontrol/internal/store"
)

// previousDir keeps the binaries an update replaced, for rollback; root
// only, removed with the install journal at uninstall.
var previousDir = filepath.Join(deploy.JournalDir, "previous")

// updateStageEnv names the update's staging directory for the rayctl it
// installed: that rayctl's apply installs what the release brings and the
// rayctl that ran the update did not know (release.Extract).
const updateStageEnv = "RAYCONTROL_UPDATE_STAGE"

// nodeBinaries are the installed binaries by archive name.
var nodeBinaries = map[string]string{
	"rayd":        deploy.DefaultBinaries.Rayd,
	"rayspa":      deploy.DefaultBinaries.Rayspa,
	"rayctl":      "/usr/local/bin/rayctl",
	"xray":        deploy.DefaultBinaries.Xray,
	"niko-server": deploy.DefaultBinaries.NikoServer,
}

// update replaces the node's binaries with a verified release, restarts
// what runs them and applies the new version's deployment; if the node does
// not come back healthy, the previous binaries return (R4-12).
func (c *cli) update(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	want := fs.String("version", "latest", "release to install: latest or vX.Y.Z (an older one only when named)")
	check := fs.Bool("check", false, "only say whether a newer release exists")
	from := fs.String("from", "", "directory with SHA256SUMS, SHA256SUMS.minisig and the archive, downloaded by hand (verified the same way)")
	yes := fs.Bool("yes", false, "do not ask")
	force := fs.Bool("force", false, "install even if the release is not newer")
	rollback := fs.Bool("rollback", false, "put back the binaries the last update replaced")
	noCarry := fs.Bool("no-carry", false, "with -rollback: put the database copy back as it is, without what was revoked since (when the current database cannot be read)")
	local := fs.String("local", "", "binaries from this directory, not verified: for tests only")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if err := needRoot(); err != nil {
		return err
	}
	if err := updatable(deploy.DB, deploy.RelayBundle); err != nil {
		return err
	}
	if *rollback {
		carry := carryMust
		if *noCarry {
			carry = carrySkip
		}
		return c.rollbackUpdate(ctx, *yes, carry)
	}

	if err := os.MkdirAll(deploy.JournalDir, 0o700); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(deploy.JournalDir, "update-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stage) }()

	// The release: verified, or (tests) taken as it is.
	var newVersion string
	switch {
	case *local != "":
		for name := range nodeBinaries {
			if b, err := os.ReadFile(filepath.Join(*local, name)); err == nil { //nolint:gosec // G304: the operator's directory
				if err := os.WriteFile(filepath.Join(stage, name), b, 0o755); err != nil { //nolint:gosec // G306: executables
					return err
				}
			}
		}
		newVersion = "local"
		fmt.Println("binaries from", *local, "without verification (test mode)")
	default:
		var r release.Release
		arch := runtime.GOARCH
		if *from != "" {
			r, err = release.Local(*from, arch, release.PubKey)
		} else {
			f := &release.Fetcher{Mirrors: mirrors(), Log: func(format string, a ...any) { fmt.Printf(format+"\n", a...) }}
			r, err = f.Fetch(ctx, *want, arch, release.PubKey)
		}
		if err != nil {
			return err
		}
		newVersion = r.Version
		switch {
		case newVersion == version && !*force:
			fmt.Printf("raycontrol %s is installed, the newest release\n", version)
			return nil
		case release.Newer(version, newVersion) && *want == "latest" && !*force:
			return fmt.Errorf("installed %s is newer than the latest release %s; rayctl update -version %s goes back", version, newVersion, newVersion)
		}
		if *check {
			fmt.Printf("installed %s, release %s available: rayctl update\n", version, newVersion)
			return nil
		}
		if _, err := release.Extract(r.Archive, stage); err != nil {
			return err
		}
		if b, err := os.ReadFile(filepath.Join(stage, "VERSIONS")); err == nil { //nolint:gosec // G304: our staging directory
			fmt.Print(string(b))
		}
	}
	if *check {
		return nil
	}
	if !*yes {
		fmt.Printf("Update raycontrol %s to %s? rayd, rayspa and the data plane restart; clients reconnect and send SPA again. Type yes to go on: ",
			version, newVersion)
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(answer) != "yes" {
			return errors.New("not confirmed")
		}
	}

	// The binaries now in place go aside first: rollback needs no network.
	if err := os.RemoveAll(previousDir); err != nil {
		return err
	}
	if err := os.MkdirAll(previousDir, 0o700); err != nil {
		return err
	}
	for name, dst := range nodeBinaries {
		if b, err := os.ReadFile(dst); err == nil { //nolint:gosec // G304: fixed paths
			if err := os.WriteFile(filepath.Join(previousDir, name), b, 0o600); err != nil {
				return err
			}
		}
	}
	if err := os.WriteFile(filepath.Join(previousDir, "VERSION"), []byte(version+"\n"), 0o600); err != nil {
		return err
	}
	// The data-plane units that run now: after the update each must run
	// again. Taken before rayd stops: rayd restarts the units whose config
	// changed when it starts, and one the new niko-server refuses would be
	// in auto-restart, not active, by the time the update looked (review).
	before := activeDataPlane()
	// The database too, as it is with rayd stopped: the new version may
	// migrate it, and the old one must not run on the new schema (Q-2). The
	// data plane runs on meanwhile; the perimeter keeps its table.
	if err := run("systemctl", "stop", "rayd.service"); err != nil {
		return err
	}
	if err := copyDB(deploy.DB, filepath.Join(previousDir, "rayd.db")); err != nil {
		_ = run("systemctl", "start", "rayd.service")
		return fmt.Errorf("keeping the database: %w", err)
	}

	if err := installBinaries(stage); err != nil {
		return c.failUpdate(ctx, fmt.Errorf("installing: %w", err), before)
	}
	// Restart and rollback each get their own time, whatever the download
	// took.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), restartTimeout)
	defer cancel()
	if err := c.restartNode(rctx, newVersion, stage, before); err != nil {
		return c.failUpdate(ctx, err, before)
	}
	fmt.Printf("raycontrol %s is running; the previous binaries are kept for rayctl update -rollback\n", newVersion)
	c.belowDefaults(ctx)
	return nil
}

// belowDefaults says which services keep modes weaker than a new one of
// their kind gets: an update leaves them as they were (their clients may
// not do more), and only the operator knows when to change them.
func (c *cli) belowDefaults(ctx context.Context) {
	r, err := c.c.ListServices(ctx, connect.NewRequest(&nodev1.ListServicesRequest{}))
	if err != nil {
		return
	}
	for _, s := range r.Msg.Services {
		for _, line := range weakerModes(s.Kind, s.SettingsJson) {
			fmt.Printf("service %s: %s\n", s.Name, line)
		}
	}
}

// weakerModes lists what a DNS tunnel keeps below a new one's modes
// (provision.CreateService): dnstt auth required, both seal optional,
// masterdns auth optional.
func weakerModes(kind, settings string) []string {
	if kind != "dnstt" && kind != "masterdns" {
		return nil
	}
	var st struct {
		Auth string `json:"auth"`
		Seal string `json:"seal"`
	}
	_ = json.Unmarshal([]byte(settings), &st)
	var out []string
	switch {
	case kind == "dnstt" && st.Auth != "required":
		out = append(out, fmt.Sprintf("auth %s, a new dnstt service has required (rayctl service set <name> auth=required once its clients sign)", cmp.Or(st.Auth, "off")))
	case kind == "masterdns" && cmp.Or(st.Auth, "off") == "off":
		out = append(out, "auth off, a new masterdns service has optional (rayctl service set <name> auth=optional)")
	}
	if cmp.Or(st.Seal, "off") == "off" {
		out = append(out, "seal off, a new service has optional (rayctl service set <name> seal=optional)")
	}
	return out
}

// installBinaries puts the staged binaries in place: the control plane in
// /usr/local/bin, already in the install journal; the data plane through
// the journal (an older install may not have it yet).
func installBinaries(stage string) error {
	h, err := journaledHost()
	if err != nil {
		return err
	}
	// The data first: rayd reads the AS database when it changes.
	if err := installData(h, stage); err != nil {
		return err
	}
	for name, dst := range nodeBinaries {
		src := filepath.Join(stage, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if name == "xray" || name == "niko-server" {
			if _, err := h.InstallBinary(src, dst); err != nil {
				return err
			}
			continue
		}
		b, err := os.ReadFile(src) //nolint:gosec // G304: our staging directory
		if err != nil {
			return err
		}
		// Next to the target, then renamed: a running binary is never
		// written over.
		tmp := dst + ".raycontrol-new"
		if err := os.WriteFile(tmp, b, 0o755); err != nil { //nolint:gosec // G306: executables
			return err
		}
		if err := os.Rename(tmp, dst); err != nil {
			return err
		}
		if _, err := exec.LookPath("restorecon"); err == nil {
			_ = exec.Command("restorecon", dst).Run() //nolint:gosec // G204: a fixed path
		}
		fmt.Println("installed", dst)
	}
	return nil
}

// restartNode restarts the control plane, applies the deployment of the
// binaries now installed, restarts the perimeter and the data plane, and
// checks that the node answers with the expected version.
func (c *cli) restartNode(ctx context.Context, want, stage string, before []string) error {
	if err := run("systemctl", "restart", "rayd.service"); err != nil {
		return err
	}
	if err := c.waitRayd(ctx, want); err != nil {
		return err
	}
	// The rayctl now installed applies: its deployment may differ.
	apply := exec.CommandContext(ctx, "/usr/local/bin/rayctl", "apply")
	apply.Stdout, apply.Stderr = os.Stdout, os.Stderr
	if stage != "" {
		apply.Env = append(os.Environ(), updateStageEnv+"="+stage)
	}
	if err := apply.Run(); err != nil {
		return fmt.Errorf("rayctl apply: %w", err)
	}
	if err := run("systemctl", "restart", "rayspa.service"); err != nil {
		return err
	}
	restarts := map[string]string{} // each data-plane unit's restarts once restarted
	var units []string
	// The deployment's units too: one a new service brings that fails at
	// once is in auto-restart, not active, when listed (review).
	now := activeDataPlane()
	if d, err := c.c.GetDeployment(ctx, connect.NewRequest(&nodev1.GetDeploymentRequest{})); err == nil {
		for _, u := range d.Msg.Units {
			if !strings.HasPrefix(u, "niko-") {
				continue
			}
			if st, err := unitState(u)(); err == nil && waitsForFile(st) {
				continue
			}
			now = append(now, u)
		}
	}
	for _, u := range dataPlaneAfter(before, now, unitLoaded) {
		if err := run("systemctl", "try-restart", u); err != nil {
			return err
		}
		st, _ := unitState(u)()
		units, restarts[u] = append(units, u), st["NRestarts"]
	}
	for i := 0; ; i++ {
		if exec.Command("systemctl", "is-active", "--quiet", "rayspa.service").Run() == nil &&
			exec.Command("nft", "list", "table", "inet", "raycontrol").Run() == nil {
			break
		}
		if i == 30 {
			return errors.New("rayspa did not bring the perimeter back (journalctl -u rayspa)")
		}
		time.Sleep(time.Second)
	}
	return waitDataPlane(ctx, units, restarts, unitState, 3*time.Second, 30*time.Second, 500*time.Millisecond)
}

// waitDataPlane waits for each data-plane unit that ran before the update
// to run after it, and still a moment later: a config the new niko-server
// refuses, or a crash at start (a restart, or a unit that stays down),
// fails the update, which then puts the previous binaries back. The units
// of the front carry TCP and UDP 443 and DNS: without this check an update
// could leave the node with none and report success.
func waitDataPlane(ctx context.Context, units []string, restarts map[string]string,
	state func(string) func() (map[string]string, error), settle, limit, every time.Duration) error {
	for _, u := range units {
		if err := waitUnit(ctx, u, state(u), restarts[u], limit, every); err != nil {
			return err
		}
	}
	select {
	case <-ctx.Done():
		return errInterrupted
	case <-time.After(settle):
	}
	for _, u := range units {
		if err := waitUnit(ctx, u, state(u), restarts[u], limit, every); err != nil {
			return err
		}
	}
	return nil
}

// waitRayd waits until rayd answers, with the version wanted ("local" and
// "" take any).
func (c *cli) waitRayd(ctx context.Context, want string) error {
	var last error
	for range 60 {
		st, err := c.c.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{}))
		switch {
		case err != nil:
			last = err
		case want != "" && want != "local" && st.Msg.Version != want:
			last = fmt.Errorf("rayd reports %s, not %s", st.Msg.Version, want)
		default:
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("rayd did not come back: %w (journalctl -u rayd)", last)
}

// restartTimeout bounds a restart of the node, and a rollback, apart from
// the download before it.
const restartTimeout = 5 * time.Minute

// failUpdate puts the previous binaries and database back after a failed
// update.
func (c *cli) failUpdate(ctx context.Context, cause error, before []string) error {
	fmt.Println("update failed:", cause)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), restartTimeout)
	defer cancel()
	// The copy is minutes old: if the database the failed update left
	// cannot be read, the copy goes back as it is.
	// The units that ran before the update: the one whose failure brought
	// the rollback here is likely in auto-restart by now, not in the
	// rollback's own list (review).
	if err := c.rollback(ctx, "the update failed", true, carryTry, before...); err != nil {
		return fmt.Errorf("%w; rollback failed too: %w", cause, err)
	}
	return fmt.Errorf("update failed, the previous version runs again: %w", cause)
}

// rollbackUpdate installs the binaries the last update kept aside, asked
// for by hand: the database goes back only if the update moved its schema,
// and then only when confirmed, since what changed since is lost.
// carry is what a rollback does with what was revoked since the copy.
type carry int

const (
	carryMust carry = iota // carried, or no rollback
	carryTry               // carried if it can be, else the copy as it is
	carrySkip              // the copy as it is
)

func (c *cli) rollbackUpdate(ctx context.Context, yes bool, carry carry) error {
	saved := filepath.Join(previousDir, "rayd.db")
	fi, err := os.Stat(saved)
	if err != nil {
		// An update by an older rayctl kept no copy.
		fmt.Println("no copy of the database from before the update: it stays as it is")
		return c.rollback(ctx, "asked for", false, carry)
	}
	// rayd's database is read from root's copy: SQLite would follow a link
	// or block on a FIFO planted in rayd's directory.
	current, done, err := rootCopy(deploy.DB)
	if err != nil {
		return err
	}
	now, err := store.Schema(ctx, current)
	done()
	if err != nil {
		return err
	}
	then, err := store.Schema(ctx, saved)
	if err != nil {
		return err
	}
	restoreDB := now > then
	if restoreDB {
		kept := "What was taken away since stays taken away: revoked devices, disabled or deleted users and relays,\n" +
			"services taken from users or disabled, replaced certificates, the admin addresses.\n"
		if carry == carrySkip {
			kept = "-no-carry: what was revoked since comes back too.\n"
		}
		fmt.Printf("The update moved the database to schema %d; the previous version runs on %d.\n"+
			"The database goes back to its copy from %s: users, devices and settings added or changed since are lost,\n"+
			"credentials rotated since come back. %s",
			now, then, fi.ModTime().Format(time.DateTime), kept)
		if !yes {
			fmt.Print("Type yes to go on: ")
			answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if strings.TrimSpace(answer) != "yes" {
				return errors.New("not confirmed")
			}
		}
	}
	return c.rollback(ctx, "asked for", restoreDB, carry)
}

func (c *cli) rollback(ctx context.Context, why string, restoreDB bool, carry carry, ran ...string) error {
	b, err := os.ReadFile(filepath.Join(previousDir, "VERSION")) //nolint:gosec // G304: a fixed path
	if err != nil {
		return errors.New("no previous binaries: nothing to roll back to")
	}
	prev := strings.TrimSpace(string(b))
	fmt.Printf("rolling back to %s (%s)\n", prev, why)
	before := append(activeDataPlane(), ran...)
	saved := filepath.Join(previousDir, "rayd.db")
	if _, err := os.Stat(saved); restoreDB && err == nil {
		if err := run("systemctl", "stop", "rayd.service"); err != nil {
			return err
		}
		// Revocations since the copy stay (the copy is root's, in
		// previousDir): a rollback must not let a revoked device back in.
		if carry != carrySkip {
			current, done, err := rootCopy(deploy.DB)
			if err == nil {
				err = store.CarryRevocations(ctx, saved, current, node.AdminAccessSetting)
				done()
			}
			switch {
			case err != nil && carry == carryMust:
				return fmt.Errorf("keeping the revocations made since the update: %w (rayd is stopped; "+
					"rayctl update -rollback -no-carry puts the copy back as it is)", err)
			case err != nil:
				fmt.Println("the revocations since the update could not be carried, the copy goes back as it is:", err)
			}
		}
		if err := copyDB(saved, deploy.DB); err != nil {
			return fmt.Errorf("putting the database back: %w", err)
		}
		fmt.Println("database put back from", saved)
	}
	if err := installBinaries(previousDir); err != nil {
		return err
	}
	want := prev
	if want == "dev" {
		want = ""
	}
	return c.restartNode(ctx, want, "", before)
}

// copyDB copies a stopped SQLite database: the file, and its WAL if one is
// left. It runs as root in directories rayd owns, so it follows no link and
// trusts no name there: the source is opened without following a link and
// must be a regular file; each copy is a fresh temporary file (O_EXCL) in
// the destination directory, given the directory's owner through its
// descriptor, then renamed over the target (a rename replaces a planted link,
// it does not follow it). The stale WAL and shared memory go first, so a
// crash never leaves the new database next to the old one's WAL.
func copyDB(src, dst string) error {
	dir := filepath.Dir(dst)
	di, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !di.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	owner, _ := di.Sys().(*syscall.Stat_t)
	for _, stale := range []string{dst + "-wal", dst + "-shm"} {
		if err := os.Remove(stale); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, suffix := range []string{"", "-wal"} {
		b, err := readRegular(src + suffix)
		if errors.Is(err, os.ErrNotExist) && suffix != "" {
			continue
		}
		if err != nil {
			return err
		}
		f, err := os.CreateTemp(dir, filepath.Base(dst+suffix)+".*.tmp")
		if err != nil {
			return err
		}
		tmp := f.Name()
		werr := func() error {
			if _, err := f.Write(b); err != nil {
				return err
			}
			if err := f.Chmod(0o600); err != nil {
				return err
			}
			if owner != nil {
				if err := f.Chown(int(owner.Uid), int(owner.Gid)); err != nil {
					return err
				}
			}
			if err := f.Sync(); err != nil {
				return err
			}
			return f.Close()
		}()
		if werr != nil {
			f.Close()
			os.Remove(tmp)
			return werr
		}
		if err := os.Rename(tmp, dst+suffix); err != nil {
			os.Remove(tmp)
			return err
		}
	}
	return nil
}

// rootCopy copies rayd's database (and its WAL) into a directory of root's
// own, with copyDB's checks, for SQLite to read there; done removes it.
func rootCopy(db string) (path string, done func(), err error) {
	dir, err := os.MkdirTemp("", "rayctl-db-")
	if err != nil {
		return "", nil, err
	}
	done = func() { _ = os.RemoveAll(dir) }
	path = filepath.Join(dir, filepath.Base(db))
	if err := copyDB(db, path); err != nil {
		done()
		return "", nil, err
	}
	return path, done, nil
}

// readRegular reads a regular file without following a link to it.
func readRegular(name string) ([]byte, error) {
	// O_NONBLOCK: a FIFO planted in its place must not hang root here.
	f, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: rayd's database, opened without following a link
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s is a link, not the database", name)
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	return io.ReadAll(f)
}

// mirrors are the URL prefixes tried when github.com does not answer:
// RAYCONTROL_MIRRORS as for bootstrap.sh, or the same defaults.
func mirrors() []string {
	if m, ok := os.LookupEnv("RAYCONTROL_MIRRORS"); ok {
		return strings.Fields(m)
	}
	return release.DefaultMirrors
}

// updatable says why this host cannot be updated with rayctl update: no
// node here, or a relay (rayd is there too since v0.11), which takes a new
// release with install/bootstrap.sh -relay.
func updatable(db, relayBundle string) error {
	if _, err := os.Stat(db); err == nil {
		return nil
	}
	if _, err := os.Stat(relayBundle); err == nil {
		return errors.New("this host is a relay: install/bootstrap.sh -relay with its bundle takes a new release")
	}
	return errors.New("raycontrol is not installed here (install/bootstrap.sh)")
}

// activeDataPlane lists the niko-* units that run now.
func activeDataPlane() []string {
	out, _ := exec.Command("systemctl", "list-units", "niko-*.service", "--state=active", "--plain", "--no-legend").Output()
	var units []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			units = append(units, f[0])
		}
	}
	return units
}

// dataPlaneAfter are the units an update waits for: those that ran before
// it, unless the new deployment removed them, and those that run now.
func dataPlaneAfter(before, now []string, loaded func(string) bool) []string {
	var units []string
	for _, u := range before {
		if loaded(u) && !slices.Contains(units, u) {
			units = append(units, u)
		}
	}
	for _, u := range now {
		if !slices.Contains(units, u) {
			units = append(units, u)
		}
	}
	return units
}

// waitsForFile reports whether systemd skipped a unit for an unmet
// condition, no start queued: a service rendered once its certificate is
// issued (site, naive, reality, ygg) stays so until then, and an update
// does not wait for it.
func waitsForFile(st map[string]string) bool {
	return st["ActiveState"] == "inactive" && st["ConditionResult"] == "no" && (st["Job"] == "" || st["Job"] == "0")
}

// unitLoaded reports whether systemd has a unit file for unit.
func unitLoaded(unit string) bool {
	out, err := exec.Command("systemctl", "show", "-p", "LoadState", "--value", unit).Output() //nolint:gosec // G204: a unit name systemd listed
	return err == nil && strings.TrimSpace(string(out)) == "loaded"
}
