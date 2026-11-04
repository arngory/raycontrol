package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/deploy"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/release"
	"github.com/arngory/raycontrol/internal/store"
)

// previousDir keeps the binaries an update replaced, for rollback; root
// only, removed with the install journal at uninstall.
var previousDir = filepath.Join(deploy.JournalDir, "previous")

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
	local := fs.String("local", "", "binaries from this directory, not verified: for tests only")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if err := needRoot(); err != nil {
		return err
	}
	if _, err := os.Stat(deploy.DefaultBinaries.Rayd); err != nil {
		return errors.New("raycontrol is not installed here (install/bootstrap.sh)")
	}
	if *rollback {
		return c.rollbackUpdate(ctx, *yes)
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
		return c.failUpdate(ctx, fmt.Errorf("installing: %w", err))
	}
	// Restart and rollback each get their own time, whatever the download
	// took.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), restartTimeout)
	defer cancel()
	if err := c.restartNode(rctx, newVersion); err != nil {
		return c.failUpdate(ctx, err)
	}
	fmt.Printf("raycontrol %s is running; the previous binaries are kept for rayctl update -rollback\n", newVersion)
	return nil
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
func (c *cli) restartNode(ctx context.Context, want string) error {
	if err := run("systemctl", "restart", "rayd.service"); err != nil {
		return err
	}
	if err := c.waitRayd(ctx, want); err != nil {
		return err
	}
	// The rayctl now installed applies: its deployment may differ.
	apply := exec.CommandContext(ctx, "/usr/local/bin/rayctl", "apply")
	apply.Stdout, apply.Stderr = os.Stdout, os.Stderr
	if err := apply.Run(); err != nil {
		return fmt.Errorf("rayctl apply: %w", err)
	}
	if err := run("systemctl", "restart", "rayspa.service"); err != nil {
		return err
	}
	out, _ := exec.Command("systemctl", "list-units", "niko-*", "--state=active", "--plain", "--no-legend").Output()
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			if err := run("systemctl", "try-restart", f[0]); err != nil {
				return err
			}
		}
	}
	for i := 0; ; i++ {
		if exec.Command("systemctl", "is-active", "--quiet", "rayspa.service").Run() == nil &&
			exec.Command("nft", "list", "table", "inet", "raycontrol").Run() == nil {
			return nil
		}
		if i == 30 {
			return errors.New("rayspa did not bring the perimeter back (journalctl -u rayspa)")
		}
		time.Sleep(time.Second)
	}
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
func (c *cli) failUpdate(ctx context.Context, cause error) error {
	fmt.Println("update failed:", cause)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), restartTimeout)
	defer cancel()
	if err := c.rollback(ctx, "the update failed", true); err != nil {
		return fmt.Errorf("%w; rollback failed too: %w", cause, err)
	}
	return fmt.Errorf("update failed, the previous version runs again: %w", cause)
}

// rollbackUpdate installs the binaries the last update kept aside, asked
// for by hand: the database goes back only if the update moved its schema,
// and then only when confirmed, since what changed since is lost.
func (c *cli) rollbackUpdate(ctx context.Context, yes bool) error {
	saved := filepath.Join(previousDir, "rayd.db")
	fi, err := os.Stat(saved)
	if err != nil {
		// An update by an older rayctl kept no copy.
		fmt.Println("no copy of the database from before the update: it stays as it is")
		return c.rollback(ctx, "asked for", false)
	}
	now, err := store.Schema(ctx, deploy.DB)
	if err != nil {
		return err
	}
	then, err := store.Schema(ctx, saved)
	if err != nil {
		return err
	}
	restoreDB := now > then
	if restoreDB {
		fmt.Printf("The update moved the database to schema %d; the previous version runs on %d.\n"+
			"The database goes back to its copy from %s: users, devices and settings changed since are lost.\n",
			now, then, fi.ModTime().Format(time.DateTime))
		if !yes {
			fmt.Print("Type yes to go on: ")
			answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if strings.TrimSpace(answer) != "yes" {
				return errors.New("not confirmed")
			}
		}
	}
	return c.rollback(ctx, "asked for", restoreDB)
}

func (c *cli) rollback(ctx context.Context, why string, restoreDB bool) error {
	b, err := os.ReadFile(filepath.Join(previousDir, "VERSION")) //nolint:gosec // G304: a fixed path
	if err != nil {
		return errors.New("no previous binaries: nothing to roll back to")
	}
	prev := strings.TrimSpace(string(b))
	fmt.Printf("rolling back to %s (%s)\n", prev, why)
	saved := filepath.Join(previousDir, "rayd.db")
	if _, err := os.Stat(saved); restoreDB && err == nil {
		if err := run("systemctl", "stop", "rayd.service"); err != nil {
			return err
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
	return c.restartNode(ctx, want)
}

// copyDB copies a stopped SQLite database: the file, and its WAL if one is
// left; a stale WAL or shared-memory file at the destination goes. The copy
// keeps the owner of the file it replaces, or else of its directory: rayd
// owns the database, root the copy kept for a rollback.
func copyDB(src, dst string) error {
	owner, err := os.Stat(dst)
	if err != nil {
		if owner, err = os.Stat(filepath.Dir(dst)); err != nil {
			return err
		}
	}
	st, _ := owner.Sys().(*syscall.Stat_t)
	for _, suffix := range []string{"", "-wal"} {
		b, err := os.ReadFile(src + suffix) //nolint:gosec // G304: fixed paths
		switch {
		case errors.Is(err, os.ErrNotExist) && suffix != "":
			if err := os.Remove(dst + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			continue
		case err != nil:
			return err
		}
		tmp := dst + suffix + ".tmp"
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			return err
		}
		if st != nil {
			if err := os.Chown(tmp, int(st.Uid), int(st.Gid)); err != nil {
				return err
			}
		}
		if err := os.Rename(tmp, dst+suffix); err != nil {
			return err
		}
	}
	if err := os.Remove(dst + "-shm"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// mirrors are the URL prefixes tried when github.com does not answer:
// RAYCONTROL_MIRRORS as for bootstrap.sh, or the same defaults.
func mirrors() []string {
	if m, ok := os.LookupEnv("RAYCONTROL_MIRRORS"); ok {
		return strings.Fields(m)
	}
	return release.DefaultMirrors
}
