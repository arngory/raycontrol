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
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/deploy"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/release"
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
		return c.rollbackUpdate(ctx, "asked for")
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

	if err := installBinaries(stage); err != nil {
		return c.failUpdate(ctx, fmt.Errorf("installing: %w", err))
	}
	if err := c.restartNode(ctx, newVersion); err != nil {
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

// failUpdate puts the previous binaries back after a failed update.
func (c *cli) failUpdate(ctx context.Context, cause error) error {
	fmt.Println("update failed:", cause)
	if err := c.rollbackUpdate(ctx, "the update failed"); err != nil {
		return fmt.Errorf("%w; rollback failed too: %w", cause, err)
	}
	return fmt.Errorf("update failed, the previous version runs again: %w", cause)
}

// rollbackUpdate installs the binaries the last update kept aside.
func (c *cli) rollbackUpdate(ctx context.Context, why string) error {
	b, err := os.ReadFile(filepath.Join(previousDir, "VERSION")) //nolint:gosec // G304: a fixed path
	if err != nil {
		return errors.New("no previous binaries: nothing to roll back to")
	}
	prev := strings.TrimSpace(string(b))
	fmt.Printf("rolling back to %s (%s)\n", prev, why)
	if err := installBinaries(previousDir); err != nil {
		return err
	}
	want := prev
	if want == "dev" {
		want = ""
	}
	return c.restartNode(ctx, want)
}

// mirrors are the URL prefixes tried when github.com does not answer:
// RAYCONTROL_MIRRORS as for bootstrap.sh, or the same defaults.
func mirrors() []string {
	if m, ok := os.LookupEnv("RAYCONTROL_MIRRORS"); ok {
		return strings.Fields(m)
	}
	return release.DefaultMirrors
}
