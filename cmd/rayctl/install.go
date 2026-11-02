package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/deploy"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/perimeter"
	"github.com/arngory/raycontrol/internal/render"
)

// tested are the systems the install test runs on (docs/08-decisions.md,
// R2-1); others install with a warning if the checks below pass.
var tested = map[string][]string{"debian": {"12", "13"}, "ubuntu": {"24.04"}, "rocky": {"9", "10"}}

func isTested(id, version string) bool {
	for _, v := range tested[id] {
		// Rocky's VERSION_ID carries the minor release: "10.0".
		if version == v || (id == "rocky" && strings.HasPrefix(version, v+".")) {
			return true
		}
	}
	return false
}

// minSystemd is the first systemd with every hardening directive the units
// use (ProtectClock=).
const minSystemd = 245

// preflight checks what the node needs from the host, whatever the
// distribution: systemd, the commands raycontrol runs, polkit, and an nft
// and kernel that load the perimeter table.
func preflight() (warnings []string, err error) {
	var problems []string
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		problems = append(problems, "systemd is not running")
	} else if out, err := exec.Command("systemctl", "--version").Output(); err == nil {
		if f := strings.Fields(string(out)); len(f) > 1 {
			if v, err := strconv.Atoi(f[1]); err == nil && v < minSystemd {
				problems = append(problems, fmt.Sprintf("systemd %d is too old, %d or newer is needed", v, minSystemd))
			}
		}
	}
	for _, cmd := range []string{"nft", "systemctl", "useradd", "groupadd", "usermod", "runuser", "systemd-tmpfiles", "sysctl"} {
		if _, err := exec.LookPath(cmd); err != nil {
			problems = append(problems, "command "+cmd+" is missing")
		}
	}
	for _, bin := range []string{deploy.DefaultBinaries.Rayd, deploy.DefaultBinaries.Rayspa} {
		if _, err := os.Stat(bin); err != nil {
			problems = append(problems, bin+" is missing (install/bootstrap.sh installs it)")
		}
	}
	if _, err := os.Stat("/run/dbus/system_bus_socket"); err != nil {
		problems = append(problems, "the D-Bus system bus is not running: rayd talks to systemd over it")
	}
	if out, _ := exec.Command("systemctl", "show", "-P", "LoadState", "polkit.service").Output(); strings.TrimSpace(string(out)) != "loaded" {
		problems = append(problems, "polkit is not installed: rayd restarts data-plane units through it (apt install polkitd, dnf install polkit)")
	}
	if _, err := exec.LookPath("nft"); err == nil {
		// A dry run in the kernel: nft and the kernel must support every
		// expression of the table (inet nat, maps, dynamic sets, NFLOG).
		cmd := exec.Command("nft", "-c", "-f", "-")
		cmd.Stdin = strings.NewReader((&perimeter.NFT{NflogGroup: 7}).Ruleset())
		if out, err := cmd.CombinedOutput(); err != nil {
			problems = append(problems, fmt.Sprintf("nft or the kernel cannot load the perimeter table: %v: %s", err, strings.TrimSpace(string(out))))
		}
	}
	if id, ver := osRelease(); !isTested(id, ver) {
		warnings = append(warnings, fmt.Sprintf("%s %s is not among the tested systems (Debian 12/13, Ubuntu 24.04, Rocky Linux 9/10); "+
			"the checks passed, so the install goes on", id, ver))
	}
	if len(problems) > 0 {
		return warnings, errors.New("this host cannot run a node:\n  - " + strings.Join(problems, "\n  - "))
	}
	return warnings, nil
}

func osRelease() (id, version string) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "", ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			id = v
		case "VERSION_ID":
			version = v
		}
	}
	return id, version
}

// sshPort reads the port sshd listens on, 22 if it cannot tell.
func sshPort() int {
	out, err := exec.Command("sshd", "-T").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if v, ok := strings.CutPrefix(line, "port "); ok {
				if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
					return n
				}
			}
		}
	}
	return 22
}

// sshClient returns the address of the current SSH session, if any.
func sshClient() string {
	if f := strings.Fields(os.Getenv("SSH_CONNECTION")); len(f) > 0 {
		return f[0]
	}
	if f := strings.Fields(os.Getenv("SSH_CLIENT")); len(f) > 0 {
		return f[0]
	}
	return ""
}

func needRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("must run as root")
	}
	return nil
}

// install sets the node up on this host. The perimeter goes up last, after
// the admin address and an emergency device exist, so that the operator is
// never locked out.
func (c *cli) install(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	host := fs.String("host", "", "public address clients use (required)")
	domain := fs.String("domain", "", "base domain (needed for DNS tunnels)")
	admin := fs.String("admin", sshClient(), "addresses that reach SSH without SPA (comma-separated; default: this SSH session)")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if err := needRoot(); err != nil {
		return err
	}
	if *host == "" {
		return errors.New("-host is required")
	}
	warnings, err := preflight()
	for _, w := range warnings {
		fmt.Println("warning:", w)
	}
	if err != nil {
		return err
	}
	if *admin == "" {
		return errors.New("no admin address: pass -admin, or install from an SSH session")
	}

	h := deploy.NewHost(os.Stdout)
	if err := h.EnsureGroup(deploy.AdminGroup, 0); err != nil {
		return err
	}
	// Control plane only: rayd and rayspa units, tmpfiles, polkit, sysctl.
	base := deploy.Build(render.Model{}, nil, render.DefaultPaths, deploy.DefaultBinaries)
	for _, u := range base.Users {
		if err := h.EnsureUser(u); err != nil {
			return err
		}
	}
	for _, f := range base.Files {
		if _, err := h.WriteFile(f); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(deploy.StateDir, 0o711); err != nil { //nolint:gosec // G301: services traverse to their rendered files
		return err
	}
	if err := run("chown", "rayd:rayd", deploy.StateDir); err != nil {
		return err
	}
	initArgs := []string{"-u", "rayd", "--", deploy.DefaultBinaries.Rayd, "init", "-db", deploy.DB, "-host", *host}
	if *domain != "" {
		initArgs = append(initArgs, "-domain", *domain)
	}
	if err := run("runuser", initArgs...); err != nil {
		return err
	}
	for _, cmd := range [][]string{{"daemon-reload"}, {"enable", "--now", "rayd.service"}} {
		if err := run("systemctl", cmd...); err != nil {
			return err
		}
	}
	if err := waitSocket(deploy.Socket); err != nil {
		return err
	}

	// SSH as a service, admin access, emergency device.
	port := sshPort()
	if _, err := c.c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{
		Kind: "ssh", Name: "ssh", SettingsJson: fmt.Sprintf(`{"ports":["tcp/%d"]}`, port)})); err != nil && connect.CodeOf(err) != connect.CodeAlreadyExists {
		return err
	}
	if _, err := c.c.SetAdminAccess(ctx, connect.NewRequest(&nodev1.SetAdminAccessRequest{Cidrs: splitList(*admin)})); err != nil {
		return err
	}
	var bundle string
	if _, err := c.c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{
		Name: "emergency", Services: []string{"ssh"}, Note: "SSH only, for when SPA fails"})); err == nil {
		dev, err := c.c.CreateDevice(ctx, connect.NewRequest(&nodev1.CreateDeviceRequest{User: "emergency", Name: "offline", Role: "admin"}))
		if err != nil {
			return err
		}
		bundle = dev.Msg.Bundle
	} else if connect.CodeOf(err) != connect.CodeAlreadyExists {
		return err
	}

	if err := c.deploy(ctx, "rayspa.service"); err != nil {
		return err
	}
	if err := run("systemctl", "enable", "--now", "rayspa.service"); err != nil {
		return err
	}

	fmt.Printf("\nraycontrol is installed. The perimeter is up: every port is closed except\n"+
		"SPA, public services and SSH (tcp/%d) from %s.\n", port, *admin)
	if bundle != "" {
		fmt.Printf("\nEmergency device (SSH only). Store it offline, it is shown once:\n\n%s\n", bundle)
	}
	fmt.Println("\nRecovery from the provider console: rayspa teardown")
	return nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func waitSocket(path string) error {
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("rayd did not open %s (journalctl -u rayd)", path)
}

// apply installs what the current services need.
func (c *cli) apply(ctx context.Context, _ []string) error {
	return c.deploy(ctx)
}

// deploy applies the deployment from rayd, leaving the units in keep alone.
// rayd comes first: when its unit changed (new service groups) it restarts
// and renders the files of the new services before their units start.
func (c *cli) deploy(ctx context.Context, keep ...string) error {
	if err := needRoot(); err != nil {
		return err
	}
	resp, err := c.c.GetDeployment(ctx, connect.NewRequest(&nodev1.GetDeploymentRequest{}))
	if err != nil {
		return err
	}
	plan := deploy.Plan{Units: resp.Msg.Units, Warnings: resp.Msg.Warnings}
	for _, r := range resp.Msg.HostPorts {
		plan.HostPorts = append(plan.HostPorts, deploy.PortRange{Proto: r.Proto, From: uint16(r.From), To: uint16(r.To)})
	}
	for _, u := range resp.Msg.Users {
		plan.Users = append(plan.Users, deploy.SystemUser{Name: u.Name, UID: int(u.Uid), ExtraGroups: u.ExtraGroups})
	}
	for _, f := range resp.Msg.Files {
		plan.Files = append(plan.Files, deploy.File{Path: f.Path, Mode: f.Mode, Content: f.Content})
	}
	h := deploy.NewHost(os.Stdout)
	h.Ready = func(unit string) error {
		if unit == "rayd.service" {
			// rayd opens its socket after the first render.
			return waitSocket(deploy.Socket)
		}
		return nil
	}
	return h.Apply(plan, keep...)
}

// adminAccess shows or replaces the addresses that reach SSH without SPA.
func (c *cli) adminAccess(ctx context.Context, args []string) error {
	if len(args) > 0 {
		_, err := c.c.SetAdminAccess(ctx, connect.NewRequest(&nodev1.SetAdminAccessRequest{Cidrs: splitList(strings.Join(args, ","))}))
		if err != nil {
			return err
		}
	}
	r, err := c.c.GetAdminAccess(ctx, connect.NewRequest(&nodev1.GetAdminAccessRequest{}))
	if err != nil {
		return err
	}
	return c.print(r.Msg, func(w *tabwriter.Writer) {
		if len(r.Msg.Cidrs) == 0 {
			fmt.Fprintln(w, "no admin addresses: SSH only after SPA")
		}
		for _, p := range r.Msg.Cidrs {
			fmt.Fprintln(w, p)
		}
	})
}
