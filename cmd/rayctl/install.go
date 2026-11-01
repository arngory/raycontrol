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
	"github.com/arngory/raycontrol/internal/render"
)

// supported lists the systems raycontrol is tested on (B-6).
var supported = map[string][]string{"debian": {"12", "13"}, "ubuntu": {"24.04"}}

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
	force := fs.Bool("force", false, "install on an untested system")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if err := needRoot(); err != nil {
		return err
	}
	if *host == "" {
		return errors.New("-host is required")
	}
	id, ver := osRelease()
	if v, ok := supported[id]; (!ok || !containsStr(v, ver)) && !*force {
		return fmt.Errorf("%s %s is not a tested system (Debian 12/13, Ubuntu 24.04); -force to continue", id, ver)
	}
	for _, bin := range []string{deploy.DefaultBinaries.Rayd, deploy.DefaultBinaries.Rayspa, "/usr/sbin/nft"} {
		if _, err := os.Stat(bin); err != nil {
			return fmt.Errorf("%s is missing (install/bootstrap.sh installs raycontrol; apt install nftables)", bin)
		}
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

	if err := c.apply(ctx, nil); err != nil {
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

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
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

// apply installs what the current services need. rayd is restarted last
// when its unit changed (new service groups), since it serves this request.
func (c *cli) apply(ctx context.Context, _ []string) error {
	if err := needRoot(); err != nil {
		return err
	}
	resp, err := c.c.GetDeployment(ctx, connect.NewRequest(&nodev1.GetDeploymentRequest{}))
	if err != nil {
		return err
	}
	plan := deploy.Plan{Units: resp.Msg.Units, Warnings: resp.Msg.Warnings}
	for _, u := range resp.Msg.Users {
		plan.Users = append(plan.Users, deploy.SystemUser{Name: u.Name, UID: int(u.Uid), ExtraGroups: u.ExtraGroups})
	}
	var raydUnit []byte
	for _, f := range resp.Msg.Files {
		plan.Files = append(plan.Files, deploy.File{Path: f.Path, Mode: f.Mode, Content: f.Content})
		if f.Path == "/etc/systemd/system/rayd.service" {
			raydUnit = f.Content
		}
	}
	old, _ := os.ReadFile("/etc/systemd/system/rayd.service")
	if err := deploy.NewHost(os.Stdout).Apply(plan, "rayd.service", "rayspa.service"); err != nil {
		return err
	}
	if raydUnit != nil && string(old) != string(raydUnit) {
		fmt.Println("restarting rayd (its unit changed)")
		return run("systemctl", "restart", "rayd.service")
	}
	return nil
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
