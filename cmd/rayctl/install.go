package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/deploy"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/hostcheck"
	"github.com/arngory/raycontrol/internal/render"
)

// sshdPorts reads the ports sshd listens on (sshd -T): those of its listen
// addresses, which say them all.
func sshdPorts() ([]int, error) {
	out, err := exec.Command("sshd", "-T").Output()
	if err != nil {
		return nil, fmt.Errorf("sshd -T: %w", err)
	}
	return parseSSHDPorts(string(out))
}

func parseSSHDPorts(out string) ([]int, error) {
	var ports, listen []int
	for _, line := range strings.Split(out, "\n") {
		key, v, _ := strings.Cut(strings.TrimSpace(line), " ")
		into := &ports
		switch key {
		case "port":
		case "listenaddress":
			into = &listen
			if _, p, err := net.SplitHostPort(v); err == nil {
				v = p
			}
		default:
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("sshd -T: %s %q", key, v)
		}
		if !slices.Contains(*into, n) {
			*into = append(*into, n)
		}
	}
	if len(listen) > 0 {
		return listen, nil
	}
	return ports, nil
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

// sshClient returns the address of the SSH session this command runs in,
// if any: SSH_CONNECTION (or SSH_CLIENT) of this process or, since sudo and
// su reset the environment, of the nearest parent that has it (root reads
// their environments). Only when the chain of parents reaches sshd: a
// variable left in a tmux or screen session, or set by hand, says nothing
// about where the operator is now.
func sshClient() string {
	return sshClientIn(os.Getpid(), readProc)
}

// proc is what sshClient reads of a process.
type proc struct {
	comm string
	ppid int
	env  func(string) string
}

func sshClientIn(self int, read func(pid int) (proc, bool)) string {
	addr := ""
	pid := self
	for range 32 {
		if pid <= 1 {
			return ""
		}
		p, ok := read(pid)
		if !ok {
			return ""
		}
		if p.comm == "sshd" || strings.HasPrefix(p.comm, "sshd-") || p.comm == "dropbear" {
			return addr
		}
		if addr == "" {
			for _, v := range []string{"SSH_CONNECTION", "SSH_CLIENT"} {
				if f := strings.Fields(p.env(v)); len(f) > 0 {
					addr = f[0]
					break
				}
			}
		}
		pid = p.ppid
	}
	return ""
}

// readProc reads a process from /proc; this process's environment is its
// own, as it is now.
func readProc(pid int) (proc, bool) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)) //nolint:gosec // G304: /proc
	if err != nil {
		return proc{}, false
	}
	// pid (comm) state ppid ...: comm may hold spaces and parentheses.
	s := string(stat)
	open, end := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if open < 0 || end < open {
		return proc{}, false
	}
	f := strings.Fields(s[end+1:])
	if len(f) < 2 {
		return proc{}, false
	}
	ppid, err := strconv.Atoi(f[1])
	if err != nil {
		return proc{}, false
	}
	p := proc{comm: s[open+1 : end], ppid: ppid, env: os.Getenv}
	if pid != os.Getpid() {
		vars := map[string]string{}
		if env, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid)); err == nil { //nolint:gosec // G304: /proc
			for _, kv := range strings.Split(string(env), "\x00") {
				if k, v, ok := strings.Cut(kv, "="); ok {
					vars[k] = v
				}
			}
		}
		p.env = func(k string) string { return vars[k] }
	}
	return p, true
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
	packages := fs.String("packages", "", "packages the bootstrap installed, as manager:name,name (recorded for uninstall)")
	cfToken := fs.String("cloudflare-token-file", "", "Cloudflare API token file: DNS records and wildcard certificates (needs -domain)")
	dataplane := fs.String("dataplane", "", "directory with the xray and niko-server the bootstrap verified, installed to "+deploy.DataPlaneDir)
	services := fs.String("services", "", "services to set up now: reality, hy2-masq, hy2-obfs, doh (after reality), dnstt, masterdns (default with -domain: reality; \"none\" for none)")
	checked := fs.Bool("checked", false, "the bootstrap has shown the host check: print only required checks that fail now")
	relay := fs.String("relay", "", "make this host a relay in front of an exit (relay-v1): the bundle file from rayctl relay bundle on the exit")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if err := needRoot(); err != nil {
		return err
	}
	if *relay != "" {
		return installRelay(*relay, *packages)
	}
	if *host == "" {
		return errors.New("-host is required")
	}
	// Before anything changes: a host that cannot run a node is left as it
	// was (docs/08-decisions.md, R4-24).
	if err := hostCheck(ctx, os.Stdout, hostcheck.Options{Host: *host, Domain: *domain, Services: splitList(*services)}, *checked, false); err != nil {
		return err
	}
	for _, bin := range []string{deploy.DefaultBinaries.Rayd, deploy.DefaultBinaries.Rayspa} {
		if _, err := os.Stat(bin); err != nil {
			return fmt.Errorf("%s is missing: install/bootstrap.sh installs it", bin)
		}
	}
	if *admin == "" {
		return errors.New("no admin address: pass -admin, or install from an SSH session (not from tmux or screen)")
	}
	kinds, err := installServices(*services, *domain, fs)
	if err != nil {
		return err
	}
	// Read before anything changes: a wrong path fails the install early.
	token := ""
	if *cfToken != "" {
		if *domain == "" {
			return errors.New("-cloudflare-token-file needs -domain, the zone's domain")
		}
		t, err := readToken(*cfToken)
		if err != nil {
			return err
		}
		token = t
	}

	h, err := journaledHost()
	if err != nil {
		return err
	}
	// Recorded before anything else changes: rayctl uninstall takes all of
	// it back (docs/08-decisions.md, R4-2).
	for _, b := range []string{deploy.DefaultBinaries.Rayd, deploy.DefaultBinaries.Rayspa, "/usr/local/bin/rayctl"} {
		if _, err := os.Stat(b); err == nil {
			if err := h.Journal.Record(deploy.Change{Kind: deploy.ChangeBinary, Path: b}); err != nil {
				return err
			}
		}
	}
	if manager, names, ok := strings.Cut(*packages, ":"); ok {
		for _, name := range splitList(names) {
			if err := h.Journal.Record(deploy.Change{Kind: deploy.ChangePackage, Name: name, Value: manager}); err != nil {
				return err
			}
		}
	}
	if _, err := os.Stat(deploy.StateDir); err != nil {
		if err := h.Journal.Record(deploy.Change{Kind: deploy.ChangeState, Path: deploy.StateDir}); err != nil {
			return err
		}
	}
	if err := h.EnsureGroup(deploy.AdminGroup, 0); err != nil {
		return err
	}
	// The data plane the bootstrap downloaded and verified with the release
	// (one signature for all of it), in a directory of its own.
	if *dataplane != "" {
		for _, b := range []struct{ name, dst string }{{"xray", deploy.DefaultBinaries.Xray}, {"niko-server", deploy.DefaultBinaries.NikoServer}} {
			src := filepath.Join(*dataplane, b.name)
			if _, err := os.Stat(src); err != nil {
				fmt.Printf("warning: %s is not in %s: its services stay off until it is installed\n", b.name, *dataplane)
				continue
			}
			if _, err := h.InstallBinary(src, b.dst); err != nil {
				return fmt.Errorf("installing %s: %w", b.name, err)
			}
			fmt.Println("installed", b.dst)
		}
		if err := installData(h, *dataplane); err != nil {
			return err
		}
	}
	// Control plane only: rayd and rayspa units, tmpfiles, polkit, sysctl.
	base := deploy.Build(render.Model{}, nil, render.DefaultPaths, deploy.DefaultBinaries)
	for _, u := range base.Users {
		if err := h.EnsureUser(u); err != nil {
			return err
		}
	}
	var sysctl []deploy.File
	for _, f := range base.Files {
		changed, err := h.WriteFile(f)
		if err != nil {
			return err
		}
		if changed && strings.HasPrefix(f.Path, "/etc/sysctl.d/") {
			sysctl = append(sysctl, f)
		}
	}
	// Now, not at the next boot; the journal keeps the values it replaces.
	h.ApplySysctl(sysctl)
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
	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := h.EnableNow("rayd.service"); err != nil {
		return err
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

	// The DNS provider before the services: their certificate then goes
	// through DNS-01 from the start.
	if token != "" {
		r, err := c.c.SetDNSProvider(ctx, connect.NewRequest(&nodev1.SetDNSProviderRequest{Provider: "cloudflare", Token: token}))
		if err != nil {
			fmt.Println("warning: Cloudflare not set up (rayctl dns cloudflare later):", err)
		} else {
			fmt.Printf("Cloudflare zone %s: records kept by rayd, certificates through DNS-01.\n", r.Msg.Status.Zone)
			for _, ch := range r.Msg.Status.Changes {
				fmt.Println(" ", ch)
			}
			for _, p := range r.Msg.Status.Problems {
				fmt.Println("  problem:", p)
			}
		}
	}
	var created []string
	for _, k := range kinds {
		_, err := c.c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: k.kind, Name: k.name}))
		switch {
		case err == nil:
			created = append(created, k.name)
		case connect.CodeOf(err) == connect.CodeAlreadyExists:
		default:
			fmt.Printf("warning: service %s not created (rayctl service add %s %s later): %v\n", k.name, k.kind, k.name, err)
		}
	}

	if err := c.deploy(ctx, h, "rayspa.service"); err != nil {
		return err
	}
	if err := h.EnableNow("rayspa.service"); err != nil {
		return err
	}
	if len(created) > 0 {
		fmt.Printf("\nServices: %s.", strings.Join(created, ", "))
		if slices.Contains(created, "reality") {
			fmt.Print(" REALITY starts once its certificate is stored (journalctl -u rayd -f).")
		}
		fmt.Println()
	}

	fmt.Printf("\nraycontrol is installed. The perimeter is up: every port is closed except\n"+
		"SPA, public services and SSH (tcp/%d) from %s.\n", port, *admin)
	if bundle != "" {
		fmt.Printf("\nEmergency device (SSH only). Store it offline, it is shown once:\n\n%s\n", bundle)
	}
	fmt.Println("\nRecovery from the provider console: rayspa teardown")
	return nil
}

type serviceKind struct{ kind, name string }

// installServices turns -services into the services install creates, by
// kind with their usual names. Without the flag a node with a domain gets
// REALITY (self-steal on its own site); "none" creates none.
func installServices(list, domain string, fs *flag.FlagSet) ([]serviceKind, error) {
	set := false
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == "services" })
	if !set {
		if domain == "" {
			return nil, nil
		}
		list = "reality"
	}
	names := map[string]string{"reality": "reality", "dnstt": "dns", "masterdns": "mdns", "hy2-masq": "hy2-masq", "hy2-obfs": "hy2-obfs", "doh": "doh"}
	var out []serviceKind
	for _, k := range splitList(list) {
		if k == "none" {
			return nil, nil
		}
		name, ok := names[k]
		if !ok {
			return nil, fmt.Errorf("-services: %q is not one of reality, hy2-masq, hy2-obfs, doh, dnstt, masterdns", k)
		}
		if domain == "" {
			return nil, fmt.Errorf("-services %s needs -domain", k)
		}
		out = append(out, serviceKind{k, name})
	}
	return out, nil
}

// journaledHost acts on this machine and records every change.
func journaledHost() (*deploy.Host, error) {
	j, err := deploy.OpenJournal("")
	if err != nil {
		return nil, err
	}
	h := deploy.NewHost(os.Stdout)
	h.Journal = j
	return h, nil
}

// uninstall takes back everything rayctl install and apply changed, and
// the node's records in its DNS provider's zone.
func (c *cli) uninstall(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "do not ask")
	keep := fs.Bool("keep-state", false, "keep "+deploy.StateDir+" (users, keys, certificates) for a later install")
	keepDNS := fs.Bool("keep-dns", false, "leave raycontrol's records in the DNS provider's zone")
	purge := fs.Bool("purge-packages", false, "also remove the packages the bootstrap installed")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if err := needRoot(); err != nil {
		return err
	}
	if !*yes {
		fmt.Print("This stops the node, opens the perimeter and removes raycontrol with its users, keys and data")
		if *keep {
			fmt.Print(" (state kept)")
		}
		fmt.Print(" (rayctl backup first keeps a way back). Type yes to go on: ")
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(answer) != "yes" {
			return errors.New("not confirmed")
		}
	}
	// While rayd still runs: its DNS records go first (it holds the token).
	if !*keepDNS && !*keep {
		if _, err := os.Stat(deploy.Socket); err == nil {
			r, err := c.c.RemoveDNS(ctx, connect.NewRequest(&nodev1.RemoveDNSRequest{}))
			if err != nil {
				fmt.Println("warning: DNS records not removed (rayctl dns remove before uninstall, or by hand):", err)
			} else {
				for _, rec := range r.Msg.Removed {
					fmt.Println("removed DNS record", rec)
				}
			}
		}
	}
	h, err := journaledHost()
	if err != nil {
		return err
	}
	if err := h.Uninstall(h.Journal, deploy.UninstallOptions{KeepState: *keep, PurgePackages: *purge}); err != nil {
		return fmt.Errorf("uninstall finished with errors: %w", err)
	}
	fmt.Println("raycontrol is removed.")
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
	if err := needRoot(); err != nil {
		return err
	}
	h, err := journaledHost()
	if err != nil {
		return err
	}
	return c.deploy(ctx, h)
}

// deploy applies the deployment from rayd, leaving the units in keep alone.
// rayd comes first: when its unit changed (new service groups) it restarts
// and renders the files of the new services before their units start.
func (c *cli) deploy(ctx context.Context, h *deploy.Host, keep ...string) error {
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
	h.Ready = func(unit string) error {
		if unit == "rayd.service" {
			// rayd opens its socket after the first render.
			return waitSocket(deploy.Socket)
		}
		return nil
	}
	if err := h.Apply(plan, keep...); err != nil {
		return err
	}
	if len(resp.Msg.OutsidePorts) > 0 {
		fmt.Println("a firewall of the provider in front of the host (security group, cloud firewall) must let in:",
			outsidePorts(resp.Msg.OutsidePorts))
	}
	return nil
}

// outsidePorts lists port ranges for a person: "tcp+udp 443, tcp 22".
func outsidePorts(rs []*nodev1.PortRange) string {
	type span struct{ from, to uint32 }
	var order []span
	protos := map[span][]string{}
	for _, r := range rs {
		k := span{r.From, r.To}
		if _, ok := protos[k]; !ok {
			order = append(order, k)
		}
		protos[k] = append(protos[k], r.Proto)
	}
	slices.SortFunc(order, func(a, b span) int { return int(a.from) - int(b.from) })
	var out []string
	for _, k := range order {
		ps := protos[k]
		slices.Sort(ps)
		n := strconv.Itoa(int(k.from))
		if k.to != k.from {
			n += "-" + strconv.Itoa(int(k.to))
		}
		out = append(out, strings.Join(slices.Compact(ps), "+")+" "+n)
	}
	return strings.Join(out, ", ")
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

// installData puts the release's data (the AS database and its notice) in
// deploy.DataDir through the journal; a release without it changes nothing.
func installData(h *deploy.Host, dir string) error {
	for _, name := range deploy.DataFiles {
		b, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // G304: the verified release
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		dst := filepath.Join(deploy.DataDir, name)
		changed, err := h.WriteFile(deploy.File{Path: dst, Mode: 0o644, Content: b})
		if err != nil {
			return fmt.Errorf("installing %s: %w", name, err)
		}
		if changed {
			fmt.Println("installed", dst)
		}
	}
	return nil
}
