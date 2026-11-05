package deploy_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

func plan(t *testing.T) (deploy.Plan, render.Model) {
	t.Helper()
	m, files := plan2(t, render.DefaultPaths)
	return deploy.Build(m, files, render.DefaultPaths, deploy.DefaultBinaries), m
}

// plan2 renders the test node's services for the paths.
func plan2(t *testing.T, paths render.Paths) (render.Model, []render.File) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	for _, s := range [][3]string{{"dnstt", "dns", ""}, {"reality", "reality", `{"target":"www.example.org:443"}`}, {"olcrtc", "olc", ""}} {
		if _, err := provision.CreateService(ctx, st, store.Service{Kind: s[0], Name: s[1], Enabled: true, Settings: s[2]}); err != nil {
			t.Fatal(err)
		}
	}
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	files, _, err := render.Render(m, paths)
	if err != nil {
		t.Fatal(err)
	}
	return m, files
}

func file(p deploy.Plan, path string) string {
	for _, f := range p.Files {
		if f.Path == path {
			return string(f.Content)
		}
	}
	return ""
}

func TestBuild(t *testing.T) {
	p, _ := plan(t)
	users := map[string]deploy.SystemUser{}
	for _, u := range p.Users {
		users[u.Name] = u
	}
	if users["niko-front"].UID != 9100 || users["rayd"].UID != 9190 || users["rayspa"].UID != 9191 {
		t.Fatalf("fixed uids: %+v", users)
	}
	// The front reaches REALITY's socket (tcpmux, R2-15) and the DNS backends
	// through their -in directories, not their groups (S-1).
	if len(users["niko-front"].ExtraGroups) != 0 ||
		!slices.Equal(users["niko-dns"].ExtraGroups, []string{"niko-inner"}) ||
		!slices.Equal(users["rayd"].ExtraGroups, []string{"niko-dns", "niko-front", "niko-inner", "niko-reality"}) {
		t.Fatalf("groups: %+v", users)
	}
	if !slices.Equal(p.Units, []string{"rayd.service", "rayspa.service", "niko-inner.service", "niko-reality.service", "niko-dns.service", "niko-front.service"}) {
		t.Fatalf("units %v", p.Units)
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "olc") {
		t.Fatalf("warnings %v", p.Warnings)
	}
	// REALITY behind the front: a unix socket, no capability (R2-15).
	reality := file(p, "/etc/systemd/system/niko-reality.service")
	for _, want := range []string{"User=niko-reality", "CapabilityBoundingSet=\n",
		"ExecStart=/usr/local/libexec/raycontrol/xray run -c /var/lib/raycontrol/rendered/reality/xray.json", "ReadWritePaths=/run/niko/reality-api"} {
		if !strings.Contains(reality, want) {
			t.Errorf("reality unit lacks %q", want)
		}
	}
	if strings.Contains(reality, "CAP_NET_BIND_SERVICE") {
		t.Error("REALITY binds a port itself behind the front")
	}
	if !strings.Contains(file(p, "/etc/tmpfiles.d/raycontrol.conf"), "d /run/niko/reality-api 2750 niko-reality rayd") {
		t.Error("REALITY API directory not restricted to rayd")
	}

	dns := file(p, "/etc/systemd/system/niko-dns.service")
	for _, want := range []string{
		"User=niko-dns", "SupplementaryGroups=niko-inner", "PrivateNetwork=yes", "RestrictAddressFamilies=AF_UNIX\n",
		"ExecStartPre=+install -m 0400 -o niko-dns -g niko-dns /var/lib/raycontrol/rendered/dns/noise.key /run/niko/dns/noise.key\n", "RuntimeDirectory=niko/dns", "CapabilityBoundingSet=\n",
		"ExecStart=/usr/local/libexec/raycontrol/niko-server backend -c /var/lib/raycontrol/rendered/dns/backend.json",
	} {
		if !strings.Contains(dns, want) {
			t.Errorf("dns unit lacks %q", want)
		}
	}
	front := file(p, "/etc/systemd/system/niko-front.service")
	if !strings.Contains(front, "AmbientCapabilities=CAP_NET_BIND_SERVICE") || strings.Contains(front, "SupplementaryGroups") ||
		!strings.Contains(front, "After=network-online.target niko-dns.service niko-reality.service") {
		t.Errorf("front unit:\n%s", front)
	}
	if !strings.Contains(file(p, "/etc/systemd/system/rayspa.service"), "AmbientCapabilities=CAP_NET_ADMIN") {
		t.Error("rayspa lacks CAP_NET_ADMIN")
	}
	if !strings.Contains(file(p, "/etc/tmpfiles.d/raycontrol.conf"), "d /run/niko/inner-api 2750 niko-inner rayd") {
		t.Error("inner API directory not restricted to rayd")
	}
	// The DNS tunnels share UDP 53 with systemd-resolved's stub: the host's
	// resolver stays as it is.
	if !p.FrontDNS || file(p, deploy.ResolvedDropIn) != "" {
		t.Error("the front does not answer DNS, or the resolver is changed")
	}

	// Without systemd (rayd serve -supervise): the data-plane units only,
	// from their own lines.
	var units []string
	for _, pr := range p.Processes {
		units = append(units, pr.Unit)
	}
	if !slices.Equal(units, p.Units[2:]) {
		t.Fatalf("processes %v, units %v", units, p.Units)
	}
	d := p.Processes[2]
	if d.Unit != "niko-dns.service" || d.Dir != "/run/niko/dns" || d.Needs != "/var/lib/raycontrol/rendered/dns/backend.json" ||
		!slices.Equal(d.Args, []string{"/usr/local/libexec/raycontrol/niko-server", "backend", "-c", "/var/lib/raycontrol/rendered/dns/backend.json"}) ||
		len(d.Copies) != 1 || d.Copies[0] != [2]string{"/var/lib/raycontrol/rendered/dns/noise.key", "/run/niko/dns/noise.key"} {
		t.Errorf("dns process %+v", d)
	}
	if !slices.Contains(p.Dirs, "/run/niko") || !slices.Contains(p.Dirs, "/run/niko/reality-api") {
		t.Errorf("dirs %v", p.Dirs)
	}
	// Paths outside /run stay where they are.
	other := render.Paths{Rendered: "/tmp/r", Run: "/tmp/run"}
	m, files := plan2(t, other)
	q := deploy.Build(m, files, other, deploy.DefaultBinaries)
	if q.Processes[0].Dir != "/tmp/run/inner" || !slices.Contains(q.Dirs, "/tmp/run/inner-api") {
		t.Errorf("inner process %+v, dirs %v", q.Processes[0], q.Dirs)
	}
}

func TestHostApply(t *testing.T) {
	p, _ := plan(t)
	root := t.TempDir()
	var cmds []string
	existing := map[string]int{"rayd": 9190}
	h := &deploy.Host{
		Root: root,
		Out:  &bytes.Buffer{},
		Run: func(name string, args ...string) ([]byte, error) {
			cmds = append(cmds, name+" "+strings.Join(args, " "))
			return nil, nil
		},
		LookupUser: func(n string) (int, error) {
			if uid, ok := existing[n]; ok {
				return uid, nil
			}
			return 0, errors.New("unknown user")
		},
		LookupGroup: func(n string) (int, error) {
			if uid, ok := existing[n]; ok {
				return uid, nil
			}
			return 0, errors.New("unknown group")
		},
	}
	// Only xray and rayd exist on this host; niko-server is not installed yet.
	for _, bin := range []string{deploy.DefaultBinaries.Xray, deploy.DefaultBinaries.Rayd} {
		os.MkdirAll(filepath.Join(root, filepath.Dir(bin)), 0o755)
		os.WriteFile(filepath.Join(root, bin), nil, 0o755)
	}
	// A unit of a deleted service and resolv.conf on the stub.
	os.MkdirAll(filepath.Join(root, "/etc/systemd/system"), 0o755)
	os.WriteFile(filepath.Join(root, "/etc/systemd/system/niko-old.service"), []byte("x"), 0o644)
	os.Symlink("../run/systemd/resolve/stub-resolv.conf", filepath.Join(root, "/etc/resolv.conf"))

	if err := h.Apply(p, "rayd.service"); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(cmds, "\n")
	for _, want := range []string{
		"useradd --system --uid 9100 --gid niko-front", "groupadd --system --gid 9100 niko-front",
		"usermod --groups  niko-front", "usermod --groups niko-inner niko-dns",
		"systemctl enable --now niko-inner.service", "systemctl disable --now niko-old.service",
		"systemd-tmpfiles --create",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing command %q in:\n%s", want, all)
		}
	}
	for _, unwanted := range []string{"useradd --system --uid 9190", "enable --now niko-dns.service", "enable --now rayd.service",
		"systemd-resolved"} {
		if strings.Contains(all, unwanted) {
			t.Errorf("unexpected %q", unwanted)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "/etc/systemd/system/niko-old.service")); !os.IsNotExist(err) {
		t.Error("stale unit kept")
	}
	if target, _ := os.Readlink(filepath.Join(root, "/etc/resolv.conf")); target != "../run/systemd/resolve/stub-resolv.conf" {
		t.Errorf("resolv.conf -> %s", target)
	}

	// A second apply changes nothing and restarts nothing.
	cmds = nil
	if err := h.Apply(p, "rayd.service"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(cmds, "\n"), "try-restart") {
		t.Errorf("second apply restarted: %v", cmds)
	}
}

func TestUIDConflict(t *testing.T) {
	h := &deploy.Host{
		Run:         func(string, ...string) ([]byte, error) { return nil, nil },
		LookupUser:  func(string) (int, error) { return 1234, nil },
		LookupGroup: func(string) (int, error) { return 9190, nil },
	}
	if err := h.EnsureUser(deploy.SystemUser{Name: "rayd", UID: 9190}); err == nil {
		t.Fatal("existing user with another uid accepted")
	}
}

func TestMergePorts(t *testing.T) {
	got := deploy.MergePorts([]deploy.PortRange{
		{"udp", 40000, 44095}, {"tcp", 443, 443}, {"udp", 53, 53}, {"tcp", 22, 22},
		{"udp", 443, 443}, {"tcp", 443, 443}, {"udp", 44096, 44096}, {"tcp", 40000, 44095},
	})
	var s []string
	for _, r := range got {
		s = append(s, r.String())
	}
	if want := "tcp/22 tcp/443 tcp/40000-44095 udp/53 udp/443 udp/40000-44096"; strings.Join(s, " ") != want {
		t.Fatalf("merged %v", s)
	}
}

func TestHostFirewalls(t *testing.T) {
	p, _ := plan(t)
	p.HostPorts = []deploy.PortRange{{"tcp", 22, 22}, {"tcp", 40000, 44095}, {"udp", 53, 53}}
	p.Files = append(p.Files, deploy.FirewallFiles(p.HostPorts)...)
	if xml := file(p, deploy.FirewalldService); !strings.Contains(xml, `<port protocol="tcp" port="40000-44095"/>`) {
		t.Fatalf("firewalld service:\n%s", xml)
	}
	if prof := file(p, deploy.UFWProfile); !strings.Contains(prof, "ports=22/tcp|40000:44095/tcp|53/udp\n") {
		t.Fatalf("ufw profile:\n%s", prof)
	}

	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "/etc/firewalld"), 0o755)
	os.MkdirAll(filepath.Join(root, "/proc/net"), 0o755)
	// 127.0.0.1:53 held by uid 101 (another resolver), 0.0.0.0:53 by the front.
	os.WriteFile(filepath.Join(root, "/proc/net/udp"), []byte(
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"+
			"  1: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 1 2 0 0\n"+
			"  2: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000  9100        0 1 2 0 0\n"), 0o644)
	var cmds []string
	out := &bytes.Buffer{}
	h := &deploy.Host{
		Root: root,
		Out:  out,
		Run: func(name string, args ...string) ([]byte, error) {
			c := name + " " + strings.Join(args, " ")
			cmds = append(cmds, c)
			switch {
			case c == "firewall-cmd --get-default-zone":
				return []byte("public\n"), nil
			case c == "firewall-cmd --get-active-zones":
				return []byte("public\n  interfaces: eth0\ninternal\n  sources: 10.0.0.0/8\n"), nil
			case strings.Contains(c, "--query-service"):
				return nil, errors.New("exit status 1")
			case c == "nft -j list chains":
				return []byte(`{"nftables":[{"metainfo":{}},` +
					`{"chain":{"family":"inet","table":"raycontrol","name":"input","hook":"input","policy":"drop"}},` +
					`{"chain":{"family":"inet","table":"filter","name":"input","hook":"input","policy":"drop"}},` +
					`{"chain":{"family":"inet","table":"filter","name":"output","hook":"output","policy":"drop"}}]}`), nil
			}
			return nil, nil
		},
		LookPath:    func(name string) (string, error) { return "/usr/bin/" + name, nil },
		LookupUser:  func(string) (int, error) { return 0, errors.New("unknown") },
		LookupGroup: func(string) (int, error) { return 0, errors.New("unknown") },
	}
	if err := h.Apply(p, "rayd.service"); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(cmds, "\n")
	for _, want := range []string{
		"firewall-cmd --permanent --zone=internal --add-service=raycontrol",
		"firewall-cmd --permanent --zone=public --add-service=raycontrol",
		"firewall-cmd --reload",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
	if strings.Contains(all, "ufw") {
		t.Error("ufw configured though /etc/ufw does not exist")
	}
	if _, err := os.Stat(filepath.Join(root, deploy.UFWProfile)); !os.IsNotExist(err) {
		t.Error("ufw profile written without ufw")
	}
	log := out.String()
	for _, want := range []string{
		"warning: nftables chain inet filter input drops incoming packets by default; it must accept tcp/22 tcp/40000-44095 udp/53",
		"warning: UDP port 53 (127.0.0.1) is taken by ",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("missing %q in:\n%s", want, log)
		}
	}
	if strings.Contains(log, "raycontrol input drops") || strings.Contains(log, "0.0.0.0") {
		t.Errorf("own table or the front reported:\n%s", log)
	}
}

func TestBuildSelfSteal(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	files, skipped, err := render.Render(m, render.DefaultPaths)
	if err != nil {
		t.Fatal(err)
	}
	// No certificate yet: site and REALITY wait; their units exist but are
	// skipped by their conditions until rayd renders the files.
	if len(skipped) != 2 {
		t.Fatalf("skipped %v", skipped)
	}
	p := deploy.Build(m, files, render.DefaultPaths, deploy.DefaultBinaries)
	if p.FrontDNS {
		t.Error("the front answers DNS on a node without DNS tunnels")
	}
	site := file(p, "/etc/systemd/system/niko-site.service")
	for _, want := range []string{
		"ConditionPathExists=/var/lib/raycontrol/rendered/site/chain.pem\n",
		"ExecStartPre=+install -m 0400 -o niko-site -g niko-site /var/lib/raycontrol/rendered/site/key.pem /run/niko/site/key.pem\n",
		// The default answer: 404 to everything, no content directory (R4-8).
		"ExecStart=/usr/local/bin/rayd site -answer 404 -chain /var/lib/raycontrol/rendered/site/chain.pem -key /run/niko/site/key.pem -socket /run/niko/site/tls.sock\n",
		"PrivateNetwork=yes\n", "RestrictAddressFamilies=AF_UNIX\n",
	} {
		if !strings.Contains(site, want) {
			t.Errorf("site unit lacks %q:\n%s", want, site)
		}
	}
	if !strings.Contains(file(p, "/etc/systemd/system/niko-r.service"), "ConditionPathExists=/var/lib/raycontrol/rendered/r/xray.json\n") {
		t.Error("REALITY unit without its condition")
	}
	for _, u := range p.Users {
		if u.Name == "niko-r" && !slices.Equal(u.ExtraGroups, []string{"niko-site"}) {
			t.Errorf("REALITY user groups %v: it must reach the site socket", u.ExtraGroups)
		}
	}
}

func TestJournalAndUninstall(t *testing.T) {
	p, _ := plan(t)
	p.HostPorts = []deploy.PortRange{{"tcp", 22, 22}}
	p.Files = append(p.Files, deploy.FirewallFiles(p.HostPorts)...)
	root := t.TempDir()
	write := func(path, content string) {
		os.MkdirAll(filepath.Join(root, filepath.Dir(path)), 0o755)
		os.WriteFile(filepath.Join(root, path), []byte(content), 0o644)
	}
	// The host before: a firewalld zone of its own, resolv.conf on the stub,
	// an existing sysctl directory and binaries.
	write("/etc/firewalld/zones/public.xml", "<zone>original</zone>\n")
	write("/etc/sysctl.d/10-local.conf", "vm.swappiness = 10\n")
	write("/usr/local/bin/xray", "")
	os.Symlink("../run/systemd/resolve/stub-resolv.conf", filepath.Join(root, "/etc/resolv.conf"))

	users := map[string]int{}
	var cmds []string
	congestion := "cubic"
	h := &deploy.Host{
		Root: root,
		Out:  &bytes.Buffer{},
		Run: func(name string, args ...string) ([]byte, error) {
			c := name + " " + strings.Join(args, " ")
			cmds = append(cmds, c)
			switch {
			case name == "useradd" || name == "groupadd":
				users[name[:1]+args[len(args)-1]] = 1
			case name == "userdel" || name == "groupdel":
				delete(users, name[:1]+args[len(args)-1])
			case c == "sysctl -n net.ipv4.tcp_congestion_control":
				return []byte(congestion + "\n"), nil
			case c == "sysctl -n net.core.rmem_max":
				return []byte("4194304\n"), nil // a global key a container cannot set
			case strings.HasPrefix(c, "sysctl -q -e -p "):
				congestion = "bbr"
			case strings.HasPrefix(c, "sysctl -q -w net.ipv4.tcp_congestion_control="):
				congestion = strings.TrimPrefix(c, "sysctl -q -w net.ipv4.tcp_congestion_control=")
			case c == "firewall-cmd --get-default-zone":
				return []byte("public\n"), nil
			case strings.Contains(c, "--query-service"):
				return nil, errors.New("exit status 1")
			}
			return nil, nil
		},
		LookPath: func(name string) (string, error) {
			if name == "firewall-cmd" {
				return "/usr/bin/firewall-cmd", nil
			}
			return "", errors.New("not found")
		},
		LookupUser: func(n string) (int, error) {
			if _, ok := users["u"+n]; ok {
				return 1, nil
			}
			return 0, errors.New("unknown")
		},
		LookupGroup: func(n string) (int, error) {
			if _, ok := users["g"+n]; ok {
				return 1, nil
			}
			return 0, errors.New("unknown")
		},
	}
	j, err := deploy.OpenJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	h.Journal = j
	os.MkdirAll(filepath.Join(root, "/etc/firewalld/services"), 0o755)
	if err := h.Apply(p); err != nil {
		t.Fatal(err)
	}
	// rayd wrote its state; firewalld rewrote the zone.
	j.Record(deploy.Change{Kind: deploy.ChangeState, Path: deploy.StateDir})
	write(deploy.StateDir+"/rayd.db", "db")
	write("/etc/firewalld/zones/public.xml", "<zone>with raycontrol</zone>\n")

	j2, err := deploy.OpenJournal(root)
	if err != nil || !j2.Exists() || len(j2.Changes) == 0 {
		t.Fatalf("journal not saved: %v", err)
	}
	cmds = nil
	if err := h.Uninstall(j2, deploy.UninstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "/etc/firewalld/zones/public.xml")); string(b) != "<zone>original</zone>\n" {
		t.Fatalf("zone file %q", b)
	}
	if target, _ := os.Readlink(filepath.Join(root, "/etc/resolv.conf")); target != "../run/systemd/resolve/stub-resolv.conf" {
		t.Fatalf("resolv.conf -> %s", target)
	}
	for _, gone := range []string{"/etc/systemd/system/rayd.service", "/etc/systemd/system/niko-dns.service",
		"/etc/sysctl.d/90-raycontrol.conf", "/etc/tmpfiles.d/raycontrol.conf", deploy.FirewalldService,
		"/etc/systemd/resolved.conf.d", deploy.StateDir, deploy.JournalDir} {
		if _, err := os.Stat(filepath.Join(root, gone)); !os.IsNotExist(err) {
			t.Errorf("%s still there", gone)
		}
	}
	for _, kept := range []string{"/etc/sysctl.d/10-local.conf", "/usr/local/bin/xray", "/etc/firewalld/services"} {
		if _, err := os.Stat(filepath.Join(root, kept)); err != nil {
			t.Errorf("%s removed: %v", kept, err)
		}
	}
	if len(users) != 0 {
		t.Errorf("users and groups left: %v", users)
	}
	all := strings.Join(cmds, "\n")
	for _, want := range []string{"systemctl disable --now niko-front.service", "nft delete table inet raycontrol",
		"sysctl -q -w net.ipv4.tcp_congestion_control=cubic", "firewall-cmd --reload", "systemctl daemon-reload"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
	if strings.Index(all, "disable --now rayspa.service") > strings.Index(all, "disable --now rayd.service") {
		t.Error("rayspa must stop before rayd")
	}
	if strings.Contains(all, "-w net.core.rmem_max") {
		t.Error("set back a value that never changed")
	}
}

func TestUninstallWithoutJournal(t *testing.T) {
	root := t.TempDir()
	write := func(path, content string) {
		os.MkdirAll(filepath.Join(root, filepath.Dir(path)), 0o755)
		os.WriteFile(filepath.Join(root, path), []byte(content), 0o644)
	}
	write("/etc/systemd/system/rayd.service", "# Generated by raycontrol\n")
	write("/etc/systemd/system/niko-dns.service", "# Generated by raycontrol\n")
	write("/etc/systemd/system/other.service", "[Unit]\n")
	write("/etc/sysctl.d/90-raycontrol.conf", "# Generated by raycontrol\n")
	write("/etc/passwd", "root:x:0:0::/root:/bin/sh\nrayd:x:9190:9190::/nonexistent:/usr/sbin/nologin\nniko-dns:x:9111:9111::/x:/x\nniko-fan:x:1001:1001::/x:/x\n")
	write("/var/lib/raycontrol/rayd.db", "db")
	write("/usr/local/bin/rayd", "")
	var cmds []string
	h := &deploy.Host{Root: root, Out: &bytes.Buffer{},
		Run: func(name string, args ...string) ([]byte, error) {
			cmds = append(cmds, name+" "+strings.Join(args, " "))
			return nil, nil
		},
		LookupUser:  func(string) (int, error) { return 1, nil },
		LookupGroup: func(string) (int, error) { return 1, nil },
	}
	j, _ := deploy.OpenJournal(root)
	if err := h.Uninstall(j, deploy.UninstallOptions{}); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(cmds, "\n")
	for _, want := range []string{"userdel rayd", "userdel niko-dns", "groupdel raycontrol", "systemctl disable --now niko-dns.service"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
	if strings.Contains(all, "niko-fan") {
		t.Error("a user outside the raycontrol UID range removed")
	}
	if _, err := os.Stat(filepath.Join(root, "/etc/systemd/system/other.service")); err != nil {
		t.Error("a foreign unit removed")
	}
	for _, gone := range []string{"/etc/systemd/system/rayd.service", "/etc/sysctl.d/90-raycontrol.conf", "/var/lib/raycontrol", "/usr/local/bin/rayd"} {
		if _, err := os.Stat(filepath.Join(root, gone)); !os.IsNotExist(err) {
			t.Errorf("%s still there", gone)
		}
	}
}

func TestJournalTwoInstances(t *testing.T) {
	root := t.TempDir()
	a, _ := deploy.OpenJournal(root)
	if err := a.Record(deploy.Change{Kind: deploy.ChangeUnit, Name: "rayd.service"}); err != nil {
		t.Fatal(err)
	}
	// A nested run records through its own instance...
	b, _ := deploy.OpenJournal(root)
	b.Record(deploy.Change{Kind: deploy.ChangeFile, Path: "/etc/ufw/user.rules", Backup: "x"})
	// ...and the outer one must not save over it with its stale copy.
	a.Record(deploy.Change{Kind: deploy.ChangeUnit, Name: "rayspa.service"})
	// The first record of a path wins even if a stale instance has another.
	b.Record(deploy.Change{Kind: deploy.ChangeFile, Path: "/etc/ufw/user.rules", Backup: "later"})
	c, _ := deploy.OpenJournal(root)
	if len(c.Changes) != 3 || c.Changes[1].Backup != "x" {
		t.Fatalf("journal %+v", c.Changes)
	}
}

// ufw comes back the way the host loads it at boot: ufw.service restarted,
// not ufw reload, which adds rate-limit rules the boot does not.
func TestUninstallUFW(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "/etc/ufw"), 0o755)
	os.WriteFile(filepath.Join(root, "/etc/ufw/user.rules"), []byte("*filter\nCOMMIT\n"), 0o640)
	j, _ := deploy.OpenJournal(root)
	if err := j.RecordFile("/etc/ufw/user.rules"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "/etc/ufw/user.rules"), []byte("*filter\n-A ufw-user-input -j ACCEPT\nCOMMIT\n"), 0o644)
	var cmds []string
	active := true
	h := &deploy.Host{Root: root, Out: &bytes.Buffer{},
		Run: func(name string, args ...string) ([]byte, error) {
			c := name + " " + strings.Join(args, " ")
			cmds = append(cmds, c)
			if c == "systemctl is-active --quiet ufw.service" && !active {
				return nil, errors.New("exit status 3")
			}
			if c == "ufw status" {
				return []byte("Status: active\n"), nil
			}
			return nil, nil
		},
		LookupUser:  func(string) (int, error) { return 0, errors.New("unknown") },
		LookupGroup: func(string) (int, error) { return 0, errors.New("unknown") },
	}
	if err := h.Uninstall(j, deploy.UninstallOptions{}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(root, "/etc/ufw/user.rules"))
	st, _ := os.Stat(filepath.Join(root, "/etc/ufw/user.rules"))
	all := strings.Join(cmds, "\n")
	if string(b) != "*filter\nCOMMIT\n" || st.Mode().Perm() != 0o640 || !strings.Contains(all, "systemctl restart ufw.service") ||
		strings.Contains(all, "ufw reload") {
		t.Fatalf("file %q %v, commands:\n%s", b, st.Mode(), all)
	}

	// Without the unit (ufw run some other way): ufw reload.
	j, _ = deploy.OpenJournal(root)
	j.RecordFile("/etc/ufw/user.rules")
	cmds, active = nil, false
	if err := h.Uninstall(j, deploy.UninstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if all = strings.Join(cmds, "\n"); !strings.Contains(all, "ufw reload") {
		t.Fatalf("no ufw reload:\n%s", all)
	}
}

// Hysteria2 on Xray (R3-1): the key copied in by root, the bind capability
// only for UDP 443.
func TestBuildHysteria(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	for _, k := range []string{"hy2-masq", "hy2-obfs"} {
		if _, err := provision.CreateService(ctx, st, store.Service{Kind: k, Name: k, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	files, _, err := render.Render(m, render.DefaultPaths)
	if err != nil {
		t.Fatal(err)
	}
	p := deploy.Build(m, files, render.DefaultPaths, deploy.DefaultBinaries)
	masq, obfs := file(p, "/etc/systemd/system/niko-hy2-masq.service"), file(p, "/etc/systemd/system/niko-hy2-obfs.service")
	// niko-server backends behind the UDP front (R3-4): no capability, the
	// key (and salamander) copied in by root, out to public addresses only.
	for name, u := range map[string]string{"masq": masq, "obfs": obfs} {
		for _, want := range []string{"ExecStart=/usr/local/libexec/raycontrol/niko-server backend -c /var/lib/raycontrol/rendered/hy2-",
			"ExecStartPre=+install -m 0400 -o niko-hy2-", "CapabilityBoundingSet=\n", "IPAddressDeny=localhost"} {
			if !strings.Contains(u, want) {
				t.Errorf("%s unit lacks %q:\n%s", name, want, u)
			}
		}
		if strings.Contains(u, "CAP_NET_BIND_SERVICE") {
			t.Errorf("%s binds a port itself", name)
		}
	}
	if !strings.Contains(obfs, "/run/niko/hy2-obfs/salamander") {
		t.Error("hy2-obfs gets no salamander password")
	}
	front := file(p, "/etc/systemd/system/niko-front.service")
	if strings.Contains(front, "SupplementaryGroups") {
		t.Errorf("the front is in the backends' groups (S-1):\n%s", front)
	}
	for _, want := range []string{
		"ExecStartPre=+install -m 0400 -o niko-front -g niko-front /var/lib/raycontrol/rendered/front/hy2-obfs.salamander /run/niko/front/hy2-obfs.salamander",
		"RuntimeDirectory=niko/front\n", "AmbientCapabilities=CAP_NET_BIND_SERVICE"} {
		if !strings.Contains(front, want) {
			t.Errorf("front unit lacks %q:\n%s", want, front)
		}
	}
}

func TestBuildNaive(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	for _, k := range []string{"reality", "naive"} {
		if _, err := provision.CreateService(ctx, st, store.Service{Kind: k, Name: k, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	files, _, err := render.Render(m, render.DefaultPaths)
	if err != nil {
		t.Fatal(err)
	}
	p := deploy.Build(m, files, render.DefaultPaths, deploy.DefaultBinaries)
	u := file(p, "/etc/systemd/system/niko-naive.service")
	for _, want := range []string{
		"ExecStart=/usr/local/bin/rayd naive -answer 404 -users /var/lib/raycontrol/rendered/naive/users.json",
		"-socket /run/niko/naive-in/naive.sock", "ExecStartPre=+install -m 0400 -o niko-naive",
		"IPAddressDeny=localhost link-local multicast 10.0.0.0/8", "CapabilityBoundingSet=\n",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("naive unit lacks %q:\n%s", want, u)
		}
	}
	if !strings.Contains(file(p, "/etc/tmpfiles.d/raycontrol.conf"), "d /run/niko/naive-in 2750 niko-naive niko-front -") {
		t.Errorf("no socket directory for the site:\n%s", file(p, "/etc/tmpfiles.d/raycontrol.conf"))
	}
	if len(p.Warnings) != 0 {
		t.Errorf("warnings %v", p.Warnings)
	}
}

// A DNS tunnel that failed to render keeps its earlier files (Q-1); its unit
// must still copy the key in, or the next start runs without one.
func TestBuildDNSKeyWithoutRender(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	for _, k := range []string{"dnstt", "masterdns"} {
		if _, err := provision.CreateService(ctx, st, store.Service{Kind: k, Name: k, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	m, err := render.CollectForRender(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	files, _, err := render.Render(m, render.DefaultPaths)
	if err != nil {
		t.Fatal(err)
	}
	others := slices.DeleteFunc(files, func(f render.File) bool { return f.Service == "dnstt" || f.Service == "masterdns" })
	p := deploy.Build(m, others, render.DefaultPaths, deploy.DefaultBinaries)
	for name, key := range map[string]string{"dnstt": "noise.key", "masterdns": "encryption.key"} {
		want := "ExecStartPre=+install -m 0400 -o niko-" + name + " -g niko-" + name +
			" /var/lib/raycontrol/rendered/" + name + "/" + key + " /run/niko/" + name + "/" + key
		if u := file(p, "/etc/systemd/system/niko-"+name+".service"); !strings.Contains(u, want) {
			t.Errorf("%s unit lacks %q:\n%s", name, want, u)
		}
	}
}

// A relay host (relay-v1 §3.1): rayspa alone, with the bundle root copies in
// for it at each start, and forwarding on.
func TestRelayPlan(t *testing.T) {
	p := deploy.RelayPlan(deploy.DefaultBinaries)
	if !slices.Equal(p.Units, []string{"rayspa.service", deploy.RelayProbeUnit}) || len(p.Users) != 2 ||
		p.Users[0].Name != "rayspa" || p.Users[1].Name != "rayd" {
		t.Fatalf("plan units %v, users %v", p.Units, p.Users)
	}
	// rayd relay: no privileges, its own copy of the bundle (relay-v1 §9.1).
	probe := file(p, "/etc/systemd/system/"+deploy.RelayProbeUnit)
	for _, want := range []string{
		"ExecStartPre=+install -m 0400 -o rayd -g rayd /etc/raycontrol/relay.bundle /run/rayd-relay/relay.bundle",
		"ExecStart=/usr/local/bin/rayd relay -bundle /run/rayd-relay/relay.bundle -state /var/lib/rayd-relay/devices.json",
		"StateDirectory=rayd-relay\n", "StateDirectoryMode=0700",
		"User=rayd", "CapabilityBoundingSet=\n", "After=network-online.target rayspa.service",
		"PartOf=rayspa.service\n", "Requisite=rayspa.service\n", "[Install]\nWantedBy=rayspa.service\n",
	} {
		if !strings.Contains(probe, want) {
			t.Errorf("rayd relay unit lacks %q:\n%s", want, probe)
		}
	}
	u := file(p, "/etc/systemd/system/rayspa.service")
	for _, want := range []string{
		"ExecStartPre=+install -m 0400 -o rayspa -g rayspa /etc/raycontrol/relay.bundle /run/rayspa/relay.bundle",
		"ExecStart=/usr/local/bin/rayspa run -relay /run/rayspa/relay.bundle -state /var/lib/rayspa/snapshot.pb",
		"User=rayspa", "CapabilityBoundingSet=CAP_NET_ADMIN\n", "RuntimeDirectoryMode=0700",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("relay unit lacks %q:\n%s", want, u)
		}
	}
	if !strings.Contains(file(p, "/etc/sysctl.d/91-raycontrol-relay.conf"), "net.ipv4.ip_forward = 1") ||
		!strings.Contains(file(p, "/etc/sysctl.d/90-raycontrol.conf"), "accept_redirects = 0") {
		t.Error("relay sysctl")
	}
}

// The DNS tunnels share UDP 53 with systemd-resolved's stub: its sockets on
// 127.0.0.53 and 127.0.0.54 draw no warning, another resolver's do; and a
// host where an install before v0.11 turned the stub off gets it back: the
// front restarts before resolved (an older front holds 53 alone, and the
// stub could not bind beside it), and resolv.conf goes back on the stub
// only once the stub is up, else at a later apply. A drop-in that is not
// ours stays, and so does a resolv.conf raycontrol did not change.
func TestPort53(t *testing.T) {
	const (
		restartFront    = "systemctl try-restart niko-front.service"
		restartResolved = "systemctl try-restart systemd-resolved.service"
		header          = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
		stub            = "  1: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   991        0 1 2 0 0\n" +
			"  2: 3600007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   991        0 1 2 0 0\n"
		other = "  3: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   992        0 1 2 0 0\n"
		ours  = "# Generated by raycontrol: the node answers its DNS tunnel zones on port 53.\n[Resolve]\nDNSStubListener=no\n"
	)
	type host struct {
		root string
		h    *deploy.Host
		cmds *[]string
		out  *bytes.Buffer
	}
	// newHost: udp is /proc/net/udp now; stubComes, whether the stub binds
	// when resolved restarts; niko is the installed niko-server's version.
	niko, resolvedState := "v0.8.2", "loaded"
	newHost := func(t *testing.T, udp, dropIn string, oldResolv, stubComes bool) host {
		t.Helper()
		root := t.TempDir()
		os.MkdirAll(filepath.Join(root, "/proc/net"), 0o755)
		procUDP := filepath.Join(root, "/proc/net/udp")
		os.WriteFile(procUDP, []byte(header+udp), 0o644)
		os.MkdirAll(filepath.Join(root, "/etc"), 0o755)
		os.MkdirAll(filepath.Join(root, deploy.DataPlaneDir), 0o755)
		os.WriteFile(filepath.Join(root, deploy.DefaultBinaries.NikoServer), nil, 0o755)
		if dropIn != "" {
			os.MkdirAll(filepath.Join(root, filepath.Dir(deploy.ResolvedDropIn)), 0o755)
			os.WriteFile(filepath.Join(root, deploy.ResolvedDropIn), []byte(dropIn), 0o644)
		}
		j, err := deploy.OpenJournal(root)
		if err != nil {
			t.Fatal(err)
		}
		if oldResolv {
			// What an install before v0.11 did, journaled.
			j.Record(deploy.Change{Kind: deploy.ChangeSymlink, Path: "/etc/resolv.conf", Target: "../run/systemd/resolve/stub-resolv.conf"})
			os.Symlink("/run/systemd/resolve/resolv.conf", filepath.Join(root, "/etc/resolv.conf"))
		} else {
			os.Symlink("../run/systemd/resolve/stub-resolv.conf", filepath.Join(root, "/etc/resolv.conf"))
		}
		out := &bytes.Buffer{}
		var cmds []string
		h := &deploy.Host{
			Root: root, Out: out, Journal: j,
			Run: func(name string, args ...string) ([]byte, error) {
				c := name + " " + strings.Join(args, " ")
				cmds = append(cmds, c)
				switch {
				case c == restartResolved && stubComes:
					os.WriteFile(procUDP, []byte(header+stub+udp), 0o644)
				case c == deploy.DefaultBinaries.NikoServer+" version":
					return []byte("niko-server " + niko + "\n"), nil
				case c == "systemctl show --property=LoadState --value systemd-resolved.service":
					return []byte(resolvedState + "\n"), nil
				case strings.HasPrefix(c, "systemctl show --property=LoadState --value "):
					return []byte("loaded\n"), nil
				}
				return nil, nil
			},
			LookPath:    func(string) (string, error) { return "", errors.New("none") },
			LookupUser:  func(string) (int, error) { return 0, errors.New("unknown") },
			LookupGroup: func(string) (int, error) { return 0, errors.New("unknown") },
		}
		return host{root, h, &cmds, out}
	}
	apply := func(t *testing.T, h host, p deploy.Plan) {
		t.Helper()
		*h.cmds = nil
		if err := h.h.Apply(p, "rayd.service"); err != nil {
			t.Fatal(err)
		}
	}
	resolv := func(h host) string {
		target, _ := os.Readlink(filepath.Join(h.root, "/etc/resolv.conf"))
		return target
	}

	p, _ := plan(t)
	if !p.FrontDNS || !slices.Contains(p.Units, "niko-front.service") {
		t.Fatalf("the test plan has no front or no DNS tunnels: %v", p.Units)
	}

	// A fresh host: the stub stays, untouched and unmentioned.
	h := newHost(t, stub, "", false, true)
	apply(t, h, p)
	if slices.Contains(*h.cmds, restartResolved) || strings.Contains(h.out.String(), "UDP port 53") {
		t.Errorf("the stub touched or reported:\n%s\n%s", strings.Join(*h.cmds, "\n"), h.out)
	}
	// Another resolver on 53: reported.
	h = newHost(t, stub+other, "", false, true)
	apply(t, h, p)
	if !strings.Contains(h.out.String(), "warning: UDP port 53 (127.0.0.1) is taken") {
		t.Errorf("another resolver not reported:\n%s", h.out)
	}
	// After an older install: the front, then resolved, then resolv.conf.
	h = newHost(t, "", ours, true, true)
	apply(t, h, p)
	front, resolved := slices.Index(*h.cmds, restartFront), slices.Index(*h.cmds, restartResolved)
	if _, err := os.Stat(filepath.Join(h.root, deploy.ResolvedDropIn)); !os.IsNotExist(err) || front < 0 || resolved < front {
		t.Errorf("the stub not given back, or resolved before the front: %v\n%s", err, strings.Join(*h.cmds, "\n"))
	}
	if got := resolv(h); got != "../run/systemd/resolve/stub-resolv.conf" {
		t.Errorf("resolv.conf -> %s", got)
	}
	// The stub does not come up: resolv.conf stays on the uplink list, said;
	// the next apply tries resolved again (not the front), and once the
	// stub is up, finishes without restarting anything.
	h = newHost(t, "", ours, true, false)
	apply(t, h, p)
	if got := resolv(h); got != "/run/systemd/resolve/resolv.conf" || !strings.Contains(h.out.String(), "stub is not on 127.0.0.53") {
		t.Errorf("resolv.conf -> %s without the stub:\n%s", got, h.out)
	}
	apply(t, h, p)
	if !slices.Contains(*h.cmds, restartResolved) || slices.Contains(*h.cmds, restartFront) {
		t.Errorf("the next apply: resolved again, the front not:\n%s", strings.Join(*h.cmds, "\n"))
	}
	os.WriteFile(filepath.Join(h.root, "/proc/net/udp"), []byte(header+stub), 0o644)
	apply(t, h, p)
	if got := resolv(h); got != "../run/systemd/resolve/stub-resolv.conf" || slices.Contains(*h.cmds, restartResolved) {
		t.Errorf("resolv.conf -> %s with the stub up, restarts:\n%s", got, strings.Join(*h.cmds, "\n"))
	}
	apply(t, h, p)
	if slices.Contains(*h.cmds, restartResolved) {
		t.Error("resolved restarted again once all is back")
	}
	// Another DNS server holds 53 (the stub off for it): the stub stays off.
	h = newHost(t, other, ours, true, true)
	apply(t, h, p)
	if _, err := os.Stat(filepath.Join(h.root, deploy.ResolvedDropIn)); err != nil || slices.Contains(*h.cmds, restartResolved) {
		t.Errorf("the stub given back over another DNS server: %v\n%s", err, h.out)
	}
	// systemd-resolved gone since: applies go on, again and again.
	resolvedState = "not-found"
	h = newHost(t, "", ours, true, true)
	apply(t, h, p)
	apply(t, h, p)
	resolvedState = "loaded"
	// An older niko-server, which cannot share 53: nothing changes yet.
	niko = "v0.8.1"
	h = newHost(t, "", ours, true, true)
	apply(t, h, p)
	if _, err := os.Stat(filepath.Join(h.root, deploy.ResolvedDropIn)); err != nil || slices.Contains(*h.cmds, restartResolved) ||
		resolv(h) != "/run/systemd/resolve/resolv.conf" || !strings.Contains(h.out.String(), "older than v0.8.2") {
		t.Errorf("the stub given back beside an older front: %v\n%s", err, h.out)
	}
	niko = "v0.8.2"
	// A run that stopped halfway (drop-in moved aside), then uninstall: it
	// goes too.
	h = newHost(t, "", ours, true, false)
	apply(t, h, p)
	if _, err := os.Stat(filepath.Join(h.root, deploy.ResolvedDropIn+".gone")); err != nil {
		t.Fatalf("no mark of the stub being given back: %v", err)
	}
	if err := h.h.Uninstall(h.h.Journal, deploy.UninstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.root, deploy.ResolvedDropIn+".gone")); !os.IsNotExist(err) {
		t.Errorf("uninstall left the moved drop-in: %v", err)
	}
	// A drop-in of the administrator's at that path stays; a resolv.conf on
	// the uplink list the journal does not know of stays too.
	h = newHost(t, stub, "[Resolve]\nDNSStubListener=no\n", false, true)
	os.Remove(filepath.Join(h.root, "/etc/resolv.conf"))
	os.Symlink("/run/systemd/resolve/resolv.conf", filepath.Join(h.root, "/etc/resolv.conf"))
	apply(t, h, p)
	if _, err := os.Stat(filepath.Join(h.root, deploy.ResolvedDropIn)); err != nil || slices.Contains(*h.cmds, restartResolved) ||
		resolv(h) != "/run/systemd/resolve/resolv.conf" {
		t.Errorf("the administrator's resolver changed: %v %s\n%s", err, resolv(h), strings.Join(*h.cmds, "\n"))
	}
	// Without DNS tunnels, 53 is not the front's: nothing said.
	p.FrontDNS = false
	h = newHost(t, stub+other, "", false, true)
	apply(t, h, p)
	if strings.Contains(h.out.String(), "UDP port 53") {
		t.Errorf("no DNS tunnels, yet:\n%s", h.out)
	}
}

// Under a umask of 077 the directories a plan's files need are still open
// to the services, and an install that left ours closed is opened again;
// nothing else changes.
func TestModesUnderUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	root := t.TempDir()
	os.Chmod(root, 0o755)
	h := &deploy.Host{Root: root, Out: &bytes.Buffer{}}
	if _, err := h.WriteFile(deploy.File{Path: deploy.DefaultBinaries.Xray, Mode: 0o755, Content: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"/usr", "/usr/local", "/usr/local/libexec", deploy.DataPlaneDir} {
		if fi, err := os.Stat(filepath.Join(root, d)); err != nil || fi.Mode().Perm() != 0o755 {
			t.Errorf("%s: %v %v", d, fi.Mode().Perm(), err)
		}
	}

	// As an older install under that umask left them.
	for _, d := range []string{deploy.DataPlaneDir, "/usr/local/libexec", deploy.StateDir, "/etc/private"} {
		os.MkdirAll(filepath.Join(root, d), 0o700)
		os.Chmod(filepath.Join(root, d), 0o700)
	}
	os.Chmod(filepath.Join(root, deploy.DefaultBinaries.Xray), 0o700)
	out := &bytes.Buffer{}
	h = &deploy.Host{Root: root, Out: out, Run: func(string, ...string) ([]byte, error) { return nil, nil },
		LookPath: func(string) (string, error) { return "", errors.New("none") }}
	if err := h.Apply(deploy.Plan{}); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{
		deploy.DataPlaneDir: 0o755, "/usr/local/libexec": 0o755, deploy.StateDir: 0o711,
		deploy.DefaultBinaries.Xray: 0o755, "/etc/private": 0o700,
	} {
		if fi, err := os.Stat(filepath.Join(root, p)); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: %v, want %v (%v)", p, fi.Mode().Perm(), want, err)
		}
	}
	if !strings.Contains(out.String(), deploy.DataPlaneDir+" was mode -rwx------, closed to the services") {
		t.Errorf("not said:\n%s", out)
	}
}
