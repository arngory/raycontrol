package deploy_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

func plan(t *testing.T) (deploy.Plan, render.Model) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	for _, s := range [][3]string{{"dnstt", "dns", ""}, {"reality", "reality", `{"target":"www.example.org:443"}`}, {"naive", "naive", ""}} {
		if _, err := provision.CreateService(ctx, st, store.Service{Kind: s[0], Name: s[1], Enabled: true, Settings: s[2]}); err != nil {
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
	return deploy.Build(m, files, render.DefaultPaths, deploy.DefaultBinaries), m
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
	if !slices.Equal(users["niko-front"].ExtraGroups, []string{"niko-dns"}) ||
		!slices.Equal(users["niko-dns"].ExtraGroups, []string{"niko-inner"}) ||
		!slices.Equal(users["rayd"].ExtraGroups, []string{"niko-dns", "niko-front", "niko-inner", "niko-reality"}) {
		t.Fatalf("groups: %+v", users)
	}
	if !slices.Equal(p.Units, []string{"rayd.service", "rayspa.service", "niko-inner.service", "niko-reality.service", "niko-dns.service", "niko-front.service"}) {
		t.Fatalf("units %v", p.Units)
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "naive") {
		t.Fatalf("warnings %v", p.Warnings)
	}
	// REALITY binds TCP 443 itself until the front has tcpmux (R2-7).
	reality := file(p, "/etc/systemd/system/niko-reality.service")
	for _, want := range []string{"User=niko-reality", "AmbientCapabilities=CAP_NET_BIND_SERVICE\n", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n",
		"ExecStart=/usr/local/bin/xray run -c /var/lib/raycontrol/rendered/reality/xray.json", "ReadWritePaths=/run/niko/reality-api"} {
		if !strings.Contains(reality, want) {
			t.Errorf("reality unit lacks %q", want)
		}
	}
	if !strings.Contains(file(p, "/etc/tmpfiles.d/raycontrol.conf"), "d /run/niko/reality-api 2750 niko-reality rayd") {
		t.Error("REALITY API directory not restricted to rayd")
	}

	dns := file(p, "/etc/systemd/system/niko-dns.service")
	for _, want := range []string{
		"User=niko-dns", "SupplementaryGroups=niko-inner", "PrivateNetwork=yes", "RestrictAddressFamilies=AF_UNIX\n",
		"ExecStartPre=+install -m 0400 -o niko-dns -g niko-dns /var/lib/raycontrol/rendered/dns/noise.key /run/niko/dns/noise.key\n", "RuntimeDirectory=niko/dns", "CapabilityBoundingSet=\n",
		"ExecStart=/usr/local/bin/niko-server backend -c /var/lib/raycontrol/rendered/dns/backend.json",
	} {
		if !strings.Contains(dns, want) {
			t.Errorf("dns unit lacks %q", want)
		}
	}
	front := file(p, "/etc/systemd/system/niko-front.service")
	if !strings.Contains(front, "AmbientCapabilities=CAP_NET_BIND_SERVICE") || !strings.Contains(front, "SupplementaryGroups=niko-dns") {
		t.Errorf("front unit:\n%s", front)
	}
	if !strings.Contains(file(p, "/etc/systemd/system/rayspa.service"), "AmbientCapabilities=CAP_NET_ADMIN") {
		t.Error("rayspa lacks CAP_NET_ADMIN")
	}
	if !strings.Contains(file(p, "/etc/tmpfiles.d/raycontrol.conf"), "d /run/niko/inner-api 2750 niko-inner rayd") {
		t.Error("inner API directory not restricted to rayd")
	}
	if !strings.Contains(file(p, "/etc/systemd/resolved.conf.d/raycontrol.conf"), "DNSStubListener=no") {
		t.Error("resolved stub not disabled though DNS tunnels exist")
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
		"usermod --append --groups niko-dns niko-front",
		"systemctl enable --now niko-inner.service", "systemctl disable --now niko-old.service",
		"systemd-tmpfiles --create", "systemctl try-restart systemd-resolved.service",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing command %q in:\n%s", want, all)
		}
	}
	for _, unwanted := range []string{"useradd --system --uid 9190", "enable --now niko-dns.service", "enable --now rayd.service"} {
		if strings.Contains(all, unwanted) {
			t.Errorf("unexpected %q", unwanted)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "/etc/systemd/system/niko-old.service")); !os.IsNotExist(err) {
		t.Error("stale unit kept")
	}
	if target, _ := os.Readlink(filepath.Join(root, "/etc/resolv.conf")); target != "/run/systemd/resolve/resolv.conf" {
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
	// 127.0.0.53:53 held by uid 101 (a resolver), 0.0.0.0:53 by the front.
	os.WriteFile(filepath.Join(root, "/proc/net/udp"), []byte(
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"+
			"  1: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 1 2 0 0\n"+
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
		"warning: UDP port 53 (127.0.0.53) is taken by user ",
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
	site := file(p, "/etc/systemd/system/niko-site.service")
	for _, want := range []string{
		"ConditionPathExists=/var/lib/raycontrol/rendered/site/chain.pem\n",
		"ExecStartPre=+install -m 0400 -o niko-site -g niko-site /var/lib/raycontrol/rendered/site/key.pem /run/niko/site/key.pem\n",
		"ExecStart=/usr/local/bin/rayd site -root /var/lib/raycontrol/rendered/site/www -chain /var/lib/raycontrol/rendered/site/chain.pem -key /run/niko/site/key.pem -socket /run/niko/site/tls.sock\n",
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
				return []byte("cubic\n"), nil
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
