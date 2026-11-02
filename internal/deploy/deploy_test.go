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
	for _, s := range [][2]string{{"dnstt", "dns"}, {"reality", "reality"}} {
		if _, err := provision.CreateService(ctx, st, store.Service{Kind: s[0], Name: s[1], Enabled: true}); err != nil {
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
		!slices.Equal(users["rayd"].ExtraGroups, []string{"niko-dns", "niko-front", "niko-inner"}) {
		t.Fatalf("groups: %+v", users)
	}
	if !slices.Equal(p.Units, []string{"rayd.service", "rayspa.service", "niko-inner.service", "niko-dns.service", "niko-front.service"}) {
		t.Fatalf("units %v", p.Units)
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "reality") {
		t.Fatalf("warnings %v", p.Warnings)
	}

	dns := file(p, "/etc/systemd/system/niko-dns.service")
	for _, want := range []string{
		"User=niko-dns", "SupplementaryGroups=niko-inner", "PrivateNetwork=yes", "RestrictAddressFamilies=AF_UNIX\n",
		"LoadCredential=noise.key:/var/lib/raycontrol/rendered/dns/noise.key", "RuntimeDirectory=niko/dns", "CapabilityBoundingSet=\n",
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
