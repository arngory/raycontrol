package hostcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeHost is a Debian 13 KVM guest with 2 GiB, 2 CPUs, everything in
// place; tests break one thing at a time.
func fakeHost(t *testing.T) (*Host, string, map[string]string) {
	t.Helper()
	root := t.TempDir()
	write := func(p, s string) {
		t.Helper()
		os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755)
		if err := os.WriteFile(filepath.Join(root, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"/run/systemd/system", "/lib/modules/6.12.48-amd64"} {
		os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	write("/run/dbus/system_bus_socket", "")
	write("/proc/sys/kernel/osrelease", "6.12.48-amd64\n")
	write("/proc/meminfo", "MemTotal:        2014000 kB\n")
	write("/proc/sys/net/ipv4/tcp_available_congestion_control", "reno cubic bbr\n")
	write("/proc/sys/net/core/rmem_max", "16777216\n")
	write("/proc/sys/net/core/wmem_max", "16777216\n")
	write("/etc/os-release", "ID=debian\nVERSION_ID=\"13\"\n")
	write("/etc/resolv.conf", "nameserver 127.0.0.53\n")
	write("/etc/apt/apt.conf.d/20auto-upgrades", "APT::Periodic::Unattended-Upgrade \"1\";\n")
	write("/usr/bin/unattended-upgrade", "")
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	write("/proc/net/tcp", header+
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1\n")
	write("/proc/net/udp", header)
	write("/proc/net/tcp6", header)
	write("/proc/net/udp6", header)
	out := map[string]string{
		"systemctl --version":                         "systemd 257 (257.13-1~deb13u1)\n",
		"systemctl show -P LoadState polkit.service":  "loaded\n",
		"timedatectl show -p NTPSynchronized --value": "yes\n",
		"systemd-detect-virt -v":                      "kvm\n",
	}
	h := &Host{Root: root,
		Run: func(_ context.Context, _, name string, args ...string) ([]byte, error) {
			k := strings.Join(append([]string{name}, args...), " ")
			if name == "systemd-detect-virt" && args[0] == "-c" {
				if v, ok := out[k]; ok {
					return []byte(v), nil
				}
				return []byte("none\n"), errors.New("exit status 1")
			}
			if name == "nft" || name == "systemd-run" {
				if v, ok := out[name]; ok {
					return []byte(v), errors.New("exit status 1")
				}
				return nil, nil
			}
			if v, ok := out[k]; ok {
				return []byte(v), nil
			}
			return nil, errors.New("exit status 1")
		},
		LookPath: func(string) error { return nil },
		Euid:     func() int { return 0 },
		Free:     func(string) (uint64, error) { return 8 << 30, nil },
		Addrs: func() ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8::7")}, nil
		},
		CPUs:  func() int { return 2 },
		Reach: func(context.Context, string) error { return nil },
	}
	return h, root, out
}

func find(rs []Result, level Level, name string) (Result, bool) {
	for _, r := range rs {
		if r.Level == level && r.Name == name {
			return r, true
		}
	}
	return Result{}, false
}

func TestGoodHost(t *testing.T) {
	h, _, _ := fakeHost(t)
	rs := h.Check(context.Background(), Options{Host: "203.0.113.7", Domain: "example.com", Services: []string{"reality", "dnstt"}})
	for _, r := range rs {
		// 2001:db8:: is documentation space, not a public address.
		if !r.OK && r.Name != "IPv6" {
			t.Errorf("%s %s: %s", r.Level, r.Name, r.Detail)
		}
	}
	var b bytes.Buffer
	Report(&b, rs, false)
	for _, want := range []string{"Required: without these", "ok    nftables: the perimeter table loads in kernel 6.12.48-amd64",
		"ok    port tcp 443: free", "ok    virtualization: kvm", "Only a probe from outside"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, b.String())
		}
	}
	b.Reset()
	Report(&b, rs, true)
	if b.Len() != 0 {
		t.Errorf("quiet report of a good host:\n%s", b.String())
	}
}

func TestRequiredFailures(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name  string
		check string
		edit  func(h *Host, root string, out map[string]string)
	}{
		{"not root", "root", func(h *Host, _ string, _ map[string]string) { h.Euid = func() int { return 1000 } }},
		{"old systemd", "systemd", func(_ *Host, _ string, out map[string]string) { out["systemctl --version"] = "systemd 239\n" }},
		{"no polkit", "polkit", func(_ *Host, _ string, out map[string]string) {
			out["systemctl show -P LoadState polkit.service"] = "not-found\n"
		}},
		{"no nft", "commands", func(h *Host, _ string, _ map[string]string) {
			h.LookPath = func(n string) error {
				if n == "nft" {
					return errors.New("not found")
				}
				return nil
			}
		}},
		{"old kernel", "nftables", func(_ *Host, _ string, out map[string]string) {
			out["nft"] = "Error: Could not process rule: No such file or directory\n"
		}},
		{"LXC without nesting", "systemd sandbox", func(_ *Host, _ string, out map[string]string) {
			out["systemd-run"] = "Job for run-u12.service failed because the control process exited with error code.\n"
		}},
		{"raycontrol v0", "raycontrol v0", func(_ *Host, root string, _ map[string]string) {
			os.MkdirAll(filepath.Join(root, "/etc/ray-aio"), 0o755)
		}},
		{"256 MB", "memory", func(_ *Host, root string, _ map[string]string) {
			os.WriteFile(filepath.Join(root, "/proc/meminfo"), []byte("MemTotal: 250000 kB\n"), 0o644)
		}},
		{"full disk", "disk", func(h *Host, _ string, _ map[string]string) {
			h.Free = func(string) (uint64, error) { return 100 << 20, nil }
		}},
		{"nginx on 443", "port tcp 443", func(_ *Host, root string, _ map[string]string) {
			f := filepath.Join(root, "/proc/net/tcp6")
			b, _ := os.ReadFile(f)
			os.WriteFile(f, append(b, "   1: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1\n"...), 0o644)
			os.MkdirAll(filepath.Join(root, "/proc/812/fd"), 0o755)
			os.WriteFile(filepath.Join(root, "/proc/812/comm"), []byte("nginx\n"), 0o644)
			os.Symlink("socket:[4242]", filepath.Join(root, "/proc/812/fd/6"))
		}},
		{"dnsmasq on 53", "port udp 53", func(_ *Host, root string, _ map[string]string) {
			f := filepath.Join(root, "/proc/net/udp")
			b, _ := os.ReadFile(f)
			os.WriteFile(f, append(b, "   2: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 5151 2\n"...), 0o644)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, root, out := fakeHost(t)
			h.Sandbox = true
			c.edit(h, root, out)
			rs := h.Check(ctx, Options{Host: "203.0.113.7", Services: []string{"dnstt"}})
			failed := Failed(rs)
			if len(failed) != 1 || failed[0].Name != c.check || failed[0].Fix == "" {
				t.Fatalf("failed: %+v", failed)
			}
			if c.name == "nginx on 443" && !strings.Contains(failed[0].Detail, "tcp [::]:443 is taken by nginx (pid 812)") {
				t.Errorf("detail: %s", failed[0].Detail)
			}
		})
	}
}

// addListener puts a socket on proto/port in the fake /proc, held by a
// process with this name and binary.
func addListener(root, file, line, pid, inode, comm, exe string) {
	f := filepath.Join(root, "/proc/net", file)
	b, _ := os.ReadFile(f)
	os.WriteFile(f, append(b, line...), 0o644)
	os.MkdirAll(filepath.Join(root, "/proc", pid, "fd"), 0o755)
	os.WriteFile(filepath.Join(root, "/proc", pid, "comm"), []byte(comm+"\n"), 0o644)
	os.Symlink("socket:["+inode+"]", filepath.Join(root, "/proc", pid, "fd", "3"))
	if exe != "" {
		os.Symlink(exe, filepath.Join(root, "/proc", pid, "exe"))
	}
}

const tcp443 = "   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 7001 1\n"

func TestOwnListenersAndResolved(t *testing.T) {
	h, root, _ := fakeHost(t)
	// The node's own front on 443 (rayctl check on an installed node, after
	// an update: the replaced binary reads "(deleted)"), and
	// systemd-resolved's stub on 127.0.0.53:53, which shares the port with
	// the front.
	addListener(root, "tcp", tcp443, "900", "7001", "niko-server", "/usr/local/libexec/raycontrol/niko-server (deleted)")
	addListener(root, "udp", "   2: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   991        0 7002 2\n",
		"300", "7002", "systemd-resolve", "/usr/lib/systemd/systemd-resolved")
	rs := h.Check(context.Background(), Options{Services: []string{"masterdns"}})
	if f := Failed(rs); len(f) != 0 {
		t.Fatalf("failed: %+v", f)
	}
	if r, _ := find(rs, Required, "port udp 53"); !r.OK {
		t.Fatalf("resolved's stub: %+v", r)
	}
	// resolved on another address (DNSStubListenerExtra=0.0.0.0): the
	// front's port is taken.
	addListener(root, "udp", "   3: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   991        0 7003 2\n",
		"301", "7003", "systemd-resolve", "/usr/lib/systemd/systemd-resolved")
	if r, _ := find(h.Check(context.Background(), Options{Services: []string{"masterdns"}}), Required, "port udp 53"); r.OK {
		t.Fatalf("resolved on 0.0.0.0:53 passed: %+v", r)
	}
}

func TestForeignXrayAndV0(t *testing.T) {
	ctx := context.Background()
	// Someone else's Xray on 443: the name is not enough to be the node's.
	h, root, _ := fakeHost(t)
	addListener(root, "tcp", tcp443, "700", "7001", "xray", "/usr/bin/xray")
	if f := Failed(h.Check(ctx, Options{})); len(f) != 1 || f[0].Name != "port tcp 443" {
		t.Fatalf("foreign xray: %+v", f)
	}
	// v0's Xray on 443: a failure, unless v0 goes next (-remove-v0).
	h, root, _ = fakeHost(t)
	os.MkdirAll(filepath.Join(root, "/etc/ray-aio"), 0o755)
	addListener(root, "tcp", tcp443, "701", "7001", "xray", "/usr/local/bin/xray")
	if f := Failed(h.Check(ctx, Options{})); len(f) != 2 {
		t.Fatalf("v0 without -allow-v0: %+v", f)
	}
	rs := h.Check(ctx, Options{AllowV0: true})
	if f := Failed(rs); len(f) != 0 {
		t.Fatalf("v0 with -allow-v0: %+v", f)
	}
	if r, ok := find(rs, Advised, "raycontrol v0"); !ok || !strings.Contains(r.Detail, "goes next") {
		t.Fatalf("v0 advisory: %+v", r)
	}
}

func TestAdvised(t *testing.T) {
	h, root, out := fakeHost(t)
	out["systemd-detect-virt -c"] = "lxc\n"
	out["timedatectl show -p NTPSynchronized --value"] = "no\n"
	os.WriteFile(filepath.Join(root, "/proc/sys/net/ipv4/tcp_available_congestion_control"), []byte("reno cubic\n"), 0o644)
	os.MkdirAll(filepath.Join(root, "/lib/modules/6.12.57-amd64"), 0o755)
	os.WriteFile(filepath.Join(root, "/proc/meminfo"), []byte("MemTotal: 496000 kB\n"), 0o644)
	os.WriteFile(filepath.Join(root, "/proc/sys/net/core/rmem_max"), []byte("212992\n"), 0o644)
	os.Chmod(filepath.Join(root, "/proc/sys/net/core/rmem_max"), 0o444)
	os.Chmod(filepath.Join(root, "/etc/resolv.conf"), 0o600) // written under umask 077
	h.CPUs = func() int { return 1 }
	h.Reach = func(context.Context, string) error { return errors.New("connection refused") }
	h.Addrs = func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil }
	rs := h.Check(context.Background(), Options{Host: "203.0.113.7", Domain: "example.com"})
	if f := Failed(rs); len(f) != 0 {
		t.Fatalf("failed: %+v", f)
	}
	for _, name := range []string{"virtualization", "clock", "BBR", "memory", "processors", "updates", "Let's Encrypt", "IPv6", "resolver"} {
		if r, ok := find(rs, Advised, name); !ok || r.OK {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if os.Geteuid() != 0 { // root writes through 0444
		if r, _ := find(rs, Advised, "UDP buffers"); r.OK {
			t.Errorf("read-only buffers: %+v", r)
		}
	}
	if r, _ := find(rs, Advised, "public address"); !strings.Contains(r.Detail, "1:1 NAT") {
		t.Errorf("NAT: %+v", r)
	}
	if r, _ := find(rs, Advised, "updates"); !strings.Contains(r.Detail, "kernel 6.12.57-amd64 is installed but 6.12.48-amd64 is running") {
		t.Errorf("kernel: %+v", r)
	}
}

// naive's ICMP on (spec/icmp-v1.md): advised that the range holds the data
// plane's groups; not looked at otherwise.
func TestICMPSockets(t *testing.T) {
	h, root, _ := fakeHost(t)
	path := filepath.Join(root, "/proc/sys/net/ipv4/ping_group_range")
	for _, c := range []struct {
		value string
		on    bool
		ok    bool
	}{
		{"0\t2147483647\n", true, true},
		{"1\t0\n", true, false},
		{"9100\t9178\n", true, false},
		{"1\t0\n", false, true}, // off: no such check
		{"", true, false},       // not read: cannot tell, not good
	} {
		os.WriteFile(path, []byte(c.value), 0o644)
		rs := h.Check(context.Background(), Options{Host: "203.0.113.7", ICMP: c.on})
		r, found := find(rs, Advised, "ICMP sockets")
		if found != c.on || (found && r.OK != c.ok) {
			t.Errorf("%q, icmp %v: found %v, %+v", c.value, c.on, found, r)
		}
		if c.value == "" {
			if !strings.Contains(r.Detail, "cannot be told") {
				t.Errorf("unread: %+v", r)
			}
			continue
		}
		if found && !r.OK && (!strings.Contains(r.Detail, "net.ipv4.ping_group_range "+strings.Join(strings.Fields(c.value), " ")) || !strings.Contains(r.Fix, "rayctl apply")) {
			t.Errorf("%q: %+v", c.value, r)
		}
	}
}

func TestParseHexAddr(t *testing.T) {
	for in, want := range map[string]string{
		"0100007F:01BB":                         "127.0.0.1:443",
		"00000000000000000000000001000000:0035": "[::1]:53",
		"0000000000000000FFFF00000100007F:0050": "127.0.0.1:80",
	} {
		got, ok := parseHexAddr(in)
		if !ok || got.String() != want {
			t.Errorf("%s: %v %v, want %s", in, got, ok, want)
		}
	}
	if !VersionLess("6.1.0-27-amd64", "6.1.0-28-amd64") || VersionLess("6.12.9", "6.2.1") || !VersionLess("5.14.0-427.el9", "5.14.0-503.el9") {
		t.Fatal("VersionLess")
	}
}

// The Internet level (rayd's check of the DNS zones): shown, never a
// failure of the host, not in a quiet report.
func TestInternetLevel(t *testing.T) {
	rs := []Result{{Level: Required, Name: "nftables", OK: true},
		{Level: Internet, Name: "DNS zone t3x.example.com (dns)", OK: false, Detail: "example.com has no NS for t3x.example.com", Fix: "rayctl dns sync"},
		{Level: Internet, Name: "DNS zone k2p.example.com (mdns)", OK: true, Detail: "delegated; 3/3 resolvers (4m ago)"}}
	if f := Failed(rs); len(f) != 0 {
		t.Fatalf("failed %+v", f)
	}
	var b bytes.Buffer
	Report(&b, rs, false)
	for _, want := range []string{"Internet: the node's DNS zones as rayd last checked them (rayctl dns check)\n",
		"  FAIL  DNS zone t3x.example.com (dns): example.com has no NS for t3x.example.com\n          → rayctl dns sync\n",
		"  ok    DNS zone k2p.example.com (mdns): delegated; 3/3 resolvers (4m ago)\n"} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("report lacks %q:\n%s", want, b.String())
		}
	}
	b.Reset()
	Report(&b, rs, true)
	if strings.Contains(b.String(), "DNS zone") {
		t.Fatalf("quiet report:\n%s", b.String())
	}
	if j, err := json.Marshal(rs[1]); err != nil || !strings.Contains(string(j), `"level":"internet"`) {
		t.Fatalf("json %s %v", j, err)
	}
}

// The egress policy (rayctl egress) through the kernel's dry run, after the
// table: advised, so a kernel that refuses it holds back no install; the
// refusal says why. Without @ih, the TCP rule by tcp doff.
func TestEgressPolicyCheck(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name   string
		refuse string // nft -c refuses the scripts with this
		ok     bool
		detail string
	}{
		{"kernel takes it", "", true, "the BitTorrent and SMTP filter loads (rayctl egress)"},
		{"no @ih", "@ih", true, "no @ih in this kernel"},
		{"refused", "udp length 38", false, "cannot load the BitTorrent and SMTP filter: exit status 1: Error: Could not process rule: Operation not supported"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, _, _ := fakeHost(t)
			run := h.Run
			h.Run = func(ctx context.Context, stdin, name string, args ...string) ([]byte, error) {
				if name == "nft" && slices.Equal(args, []string{"-c", "-f", "-"}) && c.refuse != "" && strings.Contains(stdin, c.refuse) {
					return []byte("Error: Could not process rule: Operation not supported\n"), errors.New("exit status 1")
				}
				return run(ctx, stdin, name, args...)
			}
			rs := h.Check(ctx, Options{Host: "203.0.113.7"})
			r, ok := find(rs, Advised, "egress policy")
			if !ok || r.OK != c.ok || !strings.Contains(r.Detail, c.detail) || !c.ok && r.Fix == "" {
				t.Fatalf("%+v", r)
			}
			if f := Failed(rs); len(f) != 0 {
				t.Fatalf("required checks failed: %+v", f)
			}
		})
	}
	// No egress check where the table itself does not load.
	h, _, out := fakeHost(t)
	out["nft"] = "Error: Could not process rule: No such file or directory\n"
	if _, ok := find(h.Check(ctx, Options{Host: "203.0.113.7"}), Advised, "egress policy"); ok {
		t.Fatal("egress checked without the table")
	}
}
