package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The default route's interface, as /proc/net/route and ipv6_route have
// it: the lowest metric, up, not rejected; IPv6's only without IPv4's.
func TestDefaultIface(t *testing.T) {
	route := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth1	00000000	0102A8C0	0003	0	0	200	00000000	0	0	0
eth0	00000000	010200C0	0003	0	0	100	00000000	0	0	0
eth0	000200C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
wg0	00000000	00000000	0201	0	0	0	00000000	0	0	0
`
	if got := defaultIface4(strings.NewReader(route)); got != "eth0" {
		t.Errorf("IPv4: %q", got)
	}
	zero := strings.Repeat("0", 32)
	route6 := zero + " 00 " + zero + " 00 " + zero + " ffffffff 00000001 00000000 00200200       lo\n" +
		"20010db8000000000000000000000000 40 " + zero + " 00 " + zero + " 00000100 00000001 00000000 00000001     ens3\n" +
		zero + " 00 " + zero + " 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     ens3\n"
	if got := defaultIface6(strings.NewReader(route6)); got != "ens3" {
		t.Errorf("IPv6: %q", got)
	}
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	noDefault := write("route", "Iface\tDestination\nbr0\t000200C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n")
	if got := defaultIface(noDefault, write("ipv6_route", route6)); got != "ens3" {
		t.Errorf("no IPv4 default: %q", got)
	}
	if got := defaultIface(filepath.Join(dir, "none"), filepath.Join(dir, "none6")); got != "" {
		t.Errorf("no tables: %q", got)
	}
	// A name that is a path is none.
	if got := defaultIface4(strings.NewReader("h\n../x\t00000000\t0\t0003\t0\t0\t0\t00000000\n")); got != "" {
		t.Errorf("a path for a name: %q", got)
	}
}

// The speed the kernel reports, 0 for -1 and for an interface without one.
func TestLinkSpeed(t *testing.T) {
	sys := t.TempDir()
	for iface, speed := range map[string]string{"eth0": "1000\n", "ens3": "-1\n", "br0": "x"} {
		if err := os.MkdirAll(filepath.Join(sys, iface), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sys, iface, "speed"), []byte(speed), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for iface, want := range map[string]int{"eth0": 1000, "ens3": 0, "br0": 0, "wg0": 0} {
		if got := linkSpeed(sys, iface); got != want {
			t.Errorf("%s: %d, want %d", iface, got, want)
		}
	}
}

// up_mbps set wins, 0 too (none); unset, the link's speed; else none.
func TestBrutalCeiling(t *testing.T) {
	for _, c := range []struct {
		settings string
		link, up int
		from     string
	}{
		{`{}`, 0, 0, ""},
		{`{}`, 1000, 1000, "link"},
		{`{"up_mbps":500}`, 1000, 500, "up_mbps"},
		{`{"up_mbps":0}`, 1000, 0, "up_mbps"},
		{`{"down_mbps":50}`, 0, 0, ""},
		{``, 100, 100, "link"},
	} {
		if up, from := BrutalCeiling(c.settings, c.link); up != c.up || from != c.from {
			t.Errorf("%s, link %d: %d %q", c.settings, c.link, up, from)
		}
	}
}
