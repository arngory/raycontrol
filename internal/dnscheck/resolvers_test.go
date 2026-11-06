package dnscheck

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParseResolvers(t *testing.T) {
	rs, err := ParseResolvers([]string{"google, Quad9", "nsdi,udp:192.0.2.9", "tcp:[2001:db8::1]:5353", "2001:db8::2", "8.8.8.8", "google"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rs {
		got = append(got, r.String()+"/"+r.Net+"/"+r.Addr.String()+map[bool]string{true: "/warn"}[r.WarnOnly])
	}
	want := []string{
		"google 8.8.8.8/udp/8.8.8.8:53",
		"quad9 9.9.9.9/udp/9.9.9.9:53",
		"nsdi 195.208.5.1/udp/195.208.5.1:53/warn",
		"nsdi 195.208.4.1/udp/195.208.4.1:53/warn",
		"udp:192.0.2.9/udp/192.0.2.9:53",
		"tcp:[2001:db8::1]:5353/tcp/[2001:db8::1]:5353",
		"udp:2001:db8::2/udp/[2001:db8::2]:53",
		// 8.8.8.8 and google again: the same server once.
	}
	if !slices.Equal(got, want) {
		t.Fatalf("resolvers\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	defaults, err := ParseResolvers(DefaultResolvers)
	if err != nil || len(defaults) != 3 || slices.ContainsFunc(defaults, func(r Resolver) bool { return r.WarnOnly }) {
		t.Fatalf("defaults %v %v", defaults, err)
	}
	for _, bad := range []string{"example.com", "udp:", "tcp:google", "quic:1.1.1.1"} {
		if _, err := ParseResolvers([]string{bad}); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	var many []string
	for i := range 13 {
		many = append(many, netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}).String())
	}
	if _, err := ParseResolvers(many); err == nil {
		t.Error("13 resolvers at once")
	}
}

// The host's resolvers: resolv.conf, and behind systemd-resolved's stub
// the servers it forwards to.
func TestSystemResolvers(t *testing.T) {
	root := t.TempDir()
	write := func(p, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, p), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := SystemResolvers(root); err == nil {
		t.Fatal("no resolv.conf, no error")
	}
	write("/etc/resolv.conf", "# hoster\nnameserver 192.0.2.53\nnameserver 2001:db8::53\noptions edns0\n")
	if got, err := SystemResolvers(root); err != nil || len(got) != 2 || got[0].String() != "192.0.2.53:53" || got[1].String() != "[2001:db8::53]:53" {
		t.Fatalf("plain %v %v", got, err)
	}
	write("/etc/resolv.conf", "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n")
	if got, err := SystemResolvers(root); err != nil || len(got) != 1 || got[0].String() != "127.0.0.53:53" {
		t.Fatalf("stub without its upstream file %v %v", got, err)
	}
	write("/run/systemd/resolve/resolv.conf", "nameserver 198.51.100.53\nnameserver 198.51.100.54\n")
	if got, err := SystemResolvers(root); err != nil || len(got) != 2 || got[0].String() != "198.51.100.53:53" {
		t.Fatalf("behind the stub %v %v", got, err)
	}
	// A local resolver of its own (unbound) is the host's resolver.
	write("/etc/resolv.conf", "nameserver 127.0.0.1\n")
	if got, err := SystemResolvers(root); err != nil || len(got) != 1 || got[0].String() != "127.0.0.1:53" {
		t.Fatalf("local resolver %v %v", got, err)
	}
}
