package main

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/node"
)

// Where rayctl knocks and connects (spec/names-v1.md §5): -addr as it is;
// the node's name when it resolves to one of the node's addresses; the
// node's address when it resolves elsewhere or not at all; the host of a
// bundle before names-v1, and of one with no address of the node (its host
// is a name: no address to hold the name to, nor to fall back to).
func TestNodeAddr(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		b        node.Bundle
		override string
		want     string
		sni      string
		fails    bool
	}{
		{"by name", node.Bundle{Host: "127.0.0.1", DNSName: "localhost", Addrs: []string{"127.0.0.1"}}, "", "127.0.0.1", "localhost", false},
		{"resolves elsewhere", node.Bundle{Host: "192.0.2.1", DNSName: "localhost", Addrs: []string{"192.0.2.1"}}, "", "192.0.2.1", "localhost", false},
		{"no answer", node.Bundle{Host: "192.0.2.1", DNSName: "nothing.invalid", Addrs: []string{"192.0.2.1"}}, "", "192.0.2.1", "nothing.invalid", false},
		{"no address: by the host", node.Bundle{Host: "127.0.0.1", DNSName: "nothing.invalid"}, "", "127.0.0.1", "", false},
		{"no address, the host does not resolve", node.Bundle{Host: "nothing.invalid", DNSName: "localhost"}, "", "", "", true},
		{"before names-v1", node.Bundle{Host: "192.0.2.9"}, "", "192.0.2.9", "", false},
		{"-addr", node.Bundle{Host: "192.0.2.1", DNSName: "localhost", Addrs: []string{"192.0.2.1"}}, "198.51.100.3", "198.51.100.3", "", false},
	} {
		var warned string
		ip, sni, err := nodeAddr(ctx, tc.b, tc.override, func(msg string) { warned += msg })
		if (warned != "") != (tc.name == "resolves elsewhere") {
			t.Errorf("%s: warned %q", tc.name, warned)
		}
		if tc.fails {
			if err == nil {
				t.Errorf("%s: %s, want an error", tc.name, ip)
			}
			continue
		}
		if err != nil || ip != netip.MustParseAddr(tc.want) || sni != tc.sni {
			t.Errorf("%s: %s %q %v, want %s %q", tc.name, ip, sni, err, tc.want, tc.sni)
		}
	}
}

// TestKnockVersions: with a node that takes SPA v3 rayctl knocks v3,
// naming the address, and v2 after it only at an address of the node's
// own (spa-v3 §6); it keeps to the node's addresses as with v2.
func TestKnockVersions(t *testing.T) {
	ctx := context.Background()
	b := node.Bundle{Host: "192.0.2.1", DNSName: "localhost", Addrs: []string{"192.0.2.1"}, SPA: node.SPAParams{Versions: []int{2, 3}}}
	// DNS gives an address that is not the node's: the node's, warned.
	var warned string
	ip, sni, err := nodeAddr(ctx, b, "", func(msg string) { warned += msg })
	if err != nil || ip != netip.MustParseAddr("192.0.2.1") || sni != "localhost" || warned == "" {
		t.Fatalf("%s %q %v, warned %q", ip, sni, err, warned)
	}
	a := netip.MustParseAddr
	for _, c := range []struct {
		ip, override string
		v3           bool
		want         []bool
	}{
		{"192.0.2.1", "", true, []bool{true, false}},                // the node's own: v3, then v2
		{"127.0.0.1", "", true, []bool{true}},                       // DNS alone gave it: v3 only
		{"198.51.100.3", "198.51.100.3", true, []bool{true, false}}, // -addr an address: the operator's word
		{"127.0.0.1", "localhost", true, []bool{true}},              // -addr a name: DNS's word
		{"192.0.2.1", "node.example", true, []bool{true, false}},    // a name that gave the node's address
		{"127.0.0.1", "", false, []bool{false}},                     // a bundle before v3
	} {
		bb := b
		if !c.v3 {
			bb.SPA.Versions = nil
		}
		if got := knockVersions(bb, a(c.ip), c.override); !slices.Equal(got, c.want) {
			t.Errorf("%s -addr %q v3 %v: %v, want %v", c.ip, c.override, c.v3, got, c.want)
		}
	}
	now := time.Unix(1767225600, 0)
	ks := knocks(b, a("192.0.2.1"), "", []string{"udp", "tls"})
	if len(ks) != 4 || !ks[0].v3 || !ks[1].v3 || ks[2].v3 || ks[3].v3 || ks[0].carrier != "udp" || ks[3].carrier != "tls" {
		t.Fatalf("knocks %+v", ks)
	}
	if req := ks[0].request(a("192.0.2.1"), now, time.Minute); req.Dst != a("192.0.2.1") || req.TTL != time.Minute || !req.Time.Equal(now) {
		t.Fatalf("v3 request %+v", req)
	}
	if req := ks[2].request(a("192.0.2.1"), now, 0); req.Dst.IsValid() {
		t.Fatalf("v2 request %+v", req)
	}
	// -addr with a zone: the operator's word, and the packet names the
	// address without it, as the node compares it.
	zoned := a("fe80::1%eth0")
	if got := knockVersions(b, zoned, "fe80::1%eth0"); !slices.Equal(got, []bool{true, false}) {
		t.Fatalf("zoned -addr: %v", got)
	}
	if req := (attempt{"udp", true}).request(zoned, now, 0); req.Dst != a("fe80::1") {
		t.Fatalf("zoned request %+v", req)
	}
}
