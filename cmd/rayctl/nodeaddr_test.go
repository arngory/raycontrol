package main

import (
	"context"
	"net/netip"
	"testing"

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
