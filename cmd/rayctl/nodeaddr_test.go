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
// bundle before names-v1.
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
		{"no answer, no address", node.Bundle{Host: "nothing.invalid", DNSName: "nothing.invalid"}, "", "", "", true},
		{"before names-v1", node.Bundle{Host: "192.0.2.9"}, "", "192.0.2.9", "", false},
		{"-addr", node.Bundle{Host: "192.0.2.1", DNSName: "localhost", Addrs: []string{"192.0.2.1"}}, "198.51.100.3", "198.51.100.3", "", false},
	} {
		ip, sni, err := nodeAddr(ctx, tc.b, tc.override)
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
