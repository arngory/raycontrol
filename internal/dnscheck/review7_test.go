package dnscheck

import (
	"net/netip"
	"testing"
)

// A zone written with capitals or a final dot (a service's settings take
// it as given) is checked as the front matches it: delegated, no false
// "no NS" (review 7).
func TestZoneNotCanonical(t *testing.T) {
	for _, name := range []string{"T3X.example.com", dnsttZone + "."} {
		w := newWorld(t)
		zones := w.zones()[:1]
		zones[0].Name = name
		z := w.check(t, zones).Zones[0]
		if !z.Delegated || z.Parent.State == Fail {
			t.Errorf("%q: parent %v %q, delegated %v", name, z.Parent.State, z.Parent.Detail, z.Delegated)
		}
	}
}

// With the node's own address unknown, a zone the parent delegates is not
// known to lead here: no resolver is asked (review 7: the glue pointed to
// another host, and 8.8.8.8 was asked three times).
func TestUnknownNodeAsksNoResolver(t *testing.T) {
	w := newWorld(t)
	for _, p := range w.parents {
		p.set(dnsttZone, "wrongglue")
	}
	zones := w.zones()[:1]
	zones[0].Host = ""
	z := w.check(t, zones).Zones[0]
	if asked := len(w.net.sent(netip.MustParseAddr("8.8.8.8"))); asked != 0 || z.Delegated {
		t.Fatalf("delegated %v, %d queries to 8.8.8.8 (%q)", z.Delegated, asked, z.Parent.Detail)
	}
}

// Over the remote API only named resolvers and public addresses on port 53
// (review 7: loopback, private, link-local and other ports were dialled).
func TestResolverPublic(t *testing.T) {
	for in, want := range map[string]bool{
		"google": true, "udp:9.9.9.9": true, "tcp:1.1.1.1": true, "udp:[2606:4700:4700::1111]": true,
		"tcp:127.0.0.1:22": false, "udp:10.0.0.1": false, "udp:169.254.169.254": false, "udp:8.8.8.8:5353": false,
		"tcp:[::1]:53": false, "udp:192.168.1.1": false, "udp:[fe80::1]": false,
		// Review 8: CGNAT, NAT64 of a private address, site-local,
		// benchmarking, reserved, documentation, 6to4, Teredo.
		"udp:100.100.100.100": false, "udp:[64:ff9b::a00:1]": false, "udp:[fec0::1]": false, "udp:198.18.0.1": false,
		"udp:240.0.0.1": false, "udp:203.0.113.5": false, "udp:[2002:a00:1::1]": false, "udp:[2001:0:a00:1::1]": false,
		"udp:[2001:4860:4860::8888]": true,
		// Review 9: NAT64 by what it embeds (DNS64 of a public server on
		// an IPv6-only node); benchmarking, RFC 9637 documentation and
		// IPv4-compatible forms refused.
		"udp:[64:ff9b::808:808]": true, "udp:[2001:2::1]": false, "udp:[3fff::1]": false, "udp:[::a00:1]": false,
		"udp:[64:ff9b:1::808:808]": false,
		// Review 10: an address with a zone, whatever it is.
		"udp:[64:ff9b::a00:1%eth0]": false, "udp:[2002:a00:1::1%x]": false, "udp:[fec0::1%1]": false, "udp:[2001:4860:4860::8888%eth0]": false,
	} {
		rs, err := ParseResolvers([]string{in})
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got := rs[0].Public(); got != want {
			t.Errorf("%s: public %v, want %v", in, got, want)
		}
	}
}
