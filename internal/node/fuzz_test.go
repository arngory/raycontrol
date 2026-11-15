package node

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// FuzzDecodeInvite: an invite is text a person pastes (rcinv1, or the
// short rcinv2 of a QR code): whatever it holds, it parses or is refused,
// no panic; one taken has an API endpoint and an expiry, and a short one
// whose SPA parameters hold is the same bundle once written again, its
// host the same address or a name of an invite's letters.
func FuzzDecodeInvite(f *testing.F) {
	for _, b := range []Bundle{invite2Bundle("203.0.113.7", true), invite2Bundle("2001:db8::7", false), invite2Bundle("node.example.org", false)} {
		if s, err := b.EncodeInvite2(); err == nil {
			f.Add(s)
			f.Add(strings.ToLower(s))
			f.Add(s[:len(s)-3])
		}
		if s, err := b.EncodeInvite(); err == nil {
			f.Add(s)
		}
	}
	f.Add(InvitePrefix + base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"api":{"port":1},"expires":-1,"spa":{"node_id":"x"}}`)))
	f.Add("RCINV2:AIA4WADRA4AACAQDAQCQMBYIBEFAWDANBYHQAAEGJQAAABSUEAQSEIZEEUTCOKBJFIVSYLJOF4YDCMRTGQ2TMNZYHE5DWPB5HY7VLEYLRMAIQAGOUCQ2FI5EUWTKOQCBIJBUIRKGI5EESSSLJRGU4T2QKFJFGVCVKZLVQWK2LNOF2XS7AAD3YVLAMFRGGZDFMZTWQ2LKNNWG23TPOBYXE43UOV3HO6DZPJ5XY7L6P5UVOCUA")
	f.Add("RCINV2:AIEA")
	f.Fuzz(func(t *testing.T, s string) {
		b, err := DecodeInvite(s)
		if err != nil {
			return
		}
		if b.Version != 1 || b.API == nil || b.Expires == 0 {
			t.Fatalf("%q taken as %+v", s, b)
		}
		short := strings.HasPrefix(strings.ToUpper(strings.TrimSpace(s)), InvitePrefix2)
		if !short {
			return
		}
		if a, err := netip.ParseAddr(b.Host); err != nil && !hostName(b.Host) || err == nil && a.Zone() != "" {
			t.Fatalf("%q: host %q", s, b.Host)
		}
		if _, err := b.SPA.Params(); err != nil {
			return // refused where it is used (rayctl remote enroll)
		}
		again, err := b.EncodeInvite2()
		if err != nil {
			t.Fatalf("%q taken as %+v, not written again: %v", s, b, err)
		}
		c, err := DecodeInvite(again)
		if err != nil {
			t.Fatalf("%q written again as %q: %v", s, again, err)
		}
		// A mapped IPv6 host goes as the IPv4 address it is.
		if a, err := netip.ParseAddr(b.Host); err == nil && a.Is4In6() {
			b.Host = a.Unmap().String()
		}
		if !reflect.DeepEqual(b, c) {
			t.Fatalf("%q: %+v written again reads %+v", s, b, c)
		}
	})
}

// FuzzDecodeRelayBundle: a relay's bundle is the exit's text that root on
// the relay installs, rayspa reads its exit's address into the nft table
// (the DNAT target) and rayd relay into the URL of the exit's API: one
// taken names an exit by its address alone, with an API, a certificate and
// a name, and reads back the same once written again.
func FuzzDecodeRelayBundle(f *testing.F) {
	good := RelayBundle{Version: 1, Name: "msk", Exit: netip.MustParseAddr("203.0.113.7"), API: BundleSub{Port: 48213, Pin: "pin"},
		Cert: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", Probe: &RelayProbe{Port: 31000, Cert: "x"}}
	for _, b := range []RelayBundle{good, {Version: 1, Name: "r", Exit: netip.MustParseAddr("2001:db8::7"), API: BundleSub{Port: 1, Pin: "p"}, Cert: "c"}} {
		s, err := b.Encode()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(s)
	}
	for _, j := range []string{
		`{"v":1,"name":"r","exit":"fe80::1%eth0","api":{"port":1,"pin":"p"},"cert":"c"}`,
		`{"v":1,"name":"r","exit":"fe80::1%x\nflush ruleset\n","api":{"port":1,"pin":"p"},"cert":"c"}`,
		`{"v":1,"name":"r","exit":"::ffff:203.0.113.7","api":{"port":1,"pin":"p"},"cert":"c","probe":{"port":0}}`,
		`{"v":1,"name":"r","exit":"","api":{"port":70000,"pin":"p"},"cert":"c"}`,
	} {
		f.Add(RelayBundlePrefix + base64.RawURLEncoding.EncodeToString([]byte(j)))
	}
	f.Fuzz(func(t *testing.T, s string) {
		b, err := DecodeRelayBundle(s)
		if err != nil {
			return
		}
		switch {
		case !b.Exit.IsValid() || b.API.Port == 0 || b.API.Pin == "" || b.Cert == "" || b.Name == "":
			t.Fatalf("%q taken as %+v", s, b)
		case b.Probe != nil && (b.Probe.Port == 0 || b.Probe.Cert == ""):
			t.Fatalf("%q taken with probe %+v", s, b.Probe)
		case b.Exit.Zone() != "" || strings.ContainsAny(b.Exit.String(), " \t\n\r{}\";#%"):
			t.Fatalf("%q taken with exit %q", s, b.Exit)
		}
		again, err := b.Encode()
		if err != nil {
			t.Fatal(err)
		}
		c, err := DecodeRelayBundle(again)
		if err != nil {
			t.Fatalf("%+v written again: %v", b, err)
		}
		if bj, _ := json.Marshal(b); !reflect.DeepEqual(b, c) {
			t.Fatalf("%s written again reads %+v", bj, c)
		}
	})
}
