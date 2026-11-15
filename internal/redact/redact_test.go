package redact

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	r := New("example.com", "203.0.113.7")
	in := `spa granted src=198.51.100.23 device=5b2a7728b0c35433 again src=198.51.100.23 from 2001:db8::42
lo 127.0.0.1 any 0.0.0.0 private 10.1.2.3
site k3f.example.com zone a.b.example.com bare example.com and Example.COM
user 6f1c2a3b-0000-4000-8000-000000000007 key mlkem768x25519plus.native.0rtt.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCd
link vless://6f1c2a3b-0000-4000-8000-000000000007@203.0.113.7:443?security=reality#r and rcdev1:eyJ2IjoxfQ
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASC
-----END PRIVATE KEY-----
ok: unit niko-dns.service active, port 53, version v0.1.1`
	out := r.String(in)
	for _, leak := range []string{"198.51.100.23", "2001:db8::42", "10.1.2.3", "k3f", "example.com", "Example.COM", "6f1c2a3b",
		"AbCdEfGh", "eyJ2", "MIIE", "203.0.113.7", "5b2a7728"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q:\n%s", leak, out)
		}
	}
	for _, keep := range []string{"127.0.0.1", "0.0.0.0", "niko-dns.service active, port 53, version v0.1.1", "<sub>.<domain>", "<sub>.<sub>.<domain>",
		"<ip6:", "<ip4-private:", "<uuid>", "<link>", "<bundle>", "<pem>", "<secret>", "device=<id>"} {
		if !strings.Contains(out, keep) {
			t.Errorf("missing %q:\n%s", keep, out)
		}
	}
	// The same address gives the same token within a report.
	first := out[strings.Index(out, "src=")+4 : strings.Index(out, " device")]
	if strings.Count(out, first) != 2 {
		t.Errorf("token %s not stable:\n%s", first, out)
	}
	// Not across reports.
	if strings.Contains(New().String("198.51.100.23"), first) {
		t.Error("tokens match across reports")
	}
}

// Addresses and prefixes that end in "::", or in an IPv4 address, go
// whole: an admin prefix in a relay's install message is one.
func TestIPv6Ends(t *testing.T) {
	out := New().String(`admin addresses [2001:db8:1::/48 198.51.100.7/32], sshd at [2001:db8::]:22, ` +
		`nat64 64:ff9b::198.51.100.9, full 1:2:3:4:5:6:7::, at 2026-11-20T03:41:12Z 12:30:45 aa:bb:cc:dd:ee:ff`)
	for _, leak := range []string{"2001:db8", "198.51.100", "51.100.9", "1:2:3"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q: %s", leak, out)
		}
	}
	for _, keep := range []string{"<ip6:", "/48 <ip4:", "]:22,", "2026-11-20T03:41:12Z 12:30:45 aa:bb:cc:dd:ee:ff"} {
		if !strings.Contains(out, keep) {
			t.Errorf("missing %q: %s", keep, out)
		}
	}
}

// An address followed by a colon, as in an error ("from 2001:db8::5:
// refused"), goes, the colon stays; so does an IPv4 address with a
// leading zero in an octet, which netip does not parse but a reader
// reads. Times and MAC addresses with a colon after them stay.
func TestAddressEnds(t *testing.T) {
	r := New()
	out := r.String(`from 2001:db8::5: refused; 2001:db8:1:2:3:4:5:6: no; dial 203.0.113.05:443; via 198.051.100.007 and 64:ff9b::198.51.100.09; ` +
		`at 12:30:45: ok, mac aa:bb:cc:dd:ee:ff: up, lo 127.000.000.001`)
	for _, leak := range []string{"2001:db8", "1:2:3:4", "203.0.113", "198.051", "100.007", "198.51.100"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q: %s", leak, out)
		}
	}
	for _, keep := range []string{"from <ip6:", ">: refused", ">: no", ">:443", "at 12:30:45: ok", "aa:bb:cc:dd:ee:ff: up", "127.000.000.001"} {
		if !strings.Contains(out, keep) {
			t.Errorf("missing %q: %s", keep, out)
		}
	}
	// The same address, with or without its zero or its colon, the same
	// token.
	if a, b := r.String("203.0.113.5"), r.String("203.0.113.005"); a != b {
		t.Errorf("%s and %s", a, b)
	}
	if a, b := r.String("2001:db8::5"), strings.TrimSuffix(r.String("2001:db8::5:"), ":"); a != b {
		t.Errorf("%s and %s", a, b)
	}
}

// An address with all its groups written out, or seven and "::", then a
// port or a hex word after a colon, without brackets: the pattern takes
// the colon and what follows with it, and the whole does not parse (eight
// groups since 06745d2, review of v0.28.0). And one glued to a word by a
// colon ("ipv6:2001:db8::1"), where the match starts at that colon. Each
// goes, the colon and what follows it stay. Times, MAC addresses, port
// lists, durations, hex IDs and paths of Rust stay as they were.
func TestAddressBetweenColons(t *testing.T) {
	r := New()
	for _, c := range []struct{ in, addr, want string }{
		{"dial 2001:db8:1:2:3:4:5:6:443 refused", "2001:db8:1:2:3:4:5:6", "dial {a}:443 refused"},
		{"dial 2001:db8:1:2:3:4::5:443 refused", "2001:db8:1:2:3:4::5", "dial {a}:443 refused"},
		{"conn 2001:db8:1:2:3:4:5:6:1bb", "2001:db8:1:2:3:4:5:6", "conn {a}:1bb"},
		{"from 2001:db8:1:2:3:4:5:6:7:8", "2001:db8:1:2:3:4:5:6", "from {a}:7:8"},
		{"from 2001:db8:1:2:3:4:5:6: no", "2001:db8:1:2:3:4:5:6", "from {a}: no"},
		{"from 2001:db8::5: refused", "2001:db8::5", "from {a}: refused"},
		{"ipv6:2001:db8::1 up", "2001:db8::1", "ipv6:{a} up"},
		{"src:2001:db8:1::7, dst", "2001:db8:1::7", "src:{a}, dst"},
		{"peer=[2001:db8::9]:443 src:2001:db8::9", "2001:db8::9", "peer=[{a}]:443 src:{a}"},
		{"src:2001:db8:1:2:3:4:5:6:443", "2001:db8:1:2:3:4:5:6", "src:{a}:443"},
		{"src:2001:db8::5: refused", "2001:db8::5", "src:{a}: refused"},
		{"nat64:64:ff9b::198.51.100.9:53", "64:ff9b::198.51.100.9", "nat64:{a}:53"},
		{"lo:::1 and ipv6:::1", "", "lo:::1 and ipv6:::1"},
		{"at 12:34:56 ok", "", "at 12:34:56 ok"},
		{"at 12:30:45: ok", "", "at 12:30:45: ok"},
		{"time:12:34:56 ok", "", "time:12:34:56 ok"},
		{"mac aa:bb:cc:dd:ee:ff up, aa:bb:cc:dd:ee:ff: down, mac:aa:bb:cc:dd:ee:ff", "", "mac aa:bb:cc:dd:ee:ff up, aa:bb:cc:dd:ee:ff: down, mac:aa:bb:cc:dd:ee:ff"},
		{"ports 80:443:8443 and 53:5353", "", "ports 80:443:8443 and 53:5353"},
		{"after 1m30s, 250ms, 1h2m3.5s", "", "after 1m30s, 250ms, 1h2m3.5s"},
		{"device 5b2a7728b0c35433: up", "", "device <id>: up"},
		{"std::io::Error: os::unix", "", "std::io::Error: os::unix"},
	} {
		want := c.want
		if c.addr != "" {
			tok := r.String(c.addr)
			if !strings.HasPrefix(tok, "<ip") {
				t.Fatalf("%s: no token: %s", c.addr, tok)
			}
			want = strings.ReplaceAll(want, "{a}", tok)
		}
		if out := r.String(c.in); out != want {
			t.Errorf("%q:\n got %q\nwant %q", c.in, out, want)
		}
	}
}

// Names learned later (a node's DNS tunnel zones) are hidden as well.
func TestAdd(t *testing.T) {
	r := New("203.0.113.7")
	r.Add("T.Example.com.", "example.com", "")
	out := r.String("zone t.example.com, NS ns9.example.com, other www.example.org")
	if strings.Contains(out, "t.example.com") || strings.Contains(out, "ns9.example.com") || !strings.Contains(out, "www.example.org") {
		t.Fatalf("%q", out)
	}
}
