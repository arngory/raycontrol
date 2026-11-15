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

// Names learned later (a node's DNS tunnel zones) are hidden as well.
func TestAdd(t *testing.T) {
	r := New("203.0.113.7")
	r.Add("T.Example.com.", "example.com", "")
	out := r.String("zone t.example.com, NS ns9.example.com, other www.example.org")
	if strings.Contains(out, "t.example.com") || strings.Contains(out, "ns9.example.com") || !strings.Contains(out, "www.example.org") {
		t.Fatalf("%q", out)
	}
}
