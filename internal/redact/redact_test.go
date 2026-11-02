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
