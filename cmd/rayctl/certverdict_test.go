package main

import (
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/testca"
)

// TestCertVerdict: after rayctl service cert the administrator is told
// which of the three cases the chain is, and what naive checks.
func TestCertVerdict(t *testing.T) {
	// A public chain as api.cloudflare.com served it, at that time.
	public, err := os.ReadFile("../../internal/roots/testdata/api.cloudflare.com.pem")
	if err != nil {
		t.Fatal(err)
	}
	served := time.Date(2026, 11, 14, 21, 0, 0, 0, time.UTC)
	now := time.Now()
	ch, err := testca.New([]string{"site.example.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	leaf, rest := pem.Decode(ch.ChainPEM)
	inter, _ := pem.Decode(rest)
	noRoot := append(pem.EncodeToMemory(leaf), pem.EncodeToMemory(inter)...)
	for _, tc := range []struct {
		name  string
		chain []byte
		at    time.Time
		want  string
	}{
		{"public", public, served, "the chain leads to GTS Root R4, a public root clients know: naive and DoH clients accept it\n"},
		{"private", ch.ChainPEM, now, "warning: the chain leads to raycontrol test root, a root that is not in the clients' list: " +
			"naive and DoH clients will\nrefuse it unless the root is added in the certificate field of each profile; over QUIC it works only so\n"},
		{"incomplete", noRoot, now, "warning: the chain is incomplete: it ends at raycontrol test intermediate, issued by raycontrol test root"},
	} {
		got := certVerdict(tc.chain, tc.at)
		if !strings.HasPrefix(got, tc.want) || !strings.Contains(got, "naive verifies it as Chrome does") ||
			!strings.Contains(got, "roots installed on the phone count only with an app setting, over HTTP/2") {
			t.Errorf("%s:\n%s", tc.name, got)
		}
		if strings.Count(got, "\n") > 4 {
			t.Errorf("%s: %d lines", tc.name, strings.Count(got, "\n"))
		}
	}
}
