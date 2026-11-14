package roots_test

import (
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/roots"
	"github.com/arngory/raycontrol/internal/testca"
)

// served is when testdata/api.cloudflare.com.pem was taken: a public
// chain (WE1, GTS Root R4 cross-signed by GlobalSign Root CA).
var served = time.Date(2026, 11, 14, 21, 0, 0, 0, time.UTC)

// TestCheckChain: the three cases an import is told of.
func TestCheckChain(t *testing.T) {
	public, err := os.ReadFile("testdata/api.cloudflare.com.pem")
	if err != nil {
		t.Fatal(err)
	}
	if c := roots.CheckChain(public, served); c.Kind != roots.Public || c.Root != "GTS Root R4" {
		t.Fatalf("public: %+v", c)
	}
	// Without its intermediate the public chain is incomplete.
	leaf, _ := pem.Decode(public)
	if c := roots.CheckChain(pem.EncodeToMemory(leaf), served); c.Kind != roots.Incomplete || c.Top != "api.cloudflare.com" || c.Issuer != "WE1" {
		t.Fatalf("leaf alone: %+v", c)
	}
	now := time.Now()
	ch, err := testca.New([]string{"site.example.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if c := roots.CheckChain(ch.ChainPEM, now); c.Kind != roots.Private || c.Root != "raycontrol test root" {
		t.Fatalf("private: %+v", c)
	}
	// Leaf and intermediate, no root: incomplete, up to the intermediate.
	var noRoot []byte
	rest := ch.ChainPEM
	for range 2 {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		noRoot = append(noRoot, pem.EncodeToMemory(b)...)
	}
	if c := roots.CheckChain(noRoot, now); c.Kind != roots.Incomplete || c.Top != "raycontrol test intermediate" || c.Issuer != "raycontrol test root" {
		t.Fatalf("no root: %+v", c)
	}
	if c := roots.CheckChain([]byte("nothing"), now); c.Kind != roots.Incomplete {
		t.Fatalf("no certificate: %+v", c)
	}
}
