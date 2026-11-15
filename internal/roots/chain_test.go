package roots_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
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

// TestCheckChainInvalid: a chain that reaches a root, of the list or its
// own, but fails for another reason says that reason, not "incomplete".
func TestCheckChainInvalid(t *testing.T) {
	public, err := os.ReadFile("testdata/api.cloudflare.com.pem")
	if err != nil {
		t.Fatal(err)
	}
	// The leaf expired (2027-01-10), its issuers did not.
	later := time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)
	if c := roots.CheckChain(public, later); c.Kind != roots.Invalid || !c.Listed || c.Root != "GTS Root R4" || !strings.Contains(c.Reason, "expired") {
		t.Fatalf("expired public leaf: %+v", c)
	}
	// A private CA's leaf without serverAuth.
	now := time.Now()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "own root"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "site.example.test"}, DNSNames: []string{"site.example.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	if c := roots.CheckChain(chain, now); c.Kind != roots.Invalid || c.Listed || c.Root != "own root" || !strings.Contains(c.Reason, "key usage") {
		t.Fatalf("no serverAuth: %+v", c)
	}
}
