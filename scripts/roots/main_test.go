package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func root(t *testing.T, cn string, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestIntersect: a root is kept when its key is in both lists, as the
// first list has it, once, in that list's order; the output parses back.
func TestIntersect(t *testing.T) {
	k := func() *ecdsa.PrivateKey { k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); return k }
	ka, kb, kc := k(), k(), k()
	a, b, c := root(t, "A", ka), root(t, "B", kb), root(t, "C only in Chrome", kc)
	b2 := root(t, "B, reissued", kb) // the same key under another certificate
	out := Intersect([]*x509.Certificate{c, b, a, b}, []*x509.Certificate{a, b2, root(t, "D only in Mozilla", k())},
		Header{Source: "test", Date: "2026-11-14", Chrome: 4, Mozilla: 3})
	s := string(out)
	if !strings.Contains(s, "# count: 2\n") || !strings.Contains(s, "# date: 2026-11-14\n") || strings.Contains(s, "only in") ||
		strings.Index(s, "# CN=B\n") > strings.Index(s, "# CN=A\n") || strings.Contains(s, "reissued") {
		t.Fatalf("output:\n%s", s)
	}
	dir := t.TempDir()
	f := filepath.Join(dir, "out.pem")
	if err := os.WriteFile(f, out, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(f, f, "test", "2026-11-14", filepath.Join(dir, "again.pem")); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(filepath.Join(dir, "again.pem"))
	if !strings.Contains(string(again), "# count: 2\n") {
		t.Fatalf("again:\n%s", again)
	}
}
