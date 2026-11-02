package certs

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
)

func TestManager(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	site, err := provision.CreateService(ctx, st, store.Service{Kind: "site", Name: "site", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	name := provision.SiteName(site)

	now := time.Unix(1767225600, 0)
	var issued []string
	fail := false
	notified := 0
	m := &Manager{Store: st, Notify: func() { notified++ }, Issue: func(_ context.Context, names []string, key crypto.Signer) ([][]byte, error) {
		if fail {
			return nil, errors.New("rate limited")
		}
		issued = append(issued, names...)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
			NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		return [][]byte{der}, err
	}}

	if n := m.Once(ctx, now); n != 1 || len(issued) != 1 || issued[0] != name || notified != 1 {
		t.Fatalf("first run: stored %d, issued %v, notified %d", n, issued, notified)
	}
	secrets, _ := st.ServiceSecrets(ctx, site.ID)
	if block, _ := pem.Decode(secrets[provision.SecretTLSChain]); block == nil || len(secrets[provision.SecretTLSKey]) == 0 {
		t.Fatal("chain or key not stored")
	}
	if _, err := x509.ParsePKCS8PrivateKey(secrets[provision.SecretTLSKey]); err != nil {
		t.Fatal(err)
	}

	// Nothing due a month later; due after two.
	if n := m.Once(ctx, now.Add(30*24*time.Hour)); n != 0 {
		t.Fatalf("renewed a month in: %d", n)
	}
	fail = true
	if n := m.Once(ctx, now.Add(61*24*time.Hour)); n != 0 {
		t.Fatal("stored despite a failure")
	}
	// Backs off: no new attempt within the hour.
	fail = false
	if n := m.Once(ctx, now.Add(61*24*time.Hour+30*time.Minute)); n != 0 || len(issued) != 1 {
		t.Fatalf("retried within the backoff: %v", issued)
	}
	if n := m.Once(ctx, now.Add(61*24*time.Hour+2*time.Hour)); n != 1 || len(issued) != 2 {
		t.Fatalf("renewal after the backoff: %d %v", n, issued)
	}
}

func TestAccountKey(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a, err := AccountKey(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	b, err := AccountKey(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(b.Public()) {
		t.Fatal("account key not kept")
	}
}
