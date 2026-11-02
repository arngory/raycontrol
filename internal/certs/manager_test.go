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
	"slices"
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

// A REALITY service moving to a new name (R4-7): the certificate covers
// both; when the new name fails, the name in use still gets one.
func TestManagerNextName(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	r, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	site, _ := st.ServiceByName(ctx, "site")
	name := provision.SiteName(site)
	epoch := provision.RealityEpoch{Period: 90 * 24 * time.Hour, Lead: 3 * 24 * time.Hour, Prepare: 24 * time.Hour}
	ok := func(context.Context, string) error { return nil }
	if n, err := provision.RotateReality(ctx, st, r.CreatedAt.Add(86*24*time.Hour), epoch, ok, nil); err != nil || n != 1 {
		t.Fatalf("prepare: %d %v", n, err)
	}
	r, _ = st.ServiceByName(ctx, "r")
	next := provision.ParseRealityState(r).SNINext

	now := time.Now()
	var issued [][]string
	failNew := true
	m := &Manager{Store: st, Issue: func(_ context.Context, names []string, key crypto.Signer) ([][]byte, error) {
		if failNew && len(names) > 1 {
			return nil, errors.New("no DNS record for the new name")
		}
		issued = append(issued, names)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: names, NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		return [][]byte{der}, err
	}}
	if n := m.Once(ctx, now); n != 1 || len(issued) != 1 || len(issued[0]) != 1 || issued[0][0] != name {
		t.Fatalf("fallback to the name in use: %d %v", n, issued)
	}
	failNew = false
	m.next = nil
	m.fails = nil
	if n := m.Once(ctx, now); n != 1 || len(issued) != 2 || len(issued[1]) != 2 || issued[1][0] != name || issued[1][1] != next {
		t.Fatalf("both names: %d %v", n, issued)
	}
	all, _ := st.ListServices(ctx)
	if !provision.SiteCovers(ctx, st, all, "site", next) {
		t.Fatal("site does not cover the next name")
	}
	if n := m.Once(ctx, now.Add(time.Hour)); n != 0 {
		t.Fatal("issued again")
	}
}

// With DNS-01 one wildcard covers the site's name and every name REALITY
// moves to: a rotation needs no new certificate (R4-10).
func TestManagerWildcard(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	r, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var issued [][]string
	m := &Manager{Store: st, Wildcard: func(context.Context) string { return "example.com" },
		Issue: func(_ context.Context, names []string, key crypto.Signer) ([][]byte, error) {
			issued = append(issued, names)
			tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: names, NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour)}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
			return [][]byte{der}, err
		}}
	if n := m.Once(ctx, now); n != 1 || len(issued) != 1 || !slices.Equal(issued[0], []string{"*.example.com"}) {
		t.Fatalf("first: %d %v", n, issued)
	}
	epoch := provision.RealityEpoch{Period: 90 * 24 * time.Hour, Lead: 3 * 24 * time.Hour, Prepare: 24 * time.Hour}
	ok := func(context.Context, string) error { return nil }
	provision.RotateReality(ctx, st, r.CreatedAt.Add(86*24*time.Hour), epoch, ok, nil)
	if n := m.Once(ctx, now.Add(time.Hour)); n != 0 {
		t.Fatalf("issued again for the next name: %v", issued)
	}
	// Published at once: the wildcard covers the next name already.
	if n, _ := provision.RotateReality(ctx, st, r.CreatedAt.Add(86*24*time.Hour+time.Minute), epoch, ok, nil); n != 1 {
		t.Fatal("rotation waits for a certificate it has")
	}
}
