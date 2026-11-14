package provision

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

// The pin's test vectors of spec/cert-pin-v1.md §9: SubjectPublicKeyInfo
// (DER) of two P-256 keys, the private scalars the bytes 01..20 and 21..40,
// and their pins. Never keys of a node.
var pinVectors = []struct {
	d    byte // the first byte of the private scalar
	spki string
	pin  string
}{
	{0x01, "3059301306072a8648ce3d020106082a8648ce3d03010703420004515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f" +
		"4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354", "8dWUSbcnFl3nMr8oMzgSK5liimFZGP7cZ9h4__z0fac"},
	{0x21, "3059301306072a8648ce3d020106082a8648ce3d030107034200041f140146bfb1b251f84f4ddbe0d4cdcfd77afd984a9520e35794021f8312bb9e" +
		"ec995a08b1fa7704df3dcc0b50a9665263fb7711f95f9f8a449c5096e47c892b", "aKDy1GvP0Ev823jJBZeuwhvSD4gJN1ax7KUDa0YLvnM"},
}

func vectorKey(t *testing.T, first byte) *ecdsa.PrivateKey {
	t.Helper()
	d := make([]byte, 32)
	for i := range d {
		d[i] = first + byte(i)
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func selfSignedFor(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"site.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// The pin is base64url without padding of SHA-256 over the DER
// SubjectPublicKeyInfo, 32 bytes: the same for a key (the next one, which
// has no certificate yet) and for a certificate of that key.
func TestPublicKeyPinVectors(t *testing.T) {
	for _, v := range pinVectors {
		spki, err := hex.DecodeString(v.spki)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(spki)
		if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != v.pin {
			t.Errorf("vector %02x: SHA-256 of the SPKI gives %s, want %s", v.d, got, v.pin)
		}
		key := vectorKey(t, v.d)
		if got, err := PublicKeyPin(key.Public()); err != nil || got != v.pin {
			t.Errorf("vector %02x: the key's pin %s %v, want %s", v.d, got, err, v.pin)
		}
		der := selfSignedFor(t, key)
		if got, err := SPKIPin(der); err != nil || got != v.pin {
			t.Errorf("vector %02x: the certificate's pin %s %v, want %s", v.d, got, err, v.pin)
		}
		if b, err := base64.RawURLEncoding.DecodeString(v.pin); err != nil || len(b) != 32 {
			t.Errorf("vector %02x: the pin is not 32 bytes", v.d)
		}
	}
	// The node's own keys are RSA: the next key's pin, made from the key,
	// is the pin of the certificate it gets later.
	key, _, err := newSiteKey()
	if err != nil {
		t.Fatal(err)
	}
	pin, err := PublicKeyPin(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if got, err := SPKIPin(selfSignedFor(t, key)); err != nil || got != pin {
		t.Fatalf("RSA: the certificate's pin %s %v, the key's %s", got, err, pin)
	}
}

// SiteKeyPins: the leaf's key, then the next key; none where the node
// promises nothing about the next certificate.
func TestSiteKeyPins(t *testing.T) {
	cur, next := vectorKey(t, 0x01), vectorKey(t, 0x21)
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfSignedFor(t, cur)})
	curDER, _ := x509.MarshalPKCS8PrivateKey(cur)
	nextDER, _ := x509.MarshalPKCS8PrivateKey(next)
	site := store.Service{Kind: "site", Name: "site", Settings: `{}`}
	full := map[string][]byte{SecretTLSChain: chain, SecretTLSKey: curDER, NextSecret(SecretTLSKey): nextDER}

	got := SiteKeyPins(site, full)
	if len(got) != 2 || got[0] != pinVectors[0].pin || got[1] != pinVectors[1].pin {
		t.Fatalf("pins %v", got)
	}
	for name, c := range map[string]struct {
		svc     store.Service
		secrets map[string][]byte
	}{
		"the operator's certificate": {store.Service{Kind: "site", Settings: `{"tls_imported":true}`}, full},
		"no next key":                {site, map[string][]byte{SecretTLSChain: chain, SecretTLSKey: curDER}},
		"no certificate":             {site, map[string][]byte{SecretTLSKey: curDER, NextSecret(SecretTLSKey): nextDER}},
		"a chain that is no PEM":     {site, map[string][]byte{SecretTLSChain: []byte("garbage"), NextSecret(SecretTLSKey): nextDER}},
		"a next key that is no key":  {site, map[string][]byte{SecretTLSChain: chain, NextSecret(SecretTLSKey): []byte("garbage")}},
		"the next key is the leaf's": {site, map[string][]byte{SecretTLSChain: chain, NextSecret(SecretTLSKey): curDER}},
		"not a site":                 {store.Service{Kind: "naive", Settings: `{}`}, full},
	} {
		if got := SiteKeyPins(c.svc, c.secrets); got != nil {
			t.Errorf("%s: pins %v", name, got)
		}
	}
}

func TestSiteKeyPolicyCheck(t *testing.T) {
	day := 24 * time.Hour
	for _, p := range []SiteKeyPolicy{{}, {Period: DefaultSiteKeyPeriod, Lead: DefaultSiteKeyLead}, {Lead: 14 * day}, {Period: 30 * day}} {
		if err := p.Check(); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	for _, p := range []SiteKeyPolicy{{Period: 14 * day, Lead: 14 * day}, {Period: day, Lead: 2 * day}, {Period: -day}, {Lead: -day}} {
		if err := p.Check(); err == nil {
			t.Errorf("%+v passed", p)
		}
	}
	if DefaultSiteKeyPeriod != 180*day || DefaultSiteKeyLead != 14*day {
		t.Fatalf("defaults %v, %v: spec/cert-pin-v1.md §5 says 180 and 14 days", DefaultSiteKeyPeriod, DefaultSiteKeyLead)
	}
}
