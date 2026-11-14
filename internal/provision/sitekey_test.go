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
	"fmt"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

// The pin's test vectors of spec/cert-pin-v1.md §10: SubjectPublicKeyInfo
// (DER) of three P-256 keys, the private scalars the bytes 01..20, 21..40
// and 41..60, and their pins. Never keys of a node.
var pinVectors = []struct {
	d    byte // the first byte of the private scalar
	spki string
	pin  string
}{
	{0x01, "3059301306072a8648ce3d020106082a8648ce3d03010703420004515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f" +
		"4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354", "8dWUSbcnFl3nMr8oMzgSK5liimFZGP7cZ9h4__z0fac"},
	{0x21, "3059301306072a8648ce3d020106082a8648ce3d030107034200041f140146bfb1b251f84f4ddbe0d4cdcfd77afd984a9520e35794021f8312bb9e" +
		"ec995a08b1fa7704df3dcc0b50a9665263fb7711f95f9f8a449c5096e47c892b", "aKDy1GvP0Ev823jJBZeuwhvSD4gJN1ax7KUDa0YLvnM"},
	{0x41, "3059301306072a8648ce3d020106082a8648ce3d03010703420004261efbd3550cf068ef013ed7366ba32f5d6fe557b4b2abce8ade58cba168a55e" +
		"1788a0b29a56a6abec4084c0c96bd3dcbca6b507f35dbea9e985708479d8bdc9", "YZcjdu03922roQ30O9I6r26d48YyWMiges0KEq_U8Z0"},
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

// SiteKeyPins: the leaf's key, then the next key, then for its hour the key
// before; none where the node promises nothing about the next certificate.
func TestSiteKeyPins(t *testing.T) {
	cur, next := vectorKey(t, 0x01), vectorKey(t, 0x21)
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfSignedFor(t, cur)})
	curDER, _ := x509.MarshalPKCS8PrivateKey(cur)
	nextDER, _ := x509.MarshalPKCS8PrivateKey(next)
	now := time.Unix(1767225600, 0)
	site := store.Service{Kind: "site", Name: "site", Settings: `{}`}
	full := map[string][]byte{SecretTLSChain: chain, SecretTLSKey: curDER, NextSecret(SecretTLSKey): nextDER}
	a, b, c := pinVectors[0].pin, pinVectors[1].pin, pinVectors[2].pin

	// The next key's pin: from the key, for a store from before the pin was
	// kept beside it.
	if got := SiteKeyPins(site, full, now); !slices.Equal(got, []string{a, b}) {
		t.Fatalf("pins %v", got)
	}
	// And as stored when the key was made: the key is not parsed for every
	// line of every subscription.
	stored := store.Service{Kind: "site", Settings: `{"tls_next_pin":"` + b + `"}`}
	notParsed := map[string][]byte{SecretTLSChain: chain, NextSecret(SecretTLSKey): []byte("a key that is never parsed")}
	if got := SiteKeyPins(stored, notParsed, now); !slices.Equal(got, []string{a, b}) {
		t.Fatalf("pins with the next key's pin stored: %v", got)
	}
	// The key before, third, until its time is over; never twice.
	prev := func(pin string, until time.Time) store.Service {
		return store.Service{Kind: "site", Settings: fmt.Sprintf(`{"tls_next_pin":%q,"tls_prev_pin":%q,"tls_prev_until":%d}`, b, pin, until.Unix())}
	}
	if got := SiteKeyPins(prev(c, now.Add(time.Hour)), full, now); !slices.Equal(got, []string{a, b, c}) {
		t.Fatalf("pins with the key before: %v", got)
	}
	if got := SiteKeyPins(prev(c, now.Add(time.Hour)), full, now.Add(time.Hour)); !slices.Equal(got, []string{a, b}) {
		t.Fatalf("pins when the hour of the key before is over: %v", got)
	}
	if got := SiteKeyPins(prev(a, now.Add(time.Hour)), full, now); !slices.Equal(got, []string{a, b}) {
		t.Fatalf("pins when the key before is the one in use: %v", got)
	}
	for name, c := range map[string]struct {
		svc     store.Service
		secrets map[string][]byte
	}{
		"the operator's certificate":      {store.Service{Kind: "site", Settings: `{"tls_imported":true}`}, full},
		"no next key":                     {site, map[string][]byte{SecretTLSChain: chain, SecretTLSKey: curDER}},
		"a pin stored, the next key gone": {stored, map[string][]byte{SecretTLSChain: chain, SecretTLSKey: curDER}},
		"no certificate":                  {site, map[string][]byte{SecretTLSKey: curDER, NextSecret(SecretTLSKey): nextDER}},
		"a chain that is no PEM":          {site, map[string][]byte{SecretTLSChain: []byte("garbage"), NextSecret(SecretTLSKey): nextDER}},
		"a next key that is no key":       {site, map[string][]byte{SecretTLSChain: chain, NextSecret(SecretTLSKey): []byte("garbage")}},
		"the next key is the leaf's":      {site, map[string][]byte{SecretTLSChain: chain, NextSecret(SecretTLSKey): curDER}},
		"not a site":                      {store.Service{Kind: "naive", Settings: `{}`}, full},
	} {
		if got := SiteKeyPins(c.svc, c.secrets, now); got != nil {
			t.Errorf("%s: pins %v", name, got)
		}
	}
}

// With the next key's pin stored, the pins of a line cost no parse of an
// RSA key (the reviewer's benchmark: every pinned line of every
// subscription paid one).
func BenchmarkSiteKeyPins(b *testing.B) {
	cur, curDER, _ := newSiteKey()
	next, nextDER, _ := newSiteKey()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"a.example.com"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, cur.Public(), cur)
	secrets := map[string][]byte{SecretTLSChain: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), SecretTLSKey: curDER,
		NextSecret(SecretTLSKey): nextDER}
	pin, _ := PublicKeyPin(next.Public())
	svc := store.Service{Kind: "site", Settings: `{"tls_next_pin":"` + pin + `"}`}
	now := time.Now()
	b.ResetTimer()
	for range b.N {
		if len(SiteKeyPins(svc, secrets, now)) != 2 {
			b.Fatal("no pins")
		}
	}
}

func TestSiteKeyPolicyCheck(t *testing.T) {
	day := 24 * time.Hour
	for _, p := range []SiteKeyPolicy{{Period: DefaultSiteKeyPeriod, Lead: DefaultSiteKeyLead}, {Lead: 14 * day}, {Lead: SiteKeyMinAge},
		{Period: 30 * day, Lead: 14 * day}} {
		if err := p.Check(); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	// A lead under a subscription's lifetime leaves lists in use without
	// the next key: refused, for the period and for the command alike.
	for _, p := range []SiteKeyPolicy{{}, {Period: 30 * day}, {Lead: SiteKeyMinAge - time.Second}, {Period: 14 * day, Lead: 14 * day},
		{Period: day, Lead: 2 * day}, {Period: -day, Lead: 14 * day}, {Lead: -day}} {
		if err := p.Check(); err == nil {
			t.Errorf("%+v passed", p)
		}
	}
	if DefaultSiteKeyPeriod != 180*day || DefaultSiteKeyLead != 14*day {
		t.Fatalf("defaults %v, %v: spec/cert-pin-v1.md §5 says 180 and 14 days", DefaultSiteKeyPeriod, DefaultSiteKeyLead)
	}
}
