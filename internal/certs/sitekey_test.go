package certs

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/testca"
)

const day = 24 * time.Hour

// testCA is one CA for the package's tests: its keys take seconds to make.
var testCA = sync.OnceValues(func() (*testca.CA, error) {
	return testca.NewCA(time.Unix(1700000000, 0), time.Unix(2100000000, 0))
})

// siteNode is a node with a site and a manager whose certificates come
// from the test CA, 90 days each, as an ACME CA's: for the key it is given.
type siteNode struct {
	t      *testing.T
	st     *store.Store
	m      *Manager
	id     int64
	issued int // certificates issued
	fail   bool
}

func newSiteNode(t *testing.T, keys provision.SiteKeyPolicy) *siteNode {
	t.Helper()
	ctx := context.Background()
	ca, err := testCA()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	// REALITY brings its site, and naive and DoH need both.
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "reality", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	site, err := st.ServiceByName(ctx, "site")
	if err != nil {
		t.Fatal(err)
	}
	n := &siteNode{t: t, st: st, id: site.ID}
	n.m = &Manager{Store: st, Keys: keys}
	return n.at(ca, nil)
}

// at makes the manager's certificates start at the time of the order (now
// points to the test's clock; nil: the time of the first order stays).
func (n *siteNode) at(ca *testca.CA, now *time.Time) *siteNode {
	n.m.Issue = func(_ context.Context, names []string, key crypto.Signer) ([][]byte, error) {
		if n.fail {
			return nil, errors.New("rate limited")
		}
		n.issued++
		from := time.Unix(1767225600, 0)
		if now != nil {
			from = *now
		}
		return ca.Issue(names, key.Public(), from.Add(-time.Hour), from.Add(90*day))
	}
	return n
}

// operatorCert is a certificate with a key of its own, as an operator
// brings one (rayctl service cert): chain and key in PEM.
func operatorCert(t *testing.T, from, to time.Time) (chainPEM, keyPEM []byte) {
	t.Helper()
	ca, err := testCA()
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ca.Issue([]string{"*.example.com"}, &key.PublicKey, from, to)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return testca.PEM(chain), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// state is what the store holds for the site.
type siteState struct {
	leaf      *x509.Certificate
	leafPin   string
	key, next []byte
	pins      []string
	keys      provision.SiteKeyState
}

func (n *siteNode) state() siteState {
	n.t.Helper()
	ctx := context.Background()
	svc, err := n.st.ServiceByName(ctx, "site")
	if err != nil {
		n.t.Fatal(err)
	}
	secrets, err := n.st.ServiceSecrets(ctx, n.id)
	if err != nil {
		n.t.Fatal(err)
	}
	s := siteState{key: secrets[provision.SecretTLSKey], next: secrets[provision.NextSecret(provision.SecretTLSKey)],
		pins: provision.SiteKeyPins(svc, secrets), keys: provision.ParseSiteKeyState(svc)}
	if block, _ := pem.Decode(secrets[provision.SecretTLSChain]); block != nil {
		if s.leaf, err = x509.ParseCertificate(block.Bytes); err != nil {
			n.t.Fatal(err)
		}
		if s.leafPin, err = provision.SPKIPin(block.Bytes); err != nil {
			n.t.Fatal(err)
		}
	}
	return s
}

// pinOf is the pin of a stored key (PKCS#8).
func pinOf(t *testing.T, der []byte) string {
	t.Helper()
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := provision.PublicKeyPin(key.(crypto.Signer).Public())
	if err != nil {
		t.Fatal(err)
	}
	return pin
}

// Obligation 1 (cert-pin-v1 §4): the site keeps its key across issuances.
// A renewal and a new set of names give another certificate with the same
// SubjectPublicKeyInfo, so no pin changes.
func TestManagerKeepsKey(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1767225600, 0)
	n := newSiteNode(t, provision.SiteKeyPolicy{Period: provision.DefaultSiteKeyPeriod, Lead: provision.DefaultSiteKeyLead})
	ca, _ := testCA()
	n.at(ca, &now)

	if got := n.m.Once(ctx, now); got != 1 {
		t.Fatalf("first run stored %d", got)
	}
	first := n.state()
	if first.leaf == nil || len(first.key) == 0 || len(first.next) == 0 {
		t.Fatal("no chain, key or next key after the first certificate")
	}
	if first.leafPin != pinOf(t, first.key) || !slices.Equal(first.pins, []string{first.leafPin, pinOf(t, first.next)}) {
		t.Fatalf("pins %v, leaf %s", first.pins, first.leafPin)
	}
	if first.keys.KeyAt != now.Unix() || first.keys.NextAt != now.Unix() {
		t.Fatalf("times of the keys: %+v", first.keys)
	}

	// The renewal, 61 days in: another certificate, the same key.
	now = now.Add(61 * day)
	if got := n.m.Once(ctx, now); got != 1 || n.issued != 2 {
		t.Fatalf("renewal: stored %d, issued %d", got, n.issued)
	}
	renewed := n.state()
	if bytes.Equal(renewed.leaf.Raw, first.leaf.Raw) {
		t.Fatal("the renewal stored the same certificate")
	}
	if renewed.leafPin != first.leafPin || !bytes.Equal(renewed.key, first.key) || !bytes.Equal(renewed.next, first.next) {
		t.Fatal("the renewal changed a key")
	}
	if !slices.Equal(renewed.pins, first.pins) || renewed.keys != first.keys {
		t.Fatalf("the renewal changed the pins or their times: %v %+v", renewed.pins, renewed.keys)
	}

	// New names (a service under the site): issued again at once, the same key.
	now = now.Add(day)
	if _, err := provision.CreateService(ctx, n.st, store.Service{Kind: "naive", Name: "naive", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if got := n.m.Once(ctx, now); got != 1 || n.issued != 3 {
		t.Fatalf("new name: stored %d, issued %d", got, n.issued)
	}
	named := n.state()
	if len(named.leaf.DNSNames) != 2 || named.leafPin != first.leafPin || !bytes.Equal(named.key, first.key) || !slices.Equal(named.pins, first.pins) {
		t.Fatalf("new names changed the key: names %v, pins %v", named.leaf.DNSNames, named.pins)
	}
}

// Obligation 2 (§4): a node updated to cert-pin-v1 has a certificate and
// its key, as raycontrol stored them before, and nothing else. The manager
// makes the next key at its first check, without an order; until then the
// lines carry no pins.
func TestManagerNextKeyOnUpdatedStore(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1767225600, 0)
	n := newSiteNode(t, provision.SiteKeyPolicy{})
	oldChain, oldKey := operatorCert(t, now.Add(-20*day), now.Add(70*day))
	block, _ := pem.Decode(oldKey)
	n.st.SetServiceSecret(ctx, n.id, provision.SecretTLSChain, oldChain)
	n.st.SetServiceSecret(ctx, n.id, provision.SecretTLSKey, block.Bytes)

	before := n.state()
	if before.pins != nil || len(before.next) != 0 {
		t.Fatalf("before the first check: pins %v", before.pins)
	}
	if got := n.m.Once(ctx, now); got != 0 || n.issued != 0 {
		t.Fatalf("the first check ordered a certificate: stored %d, issued %d", got, n.issued)
	}
	after := n.state()
	if len(after.next) == 0 || !bytes.Equal(after.key, block.Bytes) || !bytes.Equal(after.leaf.Raw, before.leaf.Raw) {
		t.Fatal("no next key, or the certificate changed")
	}
	if !slices.Equal(after.pins, []string{before.leafPin, pinOf(t, after.next)}) {
		t.Fatalf("pins %v", after.pins)
	}
	// The next key's lead starts now; the key in use is as old as its
	// certificate (the old raycontrol made one with each).
	if after.keys.NextAt != now.Unix() || after.keys.KeyAt != now.Add(-20*day).Unix() {
		t.Fatalf("times of the keys: %+v", after.keys)
	}
	// Made once.
	if n.m.Once(ctx, now.Add(time.Hour)); !bytes.Equal(n.state().next, after.next) || n.state().keys != after.keys {
		t.Fatal("the second check made another next key")
	}
	// In a back-off too: it needs no order.
	n2 := newSiteNode(t, provision.SiteKeyPolicy{})
	n2.fail = true
	n2.m.Once(ctx, now) // the first certificate fails: an hour's wait
	n2.st.SetServiceSecret(ctx, n2.id, provision.SecretTLSChain, oldChain)
	n2.st.SetServiceSecret(ctx, n2.id, provision.SecretTLSKey, block.Bytes)
	if n2.m.Once(ctx, now.Add(time.Minute)); len(n2.state().next) == 0 {
		t.Fatal("no next key while the site waits after a failure")
	}
}

// Obligation 3b (§5): at an issuance the key gives way to the next one
// once it is a period old and the next has been in subscriptions for the
// lead; the switch makes a new next key.
func TestManagerRotatesAtPeriod(t *testing.T) {
	ctx := context.Background()
	start := time.Unix(1767225600, 0)
	now := start
	n := newSiteNode(t, provision.SiteKeyPolicy{Period: 180 * day, Lead: 14 * day})
	ca, _ := testCA()
	n.at(ca, &now)
	n.m.Once(ctx, now)
	first := n.state()

	// Renewals at 61 and 122 days: the key is younger than the period.
	for _, d := range []time.Duration{61 * day, 122 * day} {
		now = start.Add(d)
		if got := n.m.Once(ctx, now); got != 1 {
			t.Fatalf("renewal at %v: stored %d", d, got)
		}
		if s := n.state(); s.leafPin != first.leafPin || !slices.Equal(s.pins, first.pins) {
			t.Fatalf("the key changed %v in", d)
		}
	}
	// The renewal at 183 days: the next key takes over.
	now = start.Add(183 * day)
	if got := n.m.Once(ctx, now); got != 1 {
		t.Fatalf("renewal at the period: stored %d", got)
	}
	second := n.state()
	if second.leafPin != first.pins[1] || !bytes.Equal(second.key, first.next) {
		t.Fatalf("the certificate is not for the next key: leaf %s, pins before %v", second.leafPin, first.pins)
	}
	if len(second.next) == 0 || bytes.Equal(second.next, first.next) || bytes.Equal(second.next, first.key) {
		t.Fatal("no new next key")
	}
	if !slices.Equal(second.pins, []string{first.pins[1], pinOf(t, second.next)}) {
		t.Fatalf("pins after the switch %v", second.pins)
	}
	if second.keys.KeyAt != now.Unix() || second.keys.NextAt != now.Unix() {
		t.Fatalf("times after the switch: %+v", second.keys)
	}

	// A period of a day now: the key is old enough at once, the next one
	// not yet 14 days in subscriptions. An issuance (a new name) keeps the
	// key until then.
	n.m.Keys = provision.SiteKeyPolicy{Period: day, Lead: 14 * day}
	now = start.Add(188 * day)
	if _, err := provision.CreateService(ctx, n.st, store.Service{Kind: "naive", Name: "naive", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if got := n.m.Once(ctx, now); got != 1 {
		t.Fatalf("new name: stored %d", got)
	}
	if s := n.state(); s.leafPin != second.leafPin || !slices.Equal(s.pins, second.pins) {
		t.Fatal("switched to a next key 5 days in subscriptions")
	}
	now = start.Add(198 * day)
	if _, err := provision.CreateService(ctx, n.st, store.Service{Kind: "doh", Name: "doh", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if got := n.m.Once(ctx, now); got != 1 {
		t.Fatalf("second new name: stored %d", got)
	}
	if s := n.state(); s.leafPin != second.pins[1] {
		t.Fatal("no switch 15 days after the next key was published")
	}
	// No period: only when asked.
	n.m.Keys = provision.SiteKeyPolicy{}
	third := n.state()
	now = start.Add(600 * day)
	if n.m.Once(ctx, now); n.state().leafPin != third.leafPin {
		t.Fatal("switched without a period")
	}
}

// Obligation 3a (§5): the operator's switch. Too early it is a failed
// precondition, as a seal key's (checkGrace's pattern); with force, or
// after the lead, rayd orders a certificate with the next key at once.
func TestManagerRotatesWhenAsked(t *testing.T) {
	ctx := context.Background()
	start := time.Unix(1767225600, 0)
	now := start
	n := newSiteNode(t, provision.SiteKeyPolicy{})
	ca, _ := testCA()
	n.at(ca, &now)
	lead := 14 * day

	// No certificate yet.
	if err := provision.RequestSiteKeyRotation(ctx, n.st, "site", now, lead, true); !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("without a certificate: %v", err)
	}
	n.m.Once(ctx, now)
	first := n.state()

	now = start.Add(13 * day)
	err := provision.RequestSiteKeyRotation(ctx, n.st, "site", now, lead, false)
	if !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("13 days in: %v", err)
	}
	// The message says since when, from when, and how to do it anyway.
	for _, want := range []string{"since " + start.UTC().Format(time.RFC3339), "switch after " + start.Add(lead).UTC().Format(time.RFC3339),
		"rayctl service rotate site -force"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal lacks %q: %v", want, err)
		}
	}
	if n.m.Once(ctx, now); n.issued != 1 || n.state().keys.RotateAt != 0 {
		t.Fatal("a refused switch left a request")
	}

	// Anyway.
	if err := provision.RequestSiteKeyRotation(ctx, n.st, "site", now, lead, true); err != nil {
		t.Fatal(err)
	}
	if n.state().keys.RotateAt != now.Unix() {
		t.Fatal("no request stored")
	}
	// The order fails: the request stays, the key too.
	n.fail = true
	if got := n.m.Once(ctx, now); got != 0 || n.state().leafPin != first.leafPin || n.state().keys.RotateAt == 0 {
		t.Fatalf("after a failed order: stored %d", got)
	}
	n.fail = false
	now = now.Add(2 * time.Hour) // past the back-off
	if got := n.m.Once(ctx, now); got != 1 || n.issued != 2 {
		t.Fatalf("the switch: stored %d, issued %d", got, n.issued)
	}
	second := n.state()
	if second.leafPin != first.pins[1] || !slices.Equal(second.pins, []string{first.pins[1], pinOf(t, second.next)}) {
		t.Fatalf("after the switch: leaf %s, pins %v, before %v", second.leafPin, second.pins, first.pins)
	}
	if second.keys.RotateAt != 0 || second.keys.KeyAt != now.Unix() || second.keys.NextAt != now.Unix() {
		t.Fatalf("state after the switch: %+v", second.keys)
	}
	// Once: the next check orders nothing.
	if got := n.m.Once(ctx, now.Add(time.Hour)); got != 0 {
		t.Fatal("ordered again after the switch")
	}

	// The new next key has its own lead; after it no force is needed.
	if err := provision.RequestSiteKeyRotation(ctx, n.st, "site", now.Add(lead-time.Minute), lead, false); !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("before the new key's lead: %v", err)
	}
	now = now.Add(lead)
	if err := provision.RequestSiteKeyRotation(ctx, n.st, "site", now, lead, false); err != nil {
		t.Fatalf("after the lead: %v", err)
	}
	// Asked twice: one request.
	if err := provision.RequestSiteKeyRotation(ctx, n.st, "site", now.Add(time.Minute), lead, false); err != nil || n.state().keys.RotateAt != now.Unix() {
		t.Fatalf("asked twice: %v", err)
	}
	if got := n.m.Once(ctx, now); got != 1 || n.state().leafPin != second.pins[1] {
		t.Fatalf("the switch after the lead: stored %d", got)
	}
	// Not a site.
	if err := provision.RequestSiteKeyRotation(ctx, n.st, "reality", now, lead, true); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("a REALITY service: %v", err)
	}
}

// The operator's certificate (§7): no pins and no switch while it is on
// the site, and no next key made for it. When the manager issues for the
// site again, the next key from before takes over, so clients that still
// hold its pin get in; the operator's key is not ordered with.
func TestManagerAfterImport(t *testing.T) {
	ctx := context.Background()
	start := time.Now().Truncate(time.Second)
	now := start
	n := newSiteNode(t, provision.SiteKeyPolicy{})
	ca, _ := testCA()
	n.at(ca, &now)
	n.m.Once(ctx, now)
	first := n.state()

	ownChain, ownKey := operatorCert(t, now.Add(-time.Hour), now.Add(30*day))
	got, err := provision.SetCertificate(ctx, n.st, "site", ownChain, ownKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Unpinned {
		t.Fatal("the import does not say that pinned clients are cut")
	}
	imported := n.state()
	if !imported.keys.Imported || imported.pins != nil || !bytes.Equal(imported.next, first.next) {
		t.Fatalf("after the import: %+v, pins %v", imported.keys, imported.pins)
	}
	if err := provision.RequestSiteKeyRotation(ctx, n.st, "site", now, 0, true); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("a switch on the operator's certificate: %v", err)
	}
	// Again, the same key: no client is cut by it.
	if got, err := provision.SetCertificate(ctx, n.st, "site", ownChain, ownKey, now); err != nil || got.Unpinned {
		t.Fatalf("second import: %+v %v", got, err)
	}
	// Not due: nothing ordered, no pins.
	if got := n.m.Once(ctx, now.Add(day)); got != 0 || n.state().pins != nil {
		t.Fatal("the manager touched the operator's certificate before it was due")
	}
	// Due (a third of 30 days left): the manager's own again.
	now = start.Add(21 * day)
	if got := n.m.Once(ctx, now); got != 1 {
		t.Fatalf("renewal of the operator's certificate: stored %d", got)
	}
	back := n.state()
	if back.keys.Imported || back.leafPin != first.pins[1] || bytes.Equal(back.key, imported.key) {
		t.Fatalf("after the manager took over: %+v, leaf %s, pins before %v", back.keys, back.leafPin, first.pins)
	}
	if !slices.Equal(back.pins, []string{first.pins[1], pinOf(t, back.next)}) || back.keys.NextAt != now.Unix() {
		t.Fatalf("pins after the manager took over: %v %+v", back.pins, back.keys)
	}

	// An import on a site that never had the node's keys: nothing was
	// pinned, nothing is cut, and no next key is made for it.
	n2 := newSiteNode(t, provision.SiteKeyPolicy{})
	if got, err := provision.SetCertificate(ctx, n2.st, "site", ownChain, ownKey, start); err != nil || got.Unpinned {
		t.Fatalf("import on a new site: %+v %v", got, err)
	}
	if n2.m.Once(ctx, start); len(n2.state().next) != 0 || n2.state().pins != nil || n2.issued != 0 {
		t.Fatal("a next key or pins for the operator's certificate")
	}
}

// An order that the operator's certificate overtakes stores nothing: theirs
// stays, and it is no failure.
func TestManagerImportDuringOrder(t *testing.T) {
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	n := newSiteNode(t, provision.SiteKeyPolicy{})
	ca, _ := testCA()
	ownChain, ownKey := operatorCert(t, now.Add(-time.Hour), now.Add(30*day))
	reported := 0
	n.m.Report = func(string, error) { reported++ }
	n.m.Issue = func(_ context.Context, names []string, key crypto.Signer) ([][]byte, error) {
		if _, err := provision.SetCertificate(ctx, n.st, "site", ownChain, ownKey, now); err != nil {
			t.Error(err)
		}
		return ca.Issue(names, key.Public(), now.Add(-time.Hour), now.Add(90*day))
	}
	if got := n.m.Once(ctx, now); got != 0 || reported != 0 || len(n.m.fails) != 0 {
		t.Fatalf("stored %d, reported %d, failures %v", got, reported, n.m.fails)
	}
	s := n.state()
	if !s.keys.Imported || !bytes.Equal(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: s.key}), ownKey) {
		t.Fatal("the operator's certificate did not stay")
	}
}

// A CA that answers with a certificate for another key: not stored, the
// pins would promise a key the node does not serve.
func TestManagerRefusesAnotherKey(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1767225600, 0)
	n := newSiteNode(t, provision.SiteKeyPolicy{})
	otherChain, _ := operatorCert(t, now.Add(-time.Hour), now.Add(90*day))
	n.m.Issue = func(context.Context, []string, crypto.Signer) ([][]byte, error) {
		var chain [][]byte
		for rest := otherChain; ; {
			var b *pem.Block
			if b, rest = pem.Decode(rest); b == nil {
				return chain, nil
			}
			chain = append(chain, b.Bytes)
		}
	}
	if got := n.m.Once(ctx, now); got != 0 || n.state().leaf != nil || n.m.fails["site"] != 1 {
		t.Fatalf("a certificate for another key: stored %d", got)
	}
}
