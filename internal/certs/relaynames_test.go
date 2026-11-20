package certs

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/testca"
)

// relay-names-v1 §6: a relay's name passes the check before an order when
// it resolves to its relay alone, not to the node; the node's names as
// before.
func TestCheckDNSRelayNames(t *testing.T) {
	relay := netip.MustParseAddr("198.51.100.20")
	answers := map[string][]netip.Addr{
		"site.example.com": {netip.MustParseAddr("203.0.113.7")},
		"abc.example.com":  {relay},
		"def.example.com":  {netip.MustParseAddr("203.0.113.7")},
		"ghi.example.com":  {relay, netip.MustParseAddr("203.0.113.7")},
	}
	is := &Issuer{Expect: []netip.Addr{netip.MustParseAddr("203.0.113.7")},
		Resolve: func(_ context.Context, name string) ([]netip.Addr, error) {
			if a, ok := answers[name]; ok {
				return a, nil
			}
			return nil, errors.New("no such host")
		},
		RelayAddrs: func(context.Context) (map[string]netip.Addr, error) {
			return map[string]netip.Addr{"abc.example.com": relay, "def.example.com": relay, "ghi.example.com": relay, "jkl.example.com": relay}, nil
		}}
	ctx := context.Background()
	if err := is.CheckDNS(ctx, []string{"site.example.com", "abc.example.com"}); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"def.example.com": "not to its relay",
		"ghi.example.com": "not to its relay",
		"jkl.example.com": "does not resolve",
	} {
		if err := is.CheckDNS(ctx, []string{"site.example.com", name}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// relayManager is a site with REALITY on it, and a manager whose orders
// fail while fail says so for the names given.
func relayManager(t *testing.T, relayNames func() []string, fail func(names []string) error) (context.Context, *store.Store, *Manager, *[][]string) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	issued := &[][]string{}
	m := &Manager{Store: st, RelayNames: func(_ context.Context, site string) []string {
		if site != "site" {
			t.Errorf("relay names asked for %s", site)
		}
		return relayNames()
	}, Issue: func(_ context.Context, names []string, key crypto.Signer) ([][]byte, error) {
		if err := fail(names); err != nil {
			return nil, err
		}
		*issued = append(*issued, names)
		now := time.Now()
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: names, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		return [][]byte{der}, err
	}}
	return ctx, st, m, issued
}

// relay-names-v1 §5, §6: the relays' names go into the site's order after
// its own; an order with them that fails is made again at once without
// them, and they wait out a back-off of their own, reported; a later
// order takes them; none with a wildcard; a certificate that has them is
// not ordered again for them.
func TestManagerRelayNames(t *testing.T) {
	relay := []string{"abc.example.com", "def.example.com"}
	failing := true
	ctx, st, m, issued := relayManager(t, func() []string { return relay }, func(names []string) error {
		if failing && slices.Contains(names, "abc.example.com") {
			return errors.New("acme validation of abc.example.com: connection refused")
		}
		return nil
	})
	var reports []string
	m.RelayReport = func(site string, names []string, err error) {
		reports = append(reports, fmt.Sprint(site, names, err != nil))
	}
	site, _ := st.ServiceByName(ctx, "site")
	own := provision.SiteName(site)
	now := time.Now()
	if n := m.Once(ctx, now); n != 1 || len(*issued) != 1 || !slices.Equal((*issued)[0], []string{own}) {
		t.Fatalf("an order with the relays' names that fails: stored %d, issued %v", n, *issued)
	}
	if !slices.Equal(reports, []string{"site[abc.example.com def.example.com] true"}) {
		t.Fatalf("reports %v", reports)
	}
	// In their back-off: the site is not ordered again for them.
	failing = false
	if n := m.Once(ctx, now.Add(10*time.Minute)); n != 0 || len(*issued) != 1 {
		t.Fatalf("in the relays' names' back-off: stored %d, issued %v", n, *issued)
	}
	// Past it: the site's own first, then theirs.
	if n := m.Once(ctx, now.Add(2*time.Hour)); n != 1 || len(*issued) != 2 || !slices.Equal((*issued)[1], append([]string{own}, relay...)) {
		t.Fatalf("past the back-off: stored %d, issued %v", n, *issued)
	}
	if reports[len(reports)-1] != "site[abc.example.com def.example.com] false" {
		t.Fatalf("reports %v", reports)
	}
	all, _ := st.ListServices(ctx)
	if !provision.SiteCovers(ctx, st, all, "site", "def.example.com") {
		t.Fatal("the certificate does not cover a relay's name")
	}
	if n := m.Once(ctx, now.Add(3*time.Hour)); n != 0 {
		t.Fatal("ordered again with the names in the certificate")
	}
	// A relay's name it has not: ordered.
	relay = append(relay, "ghi.example.com")
	if n := m.Once(ctx, now.Add(4*time.Hour)); n != 1 || !slices.Contains((*issued)[len(*issued)-1], "ghi.example.com") {
		t.Fatalf("a new relay name: %d %v", n, *issued)
	}

	// With a wildcard (a DNS provider): none asked for; at the renewal,
	// the wildcard alone.
	m.Wildcard = func(context.Context) string { return "example.com" }
	m.RelayNames = func(context.Context, string) []string { t.Error("relay names asked for under a wildcard"); return nil }
	if m.Once(ctx, now.Add(70*24*time.Hour)); !slices.Equal((*issued)[len(*issued)-1], []string{"*.example.com"}) {
		t.Fatalf("under a wildcard: %v", *issued)
	}
}

// An order with the relays' names that fails, for a site that is not due
// for its own: nothing else ordered, no failure of the site.
func TestManagerRelayNamesNotDue(t *testing.T) {
	var relay []string
	ctx, _, m, issued := relayManager(t, func() []string { return relay }, func(names []string) error {
		if len(names) > 1 {
			return errors.New("no")
		}
		return nil
	})
	now := time.Now()
	m.Once(ctx, now)
	relay = []string{"abc.example.com"}
	if n := m.Once(ctx, now.Add(time.Minute)); n != 0 || len(*issued) != 1 || m.fails["site"] != 0 {
		t.Fatalf("stored %d, issued %v, fails %d", n, *issued, m.fails["site"])
	}
}

// The CA takes MaxNames names: the relays' beyond them, after the site's
// own, are left out and reported.
func TestManagerRelayNamesCap(t *testing.T) {
	var relay []string
	for i := range MaxNames + 5 {
		relay = append(relay, fmt.Sprintf("r%03d.example.com", i))
	}
	ctx, _, m, issued := relayManager(t, func() []string { return relay }, func([]string) error { return nil })
	var left []string
	m.RelayReport = func(_ string, names []string, err error) {
		if errors.Is(err, ErrTooManyNames) {
			left = names
		}
	}
	if n := m.Once(ctx, time.Now()); n != 1 || len((*issued)[0]) != MaxNames {
		t.Fatalf("stored %d, %d names", n, len((*issued)[0]))
	}
	if len(left) != 6 || left[0] != relay[MaxNames-1] {
		t.Fatalf("left out %v", left)
	}
}

// The operator's certificate (rayctl service cert) is not asked to cover
// the relays' names (relay-names-v1 §5): one for the site's own names is
// taken while a relay has names for the site's services, none of them
// missing; and the manager orders none for them while the site has it.
func TestManagerRelayNamesImported(t *testing.T) {
	asked := 0
	ctx, st, m, issued := relayManager(t, func() []string { asked++; return []string{"abc.example.com"} }, func([]string) error { return nil })
	if _, err := st.CreateRelay(ctx, "r1", netip.MustParseAddr("198.51.100.20")); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRelayCertPin(ctx, "r1", "pin"); err != nil {
		t.Fatal(err)
	}
	if names, err := provision.RelayNames(ctx, st); err != nil || len(names) != 1 {
		t.Fatalf("relay names %v %v", names, err)
	}
	site, _ := st.ServiceByName(ctx, "site")
	all, _ := st.ListServices(ctx)
	own, next := provision.SiteNames(site, all)
	now := time.Now()
	ca, err := testCA()
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ca.Issue(append(own, next...), &key.PublicKey, now.Add(-time.Hour), now.Add(90*day))
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	got, err := provision.SetCertificate(ctx, st, "site", testca.PEM(chain), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), now, true)
	if err != nil || len(got.MissingNext) != 0 {
		t.Fatalf("an import without the relays' names: %+v %v", got, err)
	}
	if n := m.Once(ctx, now); n != 0 || len(*issued) != 0 || asked != 0 {
		t.Fatalf("on the operator's certificate: stored %d, issued %v, asked %d", n, *issued, asked)
	}
}
