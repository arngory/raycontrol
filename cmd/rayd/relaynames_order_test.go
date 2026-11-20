package main

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/certs"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/testca"
)

// relay-names-v1 §5, §6, without a DNS provider: a name that resolves to
// its relay is orderable for its site's next certificate while the relay's
// rayspa has a feed open that said it forwards TCP 80, and the manager is
// woken for it; until the certificate covers it, the reason says why: the
// relay too old, its feed not open now, waiting, the order failed or left
// it out, the operator's certificate, no certificates at all. With a DNS
// provider none is asked for (the wildcard covers them).
func TestRelayNamesFor(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "reality", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateRelay(ctx, "r1", netip.MustParseAddr("198.51.100.20")); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRelayCertPin(ctx, "r1", "pin"); err != nil {
		t.Fatal(err)
	}
	names, err := provision.RelayNames(ctx, st)
	if err != nil || len(names) != 1 {
		t.Fatalf("names %v %v", names, err)
	}
	name := names[0].Name
	res := &fakeResolver{answers: map[string][]netip.Addr{}}
	c := newRelayNameCheck(st, res.lookup)
	said, open := false, false
	c.acmeForward = func(relay string) (bool, bool) { return relay == "r1" && said, relay == "r1" && open }
	orderable := func(site string) []string {
		var out []string
		for _, rn := range c.RelayNamesFor(ctx, site) {
			if rn.Relay != "r1" || rn.Name != name {
				t.Errorf("for %s: %+v", site, rn)
			}
			if rn.Orderable {
				out = append(out, rn.Name)
			}
		}
		return out
	}
	c.ordering = true
	woken := 0
	c.resolved = func() { woken++ }
	reason := func() string {
		t.Helper()
		if err := c.check(ctx); err != nil {
			t.Fatal(err)
		}
		ready, why := c.Status(name)
		if ready {
			t.Fatal("ready without a certificate that covers it")
		}
		return why
	}
	if why := reason(); !strings.Contains(why, "does not resolve") || orderable("site") != nil || woken != 0 {
		t.Fatalf("not resolving: %q, to order %v, woken %d", why, orderable("site"), woken)
	}
	res.set(name, "198.51.100.20")
	if why := reason(); !strings.Contains(why, "does not forward TCP 80") || orderable("site") != nil || woken != 1 {
		t.Fatalf("an older relay: %q, to order %v, woken %d", why, orderable("site"), woken)
	}
	// It said so, but its feed is gone: not orderable, the window would
	// not reach it.
	said = true
	if why := reason(); !strings.Contains(why, "no feed open") || orderable("site") != nil {
		t.Fatalf("a feed gone: %q, to order %v", why, orderable("site"))
	}
	// A downgrade's overlap: the older rayspa said no, the newer one's
	// feed not ended yet. Not orderable.
	said, open = false, true
	if got := orderable("site"); got != nil {
		t.Fatalf("an open feed under an older rayspa's word: to order %v", got)
	}
	said = true
	if why := reason(); !strings.Contains(why, "waiting for the certificate of site") || woken != 1 {
		t.Fatalf("waiting: %q, woken %d", why, woken)
	}
	if got := orderable("site"); len(got) != 1 || got[0] != name || c.RelayNamesFor(ctx, "other") != nil {
		t.Fatalf("to order %v", got)
	}
	c.Ordered("site", []string{name}, errors.New("acme validation: connection refused"))
	if why := reason(); !strings.Contains(why, "with it failed: acme validation: connection refused") {
		t.Fatalf("a failed order: %q", why)
	}
	c.Ordered("site", []string{name}, certs.ErrTooManyNames)
	if why := reason(); !strings.Contains(why, "left out of the certificate of site") {
		t.Fatalf("left out: %q", why)
	}
	c.ordering = false
	if why := reason(); !strings.Contains(why, "orders none") {
		t.Fatalf("no certificates: %q", why)
	}
	c.ordering = true
	// The operator's certificate, which does not cover it.
	chain, err := testca.New([]string{"*.example.org"}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	site, _ := st.ServiceByName(ctx, "site")
	if err := st.UpdateService(ctx, site.ID, store.ServiceUpdate{Settings: `{"tls_imported":true}`,
		Set: map[string][]byte{provision.SecretTLSChain: chain.ChainPEM}}); err != nil {
		t.Fatal(err)
	}
	if why := reason(); !strings.Contains(why, "operator's own") {
		t.Fatalf("the operator's certificate: %q", why)
	}
	// With a DNS provider: nothing to order, the wildcard's reason.
	for k, v := range map[string]string{"dns_provider": "cloudflare", "cloudflare_token": "t", "cloudflare_zone": `{"id":"z1","name":"example.com"}`} {
		if err := st.SetSetting(ctx, k, []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	if why := reason(); !strings.Contains(why, "wildcard") || c.RelayNamesFor(ctx, "site") != nil {
		t.Fatalf("with a DNS provider: %q, asked for %v", why, c.RelayNamesFor(ctx, "site"))
	}
}
