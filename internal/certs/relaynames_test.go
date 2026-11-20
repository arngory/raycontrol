package certs

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
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
// before. The relays' names that fail come back together, in a NamesError.
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
	var ne *NamesError
	err := is.CheckDNS(ctx, []string{"site.example.com", "abc.example.com", "def.example.com", "jkl.example.com"})
	if !errors.As(err, &ne) || !slices.Equal(ne.Names, []string{"def.example.com", "jkl.example.com"}) || strings.Contains(ne.Reason, "198.51.100") {
		t.Fatalf("the relays' names that fail: %v", err)
	}
}

// fakeACME is enough of an ACME server for Issue to reach the names'
// authorizations: the names in valid are valid already, the others fail
// their validation with the CA's detail, as Let's Encrypt says it when it
// cannot connect (the relay's address in it).
func fakeACME(t *testing.T, valid ...string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	var names []string
	reply := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Replay-Nonce", "n")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	authz := func(i int, status string) map[string]any {
		chal := map[string]any{"type": "http-01", "url": fmt.Sprintf("%s/chal/%d", srv.URL, i), "token": "tok", "status": "pending"}
		if status == "invalid" {
			chal["status"], chal["error"] = "invalid", map[string]any{"type": "urn:ietf:params:acme:error:connection",
				"detail": "198.51.100.21: Timeout during connect (likely firewall problem)"}
		}
		return map[string]any{"identifier": map[string]string{"type": "dns", "value": names[i]}, "status": status,
			"challenges": []any{chal}}
	}
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var i int
		switch {
		case r.URL.Path == "/dir":
			reply(w, http.StatusOK, map[string]string{"newNonce": srv.URL + "/nonce", "newAccount": srv.URL + "/account",
				"newOrder": srv.URL + "/order"})
		case r.URL.Path == "/nonce":
			w.Header().Set("Replay-Nonce", "n")
		case r.URL.Path == "/account":
			w.Header().Set("Location", srv.URL+"/account/1")
			reply(w, http.StatusCreated, map[string]string{"status": "valid"})
		case r.URL.Path == "/order":
			var jws struct{ Payload string }
			_ = json.NewDecoder(r.Body).Decode(&jws)
			names = orderNames(t, jws.Payload)
			var urls []string
			for i := range names {
				urls = append(urls, fmt.Sprintf("%s/authz/%d", srv.URL, i))
			}
			w.Header().Set("Location", srv.URL+"/order/1")
			reply(w, http.StatusCreated, map[string]any{"status": "pending", "authorizations": urls, "finalize": srv.URL + "/finalize"})
		case sscan(r.URL.Path, "/authz/%d", &i):
			status := "invalid"
			if slices.Contains(valid, names[i]) {
				status = "valid"
			}
			reply(w, http.StatusOK, authz(i, status))
		case sscan(r.URL.Path, "/chal/%d", &i):
			reply(w, http.StatusOK, map[string]any{"type": "http-01", "url": r.URL.String(), "token": "tok", "status": "processing"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sscan(path, format string, i *int) bool {
	_, err := fmt.Sscanf(path, format, i)
	return err == nil
}

// orderNames are the identifiers of a newOrder request's JWS payload.
func orderNames(t *testing.T, payload string) []string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	var req struct {
		Identifiers []struct{ Value string }
	}
	if err := json.Unmarshal(b, &req); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, id := range req.Identifiers {
		out = append(out, id.Value)
	}
	return out
}

// An authorization the CA did not validate fails the order with a
// NamesError naming it, the CA's detail kept in it; the reason, for the
// log, has no address.
func TestIssueNamesError(t *testing.T) {
	srv := fakeACME(t, "site.example.test")
	account, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	is := &Issuer{Directory: srv.URL + "/dir", HTTPClient: srv.Client(), AccountKey: account, Listen: "127.0.0.1:0",
		Window: func(uint16, time.Time, []string) {}}
	_, err := is.Issue(context.Background(), []string{"site.example.test", "abc.example.test"}, key)
	var ne *NamesError
	if !errors.As(err, &ne) || !slices.Equal(ne.Names, []string{"abc.example.test"}) || !strings.Contains(err.Error(), "Timeout during connect") ||
		strings.Contains(ne.Reason, "198.51.100") {
		t.Fatalf("an authorization not validated: %#v", err)
	}
}

// relayManager is a site with REALITY on it, and a manager whose orders
// fail while fail says so for the names given.
func relayManager(t *testing.T, relayNames func() []RelayName, fail func(names []string) error) (context.Context, *store.Store, *Manager, *[][]string) {
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
	m := &Manager{Store: st, RelayNames: func(_ context.Context, site string) []RelayName {
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

// orderable is a relay's name each, of a relay of its own ("r-" and its
// label), each orderable.
func orderable(names ...string) []RelayName {
	var out []RelayName
	for _, n := range names {
		out = append(out, RelayName{Relay: "r-" + strings.SplitN(n, ".", 2)[0], Name: n, Orderable: true})
	}
	return out
}

// failsFor is an Issue failure for the names among bad an order has, as
// the issuer gives it (NamesError, the CA's detail with an address).
func failsFor(bad ...string) func([]string) error {
	return func(names []string) error {
		for _, b := range bad {
			if slices.Contains(names, b) {
				return &NamesError{Names: []string{b}, Reason: "not validated by the CA",
					Err: errors.New("acme validation of " + b + ": 198.51.100.21: Timeout during connect (likely firewall problem)")}
			}
		}
		return nil
	}
}

// relay-names-v1 §5, §6: the relays' names go into the site's order after
// its own. One that fails is left out of an order made again at once, the
// other relays' names kept; its relay waits out a back-off of its own,
// reported. A later order takes it; none with a wildcard; a certificate
// that has the names is not ordered again for them.
func TestManagerRelayNames(t *testing.T) {
	relay := []string{"abc.example.com", "def.example.com"}
	failing := true
	ctx, st, m, issued := relayManager(t, func() []RelayName { return orderable(relay...) }, func(names []string) error {
		if failing {
			return failsFor("abc.example.com")(names)
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
	if n := m.Once(ctx, now); n != 1 || len(*issued) != 1 || !slices.Equal((*issued)[0], []string{own, "def.example.com"}) {
		t.Fatalf("an order with a relay's name that fails: stored %d, issued %v", n, *issued)
	}
	if !slices.Equal(reports, []string{"site[abc.example.com] true", "site[def.example.com] false"}) {
		t.Fatalf("reports %v", reports)
	}
	// In its relay's back-off: the site is not ordered again for it; Run
	// wakes at its end.
	failing = false
	if n := m.Once(ctx, now.Add(10*time.Minute)); n != 0 || len(*issued) != 1 {
		t.Fatalf("in the relay's back-off: stored %d, issued %v", n, *issued)
	}
	if w := m.wait(24*time.Hour, now.Add(10*time.Minute)); w != 50*time.Minute {
		t.Fatalf("Run sleeps %v, the back-off ends in 50m", w)
	}
	// Past it: the site's own first, then the relays'.
	if n := m.Once(ctx, now.Add(2*time.Hour)); n != 1 || len(*issued) != 2 || !slices.Equal((*issued)[1], append([]string{own}, relay...)) {
		t.Fatalf("past the back-off: stored %d, issued %v", n, *issued)
	}
	if reports[len(reports)-1] != "site[abc.example.com def.example.com] false" {
		t.Fatalf("reports %v", reports)
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
	m.RelayNames = func(context.Context, string) []RelayName {
		t.Error("relay names asked for under a wildcard")
		return nil
	}
	if m.Once(ctx, now.Add(70*24*time.Hour)); !slices.Equal((*issued)[len(*issued)-1], []string{"*.example.com"}) {
		t.Fatalf("under a wildcard: %v", *issued)
	}
}

// Review: one relay whose validation fails (its provider keeps TCP 80
// closed) held back every other relay's names, and the renewal made
// without them dropped the names the certificate had. Now the good relay's
// name stays through every renewal, the broken one's in its back-off.
func TestManagerOneBrokenRelay(t *testing.T) {
	good, broken := "aaa.example.com", "bbb.example.com"
	relay := []string{good}
	ctx, st, m, issued := relayManager(t, func() []RelayName { return orderable(relay...) }, failsFor(broken))
	now := time.Now()
	if n := m.Once(ctx, now); n != 1 {
		t.Fatalf("first order: %d %v", n, *issued)
	}
	covers := func(name string) bool {
		all, _ := st.ListServices(ctx)
		return provision.SiteCovers(ctx, st, all, "site", name)
	}
	relay = []string{good, broken}
	for i := range 70 {
		m.Once(ctx, now.Add(time.Minute+time.Duration(i)*25*time.Hour))
		if !covers(good) {
			t.Fatalf("day %d: the good relay's name %s is no longer in the certificate: %v", i, good, *issued)
		}
	}
	if m.relayFails["r-bbb"] == 0 || m.relayFails["r-aaa"] != 0 {
		t.Fatalf("back-offs %v", m.relayFails)
	}
}

// At most maxOrders orders a site a check, whatever fails: three broken
// relays, then the next ones.
func TestManagerRelayOrdersBounded(t *testing.T) {
	ctx, _, m, _ := relayManager(t, func() []RelayName {
		return orderable("aaa.example.com", "bbb.example.com", "ccc.example.com", "ddd.example.com")
	}, nil)
	orders := 0
	inner := failsFor("aaa.example.com", "bbb.example.com", "ccc.example.com")
	m.Issue = func(_ context.Context, names []string, key crypto.Signer) ([][]byte, error) {
		orders++
		if err := inner(names); err != nil {
			return nil, err
		}
		return nil, errors.New("no more")
	}
	m.Once(ctx, time.Now())
	if orders != maxOrders {
		t.Fatalf("%d orders in one check", orders)
	}
}

// A failure that is no relay's (a limit of the CA): the site's own names
// alone at once, no relay in a back-off.
func TestManagerRelayNamesNoRelaysFault(t *testing.T) {
	ctx, st, m, issued := relayManager(t, func() []RelayName { return orderable("abc.example.com") }, func(names []string) error {
		if len(names) > 1 {
			return errors.New("acme order: 429 too many requests")
		}
		return nil
	})
	site, _ := st.ServiceByName(ctx, "site")
	if n := m.Once(ctx, time.Now()); n != 1 || !slices.Equal((*issued)[0], []string{provision.SiteName(site)}) || len(m.relayFails) != 0 {
		t.Fatalf("stored %d, issued %v, back-offs %v", n, *issued, m.relayFails)
	}
}

// An order with a relay's name that fails, for a site that is not due for
// its own: nothing else ordered, no failure of the site.
func TestManagerRelayNamesNotDue(t *testing.T) {
	var relay []string
	ctx, _, m, issued := relayManager(t, func() []RelayName { return orderable(relay...) }, failsFor("abc.example.com"))
	now := time.Now()
	m.Once(ctx, now)
	relay = []string{"abc.example.com"}
	if n := m.Once(ctx, now.Add(time.Minute)); n != 0 || len(*issued) != 1 || m.fails["site"] != 0 {
		t.Fatalf("stored %d, issued %v, fails %d", n, *issued, m.fails["site"])
	}
}

// The CA takes MaxNames names: the relays' beyond them, after the site's
// own, are left out and reported, and logged once, not at every check.
func TestManagerRelayNamesCap(t *testing.T) {
	var relay []string
	for i := range MaxNames + 5 {
		relay = append(relay, fmt.Sprintf("r%03d.example.com", i))
	}
	ctx, _, m, issued := relayManager(t, func() []RelayName { return orderable(relay...) }, func([]string) error { return nil })
	var buf bytes.Buffer
	m.Log = slog.New(slog.NewTextHandler(&buf, nil))
	var left []string
	m.RelayReport = func(_ string, names []string, err error) {
		if errors.Is(err, ErrTooManyNames) {
			left = names
		}
	}
	now := time.Now()
	if n := m.Once(ctx, now); n != 1 || len((*issued)[0]) != MaxNames {
		t.Fatalf("stored %d, %d names", n, len((*issued)[0]))
	}
	if len(left) != 6 || left[0] != relay[MaxNames-1] {
		t.Fatalf("left out %v", left)
	}
	m.Once(ctx, now.Add(time.Hour))
	if n := strings.Count(buf.String(), "left out of the site's certificate"); n != 1 {
		t.Fatalf("the warning %d times:\n%s", n, buf.String())
	}
}

// importedCert puts the operator's certificate for the site's own names
// on it, valid until to.
func importedCert(t *testing.T, ctx context.Context, st *store.Store, now, to time.Time) {
	t.Helper()
	site, _ := st.ServiceByName(ctx, "site")
	all, _ := st.ListServices(ctx)
	own, next := provision.SiteNames(site, all)
	ca, err := testCA()
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ca.Issue(append(own, next...), &key.PublicKey, now.Add(-80*day), to)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	got, err := provision.SetCertificate(ctx, st, "site", testca.PEM(chain), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), now, true)
	if err != nil || len(got.MissingNext) != 0 {
		t.Fatalf("an import without the relays' names: %+v %v", got, err)
	}
}

// The operator's certificate (rayctl service cert) is not asked to cover
// the relays' names (relay-names-v1 §5): one for the site's own names is
// taken while a relay has names for the site's services, and the manager
// orders none for them while the site has it.
func TestManagerRelayNamesImported(t *testing.T) {
	ctx, st, m, issued := relayManager(t, func() []RelayName { return orderable("abc.example.com") }, func([]string) error { return nil })
	if _, err := st.CreateRelay(ctx, "r1", netip.MustParseAddr("198.51.100.20")); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRelayCertPin(ctx, "r1", "pin"); err != nil {
		t.Fatal(err)
	}
	if names, err := provision.RelayNames(ctx, st); err != nil || len(names) != 1 {
		t.Fatalf("relay names %v %v", names, err)
	}
	now := time.Now()
	importedCert(t, ctx, st, now, now.Add(90*day))
	if n := m.Once(ctx, now); n != 0 || len(*issued) != 0 {
		t.Fatalf("on the operator's certificate: stored %d, issued %v", n, *issued)
	}
}

// Review: the first certificate the node orders after the operator's
// takes the relays' names (relay-names-v1 §5), in one order, not a second
// one after it.
func TestManagerImportedThenOrdered(t *testing.T) {
	ctx, st, m, issued := relayManager(t, func() []RelayName { return orderable("abc.example.com") }, func([]string) error { return nil })
	now := time.Now()
	importedCert(t, ctx, st, now, now.Add(5*day)) // near its end: due
	m.Once(ctx, now)
	m.Once(ctx, now.Add(time.Minute))
	if len(*issued) != 1 || !slices.Contains((*issued)[0], "abc.example.com") {
		t.Fatalf("orders for the first certificate after the operator's: %v", *issued)
	}
}

// rayd's start: the relays' feeds are not back yet, and a due site whose
// certificate has a relay's name waits until RelayHoldUntil rather than
// drop it; one that expires within RelayHoldMargin does not wait.
func TestManagerRelayHold(t *testing.T) {
	back := false
	ctx, _, m, issued := relayManager(t, func() []RelayName {
		names := orderable("abc.example.com")
		names[0].Orderable = back
		return names
	}, func([]string) error { return nil })
	back = true
	now := time.Now()
	m.Once(ctx, now) // the certificate with the relay's name, valid 90 days
	back = false
	renew := now.Add(70 * day) // due for renewal
	m.RelayHoldUntil = renew.Add(2 * time.Minute)
	if n := m.Once(ctx, renew); n != 0 || len(*issued) != 1 {
		t.Fatalf("during the hold: stored %d, issued %v", n, *issued)
	}
	if w := m.wait(time.Hour, renew); w != 2*time.Minute {
		t.Fatalf("Run sleeps %v, the hold ends in 2m", w)
	}
	back = true
	if n := m.Once(ctx, renew.Add(time.Minute)); n != 1 || !slices.Contains((*issued)[1], "abc.example.com") {
		t.Fatalf("with the relay back: stored %d, issued %v", n, *issued)
	}
	// Near the end: no hold.
	back = false
	end := now.Add(85 * day)
	m.RelayHoldUntil = end.Add(2 * time.Minute)
	if n := m.Once(ctx, end); n != 1 {
		t.Fatalf("a certificate near its end waits: stored %d, issued %v", n, *issued)
	}
}

// Review: the relay's address went into rayd's log when a relay's name did
// not resolve to its relay alone at the order. Now the log has the reason
// and the count, and rayctl relay list the detail.
func TestManagerRelayAddressNotLogged(t *testing.T) {
	relayAddr := netip.MustParseAddr("198.51.100.20")
	ctx, _, m, issued := relayManager(t, func() []RelayName { return orderable("abc.example.com") }, func([]string) error { return nil })
	is := &Issuer{Expect: []netip.Addr{netip.MustParseAddr("203.0.113.7")},
		Resolve: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil // the wildcard's answer
		},
		RelayAddrs: func(context.Context) (map[string]netip.Addr, error) {
			return map[string]netip.Addr{"abc.example.com": relayAddr}, nil
		}}
	inner := m.Issue
	m.Issue = func(ctx context.Context, names []string, key crypto.Signer) ([][]byte, error) {
		if err := is.CheckDNS(ctx, names); err != nil {
			return nil, err
		}
		return inner(ctx, names, key)
	}
	var detail error
	m.RelayReport = func(_ string, _ []string, err error) {
		if err != nil {
			detail = err
		}
	}
	var buf bytes.Buffer
	m.Log = slog.New(slog.NewTextHandler(&buf, nil))
	m.Once(ctx, time.Now())
	if strings.Contains(buf.String(), relayAddr.String()) || !strings.Contains(buf.String(), "does not resolve to its relay alone") {
		t.Fatalf("log:\n%s", buf.String())
	}
	if detail == nil || !strings.Contains(detail.Error(), relayAddr.String()) || len(*issued) != 1 {
		t.Fatalf("the detail for rayctl relay list: %v; issued %v", detail, *issued)
	}
}
