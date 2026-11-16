package render_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"maps"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// siteCert gives the site a certificate for names, as the manager would:
// a real chain, so that provision.SiteCovers can read it.
func siteCert(t *testing.T, ctx context.Context, st *store.Store, names ...string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	site, err := st.ServiceByName(ctx, "site")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateService(ctx, site.ID, store.ServiceUpdate{Set: map[string][]byte{
		provision.SecretTLSChain: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), provision.SecretTLSKey: keyDER,
	}}); err != nil {
		t.Fatal(err)
	}
}

// frontConfig is the front's config as rendered now: the file, each routed
// name's backend over TCP and over UDP, and the errors of the services left
// out. A name in two routes fails the test: niko-server refuses such a
// config whole.
type frontConfig struct {
	raw      []byte
	tcp, udp map[string]string
	def      string
	err      error
}

func renderFront(t *testing.T, ctx context.Context, st *store.Store) frontConfig {
	t.Helper()
	m, err := render.CollectForRender(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	files, _, err := render.Render(m, render.DefaultPaths)
	if err != nil && !render.Partial(err) {
		t.Fatal(err)
	}
	fc := frontConfig{tcp: map[string]string{}, udp: map[string]string{}, err: err}
	for _, f := range files {
		if f.Path == render.DefaultPaths.FrontConfig() {
			fc.raw = f.Content
		}
	}
	var front struct {
		TCP struct {
			Default string
			Routes  []struct {
				SNI     []string
				Backend string
			}
		}
		UDP struct {
			Routes []struct {
				SNI     []string
				Backend string
			}
		}
	}
	if err := json.Unmarshal(fc.raw, &front); err != nil {
		t.Fatal(err)
	}
	fc.def = front.TCP.Default
	for _, r := range front.TCP.Routes {
		for _, n := range r.SNI {
			if other, ok := fc.tcp[strings.ToLower(n)]; ok {
				t.Fatalf("TCP name %s routed to %s and %s:\n%s", n, other, r.Backend, fc.raw)
			}
			fc.tcp[strings.ToLower(n)] = r.Backend
		}
	}
	for _, r := range front.UDP.Routes {
		for _, n := range r.SNI {
			if other, ok := fc.udp[strings.ToLower(n)]; ok {
				t.Fatalf("UDP name %s routed to %s and %s:\n%s", n, other, r.Backend, fc.raw)
			}
			fc.udp[strings.ToLower(n)] = r.Backend
		}
	}
	return fc
}

func sni(t *testing.T, ctx context.Context, st *store.Store, name string) string {
	t.Helper()
	svc, err := st.ServiceByName(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	return provision.SiteName(svc) // the sni setting
}

// Two REALITY services stealing from one site, and naive, DoH and hy2-masq
// beside them: every name the front routes goes to one service. The second
// REALITY gets a name of its own (both had the site's, and the front
// refused its config); after its switch its previous name leads to it, not
// to the first REALITY (the default), until its next switch.
func TestFrontNamesOneService(t *testing.T) {
	ctx := context.Background()
	st := node(t)
	for _, s := range [][2]string{{"reality", "r1"}, {"reality", "r2"}, {"naive", "nv"}, {"doh", "dh"}, {"hy2-masq", "hy"}} {
		if _, err := provision.CreateService(ctx, st, store.Service{Kind: s[0], Name: s[1], Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	site, _ := st.ServiceByName(ctx, "site")
	if sni(t, ctx, st, "r1") != provision.SiteName(site) || sni(t, ctx, st, "r2") == provision.SiteName(site) {
		t.Fatalf("names: r1 %s, r2 %s, site %s", sni(t, ctx, st, "r1"), sni(t, ctx, st, "r2"), provision.SiteName(site))
	}
	siteCert(t, ctx, st, "*.example.com")
	before := renderFront(t, ctx, st)
	if before.err != nil {
		t.Fatal(before.err)
	}
	nv, _ := st.ServiceByName(ctx, "nv")
	want := map[string]string{sni(t, ctx, st, "r1"): "r1", sni(t, ctx, st, "r2"): "r2", sni(t, ctx, st, "nv"): "nv", sni(t, ctx, st, "dh"): "dh",
		provision.ParseNaiveState(nv).SNINext: "nv"} // naive's next name, routed ahead (R4-42)
	if before.def != "r1" || len(before.tcp) != len(want) {
		t.Fatalf("default %s, routes %v", before.def, before.tcp)
	}
	for n, svc := range want {
		if before.tcp[n] != svc {
			t.Errorf("%s routed to %q, want %s", n, before.tcp[n], svc)
		}
	}
	if before.udp[sni(t, ctx, st, "hy")] != "hy" || len(before.udp) != 4 {
		t.Errorf("UDP routes %v", before.udp)
	}

	// r2 moves to a new name (the operator's switch), with a grace period.
	e := provision.RealityEpoch{Period: 90 * day, Lead: 3 * day, Prepare: day, Grace: 2 * day}
	ok := func(context.Context, string) error { return nil }
	r2, _ := st.ServiceByName(ctx, "r2")
	now := r2.CreatedAt.Add(time.Hour)
	old := sni(t, ctx, st, "r2")
	if err := provision.RequestRotation(ctx, st, "r2", now, e.Lead, false); err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{now, now.Add(time.Minute), now.Add(e.Lead)} {
		if _, err := provision.RotateReality(ctx, st, at, e, ok, nil); err != nil {
			t.Fatal(err)
		}
	}
	renamed := sni(t, ctx, st, "r2")
	if renamed == old {
		t.Fatal("r2 kept its name")
	}
	during := renderFront(t, ctx, st)
	if during.tcp[old] != "r2" || during.tcp[renamed] != "r2" || during.tcp[sni(t, ctx, st, "r1")] != "r1" || during.def != "r1" {
		t.Fatalf("after r2's switch: %v", during.tcp)
	}
	// The grace ends: the previous keys go, the route stays as it was.
	if _, err := provision.RotateReality(ctx, st, now.Add(e.Lead+e.Grace+time.Hour), e, ok, nil); err != nil {
		t.Fatal(err)
	}
	if r2, _ = st.ServiceByName(ctx, "r2"); provision.ParseRealityState(r2).PrevUntil != 0 {
		t.Fatal("grace not over")
	}
	if after := renderFront(t, ctx, st); !bytes.Equal(after.raw, during.raw) {
		t.Fatalf("the grace's end changed the front:\n%s\n%s", during.raw, after.raw)
	}

	// Two REALITY services with one name (made before this release): the
	// second is left out, and the front keeps the others.
	if err := st.UpdateService(ctx, r2.ID, store.ServiceUpdate{Settings: strings.Replace(r2.Settings, `"sni":"`+renamed+`"`, `"sni":"`+sni(t, ctx, st, "r1")+`"`, 1)}); err != nil {
		t.Fatal(err)
	}
	clash := renderFront(t, ctx, st)
	var broken render.ServiceErrors
	if !errors.As(clash.err, &broken) || len(broken) != 1 || !strings.Contains(clash.err.Error(), "service r2") {
		t.Fatalf("a name on two services: %v", clash.err)
	}
	if clash.tcp[sni(t, ctx, st, "r1")] != "r1" || clash.tcp[sni(t, ctx, st, "nv")] != "nv" || slices.Contains(slices.Collect(maps.Values(clash.tcp)), "r2") {
		t.Fatalf("routes with r2 broken: %v", clash.tcp)
	}
}

// The front's default REALITY (the only one on most nodes) keeps a route
// of its current name alone: every name no route has reaches it anyway,
// so its previous name would only change front.json, and restart the
// front, at its next keys-only switch.
func TestDefaultRealityRoute(t *testing.T) {
	ctx := context.Background()
	st := node(t)
	r, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	siteCert(t, ctx, st, "*.example.com")
	e := provision.RealityEpoch{Period: 90 * day, Lead: 3 * day, Prepare: day, Grace: 2 * day}
	ok := func(context.Context, string) error { return nil }
	old := sni(t, ctx, st, "r")
	for _, at := range []time.Duration{86 * day, 86*day + time.Minute, 90 * day} {
		if _, err := provision.RotateReality(ctx, st, r.CreatedAt.Add(at), e, ok, nil); err != nil {
			t.Fatal(err)
		}
	}
	if sni(t, ctx, st, "r") == old {
		t.Fatal("not renamed under the wildcard")
	}
	fc := renderFront(t, ctx, st)
	if len(fc.tcp) != 1 || fc.tcp[sni(t, ctx, st, "r")] != "r" || fc.def != "r" {
		t.Fatalf("the default's routes: %v", fc.tcp)
	}
}

const day = 24 * time.Hour
