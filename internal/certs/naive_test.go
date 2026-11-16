package certs

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
)

// naive's names in the site's certificate (R4-42). Under listed names
// (HTTP-01): the name in use from the start, the next one only once a
// switch wants it (rotate_sni=on: at once), the previous one after the
// switch, and the switch itself orders nothing. Under DNS-01: one
// *.<domain> for all, and no order at a switch.
func TestManagerNaiveNames(t *testing.T) {
	const day = 24 * time.Hour
	e := provision.RealityEpoch{Lead: 3 * day, Prepare: day, Grace: 2 * day, NaivePeriod: 90 * day}
	for _, wildcard := range []bool{false, true} {
		ctx := context.Background()
		st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
		for _, s := range [][2]string{{"reality", "r"}, {"naive", "nv"}} {
			if _, err := provision.CreateService(ctx, st, store.Service{Kind: s[0], Name: s[1], Enabled: true}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := provision.SetServiceOption(ctx, st, "r", "rotate_sni", "off"); err != nil {
			t.Fatal(err)
		}
		if !wildcard {
			if _, err := provision.SetServiceOption(ctx, st, "nv", "rotate_sni", "on"); err != nil {
				t.Fatal(err)
			}
		}
		nv, _ := st.ServiceByName(ctx, "nv")
		site, _ := st.ServiceByName(ctx, "site")
		first := provision.ParseNaiveState(nv)
		now := nv.CreatedAt
		var issued [][]string
		var keys []crypto.PublicKey
		m := &Manager{Store: st, Issue: func(_ context.Context, names []string, key crypto.Signer) ([][]byte, error) {
			issued = append(issued, names)
			keys = append(keys, key.Public())
			tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: names, NotBefore: now, NotAfter: now.Add(200 * day)}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
			return [][]byte{der}, err
		}}
		if wildcard {
			m.Wildcard = func(context.Context) string { return "example.com" }
		}
		round := func(at time.Time) {
			t.Helper()
			if _, err := provision.RotateReality(ctx, st, at, e, func(context.Context, string) error { return nil }, nil); err != nil {
				t.Fatal(err)
			}
		}

		m.Once(ctx, now)
		if wildcard {
			if !slices.Equal(issued[0], []string{"*.example.com"}) {
				t.Fatalf("DNS-01: %v", issued)
			}
		} else if !slices.Equal(issued[0], []string{provision.SiteName(site), first.SNI}) {
			t.Fatalf("listed names at first: %v (next %s not asked yet)", issued, first.SNINext)
		}
		// rotate_sni=on under listed names: the next name is asked at once.
		round(now.Add(time.Minute))
		m.Once(ctx, now.Add(2*time.Minute))
		want := 1
		if !wildcard {
			want = 2
			if !slices.Equal(issued[1], []string{provision.SiteName(site), first.SNI, first.SNINext}) {
				t.Fatalf("with the next name: %v", issued)
			}
		}
		if len(issued) != want {
			t.Fatalf("orders %v", issued)
		}
		// Published, switched: no order for the switch.
		round(nv.CreatedAt.Add(87 * day))
		round(nv.CreatedAt.Add(90 * day))
		sw := provision.ParseNaiveState(mustGet(t, ctx, st, "nv"))
		if sw.SNI != first.SNINext || sw.SNIPrev != first.SNI {
			t.Fatalf("not switched: %+v", sw)
		}
		all, _ := st.ListServices(ctx)
		if names, _ := provision.SiteNames(mustGet(t, ctx, st, "site"), all); !slices.Contains(names, first.SNI) || !slices.Contains(names, sw.SNI) {
			t.Fatalf("site names after the switch: %v", names)
		}
		if m.Once(ctx, nv.CreatedAt.Add(90*day+time.Minute)); len(issued) != want {
			t.Fatalf("ordered at the switch: %v", issued)
		}
		// The name after: asked at once again under listed names, beside
		// the previous one, which stays until the next switch.
		round(nv.CreatedAt.Add(90*day + 2*time.Minute))
		m.Once(ctx, nv.CreatedAt.Add(90*day+3*time.Minute))
		if !wildcard && (len(issued) != 3 || !slices.Equal(issued[2], []string{provision.SiteName(site), sw.SNI, sw.SNIPrev, sw.SNINext})) {
			t.Fatalf("after the switch: %v", issued)
		}
		if wildcard && len(issued) != 1 {
			t.Fatalf("DNS-01 ordered again: %v", issued)
		}
		// The key stays with the names (cert-pin-v1): the lines before and
		// after the switch carry the same niko-pin.
		for i, k := range keys {
			if !k.(interface{ Equal(crypto.PublicKey) bool }).Equal(keys[0]) {
				t.Fatalf("order %d with another key", i)
			}
		}
	}
}

func mustGet(t *testing.T, ctx context.Context, st *store.Store, name string) store.Service {
	t.Helper()
	svc, err := st.ServiceByName(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}
