package sub_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
)

// relay-names-v1 §8: the signed subscription carries profiles[].via_links
// for the relays of via whose name for the service is ready, and nothing
// else changes: via stays, a name not ready gives no link, nor a REALITY
// with a target of someone else's.
func TestViaLinksInSubscription(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	var ids []int64
	for _, s := range []store.Service{
		{Kind: "reality", Name: "reality", Enabled: true},
		{Kind: "reality", Name: "foreign", Enabled: true, Settings: `{"target":"www.example.org:443"}`},
		{Kind: "hy2-masq", Name: "hy2", Enabled: true},
	} {
		svc, err := provision.CreateService(ctx, f.st, s)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, svc.ID)
	}
	site, _ := f.st.ServiceByName(ctx, "site")
	keyDER, certDER, err := provision.SelfSigned("*.example.com")
	if err != nil {
		t.Fatal(err)
	}
	f.st.SetServiceSecret(ctx, site.ID, provision.SecretTLSChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	f.st.SetServiceSecret(ctx, site.ID, provision.SecretTLSKey, keyDER)
	if err := f.st.SetUserServices(ctx, "alice", ids); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.CreateRelay(ctx, "r1", netip.MustParseAddr("198.51.100.20")); err != nil {
		t.Fatal(err)
	}
	if err := f.st.SetRelayCertPin(ctx, "r1", "pin"); err != nil {
		t.Fatal(err)
	}
	names, err := provision.RelayNames(ctx, f.st)
	if err != nil || len(names) != 2 {
		t.Fatalf("relay names %v %v", names, err)
	}
	nameOf := map[int64]string{}
	for _, rn := range names {
		nameOf[rn.Service] = rn.Name
	}
	ready := map[string]bool{}
	srv := &sub.Server{Store: f.st, Keys: f.keys, Log: quiet(), RelayNameReady: func(name string) bool { return ready[name] }}
	build := func() (sub.Payload, map[string]sub.Profile) {
		t.Helper()
		env, err := srv.Build(ctx, "alice", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		p, err := sub.Verify(env, f.keys.PublicJSON())
		if err != nil {
			t.Fatal(err)
		}
		byName := map[string]sub.Profile{}
		for _, pr := range p.Profiles {
			byName[pr.Name] = pr
		}
		return p, byName
	}
	p, _ := build()
	for _, pr := range p.Profiles {
		if pr.ViaLinks != nil {
			t.Errorf("%s: via_links before a name is ready: %v", pr.Name, pr.ViaLinks)
		}
	}
	reality, _ := f.st.ServiceByName(ctx, "reality")
	ready[nameOf[reality.ID]] = true
	_, byName := build()
	r := byName["reality"]
	if len(r.Via) != 1 || r.Via[0] != "r1" || len(r.ViaLinks) != 1 {
		t.Fatalf("reality: via %v, via_links %v", r.Via, r.ViaLinks)
	}
	u, err := url.Parse(r.ViaLinks["r1"])
	if err != nil || u.Hostname() != nameOf[reality.ID] || u.Query().Get("sni") != nameOf[reality.ID] || u.Query().Get("niko-ip") != "198.51.100.20" {
		t.Fatalf("reality through r1: %s", r.ViaLinks["r1"])
	}
	if hy := byName["hy2"]; len(hy.Via) != 1 || hy.ViaLinks != nil {
		t.Errorf("hy2, its name not ready: via %v, via_links %v", hy.Via, hy.ViaLinks)
	}
	if fx := byName["foreign"]; len(fx.Via) != 1 || fx.ViaLinks != nil {
		t.Errorf("foreign REALITY: via %v, via_links %v", fx.Via, fx.ViaLinks)
	}
	// The field's name, as the client reads it.
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), `"via_links":{"r1":"vless://`) {
		t.Errorf("profile JSON %s", b)
	}
	// Without the check: none.
	srv.RelayNameReady = nil
	if _, byName = build(); byName["reality"].ViaLinks != nil {
		t.Errorf("via_links without RelayNameReady: %v", byName["reality"].ViaLinks)
	}
}
