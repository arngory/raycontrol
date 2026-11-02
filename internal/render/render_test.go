package render_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// node sets up a store with a domain, two DNS tunnels (and with them an
// inner stage) and two users.
func node(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	for _, s := range [][2]string{{"dnstt", "dns"}, {"masterdns", "mdns"}} {
		if _, err := provision.CreateService(ctx, st, store.Service{Kind: s[0], Name: s[1], Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	dns, _ := st.ServiceByName(ctx, "dns")
	mdns, _ := st.ServiceByName(ctx, "mdns")
	for _, u := range []store.User{{Name: "alice", Enabled: true}, {Name: "bob", Enabled: true}} {
		if _, err := st.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	st.SetUserServices(ctx, "alice", []int64{dns.ID, mdns.ID})
	return st
}

func TestRender(t *testing.T) {
	ctx := context.Background()
	st := node(t)
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Inner) != 1 {
		t.Fatalf("inner credentials for %d users, want only alice", len(m.Inner))
	}
	again, _ := render.Collect(ctx, st)
	for id, uuid := range m.Inner {
		if again.Inner[id] != uuid {
			t.Fatal("inner credentials changed between renders")
		}
	}

	files, skipped, err := render.Render(m, render.DefaultPaths)
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped %v", skipped)
	}
	byPath := map[string]render.File{}
	for _, f := range files {
		byPath[f.Path] = f
	}

	var front struct {
		Schema int    `json:"schema"`
		Role   string `json:"role"`
		DNS    struct {
			Listen []string                         `json:"listen"`
			Zones  []struct{ Zone, Backend string } `json:"zones"`
		} `json:"dns"`
		Backends map[string]struct {
			Socket, Mode string
			UID          int
		} `json:"backends"`
	}
	f := byPath["/var/lib/raycontrol/rendered/front/front.json"]
	if err := json.Unmarshal(f.Content, &front); err != nil {
		t.Fatal(err)
	}
	if front.Schema != 1 || front.Role != "front" || len(front.DNS.Zones) != 2 || f.Group != "niko-front" {
		t.Fatalf("front = %+v", front)
	}
	if want := m.IPv6; slices.Contains(front.DNS.Listen, "[::]:53") != want || !slices.Contains(front.DNS.Listen, "0.0.0.0:53") {
		t.Fatalf("listen %v with IPv6 %v", front.DNS.Listen, want)
	}
	// Without IPv6 sockets (ipv6.disable=1) the front must not ask for [::].
	m.IPv6 = false
	noV6, _, err := render.Render(m, render.DefaultPaths)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range noV6 {
		if f.Service == "front" && strings.Contains(string(f.Content), "[::]") {
			t.Fatalf("front listens on [::] without IPv6:\n%s", f.Content)
		}
	}
	b := front.Backends["dns"]
	if b.Mode != "packet" || b.Socket != "/run/niko/dns/packet.sock" || b.UID < 9110 || b.UID > 9179 {
		t.Fatalf("dns backend ref = %+v", b)
	}
	for _, z := range front.DNS.Zones {
		if !strings.HasSuffix(z.Zone, ".example.com") || len(z.Zone) != len("abc.example.com") {
			t.Fatalf("zone %q", z.Zone)
		}
	}

	var dnstt map[string]any
	json.Unmarshal(byPath["/var/lib/raycontrol/rendered/dns/backend.json"].Content, &dnstt)
	opts := dnstt["options"].(map[string]any)
	if dnstt["front_uid"].(float64) != 9100 || dnstt["inner"] != "/run/niko/inner/vless.sock" ||
		opts["private_key_file"] != "/run/credentials/niko-dns.service/noise.key" {
		t.Fatalf("dnstt backend = %v", dnstt)
	}
	key := byPath["/var/lib/raycontrol/rendered/dns/noise.key"]
	if key.Mode != 0o600 || key.Group != "" || len(strings.TrimSpace(string(key.Content))) != 64 {
		t.Fatalf("noise key file %+v", key)
	}

	var mdns map[string]any
	json.Unmarshal(byPath["/var/lib/raycontrol/rendered/mdns/backend.json"].Content, &mdns)
	if mdns["options"].(map[string]any)["encryption_method"].(float64) != 5 {
		t.Fatalf("masterdns must use AES-256-GCM: %v", mdns["options"])
	}
	if k := byPath["/var/lib/raycontrol/rendered/mdns/encryption.key"].Content; len(k) != 32 {
		t.Fatalf("masterdns key %q", k)
	}

	inner := string(byPath["/var/lib/raycontrol/rendered/inner/xray.json"].Content)
	for _, want := range []string{`"mlkem768x25519plus.native.600s.`, `"/run/niko/inner/vless.sock,0660"`, `"/run/niko/inner-api/api.sock"`, `"10.0.0.0/8"`, `"u1"`} {
		if !strings.Contains(inner, want) {
			t.Errorf("inner config lacks %s", want)
		}
	}
	if strings.Contains(inner, `"u2"`) {
		t.Error("bob has no tunnel but got an inner user")
	}
}

func TestDisabledInner(t *testing.T) {
	ctx := context.Background()
	st := node(t)
	st.SetServiceEnabled(ctx, "inner", false)
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := render.Render(m, render.DefaultPaths); err == nil {
		t.Fatal("tunnels rendered without the inner stage")
	}
}

func TestVLESSEncryption(t *testing.T) {
	dec, enc, err := render.VLESSEncryption(make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	// Fixed seed: values Xray would print for the same seed.
	if !strings.HasPrefix(dec, "mlkem768x25519plus.native.600s.AAAA") || !strings.HasPrefix(enc, "mlkem768x25519plus.native.0rtt.") || len(enc) < 1500 {
		t.Fatalf("dec %s enc %d chars", dec, len(enc))
	}
	if _, _, err := render.VLESSEncryption(make([]byte, 10)); err == nil {
		t.Fatal("short seed accepted")
	}
}
