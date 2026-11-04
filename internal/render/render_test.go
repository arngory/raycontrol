package render_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	nodepkg "github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/spa"
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
	if b.Mode != "packet" || b.Socket != "/run/niko/dns-in/packet.sock" || b.UID < 9110 || b.UID > 9179 {
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
		opts["private_key_file"] != "/run/niko/dns/noise.key" {
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
	// A service that does not go through inner.
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true,
		Settings: `{"target":"www.example.org:443","sni":"www.example.org"}`}); err != nil {
		t.Fatal(err)
	}
	st.SetServiceEnabled(ctx, "inner", false)
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	// The tunnels cannot be rendered; everything else still is (Q-1).
	files, _, err := render.Render(m, render.DefaultPaths)
	var broken render.ServiceErrors
	if !errors.As(err, &broken) || len(broken) != 2 || !render.Partial(err) {
		t.Fatalf("tunnels without the inner stage: %v", err)
	}
	for _, f := range files {
		if f.Service == "dns" || f.Service == "mdns" {
			t.Errorf("%s rendered without the inner stage", f.Path)
		}
		if f.Service == "front" && strings.Contains(string(f.Content), `"zones"`) {
			t.Errorf("the front routes the broken tunnels: %s", f.Content)
		}
	}
	all, _, err := render.Render(withInner(t, st), render.DefaultPaths)
	if err != nil {
		t.Fatal(err)
	}
	// What does not depend on inner is the same either way.
	want := map[string]string{}
	for _, f := range all {
		if f.Service != "dns" && f.Service != "mdns" && f.Service != "front" && f.Service != "inner" {
			want[f.Path] = string(f.Content)
		}
	}
	got := 0
	for _, f := range files {
		if c, ok := want[f.Path]; ok {
			got++
			if c != string(f.Content) {
				t.Errorf("%s differs", f.Path)
			}
		}
	}
	if got != len(want) || len(want) == 0 {
		t.Fatalf("%d of %d other files rendered", got, len(want))
	}
}

func withInner(t *testing.T, st *store.Store) render.Model {
	t.Helper()
	ctx := context.Background()
	st.SetServiceEnabled(ctx, "inner", true)
	defer st.SetServiceEnabled(ctx, "inner", false)
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	return m
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

func TestReality(t *testing.T) {
	ctx := context.Background()
	st := node(t)
	svc, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true, Settings: `{"target":"www.example.org:443"}`})
	if err != nil {
		t.Fatal(err)
	}
	alice, _ := st.UserByName(ctx, "alice")
	bob, _ := st.UserByName(ctx, "bob")
	st.SetUserServices(ctx, "bob", []int64{svc.ID})
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Creds[svc.ID]) != 1 || m.Creds[svc.ID][bob.ID] == "" || m.Creds[svc.ID][alice.ID] != "" {
		t.Fatalf("REALITY credentials %v: bob only", m.Creds)
	}
	tag, users := render.XrayUsers(m, m.Services[slices.IndexFunc(m.Services, func(s render.Service) bool { return s.ID == svc.ID })])
	if tag != render.RealityTag || len(users) != 1 {
		t.Fatalf("xray users %s %v", tag, users)
	}

	type cfg struct {
		Inbounds []struct {
			Listen   string `json:"listen"`
			Port     int    `json:"port"`
			Settings struct {
				Clients    []struct{ ID, Email, Flow string } `json:"clients"`
				Decryption string                             `json:"decryption"`
			} `json:"settings"`
			Stream struct {
				Security string `json:"security"`
				Sockopt  struct {
					AcceptProxyProtocol bool `json:"acceptProxyProtocol"`
				} `json:"sockopt"`
				Reality struct {
					Target      string   `json:"target"`
					ServerNames []string `json:"serverNames"`
					PrivateKey  string   `json:"privateKey"`
					Mldsa65Seed string   `json:"mldsa65Seed"`
					ShortIDs    []string `json:"shortIds"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	read := func(m render.Model) (cfg, map[string]any) {
		files, _, err := render.Render(m, render.DefaultPaths)
		if err != nil {
			t.Fatal(err)
		}
		var c cfg
		var front map[string]any
		for _, f := range files {
			switch f.Path {
			case "/var/lib/raycontrol/rendered/r/xray.json":
				if err := json.Unmarshal(f.Content, &c); err != nil {
					t.Fatal(err)
				}
				if f.Group != "niko-r" || f.Mode != 0o640 {
					t.Errorf("xray.json group %s mode %o", f.Group, f.Mode)
				}
			case "/var/lib/raycontrol/rendered/front/front.json":
				json.Unmarshal(f.Content, &front)
			}
		}
		return c, front
	}

	// Direct (R2-7): Xray binds the service port itself (without the front).
	m.IPv6 = false
	m.FrontTCP = false
	c, front := read(m)
	in := c.Inbounds[0]
	r := in.Stream.Reality
	if in.Listen != "0.0.0.0" || in.Port != 443 || in.Stream.Security != "reality" || in.Stream.Sockopt.AcceptProxyProtocol ||
		r.Target != "www.example.org:443" || !slices.Equal(r.ServerNames, []string{"www.example.org"}) ||
		len(r.PrivateKey) != 43 || len(r.Mldsa65Seed) != 43 || len(r.ShortIDs) != provision.RealityShortIDs ||
		!strings.HasPrefix(in.Settings.Decryption, "mlkem768x25519plus.") ||
		len(in.Settings.Clients) != 1 || in.Settings.Clients[0].Flow != render.RealityFlow {
		t.Fatalf("direct inbound %+v", in)
	}
	for _, id := range r.ShortIDs {
		if len(id) < 4 || len(id) > 16 || len(id)%2 != 0 {
			t.Errorf("shortId %q", id)
		}
	}
	if front["tcp"] != nil {
		t.Fatal("front has a TCP section though niko-server has no tcpmux yet")
	}

	// Behind the front: unix socket with PROXY v2 and an SNI route.
	m.FrontTCP = true
	c, front = read(m)
	in = c.Inbounds[0]
	if in.Listen != "/run/niko/r-in/reality.sock,0660" || in.Port != 0 || !in.Stream.Sockopt.AcceptProxyProtocol {
		t.Fatalf("inbound behind the front %+v", in)
	}
	tcp, _ := json.Marshal(front["tcp"])
	backends, _ := json.Marshal(front["backends"])
	if !strings.Contains(string(tcp), `{"backend":"r","sni":["www.example.org"]}`) || !strings.Contains(string(tcp), `"default":"r"`) ||
		!strings.Contains(string(backends), `"r":{"mode":"proxy-v2","socket":"/run/niko/r-in/reality.sock"`) {
		t.Fatalf("front tcp %s backends %s", tcp, backends)
	}

	// After a switch with a grace period (R4-19): the previous keys on an
	// inbound of their own, which the current one hands what it does not
	// recognise; it hands the target what it does not recognise in turn.
	before := in
	e := provision.RealityEpoch{Period: 90 * 24 * time.Hour, Lead: 3 * 24 * time.Hour, Prepare: 24 * time.Hour, Grace: 48 * time.Hour}
	for _, at := range []time.Duration{87, 90} {
		if n, err := provision.RotateReality(ctx, st, svc.CreatedAt.Add(at*24*time.Hour), e, nil, nil); err != nil || n != 1 {
			t.Fatalf("rotate: %d %v", n, err)
		}
	}
	if m, err = render.Collect(ctx, st); err != nil {
		t.Fatal(err)
	}
	c, _ = read(m)
	if len(c.Inbounds) != 2 {
		t.Fatalf("inbounds during the grace period: %d", len(c.Inbounds))
	}
	cur, prev := c.Inbounds[0], c.Inbounds[1]
	if cur.Stream.Reality.Target != "/run/niko/r/reality-prev.sock" || cur.Stream.Reality.PrivateKey == before.Stream.Reality.PrivateKey ||
		prev.Listen != "/run/niko/r/reality-prev.sock,0600" || prev.Stream.Sockopt.AcceptProxyProtocol ||
		prev.Stream.Reality.Target != "www.example.org:443" || prev.Stream.Reality.PrivateKey != before.Stream.Reality.PrivateKey ||
		!slices.Equal(prev.Stream.Reality.ShortIDs, before.Stream.Reality.ShortIDs) || prev.Settings.Decryption != before.Settings.Decryption ||
		!slices.Equal(prev.Stream.Reality.ServerNames, before.Stream.Reality.ServerNames) || len(prev.Settings.Clients) != 1 {
		t.Fatalf("grace period:\ncurrent %+v\nprevious %+v", cur, prev)
	}
	r2 := m.Services[slices.IndexFunc(m.Services, func(s render.Service) bool { return s.ID == svc.ID })]
	if tags := render.XrayTags(r2); !slices.Equal(tags, []string{render.RealityTag, render.RealityPrevTag}) {
		t.Fatalf("tags %v", tags)
	}
}

// dnsauth-v1: with auth on, the dnstt backend gets the mode and a keys file
// of the devices allowed on the service, derived per service; the file is
// reread by the backend, not a reason to restart it.
func TestDNSAuth(t *testing.T) {
	ctx := context.Background()
	st := node(t)
	m, _ := render.Collect(ctx, st)
	files, _, _ := render.Render(m, render.DefaultPaths)
	for _, f := range files {
		if strings.HasSuffix(f.Path, "/"+render.DNSAuthKeys) || (f.Service == "dns" && strings.Contains(string(f.Content), `"auth"`)) {
			t.Fatalf("auth without the option: %s", f.Path)
		}
	}
	if _, err := provision.SetServiceOption(ctx, st, "dns", "auth", "strict"); err == nil {
		t.Fatal("auth=strict accepted")
	}
	if _, err := provision.SetServiceOption(ctx, st, "dns", "auth", "required"); err != nil {
		t.Fatal(err)
	}
	dev, key, err := st.CreateDevice(ctx, "alice", "phone", "user")
	if err != nil {
		t.Fatal(err)
	}
	st.CreateDevice(ctx, "bob", "laptop", "user") // bob has no tunnel
	// Without the keys (Collect alone), the service is not rendered: an
	// empty keys file would lock every device out.
	m, _ = render.Collect(ctx, st)
	if _, _, err := render.Render(m, render.DefaultPaths); !render.Partial(err) || !strings.Contains(err.Error(), "dns") {
		t.Fatalf("render without the dnsauth keys: %v", err)
	}
	m, err = render.CollectForRender(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	files, _, err = render.Render(m, render.DefaultPaths)
	if err != nil {
		t.Fatal(err)
	}
	dns, _ := st.ServiceByName(ctx, "dns")
	params, _ := nodepkg.LoadParams(ctx, st)
	want := spa.DNSAuthKey(key, params.NodeID, uint16(dns.ID))
	var keys, backend string
	for _, f := range files {
		switch f.Path {
		case "/var/lib/raycontrol/rendered/dns/" + render.DNSAuthKeys:
			keys = string(f.Content)
			if f.Mode != 0o640 || f.Group != "niko-dns" || !f.Reload {
				t.Errorf("keys file %+v", f)
			}
		case "/var/lib/raycontrol/rendered/dns/backend.json":
			backend = string(f.Content)
		}
	}
	if !strings.Contains(keys, dev.ID+" "+hex.EncodeToString(want[:])+"\n") || strings.Count(keys, "\n") != 2 {
		t.Fatalf("keys file:\n%s", keys)
	}
	if !strings.Contains(backend, `"auth": "required"`) || !strings.Contains(backend, `"auth_keys_file": "/var/lib/raycontrol/rendered/dns/auth.keys"`) {
		t.Fatalf("backend:\n%s", backend)
	}
	// The other tunnel (masterdns) is left alone.
	if _, err := provision.SetServiceOption(ctx, st, "mdns", "auth", "required"); err == nil {
		t.Fatal("auth on masterdns")
	}
}
