package sub_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
)

// Vectors from yggdrasil-go's address.AddrForKey.
func TestYggdrasilAddress(t *testing.T) {
	for key, want := range map[string]string{
		"eae1c8793b5597c4b3f490e76ac31172c439690f8ee14142bb851a61f9a49f0e": "200:2a3c:6f0d:8954:d076:9816:de31:2a79",
		"627f17d893e5697a4ba2208bc80b0292e7f58d8120eb353c1b55429db9c6b196": "201:7603:a09d:b06a:5a16:d177:7dd0:dfd3",
		"2205b70216c0f4ca46301ac84029229db6fd68c34b8aac4f0d0966c1b3975f2b": "202:efd2:47ef:49f8:59ad:ce7f:29bd:feb6",
		"000000000fffffff000000000000000000000000000000000000000000000000": "224:0:1f:ffff:ffff:ffff:ffff:ffff",
		strings.Repeat("00", 32): "200::",
	} {
		raw, _ := hex.DecodeString(key)
		if got := render.YggdrasilAddress(raw); got != netip.MustParseAddr(want) {
			t.Errorf("%s: %s, want %s", key, got, want)
		}
	}
}

// A Yggdrasil service from creation to the subscription link (R4-15).
func TestYggdrasilService(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "reality", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	y, err := provision.CreateService(ctx, st, store.Service{Kind: "yggdrasil", Name: "ygg", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	var settings render.YggdrasilSettings
	json.Unmarshal([]byte(y.Settings), &settings)
	y.Secrets, _ = st.ServiceSecrets(ctx, y.ID)
	ports, _ := y.Ports()
	if settings.Site != "site" || !strings.HasSuffix(settings.SNI, ".example.com") || settings.ExitPort < 1024 ||
		!slices.Equal(ports, []store.Port{{Proto: "tcp", Num: 443}}) || len(y.Secrets[provision.SecretYggdrasilSeed]) != 32 {
		t.Fatalf("yggdrasil: %s", y.Settings)
	}
	if _, ok := provision.ServiceRotation(y); ok {
		t.Fatal("a TCP-only service has a UDP schedule")
	}
	if _, err := st.ServiceByName(ctx, "inner"); err != nil {
		t.Fatal("no inner stage for yggdrasil")
	}
	site, _ := st.ServiceByName(ctx, "site")
	all, _ := st.ListServices(ctx)
	if names, _ := provision.SiteNames(site, all); !slices.Contains(names, settings.SNI) {
		t.Fatalf("the site's certificate does not cover %s: %v", settings.SNI, names)
	}

	u, _ := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	st.SetUserServices(ctx, "alice", []int64{y.ID})
	m, _ := render.Collect(ctx, st)
	p := render.Paths{Rendered: "/r", Run: "/run/niko"}
	if _, skipped, _ := render.Render(m, p); !slices.ContainsFunc(skipped, func(s string) bool { return strings.HasPrefix(s, "ygg ") }) {
		t.Fatalf("rendered before the site has a certificate: %v", skipped)
	}
	keyDER, certDER, _ := provision.SelfSigned(settings.SNI)
	st.SetServiceSecret(ctx, site.ID, provision.SecretTLSChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	st.SetServiceSecret(ctx, site.ID, provision.SecretTLSKey, keyDER)
	m, _ = render.Collect(ctx, st)
	files, _, err := render.Render(m, p)
	if err != nil {
		t.Fatal(err)
	}
	file := func(name string) render.File {
		for _, f := range files {
			if f.Path == name {
				return f
			}
		}
		t.Fatalf("no %s", name)
		return render.File{}
	}
	var backend struct {
		Kind, Socket, Inner string
		UsersFile           string `json:"users_file"`
		Options             struct {
			PrivateKeyFile string `json:"private_key_file"`
			ExitPorts      []int  `json:"exit_ports"`
		}
	}
	json.Unmarshal(file("/r/ygg/backend.json").Content, &backend)
	if backend.Kind != "yggdrasil" || backend.Socket != "/run/niko/ygg-in/fd.sock" || backend.Inner != "/run/niko/inner/vless.sock" ||
		backend.Options.PrivateKeyFile != "/run/niko/ygg/node.key" || !slices.Equal(backend.Options.ExitPorts, []int{settings.ExitPort}) {
		t.Fatalf("backend.json: %s", file("/r/ygg/backend.json").Content)
	}
	if f := file("/r/ygg/node.key"); f.Mode != 0o600 || f.Group != "" || len(f.Content) != 65 {
		t.Fatalf("node.key: %o %q", f.Mode, f.Group)
	}
	if !file("/r/ygg/users.json").Reload {
		t.Fatal("users.json restarts the backend")
	}
	var front struct {
		TCP struct {
			Routes []struct {
				SNI     []string
				Backend string
			}
		}
		Backends map[string]struct {
			Socket, Mode string
			UID          int
		}
	}
	json.Unmarshal(file("/r/front/front.json").Content, &front)
	if b := front.Backends["ygg"]; b.Mode != "fd" || b.Socket != "/run/niko/ygg-in/fd.sock" || b.UID != y.UID ||
		!slices.ContainsFunc(front.TCP.Routes, func(r struct {
			SNI     []string
			Backend string
		}) bool {
			return r.Backend == "ygg" && slices.Equal(r.SNI, []string{settings.SNI})
		}) {
		t.Fatalf("front.json: %s", file("/r/front/front.json").Content)
	}

	// The link: VLESS to inner at the node's mesh address, the peer and the
	// user's key in niko-ygg; the server lets that key in.
	usersKeys := func() map[string]string {
		var f struct {
			Users []struct {
				Name      string
				Yggdrasil struct {
					PublicKey string `json:"public_key"`
				}
			}
		}
		json.Unmarshal(file(path.Join("/r/ygg", render.YggdrasilUsers)).Content, &f)
		out := map[string]string{}
		for _, u := range f.Users {
			out[u.Name] = u.Yggdrasil.PublicKey
		}
		return out
	}
	profiles, err := sub.Profiles(m, m.Users[0])
	if err != nil || len(profiles) != 1 {
		t.Fatalf("profiles %+v %v", profiles, err)
	}
	link, _ := url.Parse(profiles[0].Link)
	q := link.Query()
	peerURI, keyHex, _ := strings.Cut(q.Get("niko-ygg"), ";")
	peer, _ := url.Parse(peerURI)
	nodeSeed := y.Secrets[provision.SecretYggdrasilSeed]
	nodeKey := ed25519.NewKeyFromSeed(nodeSeed).Public().(ed25519.PublicKey)
	seed, _ := hex.DecodeString(keyHex)
	if link.Scheme != "vless" || link.User.Username() != m.Inner[u.ID] || link.Hostname() != render.YggdrasilAddress(nodeKey).String() ||
		link.Port() != strconv.Itoa(settings.ExitPort) || q.Get("type") != "raw" || !strings.HasPrefix(q.Get("encryption"), "mlkem768x25519plus.") ||
		peer.Scheme != "tls" || peer.Host != "203.0.113.7:443" || peer.Query().Get("sni") != settings.SNI ||
		peer.Query().Get("key") != hex.EncodeToString(nodeKey) || len(seed) != 32 {
		t.Fatalf("link %s", profiles[0].Link)
	}
	userKey := hex.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if keys := usersKeys(); len(keys) != 1 || keys[render.InnerEmail(u.ID)] != userKey {
		t.Fatalf("users %v, the link's key %s", keys, userKey)
	}

	// The inner UUID rotates: the next link has the next key, which the
	// server takes from the publication on.
	day := 24 * time.Hour
	r := store.Rotation{Period: 30 * day, Lead: 3 * day, Grace: 2 * day}
	if n, err := st.RotateCredentials(ctx, time.Now().Add(28*day), r, render.NewUUID); err != nil || n == 0 {
		t.Fatalf("publish: %d %v", n, err)
	}
	m, _ = render.Collect(ctx, st)
	files, _, _ = render.Render(m, p)
	profiles, _ = sub.Profiles(m, m.Users[0])
	inner, _ := st.ServiceByName(ctx, "inner")
	next := m.Sets[inner.ID][u.ID].Next
	if profiles[0].Next == nil || !strings.Contains(profiles[0].Next.Link, next) {
		t.Fatalf("no next link: %+v", profiles[0])
	}
	nl, _ := url.Parse(profiles[0].Next.Link)
	_, nextHex, _ := strings.Cut(nl.Query().Get("niko-ygg"), ";")
	nextSeed, _ := hex.DecodeString(nextHex)
	nextKey := hex.EncodeToString(ed25519.NewKeyFromSeed(nextSeed).Public().(ed25519.PublicKey))
	if keys := usersKeys(); keys[render.InnerEmail(u.ID)+"-n"] != nextKey || nextKey == userKey {
		t.Fatalf("users while rotating %v", keys)
	}
}

// Each device of a user has its own key in the mesh, which the node lets
// in; the user's own key stays for exported links and older subscriptions.
// Two devices with one key would take each other's links.
func TestYggdrasilDeviceKeys(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "reality", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	y, err := provision.CreateService(ctx, st, store.Service{Kind: "yggdrasil", Name: "ygg", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	var settings render.YggdrasilSettings
	json.Unmarshal([]byte(y.Settings), &settings)
	site, _ := st.ServiceByName(ctx, "site")
	keyDER, certDER, _ := provision.SelfSigned(settings.SNI)
	st.SetServiceSecret(ctx, site.ID, provision.SecretTLSChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	st.SetServiceSecret(ctx, site.ID, provision.SecretTLSKey, keyDER)
	u, _ := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	st.SetUserServices(ctx, "alice", []int64{y.ID})
	phone, phoneKey, _ := st.CreateDevice(ctx, "alice", "phone", "user")
	laptop, laptopKey, _ := st.CreateDevice(ctx, "alice", "laptop", "user")
	// Another user's device: under that user only.
	bobUser, _ := st.CreateUser(ctx, store.User{Name: "bob", Enabled: true})
	st.SetUserServices(ctx, "bob", []int64{y.ID})
	bobPhone, _, _ := st.CreateDevice(ctx, "bob", "phone", "user")

	nodeKeysAt := func(at time.Time) map[string]string {
		m, err := render.CollectForRender(ctx, st)
		if err != nil {
			t.Fatal(err)
		}
		m.Now = at
		files, _, err := render.Render(m, render.Paths{Rendered: "/r", Run: "/run/niko"})
		if err != nil {
			t.Fatal(err)
		}
		var f struct {
			Users []struct {
				Name      string
				Yggdrasil struct {
					PublicKey string `json:"public_key"`
				}
			}
		}
		for _, file := range files {
			if file.Path == path.Join("/r/ygg", render.YggdrasilUsers) {
				json.Unmarshal(file.Content, &f)
			}
		}
		out := map[string]string{}
		for _, u := range f.Users {
			out[u.Name] = u.Yggdrasil.PublicKey
		}
		return out
	}
	nodeKeys := func() map[string]string { return nodeKeysAt(time.Time{}) }
	linkKey := func(device []byte) string {
		m, _ := render.Collect(ctx, st)
		profiles, err := sub.DeviceProfiles(m, m.Users[0], device)
		if err != nil || len(profiles) != 1 {
			t.Fatalf("profiles %+v %v", profiles, err)
		}
		link, _ := url.Parse(profiles[0].Link)
		_, keyHex, _ := strings.Cut(link.Query().Get("niko-ygg"), ";")
		seed, _ := hex.DecodeString(keyHex)
		return hex.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	}
	user, ph, lp := linkKey(nil), linkKey(phoneKey[:]), linkKey(laptopKey[:])
	if user == ph || user == lp || ph == lp {
		t.Fatal("devices share a key")
	}
	// The key comes from the device's secret, not from what a sibling
	// knows (the user's UUID and the device's ID).
	m0, _ := render.Collect(ctx, st)
	if guess := hex.EncodeToString(render.YggdrasilDeviceKey(m0.Inner[u.ID], []byte(phone.ID)).Public().(ed25519.PublicKey)); guess == ph {
		t.Fatal("a device's key follows from its ID")
	}
	// The subscription a device fetches carries its own key.
	keys0, err := provision.LoadNodeKeys(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	srv := &sub.Server{Store: st, Keys: keys0, Log: slog.New(slog.DiscardHandler)}
	req := httptest.NewRequest("GET", sub.Path, nil)
	req.Header.Set(sub.DeviceHeader, phone.ID)
	req.Header.Set("Authorization", sub.AuthToken(phoneKey, time.Now().Unix()/60))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	var env sub.Envelope
	json.NewDecoder(rec.Body).Decode(&env)
	payload, err := sub.Verify(env, keys0.PublicJSON())
	if err != nil || len(payload.Profiles) != 1 {
		t.Fatalf("subscription: %v %+v", err, payload)
	}
	got, _ := url.Parse(payload.Profiles[0].Link)
	_, gotHex, _ := strings.Cut(got.Query().Get("niko-ygg"), ";")
	gotSeed, _ := hex.DecodeString(gotHex)
	if hex.EncodeToString(ed25519.NewKeyFromSeed(gotSeed).Public().(ed25519.PublicKey)) != ph {
		t.Fatal("the phone's subscription has another key than the phone's")
	}
	name, bob := render.InnerEmail(u.ID), render.InnerEmail(bobUser.ID)
	keys := nodeKeys()
	if len(keys) != 5 || keys[name] != user || keys[name+"-"+phone.ID] != ph || keys[name+"-"+laptop.ID] != lp ||
		keys[bob+"-"+bobPhone.ID] == "" || keys[name+"-"+bobPhone.ID] != "" || keys[bob+"-"+phone.ID] != "" {
		t.Fatalf("node keys %v", keys)
	}
	// A revoked device's key goes.
	if err := st.RevokeDevice(ctx, laptop.ID); err != nil {
		t.Fatal(err)
	}
	if keys := nodeKeys(); len(keys) != 4 || keys[name+"-"+laptop.ID] != "" {
		t.Fatalf("after revoking: %v", keys)
	}
	// Rotation: each device's next key, then its previous one for the
	// grace only.
	day := 24 * time.Hour
	t0 := time.Now()
	r := store.Rotation{Period: 30 * day, Lead: 3 * day, Grace: 2 * day}
	if n, err := st.RotateCredentials(ctx, t0.Add(28*day), r, render.NewUUID); err != nil || n == 0 {
		t.Fatalf("publish: %d %v", n, err)
	}
	m, _ := render.Collect(ctx, st)
	profiles, _ := sub.DeviceProfiles(m, m.Users[0], phoneKey[:])
	nl, _ := url.Parse(profiles[0].Next.Link)
	_, nextHex, _ := strings.Cut(nl.Query().Get("niko-ygg"), ";")
	nextSeed, _ := hex.DecodeString(nextHex)
	next := hex.EncodeToString(ed25519.NewKeyFromSeed(nextSeed).Public().(ed25519.PublicKey))
	if keys := nodeKeys(); keys[name+"-"+phone.ID+"-n"] != next || next == ph {
		t.Fatalf("rotation: %v", keys)
	}
	if n, err := st.RotateCredentials(ctx, t0.Add(31*day), r, render.NewUUID); err != nil || n == 0 {
		t.Fatalf("switch: %d %v", n, err)
	}
	if keys := nodeKeysAt(t0.Add(31 * day)); keys[name+"-"+phone.ID] != next || keys[name+"-"+phone.ID+"-p"] != ph {
		t.Fatalf("after the switch: %v", keys)
	}
	if keys := nodeKeysAt(t0.Add(40 * day)); keys[name+"-"+phone.ID+"-p"] != "" {
		t.Fatalf("after the grace: %v", keys)
	}
}

// The Brutal ceilings of Hysteria2 (R4-16): service options rendered into
// the backend's options; 0 removes them.
func TestBrutalCeilings(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7"})
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "hy2-obfs", Name: "hy2o", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	options := func() map[string]any {
		m, _ := render.Collect(ctx, st)
		files, _, err := render.Render(m, render.Paths{Rendered: "/r", Run: "/run/niko"})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if f.Path == "/r/hy2o/backend.json" {
				var cfg struct{ Options map[string]any }
				json.Unmarshal(f.Content, &cfg)
				return cfg.Options
			}
		}
		t.Fatal("no backend.json")
		return nil
	}
	if o := options(); o["up_mbps"] != nil || o["down_mbps"] != nil {
		t.Fatalf("ceilings by default: %v", o)
	}
	for _, kv := range [][2]string{{"up_mbps", "500"}, {"down_mbps", "50"}} {
		if _, err := provision.SetServiceOption(ctx, st, "hy2o", kv[0], kv[1]); err != nil {
			t.Fatal(err)
		}
	}
	if o := options(); o["up_mbps"] != float64(500) || o["down_mbps"] != float64(50) {
		t.Fatalf("ceilings: %v", o)
	}
	if _, err := provision.SetServiceOption(ctx, st, "hy2o", "up_mbps", "0"); err != nil {
		t.Fatal(err)
	}
	if o := options(); o["up_mbps"] != nil || o["down_mbps"] != float64(50) {
		t.Fatalf("up removed: %v", o)
	}
	if _, err := provision.SetServiceOption(ctx, st, "hy2o", "up_mbps", "-1"); err == nil {
		t.Fatal("a negative ceiling")
	}
}

// Public peers (P-14, R4-18): off by default; set, they reach the backend's
// options, the unit's network and the link as fallback peers.
func TestYggdrasilPeers(t *testing.T) {
	tooMany := ""
	for i := range provision.MaxYggdrasilPeers + 1 {
		tooMany += fmt.Sprintf("tls://h%d.example.net:443,", i)
	}
	for _, bad := range []string{"", "none,", "unix:///tmp/x", "tls://10.0.0.1:443", "tls://[fe80::1]:443", "tls://host", "http://h:80",
		"tls://u:p@h:443", "tls://h:0", "quic://ygg.example.net:443", tooMany} {
		if _, err := provision.YggdrasilPeers(bad); err == nil {
			t.Errorf("peers %q accepted", bad)
		}
	}
	peers, err := provision.YggdrasilPeers(" tls://ygg.example.net:443?key=00ff , quic://203.0.113.9:443,tls://ygg.example.net:443?key=00ff")
	if err != nil || !slices.Equal(peers, []string{"tls://ygg.example.net:443?key=00ff", "quic://203.0.113.9:443"}) {
		t.Fatalf("peers %v %v", peers, err)
	}

	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "reality", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "yggdrasil", Name: "bad", Enabled: true, Settings: `{"peers":["tcp://192.168.1.1:1"]}`}); err == nil {
		t.Fatal("a private peer at creation")
	}
	y, err := provision.CreateService(ctx, st, store.Service{Kind: "yggdrasil", Name: "ygg", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	site, _ := st.ServiceByName(ctx, "site")
	var settings render.YggdrasilSettings
	json.Unmarshal([]byte(y.Settings), &settings)
	keyDER, certDER, _ := provision.SelfSigned(settings.SNI)
	st.SetServiceSecret(ctx, site.ID, provision.SecretTLSChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	st.SetServiceSecret(ctx, site.ID, provision.SecretTLSKey, keyDER)
	st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	st.SetUserServices(ctx, "alice", []int64{y.ID})

	state := func() (backendPeers []string, unit string, via []string) {
		t.Helper()
		m, _ := render.Collect(ctx, st)
		files, _, err := render.Render(m, render.DefaultPaths)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f.Path, "/ygg/backend.json") {
				var b struct{ Options struct{ Peers []string } }
				json.Unmarshal(f.Content, &b)
				backendPeers = b.Options.Peers
			}
		}
		for _, f := range deploy.Build(deploy.InputsOf(m, files, render.DefaultPaths), render.DefaultPaths, deploy.DefaultBinaries).Files {
			if strings.HasSuffix(f.Path, "/niko-ygg.service") {
				unit = string(f.Content)
			}
		}
		profiles, err := sub.Profiles(m, m.Users[0])
		if err != nil || len(profiles) != 1 {
			t.Fatalf("profiles %v %v", profiles, err)
		}
		link, _ := url.Parse(profiles[0].Link)
		return backendPeers, unit, link.Query()["niko-ygg-via"]
	}

	bp, unit, via := state()
	if bp != nil || via != nil || !strings.Contains(unit, "PrivateNetwork=yes") || !strings.Contains(unit, "RestrictAddressFamilies=AF_UNIX\n") ||
		strings.Contains(unit, "IPAddressAllow") {
		t.Fatalf("peers by default: %v %v\n%s", bp, via, unit)
	}
	if _, err := provision.SetServiceOption(ctx, st, "ygg", "peers", "tls://ygg.example.net:443?key=00ff,quic://203.0.113.9:443"); err != nil {
		t.Fatal(err)
	}
	bp, unit, via = state()
	want := []string{"tls://ygg.example.net:443?key=00ff", "quic://203.0.113.9:443"}
	if !slices.Equal(bp, want) || !slices.Equal(via, want) || strings.Contains(unit, "PrivateNetwork") ||
		!strings.Contains(unit, "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6") || !strings.Contains(unit, "IPAddressDeny=localhost link-local") ||
		!strings.Contains(unit, "IPAddressAllow=127.0.0.53 127.0.0.54") {
		t.Fatalf("with peers: %v %v\n%s", bp, via, unit)
	}
	if _, err := provision.SetServiceOption(ctx, st, "ygg", "peers", "tls://127.0.0.1:443"); err == nil {
		t.Fatal("a loopback peer")
	}
	// A quic:// name set before names were refused stays out of the link
	// (the client could not resolve it safely), and in the node's peers.
	svc, _ := st.ServiceByName(ctx, "ygg")
	var raw map[string]any
	json.Unmarshal([]byte(svc.Settings), &raw)
	raw["peers"] = []string{"quic://ygg.example.net:443", "tls://ygg.example.net:443?key=00ff"}
	b, _ := json.Marshal(raw)
	st.UpdateService(ctx, svc.ID, store.ServiceUpdate{Settings: string(b)})
	if bp, _, via = state(); len(bp) != 2 || !slices.Equal(via, []string{"tls://ygg.example.net:443?key=00ff"}) {
		t.Fatalf("a quic name: backend %v, link %v", bp, via)
	}
	if _, err := provision.SetServiceOption(ctx, st, "ygg", "peers", "none"); err != nil {
		t.Fatal(err)
	}
	if bp, unit, via = state(); bp != nil || via != nil || !strings.Contains(unit, "PrivateNetwork=yes") {
		t.Fatalf("peers removed: %v %v\n%s", bp, via, unit)
	}
}
