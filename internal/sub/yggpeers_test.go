package sub_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
)

// The keys a peer of the operator's own lets in (render.YggdrasilPeers)
// are the ones the links carry: each device's link, now and next, holds
// the seed of the key listed for it, the user's own link (an export) the
// user's own key, and the node's peer in the link names the node's key.
func TestYggdrasilPeersAreTheLinks(t *testing.T) {
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
	y, err := provision.CreateService(ctx, st, store.Service{Kind: "yggdrasil", Name: "ygg", Enabled: true,
		Settings: `{"peers":["tls://peer.example.net:443"]}`})
	if err != nil {
		t.Fatal(err)
	}
	var settings render.YggdrasilSettings
	json.Unmarshal([]byte(y.Settings), &settings)
	site, _ := st.ServiceByName(ctx, "site")
	keyDER, certDER, _ := provision.SelfSigned(settings.SNI)
	st.SetServiceSecret(ctx, site.ID, provision.SecretTLSChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	st.SetServiceSecret(ctx, site.ID, provision.SecretTLSKey, keyDER)
	st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	st.SetUserServices(ctx, "alice", []int64{y.ID})
	phone, phoneKey, _ := st.CreateDevice(ctx, "alice", "phone", "user")
	laptop, laptopKey, _ := st.CreateDevice(ctx, "alice", "laptop", "user")
	day := 24 * time.Hour
	if _, err := render.Collect(ctx, st); err != nil { // the inner UUIDs, made
		t.Fatal(err)
	}
	if n, err := st.RotateCredentials(ctx, time.Now().Add(28*day), store.Rotation{Period: 30 * day, Lead: 3 * day, Grace: 2 * day},
		render.NewUUID); err != nil || n == 0 {
		t.Fatalf("publish: %d %v", n, err)
	}

	m, err := render.CollectForRender(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	var s, inner render.Service
	for _, x := range m.Services {
		switch x.Kind {
		case "yggdrasil":
			s = x
		case "inner":
			inner = x
		}
	}
	listed := map[string]string{} // device or "", credential: the key
	for _, p := range render.YggdrasilPeers(m, s, inner) {
		listed[p.Device+" "+p.Credential] = hex.EncodeToString(p.Key)
	}
	if len(listed) != 6 {
		t.Fatalf("listed %v", listed)
	}
	keyOf := func(link string) (device, node string) {
		t.Helper()
		u, err := url.Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		peer, seedHex, _ := strings.Cut(u.Query().Get("niko-ygg"), ";")
		seed, err := hex.DecodeString(seedHex)
		if err != nil || len(seed) != ed25519.SeedSize {
			t.Fatalf("seed %q", seedHex)
		}
		p, err := url.Parse(peer)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)), p.Query().Get("key")
	}
	_, nodeKey, err := render.YggdrasilNode(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []struct {
		id  string
		key []byte
	}{{"", nil}, {phone.ID, phoneKey[:]}, {laptop.ID, laptopKey[:]}} {
		profiles, err := sub.DeviceProfiles(m, m.Users[0], d.key)
		if err != nil || len(profiles) != 1 || profiles[0].Next == nil {
			t.Fatalf("profiles %+v %v", profiles, err)
		}
		now, node := keyOf(profiles[0].Link)
		next, _ := keyOf(profiles[0].Next.Link)
		if now != listed[d.id+" current"] || next != listed[d.id+" next"] || now == next {
			t.Errorf("device %q: links %s, %s; listed %s, %s", d.id, now, next, listed[d.id+" current"], listed[d.id+" next"])
		}
		if node != hex.EncodeToString(nodeKey) {
			t.Errorf("the link's peer key %s, the node's %x", node, nodeKey)
		}
	}
}
