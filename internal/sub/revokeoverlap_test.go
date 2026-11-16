package sub_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
)

// After a revocation with overlap (R4-43) the subscription of the user's
// other device carries each profile's next link, with the fresh next
// secret and the switch the revocation set, beside its link, which keeps
// the current secret; the revoked device gets none; another user's
// profiles have no next.
func TestSubscriptionAfterOverlapRevocation(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	dns, err := provision.CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	hy, err := provision.CreateService(ctx, st, store.Service{Kind: "hy2-obfs", Name: "hy2", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"alice", "bob"} {
		if _, err := st.CreateUser(ctx, store.User{Name: n, Enabled: true, Services: []int64{dns.ID, hy.ID}}); err != nil {
			t.Fatal(err)
		}
	}
	phone, phoneKey, _ := st.CreateDevice(ctx, "alice", "phone", "user")
	laptop, laptopKey, _ := st.CreateDevice(ctx, "alice", "laptop", "user")
	bobPhone, bobKey, _ := st.CreateDevice(ctx, "bob", "phone", "user")
	keys, err := provision.LoadNodeKeys(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	srv := &sub.Server{Store: st, Keys: keys, Log: slog.New(slog.DiscardHandler)}
	fetch := func(d store.Device, key [spa.KeySize]byte) (sub.Payload, int) {
		t.Helper()
		req := httptest.NewRequest("GET", sub.Path, nil)
		req.Header.Set(sub.DeviceHeader, d.ID)
		req.Header.Set("Authorization", sub.AuthToken(key, time.Now().Unix()/60))
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			return sub.Payload{}, rec.Code
		}
		var env sub.Envelope
		if err := json.NewDecoder(rec.Body).Decode(&env); err != nil {
			t.Fatal(err)
		}
		p, err := sub.Verify(env, keys.PublicJSON())
		if err != nil {
			t.Fatal(err)
		}
		return p, rec.Code
	}
	before, _ := fetch(laptop, laptopKey)
	if len(before.Profiles) != 2 {
		t.Fatalf("profiles %+v", before.Profiles)
	}
	for _, p := range before.Profiles {
		if p.Next != nil {
			t.Fatalf("a next before any rotation: %+v", p)
		}
	}

	rev, err := st.RevokeDeviceOverlap(ctx, phone.ID)
	if err != nil || rev.Credentials != 2 {
		t.Fatalf("revoke: %+v %v", rev, err)
	}
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	var alice, bob int64
	for _, u := range m.Users {
		switch u.Name {
		case "alice":
			alice = u.ID
		case "bob":
			bob = u.ID
		}
	}
	inner := m.Services[0]
	for _, s := range m.Services {
		if s.Kind == "inner" {
			inner = s
		}
	}
	// The secret each profile's link carries, current and next: inner's
	// UUID for the DNS tunnel, the password for Hysteria2.
	secretOf := map[uint16]store.Credential{uint16(dns.ID): m.Sets[inner.ID][alice], uint16(hy.ID): m.Sets[hy.ID][alice]}

	after, code := fetch(laptop, laptopKey)
	if code != http.StatusOK || len(after.Profiles) != 2 {
		t.Fatalf("the laptop's subscription: %d %+v", code, after.Profiles)
	}
	for i, p := range after.Profiles {
		c := secretOf[p.Svc]
		if c.Next == "" || p.Link != before.Profiles[i].Link || !strings.Contains(p.Link, c.Current) {
			t.Errorf("%s: the link changed, or the next secret is not stored: %+v", p.Name, c)
		}
		if p.Next == nil || p.Next.From != rev.SwitchAt.Unix() || !strings.Contains(p.Next.Link, c.Next) || strings.Contains(p.Next.Link, c.Current) {
			t.Errorf("%s: next %+v, want the fresh secret from %v", p.Name, p.Next, rev.SwitchAt)
		}
	}
	if _, code := fetch(phone, phoneKey); code != http.StatusNotFound {
		t.Fatalf("the revoked phone's subscription: %d", code)
	}
	b, code := fetch(bobPhone, bobKey)
	if code != http.StatusOK || len(b.Profiles) != 2 {
		t.Fatalf("bob's subscription: %d %+v", code, b.Profiles)
	}
	for _, p := range b.Profiles {
		if p.Next != nil {
			t.Errorf("bob's %s has a next: %+v", p.Name, p.Next)
		}
	}
	if m.Sets[inner.ID][bob].Next != "" {
		t.Error("bob's inner UUID rotates")
	}
}
