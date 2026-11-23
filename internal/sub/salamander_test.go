package sub_test

import (
	"bytes"
	"context"
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

// obfsNode is a node with hy2-obfs for alice, and its model.
func obfsNode(t *testing.T) (*store.Store, store.Service) {
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
	hy, err := provision.CreateService(ctx, st, store.Service{Kind: "hy2-obfs", Name: "hy2o", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true, Services: []int64{hy.ID}}); err != nil {
		t.Fatal(err)
	}
	return st, hy
}

func obfsModel(t *testing.T, st *store.Store) (render.Model, render.User, render.Service) {
	t.Helper()
	m, err := render.Collect(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range m.Services {
		if s.Kind == "hy2-obfs" {
			return m, m.Users[0], s
		}
	}
	t.Fatal("no hy2-obfs")
	return m, render.User{}, render.Service{}
}

func obfsPassword(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("obfs-password")
}

// From niko-server v0.19.3 each device's hy2-obfs line carries its own
// salamander password (spec/salamander-device-v1.md §2): of S and the
// device's SPA key, so two devices get two; the rest of the line is as
// before, S in none. Without a device (rayctl user export) there is no
// hy2-obfs line. Before v0.19.3 (the pin today) every line has S.
func TestObfsPasswordPerDevice(t *testing.T) {
	st, _ := obfsNode(t)
	other := bytes.Repeat([]byte{8}, 32)
	line := func(m render.Model, u render.User, device []byte) sub.Profile {
		t.Helper()
		ps, err := sub.DeviceProfiles(m, u, device)
		if err != nil || len(ps) != 1 {
			t.Fatalf("profiles %+v, %v", ps, err)
		}
		return ps[0]
	}
	m, u, s := obfsModel(t, st)
	secret := string(s.Secrets[provision.SecretObfsPassword])
	if !render.SalamanderDevice() {
		// The pin: one password for all, the user's export too.
		if a := line(m, u, testDevice); obfsPassword(t, a.Link) != secret || line(m, u, other).Link != a.Link {
			t.Fatalf("old mode: %s", a.Link)
		}
		if ps, err := sub.Profiles(m, u); err != nil || len(ps) != 1 || obfsPassword(t, ps[0].Link) != secret {
			t.Fatalf("old mode export: %+v, %v", ps, err)
		}
	}

	defer render.UseNikoServer("v0.19.3")()
	a, b := line(m, u, testDevice), line(m, u, other)
	pa, pb := obfsPassword(t, a.Link), obfsPassword(t, b.Link)
	if pa != store.SalamanderDevicePassword(secret, testDevice) || pb != store.SalamanderDevicePassword(secret, other) || pa == pb {
		t.Fatalf("passwords %q %q", pa, pb)
	}
	for _, p := range []sub.Profile{a, b} {
		if strings.Contains(p.Link, secret) || p.Next != nil {
			t.Fatalf("S in a line, or a next: %+v", p)
		}
		for _, problem := range strictProblems("hy2-obfs", p.Link) {
			t.Errorf("%s", problem)
		}
	}
	// The line of before but for the password, of its length.
	old := sub.HysteriaLink(m, s, m.Creds[s.ID][u.ID])
	if len(a.Link) != len(old) || strings.Replace(a.Link, pa, secret, 1) != old {
		t.Fatalf("not the shape of the line before:\n %s\n %s", a.Link, old)
	}
	if ps, err := sub.Profiles(m, u); err != nil || len(ps) != 0 {
		t.Fatalf("export: %+v, %v", ps, err)
	}
}

// A rotation of S (spec/salamander-device-v1.md §3): profiles[].next
// carries the device's password of the next S, from its switch; with the
// user's credential rotating too, one next, the earliest, with the next
// credential when S's goes first.
func TestObfsNext(t *testing.T) {
	defer render.UseNikoServer("v0.19.3")()
	ctx := context.Background()
	st, hy := obfsNode(t)
	now := time.Now()
	if _, err := provision.RotateObfsPassword(ctx, st, hy.Name, now, 72*time.Hour, false); err != nil {
		t.Fatal(err)
	}
	m, u, s := obfsModel(t, st)
	next := string(s.Secrets[provision.NextSecret(provision.SecretObfsPassword)])
	ps, err := sub.DeviceProfiles(m, u, testDevice)
	if err != nil || len(ps) != 1 || ps[0].Next == nil {
		t.Fatalf("profiles %+v, %v", ps, err)
	}
	p := ps[0]
	if p.Next.From != now.Add(72*time.Hour).Unix() || obfsPassword(t, p.Next.Link) != store.SalamanderDevicePassword(next, testDevice) ||
		obfsPassword(t, p.Link) != store.SalamanderDevicePassword(string(s.Secrets[provision.SecretObfsPassword]), testDevice) {
		t.Fatalf("next %+v", p.Next)
	}
	cred := m.Creds[s.ID][u.ID]
	if !strings.HasPrefix(p.Next.Link, "hysteria2://"+cred+"@") {
		t.Fatalf("next with another credential: %s", p.Next.Link)
	}

	// The credential's next, later than S's: S's goes, with it.
	set := m.Sets[s.ID][u.ID]
	set.Next, set.NextFrom = "f3b1c0de-0000-4000-8000-00000000000a", now.Add(96*time.Hour)
	m.Sets[s.ID][u.ID] = set
	ps, _ = sub.DeviceProfiles(m, u, testDevice)
	if n := ps[0].Next; n.From != now.Add(72*time.Hour).Unix() || !strings.HasPrefix(n.Link, "hysteria2://"+set.Next+"@") ||
		obfsPassword(t, n.Link) != store.SalamanderDevicePassword(next, testDevice) {
		t.Fatalf("S first: %+v", n)
	}
	// Earlier: the credential's, with the current S.
	set.NextFrom = now.Add(time.Hour)
	m.Sets[s.ID][u.ID] = set
	ps, _ = sub.DeviceProfiles(m, u, testDevice)
	if n := ps[0].Next; n.From != set.NextFrom.Unix() || obfsPassword(t, n.Link) != obfsPassword(t, ps[0].Link) {
		t.Fatalf("the credential first: %+v", n)
	}
}
