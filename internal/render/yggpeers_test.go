package render_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
)

// YggdrasilPeers are the keys of the users file, no more and no less, with
// whose each is: each active user's own key and each device's not
// revoked, derived from the device's SPA key and the user's inner UUID,
// for the current UUID, the next one while it is published (from its
// switch) and the previous one in its grace (until its end). A user off
// the service, disabled or without it has none.
func TestYggdrasilPeers(t *testing.T) {
	ctx := context.Background()
	st := yggNode(t)
	ygg, _ := st.ServiceByName(ctx, "ygg")
	reality, _ := st.ServiceByName(ctx, "reality")
	keys := map[string][spa.KeySize]byte{}
	ids := map[string]string{}
	for _, u := range []struct {
		name     string
		services []int64
		devices  []string
	}{
		{"alice", []int64{ygg.ID}, []string{"phone", "laptop"}},
		{"bob", []int64{ygg.ID}, []string{"phone"}},
		{"carol", []int64{reality.ID}, []string{"phone"}}, // not on Yggdrasil
		{"dave", []int64{ygg.ID}, []string{"phone"}},      // disabled below
	} {
		if _, err := st.CreateUser(ctx, store.User{Name: u.name, Enabled: true}); err != nil {
			t.Fatal(err)
		}
		st.SetUserServices(ctx, u.name, u.services)
		for _, name := range u.devices {
			d, k, err := st.CreateDevice(ctx, u.name, name, "user")
			if err != nil {
				t.Fatal(err)
			}
			keys[u.name+"/"+name], ids[u.name+"/"+name] = k, d.ID
		}
	}
	if _, _, err := st.CreateDevice(ctx, "bob", "old", "user"); err != nil {
		t.Fatal(err)
	}
	bobOld, _ := st.ListDevices(ctx, "bob")
	for _, d := range bobOld {
		if d.Name == "old" {
			if _, err := st.RevokeDevice(ctx, d.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := st.SetUserEnabled(ctx, "dave", false); err != nil {
		t.Fatal(err)
	}

	peersAt := func(at time.Time) (render.Model, int64, []render.YggdrasilPeer) {
		t.Helper()
		m, err := render.CollectForRender(ctx, st)
		if err != nil {
			t.Fatal(err)
		}
		m.Now = at
		var s, inner render.Service
		for _, x := range m.Services {
			switch x.Kind {
			case "yggdrasil":
				s = x
			case "inner":
				inner = x
			}
		}
		return m, inner.ID, render.YggdrasilPeers(m, s, inner)
	}
	pub := func(k ed25519.PrivateKey) string { return hex.EncodeToString(k.Public().(ed25519.PublicKey)) }
	check := func(at time.Time, creds ...string) {
		t.Helper()
		m, innerID, peers := peersAt(at)
		// The users file: the same keys.
		users, _, _ := yggFiles(t, st, at)
		var inFile, listed []string
		for _, e := range users {
			inFile = append(inFile, e.Yggdrasil.PublicKey)
		}
		var got []string
		for _, p := range peers {
			listed = append(listed, hex.EncodeToString(p.Key))
			got = append(got, fmt.Sprintf("%s %s %s", p.User, p.Device, p.Credential))
		}
		slices.Sort(inFile)
		slices.Sort(listed)
		if !slices.Equal(inFile, listed) {
			t.Fatalf("listed %d keys, the users file %d", len(listed), len(inFile))
		}
		// Whose, in order: per user its own keys, then each device's.
		var want []string
		for _, u := range []string{"alice", "bob"} {
			for _, c := range creds {
				want = append(want, u+"  "+c)
			}
			var devs []string
			for _, name := range []string{"phone", "laptop"} {
				if id, ok := ids[u+"/"+name]; ok {
					devs = append(devs, id)
				}
			}
			slices.Sort(devs) // the store's order, by ID
			for _, id := range devs {
				for _, c := range creds {
					want = append(want, u+" "+id+" "+c)
				}
			}
		}
		if !slices.Equal(got, want) {
			t.Fatalf("at %v:\n got %q\nwant %q", at, got, want)
		}
		// Each key from its device's secret and the UUID it names.
		for _, p := range peers {
			set := m.Sets[innerID][p.UserID]
			uuid := map[string]string{"current": set.Current, "next": set.Next, "previous": set.Prev}[p.Credential]
			want := pub(render.YggdrasilKey(uuid))
			if p.Device != "" {
				var name string
				for n, id := range ids {
					if id == p.Device {
						name = n
					}
				}
				k := keys[name]
				want = pub(render.YggdrasilDeviceKey(uuid, k[:]))
			}
			if hex.EncodeToString(p.Key) != want {
				t.Errorf("%s %s %s: not its key", p.User, p.Device, p.Credential)
			}
			if p.Credential == "next" && !p.From.Equal(set.NextFrom) || p.Credential != "next" && !p.From.IsZero() ||
				p.Credential == "previous" && !p.Until.Equal(set.PrevUntil) || p.Credential != "previous" && !p.Until.IsZero() {
				t.Errorf("%s %s %s: from %v until %v", p.User, p.Device, p.Credential, p.From, p.Until)
			}
		}
		if n := len(slices.Collect(maps.Keys(users))); n != len(peers) {
			t.Errorf("%d names in the users file, %d peers", n, len(peers))
		}
	}
	t0 := time.Now()
	check(t0, "current")
	day := 24 * time.Hour
	r := store.Rotation{Period: 30 * day, Lead: 3 * day, Grace: 2 * day}
	if n, err := st.RotateCredentials(ctx, t0.Add(28*day), r, render.NewUUID); err != nil || n == 0 {
		t.Fatalf("publish: %d %v", n, err)
	}
	check(t0.Add(28*day), "current", "next")
	if n, err := st.RotateCredentials(ctx, t0.Add(31*day), r, render.NewUUID); err != nil || n == 0 {
		t.Fatalf("switch: %d %v", n, err)
	}
	check(t0.Add(31*day), "current", "previous")
	// Past the grace: the previous keys go.
	check(t0.Add(34*day), "current")
}
