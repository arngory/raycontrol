package render_test

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// yggNode is a store with REALITY (the site), a Yggdrasil service with its
// site's certificate, and users of it.
func yggNode(t *testing.T) *store.Store {
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
	for _, s := range []store.Service{{Kind: "reality", Name: "reality"}, {Kind: "yggdrasil", Name: "ygg"}} {
		s.Enabled = true
		if _, err := provision.CreateService(ctx, st, s); err != nil {
			t.Fatal(err)
		}
	}
	site, _ := st.ServiceByName(ctx, "site")
	st.UpdateService(ctx, site.ID, store.ServiceUpdate{Set: map[string][]byte{provision.SecretTLSChain: []byte("chain"), provision.SecretTLSKey: []byte("key")}})
	return st
}

type yggEntry struct {
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Yggdrasil struct {
		PublicKey string `json:"public_key"`
		LAN       string `json:"lan"`
	} `json:"yggdrasil"`
}

// yggFiles renders the node at a moment: the Yggdrasil users by name, the
// file as it is, and the backend's config.
func yggFiles(t *testing.T, st *store.Store, at time.Time) (map[string]yggEntry, string, map[string]any) {
	t.Helper()
	m, err := render.CollectForRender(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	m.Now = at
	files, skipped, err := render.Render(m, render.Paths{Rendered: "/r", Run: "/run/niko"})
	if err != nil || len(skipped) != 0 {
		t.Fatalf("%v %v", skipped, err)
	}
	users := map[string]yggEntry{}
	var raw string
	var backend map[string]any
	for _, f := range files {
		switch f.Path {
		case "/r/ygg/" + render.YggdrasilUsers:
			raw = string(f.Content)
			var file struct{ Users []yggEntry }
			if err := json.Unmarshal(f.Content, &file); err != nil {
				t.Fatal(err)
			}
			for _, u := range file.Users {
				users[u.Name] = u
			}
		case "/r/ygg/backend.json":
			if err := json.Unmarshal(f.Content, &backend); err != nil {
				t.Fatal(err)
			}
		}
	}
	return users, raw, backend
}

// The group of LAN in the Yggdrasil users file (lan-v1 §2.2, the contract
// with niko-server v0.16.0): u<id> on the keys of the devices that show
// themselves, of users with LAN on, for every UUID of the rotation; not
// on the user's own key, a hidden device's, another user's with LAN off; a
// revoked device's key is not there at all.
func TestYggdrasilLANGroups(t *testing.T) {
	ctx := context.Background()
	st := yggNode(t)
	ygg, _ := st.ServiceByName(ctx, "ygg")
	type dev struct {
		user, id string
		shown    bool
	}
	ids := map[string]int64{}
	var devs []dev
	for _, u := range []struct {
		name    string
		lan     bool
		devices []string // a * shows itself
	}{
		{"alice", true, []string{"*phone", "laptop", "*tablet"}},
		{"bob", false, []string{"*phone"}},
		{"carol", true, []string{"*phone"}},
	} {
		user, err := st.CreateUser(ctx, store.User{Name: u.name, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		ids[u.name] = user.ID
		st.SetUserServices(ctx, u.name, []int64{ygg.ID})
		if u.lan {
			if _, err := st.SetUserLAN(ctx, u.name, true); err != nil {
				t.Fatal(err)
			}
		}
		for _, name := range u.devices {
			d, _, err := st.CreateDevice(ctx, u.name, strings.TrimPrefix(name, "*"), "user")
			if err != nil {
				t.Fatal(err)
			}
			shown := strings.HasPrefix(name, "*")
			if _, err := st.SetDeviceLAN(ctx, d.ID, shown, 0); err != nil {
				t.Fatal(err)
			}
			devs = append(devs, dev{u.name, d.ID, shown})
		}
	}
	tablet := devs[2]
	if err := st.RevokeDevice(ctx, tablet.id); err != nil {
		t.Fatal(err)
	}
	group := func(user string) string { return fmt.Sprintf("u%d", ids[user]) }
	check := func(at time.Time, suffixes ...string) {
		t.Helper()
		users, raw, _ := yggFiles(t, st, at)
		want := 0
		for _, s := range suffixes {
			for _, u := range []string{"alice", "bob", "carol"} {
				want++
				if e, ok := users[group(u)+s]; !ok || e.Yggdrasil.LAN != "" || !e.Enabled {
					t.Errorf("%s: the user's own key %+v (in: %v)", u+s, e, ok)
				}
			}
			for _, d := range devs {
				name := group(d.user) + "-" + d.id + s
				e, ok := users[name]
				if d == tablet {
					if ok {
						t.Errorf("the revoked tablet: %s", name)
					}
					continue
				}
				want++
				lan := ""
				if d.shown && d.user != "bob" {
					lan = group(d.user)
				}
				if !ok || e.Yggdrasil.LAN != lan || len(e.Yggdrasil.PublicKey) != 64 {
					t.Errorf("%s: %+v, want lan %q", name, e, lan)
				}
			}
		}
		if len(users) != want {
			t.Errorf("%d users, want %d: %v", len(users), want, users)
		}
		// The form niko-server v0.16.0 reads; no lan where there is none.
		phone := group("alice") + "-" + devs[0].id
		if !strings.Contains(raw, `"name": "`+phone+`",`) ||
			!strings.Contains(raw, `"yggdrasil": {`+"\n"+`        "public_key": "`+users[phone].Yggdrasil.PublicKey+`",`+"\n"+`        "lan": "`+group("alice")+`"`) {
			t.Errorf("the phone's entry:\n%s", raw)
		}
		if strings.Count(raw, `"lan"`) != 2*len(suffixes) {
			t.Errorf("%d groups, want %d:\n%s", strings.Count(raw, `"lan"`), 2*len(suffixes), raw)
		}
	}
	t0 := time.Now()
	check(t0, "")
	// The rotation: the next UUID's keys, then the previous one's for its
	// grace, the group on all of them.
	day := 24 * time.Hour
	r := store.Rotation{Period: 30 * day, Lead: 3 * day, Grace: 2 * day}
	if n, err := st.RotateCredentials(ctx, t0.Add(28*day), r, render.NewUUID); err != nil || n == 0 {
		t.Fatalf("publish: %d %v", n, err)
	}
	check(t0.Add(28*day), "", "-n")
	if n, err := st.RotateCredentials(ctx, t0.Add(31*day), r, render.NewUUID); err != nil || n == 0 {
		t.Fatalf("switch: %d %v", n, err)
	}
	check(t0.Add(31*day), "", "-p")

	// The administrator takes LAN back: no group left.
	if _, err := st.SetUserLAN(ctx, "alice", false); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetUserLAN(ctx, "carol", false); err != nil {
		t.Fatal(err)
	}
	if _, raw, _ := yggFiles(t, st, t0.Add(31*day)); strings.Contains(raw, `"lan"`) {
		t.Errorf("groups with LAN off:\n%s", raw)
	}
}

// lan_relay (lan-v1 §4.4): in the backend's options when it was set, 20
// too; unset, left out (niko-server's own default).
// The stats socket is the backend's, as for Hysteria2.
func TestYggdrasilLANRelay(t *testing.T) {
	ctx := context.Background()
	st := yggNode(t)
	relay := func() (any, bool) {
		t.Helper()
		_, _, backend := yggFiles(t, st, time.Time{})
		if backend["stats_socket"] != (render.Paths{Rendered: "/r", Run: "/run/niko"}).StatsSocket("ygg") {
			t.Errorf("stats socket %v", backend["stats_socket"])
		}
		v, ok := backend["options"].(map[string]any)["lan_relay_mbps"]
		return v, ok
	}
	if v, ok := relay(); ok {
		t.Fatalf("by default: %v", v)
	}
	for _, c := range []struct {
		value string
		want  any // nil: left out
	}{{"0", 0.0}, {"20", 20.0}, {"100", 100.0}, {"100000", 100000.0}, {"5", 5.0}} {
		svc, err := provision.SetServiceOption(ctx, st, "ygg", "lan_relay", c.value)
		if err != nil {
			t.Fatalf("%s: %v", c.value, err)
		}
		if !strings.Contains(svc.Settings, `"lan_relay":`+c.value) {
			t.Errorf("%s: settings %s", c.value, svc.Settings)
		}
		v, ok := relay()
		if (c.want == nil) == ok || (ok && v != c.want) {
			t.Errorf("lan_relay=%s: %v %v", c.value, v, ok)
		}
		if got := provision.LANRelay(svc); fmt.Sprint(got) != c.value {
			t.Errorf("LANRelay %d, want %s", got, c.value)
		}
	}
	for _, bad := range []string{"-1", "100001", "x", "", "1.5", "none"} {
		if _, err := provision.SetServiceOption(ctx, st, "ygg", "lan_relay", bad); err == nil {
			t.Errorf("lan_relay=%q accepted", bad)
		}
	}
	if _, err := provision.SetServiceOption(ctx, st, "reality", "lan_relay", "5"); err == nil {
		t.Error("lan_relay on REALITY")
	}
	if got := provision.LANRelay(store.Service{Settings: `{"lan_relay":-3}`}); got != provision.LANRelayDefault {
		t.Errorf("a negative one: %d", got)
	}
}
