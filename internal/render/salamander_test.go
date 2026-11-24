package render_test

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// salamanderNode is node with a hy2-obfs service hy for alice and bob,
// alice with two devices, bob with one, and carol, without hy, with one.
type salamanderNode struct {
	st     *store.Store
	hy     store.Service
	s      []byte            // its S
	keys   map[string][]byte // device ID -> SPA key
	byName map[string]string // user/device -> device ID
}

func newSalamanderNode(t *testing.T) salamanderNode {
	t.Helper()
	ctx := context.Background()
	st := node(t)
	hy, err := provision.CreateService(ctx, st, store.Service{Kind: "hy2-obfs", Name: "hy", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, store.User{Name: "carol", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	st.SetUserServices(ctx, "alice", []int64{hy.ID})
	st.SetUserServices(ctx, "bob", []int64{hy.ID})
	secrets, err := st.ServiceSecrets(ctx, hy.ID)
	if err != nil {
		t.Fatal(err)
	}
	n := salamanderNode{st: st, hy: hy, s: secrets[provision.SecretObfsPassword], keys: map[string][]byte{}, byName: map[string]string{}}
	for _, d := range [][2]string{{"alice", "a"}, {"alice", "b"}, {"bob", "c"}, {"carol", "d"}} {
		dev, key, err := st.CreateDevice(ctx, d[0], d[1], "user")
		if err != nil {
			t.Fatal(err)
		}
		n.keys[dev.ID] = key[:]
		n.byName[d[0]+"/"+d[1]] = dev.ID
	}
	return n
}

// passwords are the devices' passwords for S, by user/device.
func (n salamanderNode) passwords(t *testing.T, s []byte, names ...string) []string {
	t.Helper()
	var out []string
	for _, name := range names {
		out = append(out, store.SalamanderDevicePassword(string(s), n.keys[n.byName[name]]))
	}
	return out
}

func (n salamanderNode) render(t *testing.T, copies func(string) bool) (render.Model, map[string]render.File) {
	t.Helper()
	m, err := render.CollectForRender(context.Background(), n.st)
	if err != nil {
		t.Fatal(err)
	}
	m.FrontCopies = copies
	files, _, err := render.Render(m, render.DefaultPaths)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]render.File{}
	for _, f := range files {
		out[f.Path] = f
	}
	return m, out
}

type udpRoute struct {
	SNI      []string `json:"sni"`
	Password string   `json:"salamander_password_file"`
	List     string   `json:"salamander_passwords_file"`
	Backend  string   `json:"backend"`
}

func hyRoute(t *testing.T, files map[string]render.File) *udpRoute {
	t.Helper()
	var front struct {
		UDP struct {
			Routes []udpRoute `json:"routes"`
		} `json:"udp"`
	}
	if err := json.Unmarshal(files[render.DefaultPaths.FrontConfig()].Content, &front); err != nil {
		t.Fatal(err)
	}
	for _, r := range front.UDP.Routes {
		if r.Backend == "hy" {
			return &r
		}
	}
	return nil
}

func hyOptions(t *testing.T, files map[string]render.File) map[string]any {
	t.Helper()
	var b struct {
		Options map[string]any `json:"options"`
	}
	if err := json.Unmarshal(files[path.Join(render.DefaultPaths.Rendered, "hy", "backend.json")].Content, &b); err != nil {
		t.Fatal(err)
	}
	return b.Options
}

// Before niko-server v0.19.3 (the pin today) hy2-obfs is as it was: one
// password, S, which the front gets as a credential's copy (and waits for
// rayctl apply to copy it in) and the backend as its own; no list.
func TestSalamanderOldPin(t *testing.T) {
	n := newSalamanderNode(t)
	if render.SalamanderDevice() {
		t.Skip("the pin is v0.19.3 or later: TestSalamanderDeviceList covers it")
	}
	m, files := n.render(t, nil)
	if m.Salamander != nil {
		t.Fatalf("passwords collected: %v", m.Salamander)
	}
	p := render.DefaultPaths
	r := hyRoute(t, files)
	if r == nil || r.Password != p.FrontSalamander("hy") || r.List != "" {
		t.Fatalf("route %+v", r)
	}
	if o := hyOptions(t, files); o["obfs_password_file"] != p.Credential("hy", render.HysteriaObfs) || o["salamander_front"] != nil {
		t.Fatalf("options %v", o)
	}
	for _, f := range []string{path.Join(p.Rendered, "hy", render.HysteriaObfs), path.Join(p.Rendered, "front", "hy.salamander")} {
		if _, ok := files[f]; !ok {
			t.Errorf("no %s", f)
		}
	}
	if _, ok := files[p.FrontSalamanderKeys("hy")]; ok {
		t.Error("a list of passwords")
	}
	if _, files := n.render(t, func(string) bool { return false }); hyRoute(t, files) != nil {
		t.Error("routed before the front's unit copies the password in")
	}
}

// From niko-server v0.19.3 the front's route takes a list of the devices'
// passwords that it rereads (spec/salamander-device-v1.md §4.2): one for
// each device allowed on the service, of the user's not revoked, and not
// carol's (no hy); no credential's copy, so no wait for rayctl apply. The
// backend has no password and salamander_front. A revocation takes the
// device's password out; S itself is there while the shared window is
// open, and a revocation in it takes S out too (§5). A rotation of S adds
// each device's password of the next S (§3).
func TestSalamanderDeviceList(t *testing.T) {
	defer render.UseNikoServer("v0.19.3")()
	ctx := context.Background()
	n := newSalamanderNode(t)
	p := render.DefaultPaths
	m, files := n.render(t, func(string) bool { return false })
	r := hyRoute(t, files)
	if r == nil || r.Password != "" || r.List != p.FrontSalamanderKeys("hy") || len(r.SNI) != 0 {
		t.Fatalf("route %+v", r)
	}
	if o := hyOptions(t, files); o["obfs_password_file"] != nil || o["salamander_front"] != true {
		t.Fatalf("options %v", o)
	}
	for _, f := range []string{path.Join(p.Rendered, "hy", render.HysteriaObfs), path.Join(p.Rendered, "front", "hy.salamander")} {
		if _, ok := files[f]; ok {
			t.Errorf("%s rendered", f)
		}
	}
	list, ok := files[r.List]
	if !ok || list.Mode != 0o640 || list.Group != "niko-front" || list.Service != "front" || !list.Reload || list.Refresh || list.AtStart {
		t.Fatalf("list %+v", list)
	}
	s := n.s
	lines := func(f render.File) []string {
		t.Helper()
		got := strings.Split(strings.TrimSuffix(string(f.Content), "\n"), "\n")
		if string(f.Content) == "" {
			got = nil
		}
		return got
	}
	want := n.passwords(t, s, "alice/a", "alice/b", "bob/c")
	slices.Sort(want)
	if got := lines(list); !slices.Equal(got, want) || !slices.Equal(m.Salamander[n.hy.ID], want) {
		t.Fatalf("list %q, want %q", got, want)
	}
	// The same twice: no rewrite, no reload.
	if _, again := n.render(t, nil); string(again[r.List].Content) != string(list.Content) {
		t.Fatal("the list changed with nothing else")
	}

	if _, err := n.st.RevokeDevice(ctx, n.byName["alice/a"]); err != nil {
		t.Fatal(err)
	}
	_, files = n.render(t, nil)
	if got := lines(files[r.List]); slices.Contains(got, n.passwords(t, s, "alice/a")[0]) || len(got) != 2 {
		t.Fatalf("after alice/a's revocation: %q", got)
	}
	// bob loses hy: his device's password goes.
	n.st.SetUserServices(ctx, "bob", nil)
	_, files = n.render(t, nil)
	if got := lines(files[r.List]); !slices.Equal(got, n.passwords(t, s, "alice/b")) {
		t.Fatalf("bob without hy: %q", got)
	}
	n.st.SetUserServices(ctx, "bob", []int64{n.hy.ID})

	// The shared window: S too, until a revocation. It begins after the
	// revocation above, in a second of its own.
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second)))
	now := time.Now().Unix()
	if err := n.st.SetSetting(ctx, "salamander_shared", fmt.Appendf(nil, "%d %d", max(now, n.hy.CreatedAt.Unix()), now+3600)); err != nil {
		t.Fatal(err)
	}
	_, files = n.render(t, nil)
	if got := lines(files[r.List]); !slices.Contains(got, string(s)) || len(got) != 3 {
		t.Fatalf("in the window: %q", got)
	}
	if _, err := n.st.RevokeDevice(ctx, n.byName["bob/c"]); err != nil {
		t.Fatal(err)
	}
	_, files = n.render(t, nil)
	if got := lines(files[r.List]); !slices.Equal(got, n.passwords(t, s, "alice/b")) {
		t.Fatalf("a revocation in the window: %q", got)
	}

	// A rotation of S: alice/b's password of the next S from now on.
	if _, err := provision.RotateObfsPassword(ctx, n.st, "hy", time.Now(), 72*time.Hour, false); err != nil {
		t.Fatal(err)
	}
	secrets, err := n.st.ServiceSecrets(ctx, n.hy.ID)
	if err != nil {
		t.Fatal(err)
	}
	next := secrets[provision.NextSecret(provision.SecretObfsPassword)]
	_, files = n.render(t, nil)
	want = append(n.passwords(t, s, "alice/b"), n.passwords(t, next, "alice/b")...)
	slices.Sort(want)
	if got := lines(files[r.List]); !slices.Equal(got, want) {
		t.Fatalf("published: %q, want %q", got, want)
	}

	// Every device gone: an empty list, still the route's.
	if _, err := n.st.RevokeDevice(ctx, n.byName["alice/b"]); err != nil {
		t.Fatal(err)
	}
	_, files = n.render(t, nil)
	if f, ok := files[r.List]; !ok || len(f.Content) != 0 || hyRoute(t, files) == nil {
		t.Fatalf("no device left: %+v", f)
	}
}

// A model without the passwords (render.Collect) does not render hy2-obfs
// in the new mode: an empty list would let nobody in.
func TestSalamanderNotCollected(t *testing.T) {
	defer render.UseNikoServer("v0.19.3")()
	n := newSalamanderNode(t)
	m, err := render.Collect(context.Background(), n.st)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = render.Render(m, render.DefaultPaths)
	if err == nil || !render.Partial(err) || !strings.Contains(err.Error(), "salamander passwords not collected") {
		t.Fatalf("rendered: %v", err)
	}
}
