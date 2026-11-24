package live

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// From niko-server v0.19.3 a revocation reaches hy2-obfs's front list
// with the apply after it, without a restart: the front rereads the file
// (spec/salamander-device-v1.md §4.2). The revoked device's password goes,
// the other device's stays.
func TestApplySalamanderRevocation(t *testing.T) {
	defer render.UseNikoServer("v0.19.3")()
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	must(t, err)
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	hy, err := provision.CreateService(ctx, st, store.Service{Kind: "hy2-obfs", Name: "hy2", Enabled: true})
	must(t, err)
	_, err = st.CreateUser(ctx, store.User{Name: "alice", Enabled: true, Services: []int64{hy.ID}})
	must(t, err)
	phone, phoneKey, _ := st.CreateDevice(ctx, "alice", "phone", "user")
	_, laptopKey, _ := st.CreateDevice(ctx, "alice", "laptop", "user")
	secrets, err := st.ServiceSecrets(ctx, hy.ID)
	must(t, err)
	s := string(secrets[provision.SecretObfsPassword])

	var restarted []string
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: "/run/niko"}
	a := &Applier{
		Store: st, Paths: paths, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Restart: func(_ context.Context, verb, unit string) error {
			restarted = append(restarted, verb+" "+unit)
			return nil
		},
		Inner: func(string) InnerAPI { return &fakeInner{} },
	}
	must(t, a.Apply(ctx))
	list := func() []string {
		t.Helper()
		b, err := os.ReadFile(paths.FrontSalamanderKeys("hy2"))
		must(t, err)
		return strings.Fields(string(b))
	}
	pPhone, pLaptop := store.SalamanderDevicePassword(s, phoneKey[:]), store.SalamanderDevicePassword(s, laptopKey[:])
	if got := list(); len(got) != 2 || !slices.Contains(got, pPhone) || !slices.Contains(got, pLaptop) {
		t.Fatalf("list %q", got)
	}
	restarted = nil
	if _, err := st.RevokeDevice(ctx, phone.ID); err != nil {
		t.Fatal(err)
	}
	must(t, a.Apply(ctx))
	if got := list(); !slices.Equal(got, []string{pLaptop}) {
		t.Fatalf("after the revocation: %q", got)
	}
	if slices.ContainsFunc(restarted, func(r string) bool { return strings.Contains(r, "front") }) {
		t.Fatalf("restarted %v", restarted)
	}
}

// An update from before niko-server v0.19.3: the copies of the service's
// own salamander password (the backend's, the front's) leave the disk at
// the apply after the units that copy them in are gone, not before (a
// unit of before rayctl apply would fail its start without them).
func TestApplyDropsSharedSalamander(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	must(t, err)
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	_, err = provision.CreateService(ctx, st, store.Service{Kind: "hy2-obfs", Name: "hy2", Enabled: true})
	must(t, err)
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: "/run/niko"}
	units := filepath.Join(dir, "units")
	must(t, os.MkdirAll(units, 0o755))
	a := &Applier{
		Store: st, Paths: paths, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		FrontUnit: filepath.Join(units, render.UnitName("front")),
		Restart:   func(context.Context, string, string) error { return nil },
		Inner:     func(string) InnerAPI { return &fakeInner{} },
	}
	backend := filepath.Join(paths.Rendered, "hy2", render.HysteriaObfs)
	front := filepath.Join(paths.Rendered, "front", "hy2.salamander")
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	// Before: one password for the service, both copies written, and the
	// units of before copy them in.
	restore := render.UseNikoServer("v0.19.2")
	must(t, a.Apply(ctx))
	restore()
	if !exists(backend) || !exists(front) {
		t.Fatalf("no copies before v0.19.3: %v %v", exists(backend), exists(front))
	}
	unit := func(name, cred string) {
		must(t, os.WriteFile(filepath.Join(units, name), []byte("[Service]\nExecStartPre=+/usr/local/bin/rayd credential "+cred+"\n"), 0o644))
	}
	unit(render.UnitName("hy2"), "/var/lib raycontrol/rendered/hy2/salamander rayd niko-hy2 "+paths.Credential("hy2", render.HysteriaObfs))
	unit(render.UnitName("front"), "/var/lib raycontrol/rendered/front/hy2.salamander rayd niko-front "+paths.FrontSalamander("hy2"))
	must(t, a.Apply(ctx))
	if !exists(backend) || !exists(front) {
		t.Fatalf("a copy its installed unit takes removed: backend %v, front %v", exists(backend), exists(front))
	}
	// rayctl apply: the units of now copy neither.
	must(t, os.WriteFile(filepath.Join(units, render.UnitName("hy2")), []byte("[Service]\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(units, render.UnitName("front")), []byte("[Service]\n"), 0o644))
	must(t, a.Apply(ctx))
	if exists(backend) || exists(front) {
		t.Fatalf("the service's salamander password still on disk: backend %v, front %v", exists(backend), exists(front))
	}
}
