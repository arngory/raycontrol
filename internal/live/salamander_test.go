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
