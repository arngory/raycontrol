package live

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

type fakeInner struct {
	calls []map[string]string
}

func (f *fakeInner) SyncVLESS(_ context.Context, _, _ string, want map[string]string) (int, int, error) {
	f.calls = append(f.calls, want)
	return len(want), 0, nil
}

func TestApply(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	dns, err := provision.CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	var restarted []string
	inner := &fakeInner{}
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: "/run/niko"}
	a := &Applier{
		Store: st, Paths: paths, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Restart: func(_ context.Context, verb, unit string) error {
			restarted = append(restarted, verb+" "+unit)
			return nil
		},
		Inner: func(string) InnerAPI { return inner },
	}
	if err := a.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	slices.Sort(restarted)
	if !slices.Equal(restarted, []string{"restart niko-dns.service", "restart niko-front.service", "restart niko-inner.service"}) {
		t.Fatalf("first apply restarted %v", restarted)
	}
	if fi, err := os.Stat(paths.Rendered); err != nil || fi.Mode().Perm() != 0o711 {
		t.Fatalf("rendered dir must let service users through: %v %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Join(paths.Rendered, "dns")); err != nil || fi.Mode().Perm() != 0o750 {
		t.Fatalf("service dir: %v %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Join(paths.Rendered, "dns", "noise.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("noise key: %v %v", fi, err)
	}

	// Nothing changed: nothing restarts.
	restarted = nil
	if err := a.Apply(ctx); err != nil || len(restarted) != 0 || len(inner.calls) != 0 {
		t.Fatalf("idle apply: restarted %v, inner %v, %v", restarted, inner.calls, err)
	}

	// A new tunnel user only changes inner users: synced, not restarted.
	if _, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	st.SetUserServices(ctx, "alice", []int64{dns.ID})
	if err := a.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if len(restarted) != 0 || len(inner.calls) != 1 || len(inner.calls[0]) != 1 {
		t.Fatalf("user change: restarted %v, inner %v", restarted, inner.calls)
	}

	// inner off under the tunnel (a database from before the API refused
	// it): the tunnel keeps its files and process, the rest is applied (Q-1).
	// A new service at the same time still comes up.
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "hy2-obfs", Name: "hy2", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	st.SetServiceEnabled(ctx, "inner", false)
	restarted = nil
	err = a.Apply(ctx)
	if err == nil || !strings.Contains(err.Error(), "service dns") {
		t.Fatalf("apply without inner: %v", err)
	}
	slices.Sort(restarted)
	if !slices.Equal(restarted, []string{"restart niko-front.service", "restart niko-hy2.service"}) {
		t.Fatalf("apply without inner restarted %v", restarted)
	}
	if _, err := os.Stat(filepath.Join(paths.Rendered, "dns", "noise.key")); err != nil {
		t.Fatalf("the broken tunnel lost its files: %v", err)
	}
}

func TestSameExceptClients(t *testing.T) {
	a := []byte(`{"inbounds":[{"tag":"inner","settings":{"clients":[{"id":"1"}],"decryption":"x"}}],"log":{}}`)
	b := []byte(`{"inbounds":[{"tag":"inner","settings":{"clients":[{"id":"2"}],"decryption":"x"}}],"log":{}}`)
	c := []byte(`{"inbounds":[{"tag":"inner","settings":{"clients":[{"id":"2"}],"decryption":"y"}}],"log":{}}`)
	if !sameExceptClients(a, b) || sameExceptClients(a, c) || sameExceptClients(a, []byte("{")) {
		t.Fatal("client-only diff misdetected")
	}
}

func TestFixMeta(t *testing.T) {
	g, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Skip("no name for the current group")
	}
	p := filepath.Join(t.TempDir(), "front", "front.json")
	os.MkdirAll(filepath.Dir(p), 0o750)
	os.WriteFile(p, []byte("{}"), 0o600)
	f := render.File{Path: p, Mode: 0o640, Group: g.Name, Content: []byte("{}")}
	if fixed, err := fixMeta(f); err != nil || !fixed {
		t.Fatalf("first fix: %v %v", fixed, err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", st.Mode())
	}
	if fixed, err := fixMeta(f); err != nil || fixed {
		t.Fatalf("second fix: %v %v", fixed, err)
	}
	// A group that does not exist yet is left for later.
	f.Group = "raycontrol-no-such-group"
	if fixed, err := fixMeta(f); err != nil || fixed {
		t.Fatalf("missing group: %v %v", fixed, err)
	}
}

// naive reads its users file again by itself: a new user restarts nothing.
func TestApplyReload(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	for _, k := range []string{"reality", "naive"} {
		if _, err := provision.CreateService(ctx, st, store.Service{Kind: k, Name: k, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	site, err := st.ServiceByName(ctx, "site")
	if err != nil {
		t.Fatal(err)
	}
	key, cert, err := provision.SelfSigned("site.example.com")
	if err != nil {
		t.Fatal(err)
	}
	st.SetServiceSecret(ctx, site.ID, provision.SecretTLSKey, key)
	st.SetServiceSecret(ctx, site.ID, provision.SecretTLSChain, cert) // only its presence matters here
	naive, _ := st.ServiceByName(ctx, "naive")

	var restarted []string
	a := &Applier{
		Store: st, Paths: render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: "/run/niko"},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Restart: func(_ context.Context, verb, unit string) error {
			restarted = append(restarted, verb+" "+unit)
			return nil
		},
		Inner: func(string) InnerAPI { return &fakeInner{} },
	}
	if err := a.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(restarted, "restart niko-naive.service") {
		t.Fatalf("first apply restarted %v", restarted)
	}
	restarted = nil
	users := filepath.Join(dir, "rendered", "naive", render.NaiveUsers)
	before, _ := os.ReadFile(users)
	if _, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	st.SetUserServices(ctx, "alice", []int64{naive.ID})
	if err := a.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(users)
	if string(before) == string(after) || slices.Contains(restarted, "try-restart niko-naive.service") {
		t.Fatalf("users %s -> %s, restarted %v", before, after, restarted)
	}
}
