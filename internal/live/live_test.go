package live

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

type fakeInner struct {
	calls []map[string]string
}

func (f *fakeInner) SyncVLESS(_ context.Context, _ string, want map[string]string) (int, int, error) {
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
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: "/run/niko", Credentials: "/run/credentials"}
	a := &Applier{
		Store: st, Paths: paths, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Restart: func(_ context.Context, unit string) error { restarted = append(restarted, unit); return nil },
		Inner:   func(string) InnerAPI { return inner },
	}
	if err := a.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	slices.Sort(restarted)
	if !slices.Equal(restarted, []string{"niko-dns.service", "niko-front.service", "niko-inner.service"}) {
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
}

func TestSameExceptClients(t *testing.T) {
	a := []byte(`{"inbounds":[{"tag":"inner","settings":{"clients":[{"id":"1"}],"decryption":"x"}}],"log":{}}`)
	b := []byte(`{"inbounds":[{"tag":"inner","settings":{"clients":[{"id":"2"}],"decryption":"x"}}],"log":{}}`)
	c := []byte(`{"inbounds":[{"tag":"inner","settings":{"clients":[{"id":"2"}],"decryption":"y"}}],"log":{}}`)
	if !sameExceptClients(a, b) || sameExceptClients(a, c) || sameExceptClients(a, []byte("{")) {
		t.Fatal("client-only diff misdetected")
	}
}
