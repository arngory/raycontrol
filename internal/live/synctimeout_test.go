package live

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// hungInner is an Xray API that never answers: it waits for the call's
// context.
type hungInner struct{}

func (hungInner) SyncVLESS(ctx context.Context, _, _ string, _ map[string]string) (int, int, error) {
	<-ctx.Done()
	return 0, 0, ctx.Err()
}

// An Xray API that stopped answering does not hold Apply: the sync runs
// out after SyncTimeout and the process is restarted instead.
func TestApplySyncTimeout(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	must(t, err)
	defer st.Close()
	_, err = provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	must(t, err)
	dns, err := provision.CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true})
	must(t, err)
	_, err = st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	must(t, err)
	must(t, st.SetUserServices(ctx, "alice", []int64{dns.ID}))

	var (
		mu        sync.Mutex
		restarted []string
		inner     InnerAPI = &fakeInner{}
	)
	a := &Applier{
		Store: st, Paths: render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: "/run/niko"},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Restart: func(_ context.Context, verb, unit string) error {
			mu.Lock()
			defer mu.Unlock()
			restarted = append(restarted, verb+" "+unit)
			return nil
		},
		Inner:       func(string) InnerAPI { return inner },
		SyncTimeout: 50 * time.Millisecond,
	}
	must(t, a.Apply(ctx))
	restarted = nil
	inner = hungInner{}
	// The next credential published: a change of inner's users only, which
	// goes through the API.
	r := store.Rotation{Period: 30 * 24 * time.Hour, Lead: 3 * 24 * time.Hour, Grace: 2 * 24 * time.Hour}
	if _, err := st.RotateCredentials(ctx, time.Now().Add(28*24*time.Hour), r, render.NewUUID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- a.Apply(ctx) }()
	select {
	case err := <-done:
		must(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Apply hangs on an Xray API that does not answer")
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Contains(restarted, "try-restart "+render.UnitName("inner")) {
		t.Fatalf("restarted %v, want inner after the sync ran out", restarted)
	}
}
