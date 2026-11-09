package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/arngory/raycontrol/internal/store"
)

// DoH takes the tokens of active users only: one over the traffic limit
// is out, as a disabled one (traffic-limit-v1 §3.1).
func TestDoHTokensOverLimit(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	doh, err := st.CreateService(ctx, store.Service{Kind: "doh", Name: "doh", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	limit := int64(1000)
	u, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true, TrafficLimit: &limit})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserServices(ctx, "alice", []int64{doh.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Credentials(ctx, doh.ID, []int64{u.ID}, func() (string, error) { return "token-alice", nil }); err != nil {
		t.Fatal(err)
	}
	tokens, err := dohTokens(ctx, st, doh.ID)
	if err != nil || !tokens["token-alice"] {
		t.Fatalf("under the limit: %v %v", tokens, err)
	}
	if err := st.WriteTraffic(ctx, store.TrafficWrite{Adds: []store.TrafficAdd{{UserID: u.ID, Start: u.TrafficStart, Up: 1000}}}); err != nil {
		t.Fatal(err)
	}
	if tokens, err = dohTokens(ctx, st, doh.ID); err != nil || len(tokens) != 0 {
		t.Fatalf("over the limit: %v %v", tokens, err)
	}
}
