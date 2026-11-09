package provision

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/store"
)

// A REALITY service whose rotation fails does not hold back the others'
// (review Q-4): they rotate, and the error names the broken one.
func TestRealityRotationPastBroken(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "rayd.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := Init(ctx, st, Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	broken, err := CreateService(ctx, st, store.Service{Kind: "reality", Name: "a", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateService(ctx, st, store.Service{Kind: "reality", Name: "b", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// Settings no rewrite can take (an older database's, say): its
	// preparation fails.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE services SET settings_json = '[]' WHERE id = ?`, broken.ID); err != nil {
		t.Fatal(err)
	}
	db.Close()
	noDNS := func(context.Context, string) error { return errors.New("NXDOMAIN") }
	n, err := RotateReality(ctx, st, broken.CreatedAt.Add(88*day), epoch, noDNS, nil)
	if err == nil || !strings.Contains(err.Error(), "reality a:") || n != 1 {
		t.Fatalf("rotate past a broken service: %d changed, %v", n, err)
	}
	if _, state, _ := reload(t, ctx, st, "b"); state.NextFrom == 0 {
		t.Fatalf("b was not rotated: %+v", state)
	}
}
