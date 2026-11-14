package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// rayd init -check-ports reads the node's live database (L8): read-only,
// no migration, no file made, nothing written.
func TestOpenReadOnly(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "rayd.db")
	if _, err := OpenReadOnly(ctx, path); err == nil {
		t.Fatal("a database that is not there")
	}
	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting(ctx, "k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	// Opened read-only while the writer has it open, as beside rayd.
	ro, err := OpenReadOnly(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if v, err := ro.GetSetting(ctx, "k"); err != nil || string(v) != "v" {
		t.Fatalf("read: %q %v", v, err)
	}
	if err := ro.SetSetting(ctx, "k", []byte("w")); err == nil {
		t.Fatal("a write through the read-only store")
	}
	if v, _ := st.GetSetting(ctx, "k"); string(v) != "v" {
		t.Fatalf("the value changed: %q", v)
	}
	if _, err := ro.ListServices(ctx); err != nil {
		t.Fatalf("services: %v", err)
	}
	st.Close()

	// A database newer than this build is refused, as Open refuses it.
	st, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, 0)`, KnownSchema()+1); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if _, err := OpenReadOnly(ctx, path); !errors.Is(err, ErrNewerSchema) {
		t.Fatalf("newer schema: %v", err)
	}
}
