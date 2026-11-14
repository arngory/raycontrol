package api

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/arngory/raycontrol/internal/store"
)

// A change the store made is notified even when its audit line cannot be
// written: DoH's Forget and the data plane's apply must follow a
// revocation. The caller still gets the audit's error; a call that failed
// notifies nothing.
func TestDoneNotifiesWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "rayd.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER audit_down BEFORE INSERT ON audit_log BEGIN SELECT RAISE(FAIL, 'audit down'); END`); err != nil {
		t.Fatal(err)
	}
	var changes atomic.Int32
	srv := &Server{Store: st, OnChange: func() { changes.Add(1) }}
	if err := srv.done(ctx, "device.revoke", "d1 alice/phone", nil); err == nil {
		t.Fatal("the audit's error is lost")
	}
	if changes.Load() != 1 {
		t.Fatalf("%d notifications after a change whose audit failed", changes.Load())
	}
	if err := srv.done(ctx, "device.revoke", "d1 alice/phone", errors.New("no such device")); err == nil || changes.Load() != 1 {
		t.Fatalf("a failed call: %v, %d notifications", err, changes.Load())
	}
}
