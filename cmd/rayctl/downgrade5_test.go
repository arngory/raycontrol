package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

// Regression tests from the fifth review of R4-43.

// rollbackFixWith is rollbackFix with the node's period.
func rollbackFixWith(t *testing.T, to string, period time.Duration) *fakeNode {
	t.Helper()
	oldPrev, oldNode := previousDir, localNode
	t.Cleanup(func() { previousDir, localNode = oldPrev, oldNode })
	f := newFakeNode(t, period, false)
	previousDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(previousDir, "VERSION"), []byte(to+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyDB(f.db, filepath.Join(previousDir, "rayd.db")); err != nil {
		t.Fatal(err)
	}
	localNode = f.env()
	return f
}

// The period re-checked where rayd is stopped already: an update going
// back on a node with a period renews no one (review 5, S2, the
// reviewer's probe).
func TestStopForInstallWithPeriod(t *testing.T) {
	oldPrev := previousDir
	t.Cleanup(func() { previousDir = oldPrev })
	f := newFakeNode(t, store.DefaultRotation.Period, false)
	previousDir = t.TempDir()
	users, err := f.env().stopForInstall(context.Background(), "v0.30.2", "rayctl update -version v0.30.2")
	if err != nil || len(users) != 0 || !slices.Equal(f.calls, []string{"stop rayd.service"}) || currentSecrets(t, f.db)["alice"] != f.known["alice"] {
		t.Errorf("with a period: %v %v %q", users, err, f.calls)
	}
}

// The same for a rollback that put the database back (review 5, S2).
func TestRollbackDBBackWithPeriod(t *testing.T) {
	f := rollbackFixWith(t, "v0.30.0", store.DefaultRotation.Period)
	err := (&cli{}).rollback(context.Background(), "asked for", true, carryMust)
	if !errors.Is(err, errInstalled) || !slices.Equal(f.calls, []string{"stop rayd.service", "install"}) ||
		currentSecrets(t, f.db)["alice"] != f.known["alice"] {
		t.Errorf("rollback with the copy back, with a period: %v %q", err, f.calls)
	}
}

// rayd's own negative period, stored as it was before review 5: going
// back renews (review 5, S1).
func TestRenewForOlderNegativePeriod(t *testing.T) {
	f := newFakeNode(t, -time.Second, false)
	users, stopped, err := f.env().renewForOlder(context.Background(), "v0.30.0", false, "a", "rollback")
	if err != nil || !slices.Equal(users, []string{"alice"}) || !stopped || currentSecrets(t, f.db)["alice"] == f.known["alice"] {
		t.Errorf("%v %v %v %q", users, stopped, err, f.calls)
	}
}

// Nobody to renew: the database stays the same file (review 5, P14).
func TestRenewForOlderNobodyKeepsFile(t *testing.T) {
	ctx := context.Background()
	f := newFakeNode(t, 0, false)
	n := f.env()
	if _, _, err := n.renewForOlder(ctx, "v0.30.0", false, "a", "rollback"); err != nil {
		t.Fatal(err)
	}
	ino := func() uint64 {
		fi, err := os.Lstat(f.db)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Sys().(*syscall.Stat_t).Ino
	}
	before := ino()
	if users, _, err := n.renewForOlder(ctx, "v0.30.0", false, "a", "rollback"); err != nil || len(users) != 0 || ino() != before {
		t.Errorf("nobody: %v %v, the file replaced: %v", users, err, ino() != before)
	}
}

// copyDB: the directory's sync fails after both renames: errDBUnsynced,
// both files in place; a renewal so ended says the renewed database is in
// place, and rayd started again (review 5, N1, P7).
func TestCopyDBUnsynced(t *testing.T) {
	saved := syncDBDir
	t.Cleanup(func() { syncDBDir = saved })
	src, dst := filepath.Join(t.TempDir(), "rayd.db"), filepath.Join(t.TempDir(), "rayd.db")
	for name, body := range map[string]string{src: "new", src + "-wal": "new frames", dst: "old"} {
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	syncDBDir = func(dir string) error {
		if dir == filepath.Dir(dst) {
			return errors.New("no sync")
		}
		return syncDir(dir)
	}
	if err := copyDB(src, dst); !errors.Is(err, errDBUnsynced) || errors.Is(err, errDBPlaced) {
		t.Fatalf("%v", err)
	}
	for name, want := range map[string]string{dst: "new", dst + "-wal": "new frames"} {
		if b, err := os.ReadFile(name); err != nil || string(b) != want {
			t.Errorf("%s: %q %v", filepath.Base(name), b, err)
		}
	}

	f := newFakeNode(t, 0, false)
	syncDBDir = func(dir string) error {
		if dir == f.dir {
			return errors.New("no sync")
		}
		return syncDir(dir)
	}
	_, _, err := f.env().renewForOlder(context.Background(), "v0.30.0", false, "a", "rollback")
	if err == nil || !strings.Contains(err.Error(), "the renewed database is in place, its directory not synced, rayd started again") ||
		strings.Contains(err.Error(), "nothing changed") {
		t.Errorf("renewal: %v", err)
	}
}

// A rollback whose copy back placed the database but not its WAL stops
// there, rayd stopped, and says how to put the copy in by hand: a rollback
// again would find the schemas equal and leave it (review 5, N2, P5). One
// whose sync failed says to sync and go on.
func TestRollbackCopyBackPlaced(t *testing.T) {
	ctx := context.Background()
	f := rollbackFixWith(t, "v0.26.0", 0)
	saved := filepath.Join(previousDir, "rayd.db")
	if err := os.WriteFile(saved+"-wal", []byte("frames"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := renameDBFile
	t.Cleanup(func() { renameDBFile = old })
	renameDBFile = func(src, dst string) error {
		if dst == f.db+"-wal" {
			return errors.New("no rename")
		}
		return os.Rename(src, dst)
	}
	err := (&cli{}).rollback(ctx, "asked for", true, carrySkip)
	for _, want := range []string{"without its WAL", "install -m 0600 -o rayd -g rayd " + saved + " " + f.db,
		"install -m 0600 -o rayd -g rayd " + saved + "-wal " + f.db + "-wal", "rayctl update -rollback -no-carry"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("no %q in %v", want, err)
		}
	}
	if !slices.Equal(f.calls, []string{"stop rayd.service"}) {
		t.Errorf("systemctl %q", f.calls)
	}

	renameDBFile = old
	f = rollbackFixWith(t, "v0.26.0", 0)
	oldSync := syncDBDir
	t.Cleanup(func() { syncDBDir = oldSync })
	syncDBDir = func(dir string) error {
		if dir == f.dir {
			return errors.New("no sync")
		}
		return syncDir(dir)
	}
	err = (&cli{}).rollback(ctx, "asked for", true, carrySkip)
	if err == nil || !strings.Contains(err.Error(), "sync, then rayctl update -rollback -no-carry") || !slices.Equal(f.calls, []string{"stop rayd.service"}) {
		t.Errorf("not synced: %v %q", err, f.calls)
	}
}

// The automatic rollback of a failed update renews as its own actor; with
// carryTry a renewal that fails says what stays accepted and what to run
// (review 5, N4, N5).
func TestRollbackAutomatic(t *testing.T) {
	ctx := context.Background()
	f := rollbackFixWith(t, "v0.30.0", 0)
	if err := os.Remove(filepath.Join(previousDir, "rayd.db")); err != nil { // the database stays
		t.Fatal(err)
	}
	if err := (&cli{}).rollback(ctx, updateFailed, true, carryTry); !errors.Is(err, errInstalled) {
		t.Fatalf("%v %q", err, f.calls)
	}
	s, err := store.OpenReadOnly(ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	audit, _ := s.ListAudit(ctx, 10)
	s.Close()
	if !slices.ContainsFunc(audit, func(a store.AuditEntry) bool {
		return a.Action == "user.renew:rollback" && a.Actor == "rayctl update (automatic rollback)"
	}) {
		t.Errorf("audit %+v", audit)
	}

	f = rollbackFixWith(t, "v0.30.0", 0)
	if err := os.Remove(filepath.Join(previousDir, "rayd.db")); err != nil {
		t.Fatal(err)
	}
	f.plantFIFO(t)
	out, err := captureStdout(t, func() error { return (&cli{}).rollback(ctx, updateFailed, true, carryTry) })
	if !errors.Is(err, errInstalled) || !strings.Contains(out, "stays accepted with v0.30.0; rayctl user renew NAME") {
		t.Errorf("%v %q", err, out)
	}
}
