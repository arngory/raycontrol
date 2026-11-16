package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// Regression tests from the fourth review of R4-43.

// rollbackFix is a fake node with previousDir holding VERSION to and a
// copy of its database, for a rollback that puts the database back.
func rollbackFix(t *testing.T, to string) *fakeNode {
	t.Helper()
	oldPrev, oldNode := previousDir, localNode
	t.Cleanup(func() { previousDir, localNode = oldPrev, oldNode })
	f := newFakeNode(t, 0, false)
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

// A rollback that puts the database back (restoreDB, the copy in
// previousDir): rayd stopped once, by the rollback; the carry, the copy
// back, the renewal on it with rayd stopped, then the install; an install
// that fails says rayd is stopped and the copy back (review 4, M4, S2).
func TestRollbackDBBack(t *testing.T) {
	f := rollbackFix(t, "v0.30.0")
	err := (&cli{}).rollback(context.Background(), "asked for", true, carryMust)
	if !errors.Is(err, errInstalled) || !strings.Contains(err.Error(), "rayd is stopped, the database copy is back") ||
		!slices.Equal(f.calls, []string{"stop rayd.service", "install"}) || currentSecrets(t, f.db)["alice"] == f.known["alice"] {
		t.Errorf("%v %q", err, f.calls)
	}
}

// The renewal fails on the copy back, with carryMust: nothing installed,
// and the error says rayd is stopped and the copy back (review 4, M15). A
// trigger in the copy refuses the credentials' update; the carry changes
// none.
func TestRollbackDBBackRenewalFails(t *testing.T) {
	f := rollbackFix(t, "v0.30.0")
	db, err := sql.Open("sqlite", filepath.Join(previousDir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER no_renewal BEFORE UPDATE ON credentials BEGIN SELECT RAISE(ABORT, 'no renewal'); END`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	err = (&cli{}).rollback(context.Background(), "asked for", true, carryMust)
	if err == nil || errors.Is(err, errInstalled) || !strings.Contains(err.Error(), "rayd is stopped and the database copy is back") ||
		!slices.Equal(f.calls, []string{"stop rayd.service"}) {
		t.Errorf("%v %q", err, f.calls)
	}
}

// A rollback whose copy back fails before the database moved starts rayd
// again and says so (review 4, S2).
func TestRollbackCopyBackFails(t *testing.T) {
	f := rollbackFix(t, "v0.26.0")
	if err := syscall.Mkfifo(filepath.Join(previousDir, "rayd.db-wal"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := (&cli{}).rollback(context.Background(), "asked for", true, carrySkip)
	if err == nil || !strings.Contains(err.Error(), "putting the database back") || !strings.Contains(err.Error(), "rayd started again") ||
		!slices.Equal(f.calls, []string{"stop rayd.service", "start rayd.service"}) {
		t.Errorf("%v %q", err, f.calls)
	}
}

// A rollback whose carry fails, with carryMust, starts rayd again: nothing
// changed yet (review 4, S2). Root's copy of the database cannot be made.
func TestRollbackCarryFails(t *testing.T) {
	f := rollbackFix(t, "v0.26.0")
	t.Setenv("TMPDIR", os.Getenv("TMPDIR"))
	gone := filepath.Join(t.TempDir(), "gone")
	f.onStop = func() { os.Setenv("TMPDIR", gone) }
	err := (&cli{}).rollback(context.Background(), "asked for", true, carryMust)
	os.Setenv("TMPDIR", "")
	if err == nil || !strings.Contains(err.Error(), "keeping the revocations") || !strings.Contains(err.Error(), "nothing rolled back") ||
		!strings.Contains(err.Error(), "rayd started again") || !slices.Equal(f.calls, []string{"stop rayd.service", "start rayd.service"}) {
		t.Errorf("%v %q", err, f.calls)
	}
}

// The audit names an update going back as it was asked for (review 4,
// nit 8).
func TestUpdateActor(t *testing.T) {
	for _, c := range []struct {
		o    updateOpts
		want string
	}{
		{updateOpts{want: "v0.30.2"}, "rayctl update -version v0.30.2"},
		{updateOpts{want: "latest", from: "/root/rel"}, "rayctl update -from (v0.30.2)"},
		{updateOpts{want: "latest", local: "/root/bin"}, "rayctl update -local"},
		{updateOpts{want: "latest", force: true}, "rayctl update (v0.30.2)"},
	} {
		if got := updateActor(c.o, "v0.30.2"); got != c.want {
			t.Errorf("%+v: %q", c.o, got)
		}
	}
}

// copyDB: the new file in place, its WAL not: the error says so, and
// nothing is left beside it, the old WAL least (review 4, nit 7).
func TestCopyDBWALFailsAfterMain(t *testing.T) {
	src, dst := filepath.Join(t.TempDir(), "rayd.db"), filepath.Join(t.TempDir(), "rayd.db")
	for name, body := range map[string]string{src: "new", src + "-wal": "new frames", dst: "old", dst + "-wal": "old frames"} {
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	saved := renameDBFile
	t.Cleanup(func() { renameDBFile = saved })
	renameDBFile = func(src, dst string) error {
		if strings.HasSuffix(dst, "-wal") {
			return errors.New("no rename")
		}
		return os.Rename(src, dst)
	}
	err := copyDB(src, dst)
	if !errors.Is(err, errDBPlaced) {
		t.Fatalf("%v", err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "new" {
		t.Errorf("dst %q", b)
	}
	ents, _ := os.ReadDir(filepath.Dir(dst))
	if len(ents) != 1 {
		t.Errorf("beside the new file: %v", ents)
	}
}

// copyDB: the new file cannot go in: the old WAL goes back beside the old
// file, nothing else is left, the destination as it was (review 4, M5).
func TestCopyDBMainFails(t *testing.T) {
	src, dst := filepath.Join(t.TempDir(), "rayd.db"), filepath.Join(t.TempDir(), "rayd.db")
	for name, body := range map[string]string{src: "new", src + "-wal": "new frames", dst: "old", dst + "-wal": "old frames"} {
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	saved := renameDBFile
	t.Cleanup(func() { renameDBFile = saved })
	renameDBFile = func(string, string) error { return errors.New("no rename") }
	if err := copyDB(src, dst); err == nil || errors.Is(err, errDBPlaced) {
		t.Fatalf("%v", err)
	}
	for name, want := range map[string]string{dst: "old", dst + "-wal": "old frames"} {
		if b, err := os.ReadFile(name); err != nil || string(b) != want {
			t.Errorf("%s: %q %v", filepath.Base(name), b, err)
		}
	}
	if ents, _ := os.ReadDir(filepath.Dir(dst)); len(ents) != 2 {
		t.Errorf("left: %v", ents)
	}
}
