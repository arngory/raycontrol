package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
)

// untouched is a rayd any call to which fails the test (a nil interface:
// a call panics).
type untouched struct {
	nodev1connect.NodeServiceClient
}

// install over a running node and restore take the update lock first,
// before anything changes, as update and rollback do: held by another,
// they refuse at once (review S3). The rayctl apply they run inherits it.
func TestInstallRestoreLock(t *testing.T) {
	updateLockPath = filepath.Join(t.TempDir(), "lock")
	t.Setenv(lockEnv, "")
	saved := needRoot
	needRoot = func() error { return nil }
	t.Cleanup(func() {
		needRoot = saved
		if heldLock != nil {
			heldLock.Close()
			heldLock = nil
		}
	})
	other, err := os.OpenFile(updateLockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(other.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	other.WriteString("update by pid 4242 since 2026-11-08T18:00:00Z")
	c := &cli{c: untouched{}}
	ctx := context.Background()
	for what, run := range map[string]func() error{
		"install": func() error { return c.install(ctx, []string{"-host", "203.0.113.7", "-admin", "192.0.2.1"}) },
		"restore": func() error { return c.restore(ctx, []string{"-i", filepath.Join(t.TempDir(), "backup"), "-yes"}) },
	} {
		err := run()
		if err == nil || !strings.Contains(err.Error(), "another update by pid 4242") || !strings.Contains(err.Error(), what+" again") {
			t.Errorf("%s with the lock held: %v", what, err)
		}
	}
	// Free: taken, and the rayctl apply a restore runs is told.
	other.Close()
	if err := takeUpdateLock("restore", 0); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(applyEnv(""), lockEnv+"=held") {
		t.Error("the nested apply would wait for its own parent")
	}
}

// restore's copy of the database goes into rayd's directory without
// following a link rayd put at its name, and becomes the directory's
// owner's through its descriptor (review item 10; as copyDB).
func TestPlaceDBLink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(victim, []byte("root's\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "rayd.db.restore")
	if err := os.Symlink(victim, dst); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		os.Chown(dir, 65534, 65534) // rayd's, as /var/lib/raycontrol
		os.Chown(victim, 0, 0)
	}
	if err := placeDB(dst, []byte("SQLite format 3\x00")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "root's\n" {
		t.Errorf("written through the link: %q", b)
	}
	fi, err := os.Lstat(dst)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Errorf("%s: %v", dst, fi.Mode())
	}
	if os.Geteuid() == 0 {
		vi, _ := os.Stat(victim)
		if st.Uid != 65534 || vi.Sys().(*syscall.Stat_t).Uid != 0 {
			t.Errorf("owners: copy %d, the link's target %d", st.Uid, vi.Sys().(*syscall.Stat_t).Uid)
		}
	}
	if left, _ := os.ReadDir(dir); len(left) != 1 {
		t.Errorf("left in the directory: %v", left)
	}
}
