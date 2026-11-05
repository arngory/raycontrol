package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// copyDB takes the file and its WAL, drops a stale WAL and shared memory at
// the destination, and leaves the copy 0600 (Q-2).
func TestCopyDB(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "src.db"), filepath.Join(dir, "dst.db")
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(src, "db")
	write(dst, "old")
	write(dst+"-wal", "stale wal")
	write(dst+"-shm", "stale shm")
	if err := copyDB(src, dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "db" {
		t.Fatalf("dst = %q", b)
	}
	for _, gone := range []string{dst + "-wal", dst + "-shm"} {
		if _, err := os.Lstat(gone); !os.IsNotExist(err) {
			t.Errorf("%s left: %v", gone, err)
		}
	}
	write(src+"-wal", "wal")
	if err := copyDB(src, filepath.Join(dir, "new.db")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "new.db-wal")); string(b) != "wal" {
		t.Fatalf("wal = %q", b)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "new.db")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(m) != 0 {
		t.Fatalf("temporary files left: %v", m)
	}
}

// rayd owns the directory copyDB writes in as root: links it plants there
// must not be followed, neither where the copy is written nor where the
// database is read (security review, the copy of Q-2).
func TestCopyDBLinks(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "ld.so.preload")
	src, dst := filepath.Join(dir, "saved.db"), filepath.Join(dir, "rayd.db")
	os.WriteFile(src, []byte("db"), 0o600)
	// The old temporary name, and the target itself, planted as links.
	os.Symlink(victim, dst+".tmp")
	os.Symlink(victim, dst+"-wal.tmp")
	os.Symlink(victim, dst)
	if err := copyDB(src, dst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(victim); !os.IsNotExist(err) {
		t.Fatal("the copy went through a planted link")
	}
	if fi, _ := os.Lstat(dst); fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("the target is still the planted link")
	}
	// A database that is a link to a root-only file is not read.
	secret := filepath.Join(t.TempDir(), "shadow")
	os.WriteFile(secret, []byte("root only"), 0o600)
	linked := filepath.Join(dir, "linked.db")
	os.Symlink(secret, linked)
	if err := copyDB(linked, filepath.Join(t.TempDir(), "out.db")); err == nil || !strings.Contains(err.Error(), "link") {
		t.Fatalf("a linked database was read: %v", err)
	}
	os.Symlink(secret, src+"-wal")
	if err := copyDB(src, filepath.Join(t.TempDir(), "out.db")); err == nil {
		t.Fatal("a linked WAL was read")
	}
}

// A FIFO left in the database's place does not hang root's copy: it is
// refused at once.
func TestCopyDBFIFO(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "rayd.db"), filepath.Join(dir, "copy", "rayd.db")
	os.Mkdir(filepath.Dir(dst), 0o700)
	os.WriteFile(src, []byte("db"), 0o600)
	if err := syscall.Mkfifo(src+"-wal", 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() { done <- copyDB(src, dst) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("copy with a FIFO for the WAL: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("copyDB hangs on a FIFO")
	}
}
