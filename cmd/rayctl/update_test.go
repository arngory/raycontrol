package main

import (
	"os"
	"path/filepath"
	"testing"
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
	for _, gone := range []string{dst + "-wal", dst + "-shm", dst + ".tmp"} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
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
}
