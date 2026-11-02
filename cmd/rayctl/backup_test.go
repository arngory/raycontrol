package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSwapDB(t *testing.T) {
	dir := t.TempDir()
	db, next, aside := filepath.Join(dir, "rayd.db"), filepath.Join(dir, "rayd.db.restore"), filepath.Join(dir, "rayd.db.before-restore")
	write := func(path, content string) {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	read := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			return "<" + err.Error() + ">"
		}
		return string(b)
	}
	write(db, "old")
	write(db+"-wal", "old wal")
	write(aside, "older")
	write(next, "new")
	if err := swapDB(next, db, aside); err != nil {
		t.Fatal(err)
	}
	if read(db) != "new" || read(aside) != "old" || read(aside+"-wal") != "old wal" {
		t.Fatalf("db %q, aside %q %q", read(db), read(aside), read(aside+"-wal"))
	}
	if _, err := os.Stat(db + "-wal"); !os.IsNotExist(err) {
		t.Fatal("the old journal stayed next to the new database")
	}
	// The new copy is missing: the database goes back where it was.
	if err := swapDB(filepath.Join(dir, "missing"), db, aside); err == nil {
		t.Fatal("swapped in a missing file")
	}
	if read(db) != "new" {
		t.Fatalf("db %q after a failed swap", read(db))
	}
}
