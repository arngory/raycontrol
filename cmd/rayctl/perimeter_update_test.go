package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeSystemctl puts a systemctl on PATH that prints out for any call.
func fakeSystemctl(t *testing.T, out string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "out"), []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncat '" + filepath.Join(dir, "out") + "'\n"
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0o755); err != nil { //nolint:gosec // G306: an executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// The update's check of the perimeter (M2): the new rayspa's own table
// with rayd's snapshot, by its STATUS and its MainPID; a table in the
// kernel is not enough, it may be the old rayspa's, frozen. A rayspa whose
// STATUS names no process (a rollback to an older one) is checked by the
// table, as before.
func TestRayspaUpdated(t *testing.T) {
	tableIn := func() error { return nil }
	noTable := func() error { return errors.New("exit status 1") }
	for _, c := range []struct {
		name, show string
		table      func() error
		ok         bool
	}{
		{"its own table, rayd's snapshot", "ActiveState=active\nMainPID=200\nStatusText=perimeter up: rayd's snapshot; rayspa v0.27.1, pid 200\n", noTable, true},
		{"the old table in force", "ActiveState=active\nMainPID=200\nStatusText=waiting for rayd: the table an earlier rayspa left is in force; rayspa v0.27.1, pid 200\n", tableIn, false},
		{"its table refused", "ActiveState=active\nMainPID=200\nStatusText=PERIMETER DOWN: the host is open, the table is not in (journalctl -u rayspa); rayspa v0.27.1, pid 200\n", tableIn, false},
		{"the saved snapshot only", "ActiveState=active\nMainPID=200\nStatusText=perimeter up: the saved snapshot, until rayd answers; rayspa v0.27.1, pid 200\n", tableIn, false},
		{"behind", "ActiveState=active\nMainPID=200\nStatusText=perimeter behind: the table is in, its snapshot only in part (journalctl -u rayspa); rayspa v0.27.1, pid 200\n", tableIn, false},
		{"another process's STATUS", "ActiveState=active\nMainPID=200\nStatusText=perimeter up: rayd's snapshot; rayspa v0.27.1, pid 100\n", tableIn, false},
		{"not active", "ActiveState=activating\nMainPID=200\nStatusText=\n", tableIn, false},
		{"an older rayspa, table in", "ActiveState=active\nMainPID=200\nStatusText=perimeter up\n", tableIn, true},
		{"an older rayspa, no table", "ActiveState=active\nMainPID=200\nStatusText=\n", noTable, false},
	} {
		fakeSystemctl(t, c.show)
		err := rayspaUpdated(showRayspa, c.table)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// rayctl check and status from root (perimeterResult): the STATUS of the
// running rayspa says whether the table in the kernel is its own.
func TestPerimeterResultOwnTable(t *testing.T) {
	unit := filepath.Join(t.TempDir(), "rayspa.service")
	if err := os.WriteFile(unit, []byte("[Unit]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		status string
		ok     bool
		line   string
	}{
		{"perimeter up: rayd's snapshot; rayspa v0.27.1, pid 200", true, "ok: rayspa runs, its table is in with rayd's snapshot"},
		{"waiting for rayd: the table an earlier rayspa left is in force; rayspa v0.27.1, pid 200", false,
			"WARNING a table is in, but rayspa says: waiting for rayd: the table an earlier rayspa left"},
		{"perimeter up", true, "ok: rayspa runs, its table is in"},
	} {
		fakeSystemctl(t, "ActiveState=active\nMainPID=200\nStatusText="+c.status+"\n")
		h := perimeterHost{unitFile: unit, state: func() string { return "active" }, input: func() (bool, error) { return true, nil },
			euid: func() int { return 0 }, look: func(string) error { return nil }, show: showRayspa}
		rs := perimeterResult(h)
		if len(rs) != 1 || rs[0].OK != c.ok || !strings.HasPrefix(perimeterLine(rs[0]), c.line) {
			t.Errorf("%q: %v %q", c.status, rs, perimeterLine(rs[0]))
		}
	}
}

func TestWaitPerimeter(t *testing.T) {
	n := 0
	err := waitPerimeter(context.Background(), func() error {
		if n++; n < 3 {
			return errors.New("not yet")
		}
		return nil
	}, 5, time.Millisecond)
	if err != nil || n != 3 {
		t.Fatalf("%v after %d", err, n)
	}
	err = waitPerimeter(context.Background(), func() error { return errors.New("rayspa: waiting for rayd") }, 3, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "waiting for rayd") {
		t.Fatalf("never: %v", err)
	}
}
