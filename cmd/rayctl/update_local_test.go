package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/nodeupdate"
)

// An update by hand is noted as the node's own (spec/relay-update-remote-v1.md
// §11 p. 1): done, it names the release the exit offers its relays, by
// someone a client can show; -no-relays says the relays stay; rolled back
// or broken on the way, the release is held, and what was held stays. The
// directory is made where no update by request ever ran.
func TestNoteUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "updates", "status.json")
	started := time.Now().Add(-3 * time.Minute).UTC()
	noteUpdate(path, nil, "v0.27.0", "v0.28.0", false, started)
	st := nodeupdate.ReadStatus(path)
	if st.State != nodeupdate.Done || st.Kind != nodeupdate.Local || st.By != "rayctl on the node" || st.From != "v0.27.0" || st.To != "v0.28.0" ||
		st.Target != "v0.28.0" || st.Release != "v0.28.0" || st.NoRelays || len(st.ID) != 16 || !st.Started.Equal(started) || st.Ended.Before(started) {
		t.Fatalf("done: %+v", st)
	}
	first := st.ID
	noteUpdate(path, nil, "v0.28.0", "v0.28.1", true, started)
	if st = nodeupdate.ReadStatus(path); st.State != nodeupdate.Done || !st.NoRelays || st.ID == first {
		t.Fatalf("-no-relays: %+v", st)
	}

	nodeupdate.WriteStatus(path, nodeupdate.Status{ID: "0a", State: nodeupdate.Done, Held: []string{"v0.28.2"}})
	noteUpdate(path, rolledBack{errors.New("rayspa did not bring the perimeter back")}, "v0.28.1", "v0.28.3", false, started)
	st = nodeupdate.ReadStatus(path)
	if st.State != nodeupdate.RolledBack || st.To != "v0.28.1" || st.Error != "rayspa did not bring the perimeter back" ||
		!slices.Equal(st.Held, []string{"v0.28.2", "v0.28.3"}) {
		t.Fatalf("rolled back: %+v", st)
	}
	noteUpdate(path, errors.New("installing: no space left"), "v0.28.1", "v0.28.4", false, started)
	if st = nodeupdate.ReadStatus(path); st.State != nodeupdate.Failed || st.Untouched || st.Error != "installing: no space left" ||
		!slices.Equal(st.Held, []string{"v0.28.2", "v0.28.3", "v0.28.4"}) {
		t.Fatalf("broken on the way: %+v", st)
	}
	// Binaries of a test build: no release to hold or to name.
	noteUpdate(path, nil, "v0.28.1", "local", false, started)
	if st = nodeupdate.ReadStatus(path); st.State != nodeupdate.Done || st.To != "local" || st.Release != "" || len(st.Held) != 3 {
		t.Fatalf("-local: %+v", st)
	}
	if fi, err := os.Stat(filepath.Dir(path)); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("the status directory: %v %v", fi, err)
	}
}

// -no-relays reaches the release's rayctl the update is handed to, and only
// it: a variable left in an operator's shell does not keep the relays back,
// nor does it reach the apply.
func TestSkipRelays(t *testing.T) {
	for _, c := range []struct {
		flag         bool
		handoff, env string
		want         bool
		passedOn     string // the variable after, for a handoff
	}{
		{true, "", "", true, "1"},
		{false, "", "", false, ""},
		{false, "", "1", false, ""}, // in the shell of a command run by hand
		{false, "1", "1", true, "1"},
		{false, "1", "", false, ""},
		{true, "1", "", true, "1"},
	} {
		t.Setenv(handoffEnv, c.handoff)
		t.Setenv(noRelaysEnv, c.env)
		if got := skipRelays(c.flag); got != c.want || os.Getenv(noRelaysEnv) != c.passedOn {
			t.Errorf("%+v: %v, variable %q", c, got, os.Getenv(noRelaysEnv))
		}
		for _, kv := range applyEnv("") {
			if kv == noRelaysEnv+"=1" {
				t.Errorf("%+v: the apply gets %s", c, kv)
			}
		}
	}
}

// A rollback by hand stays a local one: the relays never follow it.
func TestNoteRollbackLocal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	nodeupdate.WriteStatus(path, nodeupdate.Status{ID: "0a", State: nodeupdate.Done})
	noteRollback(path, "v0.28.0", "v0.27.0")
	if st := nodeupdate.ReadStatus(path); st.Kind != nodeupdate.Local || st.State != nodeupdate.RolledBack || st.NoRelays {
		t.Fatalf("%+v", st)
	}
}
