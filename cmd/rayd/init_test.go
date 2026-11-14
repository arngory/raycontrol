package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

// rayd init -seq-clock, which rayctl restore runs on the database it puts
// back: the subscription's seq goes on from the clock, above what clients
// saw from the node before the restore (subscription-v1 §3). Without the
// flag the count stays, as an update's rollback needs it.
func TestInitSeqClock(t *testing.T) {
	ctx := context.Background()
	db := filepath.Join(t.TempDir(), "rayd.db")
	seq := func() int64 {
		t.Helper()
		st, err := store.Open(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		b, err := st.GetSetting(ctx, "sub_seq")
		if errors.Is(err, store.ErrNotFound) {
			return 0
		}
		if err != nil {
			t.Fatal(err)
		}
		n, _ := strconv.ParseInt(string(b), 10, 64)
		return n
	}
	if err := cmdInit([]string{"-db", db, "-host", "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	if got := seq(); got != 0 {
		t.Fatalf("init alone moved the seq to %d", got)
	}
	before := time.Now().UnixMilli()
	if err := cmdInit([]string{"-db", db, "-seq-clock"}); err != nil {
		t.Fatal(err)
	}
	if got := seq(); got < before {
		t.Fatalf("seq %d after -seq-clock, the clock says %d", got, before)
	}
}

// rayd init -ports at the first install; -check-ports, which rayctl
// install asks before it changes anything, takes the node's own ports or
// a new node's, and creates no database.
func TestInitPorts(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "rayd.db")
	if err := cmdInit([]string{"-db", db, "-ports", "spa=40000-40099,sub=40100", "-check-ports"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(db); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("-check-ports made a database: %v", err)
	}
	if err := cmdInit([]string{"-db", db, "-host", "203.0.113.7", "-ports", "spa=40000-40099,sub=40100"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdInit([]string{"-db", db, "-ports", "sub=40100", "-check-ports"}); err != nil {
		t.Errorf("its own port: %v", err)
	}
	if err := cmdInit([]string{"-db", db, "-ports", "sub=40200", "-check-ports"}); err == nil {
		t.Error("another port taken")
	}
	if err := cmdInit([]string{"-db", db, "-ports", "sub=80"}); err == nil {
		t.Error("a privileged port taken")
	}
}
