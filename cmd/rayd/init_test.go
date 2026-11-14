package main

import (
	"context"
	"errors"
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
