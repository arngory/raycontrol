package sub_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/sub"
)

// A database put back by rayctl restore holds the seq of the day of the
// backup, and rayd keeps to the stored seq for its first ten minutes
// (ClockSeqAfter, for an update that rolls back): for those minutes every
// answer was below what clients had seen, and they dropped it. Among them
// the answer a client asks for when its pins no longer fit the restored
// node (spec/cert-pin-v1.md §9). restore moves the seq to the clock before
// rayd starts (rayd init -seq-clock, SeqToClock); a rollback does not.
func TestSeqAfterRestore(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	now := time.Now()
	seq := func(srv *sub.Server, at time.Time) uint64 {
		t.Helper()
		env, err := srv.Build(ctx, "alice", at)
		if err != nil {
			t.Fatal(err)
		}
		p, err := sub.Verify(env, f.keys.PublicJSON())
		if err != nil {
			t.Fatal(err)
		}
		return p.Seq
	}
	backup := strconv.FormatInt(now.Add(-10*24*time.Hour).UnixMilli(), 10)
	seen := uint64(now.Add(-time.Minute).UnixMilli()) // a client's last answer before the restore
	started := func() *sub.Server {
		return &sub.Server{Store: f.st, Keys: f.keys, Log: quiet(), ClockSeqAfter: now.Add(10 * time.Minute)}
	}

	// The update's rollback: the old count goes on, one by one.
	f.st.SetSetting(ctx, "sub_seq", []byte(backup))
	if got := seq(started(), now); strconv.FormatUint(got-1, 10) != backup {
		t.Fatalf("after a rollback: seq %d, the stored count was %s", got, backup)
	}
	// The restore.
	f.st.SetSetting(ctx, "sub_seq", []byte(backup))
	if err := sub.SeqToClock(ctx, f.st, now); err != nil {
		t.Fatal(err)
	}
	if got := seq(started(), now.Add(time.Second)); got <= seen {
		t.Fatalf("after a restore: seq %d in rayd's first minutes, a client has seen %d and drops the answer", got, seen)
	}
	// Never down: a count ahead of the clock stays.
	ahead := strconv.FormatInt(now.Add(time.Hour).UnixMilli(), 10)
	f.st.SetSetting(ctx, "sub_seq", []byte(ahead))
	if err := sub.SeqToClock(ctx, f.st, now); err != nil {
		t.Fatal(err)
	}
	if b, _ := f.st.GetSetting(ctx, "sub_seq"); string(b) != ahead {
		t.Fatalf("SeqToClock moved the count down: %s, was %s", b, ahead)
	}
}
