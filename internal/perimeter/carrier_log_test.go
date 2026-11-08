package perimeter

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"testing"
)

// logged keeps what a logger says, at every level.
type logged struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (l *logged) Enabled(context.Context, slog.Level) bool { return true }
func (l *logged) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recs = append(l.recs, r)
	return nil
}
func (l *logged) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *logged) WithGroup(string) slog.Handler      { return l }

// levels are the levels of what was said with msg since the last call.
func (l *logged) levels(msg string) []slog.Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []slog.Level
	for _, r := range l.recs {
		if r.Message == msg {
			out = append(out, r.Level)
		}
	}
	l.recs = nil
	return out
}

// A slot port another socket holds (an outgoing connection, where it is
// not reserved): rayspa says so once a streak, at warning, then at debug
// each second it tries again, and when it listens at last; a new streak
// is said again.
func TestTCPCarrierListenFails(t *testing.T) {
	log := &logged{}
	c := &TCPCarrier{Handler: func(netip.Addr, []byte) {}, LenMax: func() int { return 160 }, Log: slog.New(log)}
	defer c.Close()
	hold, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(hold.Addr().(*net.TCPAddr).Port)
	for range 3 {
		c.Reconcile([]uint16{port})
	}
	if got := log.levels("spa tcp listen"); !slices.Equal(got, []slog.Level{slog.LevelWarn, slog.LevelDebug, slog.LevelDebug}) {
		t.Errorf("held: %v", got)
	}
	hold.Close()
	c.Reconcile([]uint16{port})
	if got := log.levels("spa tcp listen"); !slices.Equal(got, []slog.Level{slog.LevelInfo}) {
		t.Errorf("free again: %v", got)
	}
	c.Reconcile([]uint16{port})
	if got := log.levels("spa tcp listen"); len(got) != 0 {
		t.Errorf("listening: %v", got)
	}
	// The slot moves on and comes back held: a new streak.
	c.Reconcile(nil)
	hold, err = net.Listen("tcp", ":"+strconv.Itoa(int(port)))
	if err != nil {
		t.Skip(err)
	}
	defer hold.Close()
	c.Reconcile([]uint16{port})
	c.Reconcile([]uint16{port})
	if got := log.levels("spa tcp listen"); !slices.Equal(got, []slog.Level{slog.LevelWarn, slog.LevelDebug}) {
		t.Errorf("held again: %v", got)
	}
	// A streak the slot's moving on ended is not one any more.
	c.Reconcile(nil)
	c.Reconcile([]uint16{port})
	if got := log.levels("spa tcp listen"); !slices.Equal(got, []slog.Level{slog.LevelWarn}) {
		t.Errorf("held, the slot back: %v", got)
	}
}
