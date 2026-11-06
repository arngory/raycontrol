package dnsstats

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte(`{"started":1700000000,"queries":5,"sessions":2,"auth_refused":3,"seal_unsealed":4,"new_field":1}` + "\n"))
			c.Close()
		}
	}()
	s, err := Read(context.Background(), path)
	if err != nil || s.Started != 1700000000 || s.Queries != 5 || s.Sessions != 2 || s.AuthRefused != 3 || s.SealUnsealed != 4 {
		t.Fatalf("%+v %v", s, err)
	}
	if _, err := Read(context.Background(), filepath.Join(t.TempDir(), "none.sock")); err == nil {
		t.Fatal("no error without a socket")
	}
}

// A backend that takes the connection and says nothing holds its reader
// only until the deadline.
func TestReadSilent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	held := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			held <- c
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := Read(ctx, path); err == nil {
		t.Fatal("no error from a silent socket")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("held %v", d)
	}
	select {
	case c := <-held:
		c.Close()
	default:
	}
}

func TestWindow(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	started := t0.Add(-10 * time.Minute).Unix()
	w := &Window[Snapshot]{}
	if _, _, ok := w.Delta(); ok {
		t.Fatal("delta of an empty window")
	}
	// One snapshot of a backend started 10 minutes ago: since its start.
	w.Add(t0, Snapshot{Started: started, Queries: 100, SessionsAdmitted: 2, Sessions: 2})
	d, span, ok := w.Delta()
	if !ok || span != 10*time.Minute || d.Queries != 100 || d.SessionsAdmitted != 2 {
		t.Fatalf("since start: %+v %v %v", d, span, ok)
	}
	// A minute a snapshot for 90 minutes: the window keeps an hour.
	for i := 1; i <= 90; i++ {
		w.Add(t0.Add(time.Duration(i)*time.Minute), Snapshot{Started: started, Queries: 100 + uint64(i)*10, RefusedFull: uint64(i / 30), Sessions: 3})
	}
	d, span, ok = w.Delta()
	if !ok || span != time.Hour || d.Queries != 600 || d.RefusedFull != 2 || d.Sessions != 3 || len(w.points) != 61 {
		t.Fatalf("an hour: %+v %v %v (%d points)", d, span, ok, len(w.points))
	}
	// A restart starts again: since the new start.
	t1 := t0.Add(91 * time.Minute)
	w.Add(t1, Snapshot{Started: t1.Add(-time.Minute).Unix(), Queries: 7})
	d, span, ok = w.Delta()
	if !ok || span != time.Minute || d.Queries != 7 || len(w.points) != 1 {
		t.Fatalf("after a restart: %+v %v %v", d, span, ok)
	}
	// A backend long up when rayd starts: nothing until the next snapshot.
	w = &Window[Snapshot]{}
	w.Add(t0, Snapshot{Started: t0.Add(-48 * time.Hour).Unix(), Queries: 1 << 20})
	if _, _, ok := w.Delta(); ok {
		t.Fatal("delta of a long run from one snapshot")
	}
	// Without its start, a counter that went down tells a restart.
	w = &Window[Snapshot]{}
	w.Add(t0, Snapshot{Queries: 50})
	w.Add(t0.Add(time.Minute), Snapshot{Queries: 80})
	if d, _, _ := w.Delta(); d.Queries != 30 {
		t.Fatalf("delta %+v", d)
	}
	w.Add(t0.Add(2*time.Minute), Snapshot{Queries: 3})
	if _, _, ok := w.Delta(); ok || len(w.points) != 1 {
		t.Fatalf("restart without a start time: %d points", len(w.points))
	}
}

func TestSummary(t *testing.T) {
	now := Snapshot{Sessions: 3, Handshakes: 1}
	if got := Summary(now, Snapshot{}, 0, false); got != "3 sessions (1 in handshake)" {
		t.Errorf("%q", got)
	}
	d := Snapshot{Queries: 4120, SessionsAdmitted: 1, RefusedFull: 2, AuthRefused: 140, SealRefused: 1}
	want := "1 session; last 1h: 4120 queries, 1 new session, 2 session starts refused (node full), 140 refused by dnsauth, 1 refused by the seal"
	if got := Summary(Snapshot{Sessions: 1}, d, time.Hour+20*time.Second, true); got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	for d, want := range map[time.Duration]string{40 * time.Second: "40s", 12 * time.Minute: "12m", time.Hour: "1h", 65 * time.Minute: "1h5m", 25 * time.Hour: "25h"} {
		if got := short(d); got != want {
			t.Errorf("short(%v) = %q, want %q", d, got, want)
		}
	}
}

// The front's window: a zone's queries over the hour, and its summary.
func TestFrontWindow(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	started := t0.Add(-2 * time.Hour).Unix()
	w := &Window[Front]{}
	w.Add(t0, Front{Started: started, Queries: map[string]uint64{"t.example.com": 1000}, Refused: 5})
	if _, _, ok := w.Delta(); ok {
		t.Fatal("a delta from one snapshot of a front up for two hours")
	}
	if got := FrontSummary(Front{}, 0, false); got != "counting" {
		t.Errorf("%q", got)
	}
	// Clients move to the spare zone: its queries appear and grow.
	w.Add(t0.Add(30*time.Minute), Front{Started: started, Queries: map[string]uint64{"t.example.com": 1100, "s.example.net": 40},
		Refused: 7, Probes: 3, BackendAway: 1})
	d, span, ok := w.Delta()
	if !ok || span != 30*time.Minute || d.Queries["t.example.com"] != 100 || d.Queries["s.example.net"] != 40 || d.Refused != 2 || d.Probes != 3 {
		t.Fatalf("delta %+v %v %v", d, span, ok)
	}
	want := "last 30m: 140 queries (s.example.net 40, t.example.com 100), 2 refused outside the zones, 3 probes answered, 1 not passed on (backend away or busy)"
	if got := FrontSummary(d, span, ok); got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	// A zone gone from the front, or a count that went down: a restart.
	w.Add(t0.Add(31*time.Minute), Front{Started: started, Queries: map[string]uint64{"s.example.net": 41}})
	if _, _, ok := w.Delta(); ok || len(w.points) != 1 {
		t.Fatalf("a zone's count went down: %d points", len(w.points))
	}
	// One zone: no list.
	if got := FrontSummary(Front{Queries: map[string]uint64{"t.example.com": 1}}, time.Hour, true); got != "last 1h: 1 query" {
		t.Errorf("%q", got)
	}
}
