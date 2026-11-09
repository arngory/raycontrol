package traffic

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/store"
)

// atOnce answers each connection to a unix socket with answer as soon as
// it is accepted, without reading a line, and closes: niko-server
// v0.15.0's Yggdrasil stats socket. The line the reader sends may then
// reset the connection, before or after the answer is read.
func atOnce(t *testing.T, answer string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stats.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte(answer))
			c.Close()
		}
	}()
	return path
}

// The traffic line of a Yggdrasil backend (lan-v1 §4.4): the answer of
// niko-server v0.16.0 is a reading as Hysteria2's; v0.15.0's counters, or
// nothing, are no counters; anything else is an error.
func TestReadYggdrasil(t *testing.T) {
	ctx := context.Background()
	v16 := serve(t, func(c net.Conn, line string) {
		if line == "traffic\n" {
			_, _ = c.Write([]byte(`{"v":1,"boot":"0123456789abcdef","users":{"u5":{"up":7000,"down":0}}}` + "\n"))
		} else {
			_, _ = c.Write([]byte(`{"started":1794195136,"dropped_frames":3}` + "\n"))
		}
	})
	r, err := ReadYggdrasil(ctx, v16)
	if err != nil || r.Boot != "0123456789abcdef" || r.Users["u5"] != (store.TrafficCounter{Up: 7000}) {
		t.Fatalf("v0.16.0: %+v %v", r, err)
	}
	// v0.15.0, many times: the reset falls before or after the answer.
	v15 := atOnce(t, `{"started":1794195136,"dropped_frames":0}`+"\n")
	for range 50 {
		if _, err := ReadYggdrasil(ctx, v15); !errors.Is(err, ErrNoCounters) || notRunning(err) {
			t.Fatalf("v0.15.0: %v", err)
		}
	}
	if _, err := ReadYggdrasil(ctx, atOnce(t, "")); !errors.Is(err, ErrNoCounters) {
		t.Fatalf("nothing: %v", err)
	}
	for name, answer := range map[string]string{
		"not JSON":              "rtt 12\n",
		"a version 2":           `{"v":2,"boot":"b","users":{}}`,
		"a traffic answer bad":  `{"v":1,"started":1,"users":{}}`,
		"neither":               `{"dropped_frames":0}`,
		"a JSON array":          `[{"started":1}]`,
		"started, as a version": `{"v":null,"started":1}`,
	} {
		if _, err := ReadYggdrasil(ctx, atOnce(t, answer)); err == nil || errors.Is(err, ErrNoCounters) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// No socket: not running, as the others.
	if _, err := ReadYggdrasil(ctx, filepath.Join(t.TempDir(), "none.sock")); !notRunning(err) {
		t.Fatalf("no socket: %v", err)
	}
	// Hysteria2's reading takes an answer that came before a reset too.
	if r, err := ReadLine(ctx, atOnce(t, `{"v":1,"boot":"b","users":{"u1":{"up":1,"down":2}}}`)); err != nil || r.Users["u1"].Down != 2 {
		t.Fatalf("an answer before the line: %+v %v", r, err)
	}
	// One that never answers holds the poll 2 s at most.
	stuck := serve(t, func(net.Conn, string) { time.Sleep(10 * time.Second) })
	start := time.Now()
	if _, err := ReadYggdrasil(ctx, stuck); err == nil || time.Since(start) > readWait+time.Second {
		t.Fatalf("stuck: %v after %v", err, time.Since(start))
	}
}

// The Yggdrasil backend counts its users' LAN traffic through the node, by
// group u<id> (lan-v1 §4.4), for the users who have the service. One from
// before niko-server v0.16.0 gives no counters: it relays no LAN, so that
// is no failure of the count, unlike a Hysteria2 without them, and it is
// told apart from a process that does not run.
func TestYggdrasilSource(t *testing.T) {
	n := newNode(t)
	if _, err := n.st.CreateService(n.ctx, store.Service{Kind: "yggdrasil", Name: "ygg", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	n.user("alice", 1<<30, "ygg", "hy")
	n.user("bob", 1<<30, "hy")
	var src *Source
	services, _ := n.st.ListServices(n.ctx)
	for _, s := range Processes(testPaths)(services) {
		if s.Service == "ygg" {
			src = &s
		}
	}
	if src == nil || src.Key != "ygg:ygg" || src.NoCounters == "" {
		t.Fatalf("no Yggdrasil source: %+v", src)
	}
	if u, _ := n.st.UserByName(n.ctx, "bob"); src.Counts(u) {
		t.Fatal("bob's bytes count at Yggdrasil")
	}
	loop := func(name string) health.Loop {
		t.Helper()
		for _, l := range n.hb.Loops() {
			if l.Name == "traffic "+name {
				return l
			}
		}
		t.Fatalf("no loop %s: %+v", name, n.hb.Loops())
		return health.Loop{}
	}
	a := n.accountant()
	n.mu.Lock()
	n.fails = map[string]error{"ygg:ygg": ErrNoCounters, "hy2:hy": ErrNoCounters}
	n.mu.Unlock()
	n.set("naive:nv", "n1")
	a.Round(n.ctx, "", true)
	if l := loop("ygg"); l.Failing() || l.Detail != yggNoCounters {
		t.Fatalf("an old Yggdrasil: %+v", l)
	}
	if l := loop("hy"); !l.Failing() {
		t.Fatalf("an old Hysteria2: %+v", l)
	}
	n.mu.Lock()
	n.gone, n.fails = "ygg:ygg", nil
	n.mu.Unlock()
	n.tick(Every)
	a.Round(n.ctx, "", true)
	if l := loop("ygg"); l.Failing() || l.Detail != "not running" {
		t.Fatalf("not running: %+v", l)
	}

	// niko-server v0.16.0: bytes by group, counted for the users of the
	// service (bob's group carries none of his: he has no Yggdrasil).
	n.mu.Lock()
	n.gone = ""
	n.mu.Unlock()
	n.set("ygg:ygg", "y1", "u1", 0, 0, "u2", 0, 0)
	n.set("hy2:hy", "h1", "u1", 0, 0)
	n.tick(Every)
	a.Round(n.ctx, "", true)
	n.set("ygg:ygg", "y1", "u1", 7000, 0, "u2", 9000, 0)
	n.tick(Every)
	a.Round(n.ctx, "", true)
	n.wantUsed("alice", 7000, 0)
	n.wantUsed("bob", 0, 0)
	if l := loop("ygg"); l.Failing() || l.Detail != "" {
		t.Fatalf("counting: %+v", l)
	}
}
