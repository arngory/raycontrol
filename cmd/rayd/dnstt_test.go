package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/dnsstats"
	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// rayctl status says, for each dnstt service, its sessions and what the
// last hour brought; a backend without counters fails its loop, a deleted
// service is forgotten.
func TestRoundDNSTT(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"dns", "dns2"} {
		if _, err := provision.CreateService(ctx, st, store.Service{Kind: "dnstt", Name: name, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	paths := render.Paths{Run: t.TempDir()}
	line := make(chan string, 1)
	sock := paths.StatsSocket("dns")
	if err := os.MkdirAll(filepath.Dir(sock), 0o750); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", sock)
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
			_, _ = c.Write([]byte(<-line + "\n"))
			c.Close()
		}
	}()
	t0 := time.Unix(1700000000, 0)
	started := t0.Add(-2 * time.Hour).Unix() // up before the window: nothing to tell from one snapshot
	hb := &health.Board{}
	windows := map[string]*dnsstats.Window[dnsstats.Snapshot]{}
	loop := func(name string) health.Loop {
		for _, l := range hb.Loops() {
			if l.Name == name {
				return l
			}
		}
		t.Fatalf("no loop %s in %+v", name, hb.Loops())
		return health.Loop{}
	}
	line <- `{"started":` + strconv.FormatInt(started, 10) + `,"queries":1000,"sessions":2,"starts_refused_full":4}`
	roundDNSTT(ctx, st, paths, windows, t0, hb)
	if l := loop("dnstt dns"); l.Failing() || l.Detail != "2 sessions" {
		t.Fatalf("first round %+v", l)
	}
	if l := loop("dnstt dns2"); !l.Failing() || !strings.Contains(l.Err, "the backend gives no counters") {
		t.Fatalf("no socket %+v", l)
	}
	line <- `{"started":` + strconv.FormatInt(started, 10) + `,"queries":1300,"sessions":3,"starts_refused_full":6,"auth_refused":9}`
	roundDNSTT(ctx, st, paths, windows, t0.Add(time.Minute), hb)
	want := "3 sessions; last 1m: 300 queries, 0 new sessions, 2 session starts refused (node full), 9 refused by dnsauth"
	if l := loop("dnstt dns"); l.Failing() || l.Detail != want {
		t.Fatalf("second round %q", l.Detail)
	}
	// dns2 deleted: its loop and window go.
	if err := st.DeleteService(ctx, "dns2"); err != nil {
		t.Fatal(err)
	}
	line <- `{"started":` + strconv.FormatInt(started, 10) + `,"queries":1300,"sessions":3}`
	roundDNSTT(ctx, st, paths, windows, t0.Add(2*time.Minute), hb)
	for _, l := range hb.Loops() {
		if l.Name == "dnstt dns2" {
			t.Fatalf("deleted service still in status: %+v", l)
		}
	}
	if _, ok := windows["dns2"]; ok || len(windows) != 1 {
		t.Fatalf("windows %v", windows)
	}
}

// The front's loop: its hour's queries by zone; failing without counters;
// gone without a DNS tunnel.
func TestRoundFront(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	paths := render.Paths{Run: t.TempDir()}
	hb := &health.Board{}
	w := &dnsstats.Window[dnsstats.Front]{}
	t0 := time.Unix(1700000000, 0)
	// No DNS tunnel: no loop.
	roundFront(ctx, st, paths, w, t0, hb)
	if len(hb.Loops()) != 0 {
		t.Fatalf("loops without a tunnel %+v", hb.Loops())
	}
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true, Settings: `{"zone":"t.example.com"}`}); err != nil {
		t.Fatal(err)
	}
	roundFront(ctx, st, paths, w, t0, hb)
	if l := hb.Loops(); len(l) != 1 || l[0].Name != "dns-front" || !l[0].Failing() || !strings.Contains(l[0].Err, "the front gives no counters") {
		t.Fatalf("no socket %+v", l)
	}
	sock := paths.FrontStats()
	if err := os.MkdirAll(filepath.Dir(sock), 0o750); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	line := make(chan string, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte(<-line + "\n"))
			c.Close()
		}
	}()
	started := strconv.FormatInt(t0.Add(-2*time.Hour).Unix(), 10)
	line <- `{"started":` + started + `,"queries":{"t.example.com":100}}`
	roundFront(ctx, st, paths, w, t0, hb)
	if l := hb.Loops()[0]; l.Failing() || l.Detail != "counting" {
		t.Fatalf("first round %+v", l)
	}
	line <- `{"started":` + started + `,"queries":{"t.example.com":150,"s.example.net":5},"probes":2}`
	roundFront(ctx, st, paths, w, t0.Add(10*time.Minute), hb)
	if l := hb.Loops()[0]; l.Failing() || l.Detail != "last 10m: 55 queries (s.example.net 5, t.example.com 50), 2 probes answered" {
		t.Fatalf("second round %q", l.Detail)
	}
	// The tunnel gone: the loop too.
	if err := st.DeleteService(ctx, "dns"); err != nil {
		t.Fatal(err)
	}
	roundFront(ctx, st, paths, w, t0.Add(11*time.Minute), hb)
	if len(hb.Loops()) != 0 {
		t.Fatalf("loops after the tunnel went %+v", hb.Loops())
	}
}
