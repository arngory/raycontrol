package connlimit

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/traffic"
)

// fakeStats answers the traffic line on a unix socket as a Hysteria2
// backend of niko-server v0.17.0 does, with what answer gives at the time;
// "" closes without an answer (niko-server before v0.15.0).
func fakeStats(t *testing.T, answer func() string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "stats.sock")
	ln, err := net.Listen("unix", sock)
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
			line, _ := bufio.NewReader(c).ReadString('\n')
			if line == "traffic\n" {
				if a := answer(); a != "" {
					fmt.Fprintln(c, a)
				}
			}
			c.Close()
		}
	}()
	return sock
}

// xrayBoot is an Xray's run as traffic.ReadXray names it: its start by the
// wall clock, the kernel's boot and its start on the monotonic clock.
func xrayBoot(wall, mono int64) string {
	return fmt.Sprintf("xray:%d:0b2c5f2e-9d3a-4f7e-8c61-3a5d2b7e9f10:%d", wall, mono)
}

// Hysteria2 (niko-server v0.17.0: "limit" and "uptime" in its traffic
// answer) and Xray (the fork's user>>>u5>>>limit>>>KIND, its uptime) as
// sources of the monitor, as rayd gives them (cmd/rayd connLimitSources):
// the first reading of a process that has run long is a baseline, one that
// has just started counts whole; within a run only what grew counts, and
// an Xray's run is told by its start, which two readings may give a second
// apart; a source that fails to read keeps its mark; an older niko-server
// without the fields counts nothing.
func TestMonitorHysteriaXray(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	proc := t.TempDir()
	fakeProc(t, proc, 1000, 65536)
	var mu sync.Mutex
	hyAnswer := `{"v":1,"boot":"h1","users":{"u5-0123456789abcdef":{"up":1,"down":2}},"limit":{"u5":{"tcp":100}},"uptime":10800}`
	hySock := fakeStats(t, func() string { mu.Lock(); defer mu.Unlock(); return hyAnswer })
	setHy := func(a string) { mu.Lock(); hyAnswer = a; mu.Unlock() }
	xr := traffic.Reading{Boot: xrayBoot(1_699_992_800, 50_000), Age: 2 * time.Hour, AgeKnown: true,
		Limits: map[string]map[string]int64{"u5": {"tcp": 50}}}
	var xrErr error
	sources := func(context.Context) ([]Source, error) {
		of := func(r traffic.Reading, err error) (Reading, error) {
			return Reading{Boot: r.Boot, Age: r.Age, AgeKnown: r.AgeKnown, Limits: r.Limits}, err
		}
		return []Source{
			{Service: "hy", Read: func(ctx context.Context) (Reading, error) { return of(traffic.ReadLine(ctx, hySock)) }},
			{Service: "r", SameRun: traffic.SameBoot, Read: func(context.Context) (Reading, error) { return of(xr, xrErr) }},
		}, nil
	}
	hb := &health.Board{Now: func() time.Time { return now }}
	m := &Monitor{Sources: sources, Health: hb, Proc: proc, Now: func() time.Time { return now }}
	ctx := context.Background()
	refused := func(svc, kind string) uint64 { return m.Snapshot().Refused[[2]string{svc, kind}] }

	// Both have run for hours: their counters are from before rayd.
	m.Round(ctx)
	if s := m.Snapshot(); len(s.Users) != 0 || len(s.Refused) != 0 || !slices.Equal(s.Services, []string{"hy", "r"}) {
		t.Fatalf("first reading: %+v", s)
	}
	// What grew counts. Xray's start reads a second later: the same run.
	setHy(`{"v":1,"boot":"h1","users":{},"limit":{"u5":{"tcp":103},"u5-0123456789abcdef":{"tcp":7}},"uptime":10815}`)
	xr.Boot, xr.Age = xrayBoot(1_699_992_801, 50_001), xr.Age+Every
	xr.Limits = map[string]map[string]int64{"u5": {"tcp": 52}, "u9": {"dest": 4}}
	now = now.Add(Every)
	m.Round(ctx)
	if refused("hy", "tcp") != 3 || refused("r", "tcp") != 2 || refused("r", "dest") != 4 {
		t.Fatalf("deltas: %+v", m.Snapshot().Refused)
	}
	var line string
	for _, l := range hb.Loops() {
		if l.Name == "conn-limit" {
			line = l.Detail
		}
	}
	if line != "at a limit in 15 min: u5 (hy: 3), u5 (r: 2), u9 (r: 4)" {
		t.Fatalf("status line %q", line)
	}
	// Xray fails to read (restarting): its mark stays; Hysteria2 goes on.
	xrErr = errors.New("connection refused")
	setHy(`{"v":1,"boot":"h1","users":{},"limit":{"u5":{"tcp":104}},"uptime":10830}`)
	now = now.Add(Every)
	m.Round(ctx)
	if refused("hy", "tcp") != 4 || refused("r", "tcp") != 2 {
		t.Fatalf("a failed read: %+v", m.Snapshot().Refused)
	}
	// Xray restarted (the switch, an apply): a new run counts whole.
	xrErr = nil
	xr = traffic.Reading{Boot: xrayBoot(1_700_000_040, 57_240), Age: 5 * time.Second, AgeKnown: true,
		Limits: map[string]map[string]int64{"u5": {"udp": 1}}}
	now = now.Add(Every)
	m.Round(ctx)
	if refused("r", "udp") != 1 || refused("r", "tcp") != 2 {
		t.Fatalf("a new Xray run: %+v", m.Snapshot().Refused)
	}
	// The backend updated back to a niko-server without limits (no
	// "limit", no "uptime"): a new boot, nothing to count, no error.
	setHy(`{"v":1,"boot":"h2","users":{}}`)
	now = now.Add(Every)
	m.Round(ctx)
	if refused("hy", "tcp") != 4 {
		t.Fatalf("an older niko-server: %+v", m.Snapshot().Refused)
	}
	// One before v0.15.0 closes without an answer: a failed read.
	setHy("")
	now = now.Add(Every)
	m.Round(ctx)
	if s := m.Snapshot(); refused("hy", "tcp") != 4 || !slices.Equal(s.Services, []string{"hy", "r"}) {
		t.Fatalf("no answer: %+v", s)
	}

	// A rayd started anew beside processes that started since its last
	// round could have read them (uptime under 20 s): their refusals count.
	setHy(`{"v":1,"boot":"h3","users":{},"limit":{"u7":{"rate":6}},"uptime":12}`)
	xr = traffic.Reading{Boot: xrayBoot(1_700_000_100, 57_300), Age: 9 * time.Second, AgeKnown: true,
		Limits: map[string]map[string]int64{"u7": {"failed": 2}}}
	m2 := &Monitor{Sources: sources, Proc: proc, Now: func() time.Time { return now }}
	m2.Round(ctx)
	if s := m2.Snapshot(); s.Refused[[2]string{"hy", "rate"}] != 6 || s.Refused[[2]string{"r", "failed"}] != 2 ||
		len(s.Users) != 2 || s.Users[0].ID != 7 {
		t.Fatalf("fresh processes: %+v", s)
	}
}
