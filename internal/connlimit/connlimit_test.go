package connlimit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/health"
)

// fakeProc writes a /proc with the table's numbers.
func fakeProc(t *testing.T, dir string, count, max int, drops ...string) {
	t.Helper()
	nf := filepath.Join(dir, "sys/net/netfilter")
	if err := os.MkdirAll(nf, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]int{"nf_conntrack_count": count, "nf_conntrack_max": max} {
		if err := os.WriteFile(filepath.Join(nf, name), []byte(strconv.Itoa(v)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if len(drops) > 0 {
		st := filepath.Join(dir, "net/stat")
		if err := os.MkdirAll(st, 0o755); err != nil {
			t.Fatal(err)
		}
		body := "entries  clashres found new invalid ignore delete chainlength insert insert_failed drop early_drop icmp_error expect_new expect_create expect_delete search_restart\n" +
			strings.Join(drops, "\n") + "\n"
		if err := os.WriteFile(filepath.Join(st, "nf_conntrack"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// cpu is one line of net/stat/nf_conntrack with drop and early_drop.
func cpu(drop, early int) string {
	f := []string{"00000010", "0", "0", "0", "0", "0", "0", "0", "0", "0", fmt.Sprintf("%08x", drop), fmt.Sprintf("%08x", early), "0", "0", "0", "0", "0"}
	return strings.Join(f, " ")
}

// The refusals by user and service: deltas within a run, whole for a new
// run; at a limit for 15 minutes; logged once per user after an hour
// without, at the end of the quarter hour; the metrics' totals; the status lines; nothing but u<id>.
func TestMonitor(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	proc := t.TempDir()
	fakeProc(t, proc, 1000, 65536, cpu(0, 0), cpu(0, 0))
	var logs bytes.Buffer
	boot := "b1"
	limits := map[string]map[string]int64{"u5": {"tcp": 3}, "u7": {"lookup": 0}, "u7-ab12": {"tcp": 9}, "#0011": {"tcp": 9}}
	off := false
	hb := &health.Board{Now: func() time.Time { return now }}
	m := &Monitor{
		Sources: func(context.Context) ([]Source, error) {
			return []Source{
				// Started with rayd: its refusals are new.
				{Service: "nv", Read: func(context.Context) (Reading, error) {
					return Reading{Boot: boot, Age: 5 * time.Second, AgeKnown: true, Limits: limits}, nil
				}},
				{Service: "down", Read: func(context.Context) (Reading, error) { return Reading{}, errors.New("not running") }},
			}, nil
		},
		Off:    func(context.Context) (bool, error) { return off, nil },
		Health: hb, Log: slog.New(slog.NewTextHandler(&logs, nil)), Proc: proc, Now: func() time.Time { return now },
	}
	m.Round(context.Background())
	s := m.Snapshot()
	if len(s.Users) != 1 || s.Users[0].ID != 5 || s.Users[0].Service != "nv" || s.Users[0].Refused != 3 {
		t.Fatalf("users %+v", s.Users)
	}
	if s.Refused[[2]string{"nv", "tcp"}] != 3 || s.Conntrack == nil || s.Conntrack.Count != 1000 {
		t.Fatalf("snapshot %+v", s)
	}
	// The log names users at a quarter hour's end only (1_700_000_000 is
	// 800 s into one): not yet.
	lines := func() int { return strings.Count(logs.String(), "conn-limit: at a limit in the last 15 min") }
	if lines() != 0 {
		t.Fatalf("logged within the quarter hour:\n%s", logs.String())
	}
	// The same run: only what grew.
	limits = map[string]map[string]int64{"u5": {"tcp": 5, "rate": 1}}
	now = now.Add(Every)
	m.Round(context.Background())
	if s := m.Snapshot(); s.Refused[[2]string{"nv", "tcp"}] != 5 || s.Refused[[2]string{"nv", "rate"}] != 1 || s.Users[0].Refused != 6 {
		t.Fatalf("deltas: %+v", s)
	}
	if lines() != 0 {
		t.Fatalf("logged within the quarter hour:\n%s", logs.String())
	}
	// A new run of the process: whole.
	boot, limits = "b2", map[string]map[string]int64{"u5": {"tcp": 2}}
	now = now.Add(Every)
	m.Round(context.Background())
	if s := m.Snapshot(); s.Refused[[2]string{"nv", "tcp"}] != 7 {
		t.Fatalf("a new run: %+v", s.Refused)
	}
	var line string
	for _, l := range hb.Loops() {
		if l.Name == "conn-limit" {
			line = l.Detail
		}
	}
	if line != "at a limit in 15 min: u5 (nv: 8)" {
		t.Fatalf("status line %q", line)
	}
	// 15 minutes on: nobody at a limit; the quarter hour's line, once.
	now = now.Add(Window)
	m.Round(context.Background())
	if s := m.Snapshot(); len(s.Users) != 0 {
		t.Fatalf("still at a limit: %+v", s.Users)
	}
	if lines() != 1 || !strings.Contains(logs.String(), "conn-limit: at a limit in the last 15 min: u5 (nv)") {
		t.Fatalf("the quarter hour's line:\n%s", logs.String())
	}
	// After an hour without: in the next quarter hour's line.
	now = now.Add(time.Hour)
	limits = map[string]map[string]int64{"u5": {"tcp": 3}}
	m.Round(context.Background())
	now = now.Add(Window)
	m.Round(context.Background())
	if lines() != 2 {
		t.Fatalf("not logged after an hour:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "#0011") || strings.Contains(logs.String(), "u7-ab12") {
		t.Fatalf("a name that is no user's number in the log:\n%s", logs.String())
	}
	off = true
	m.Round(context.Background())
	for _, l := range hb.Loops() {
		if l.Name == "conn-limit" && !strings.HasPrefix(l.Detail, "off") {
			t.Fatalf("off: %q", l.Detail)
		}
	}
}

// The users newly at a limit go to the log in one line when a quarter hour
// of the wall clock ends (the first round after it), never in the round of
// their refusal: the log tells no time finer than 15 minutes. A user is
// named once an hour at most, with every service of its quarter hour.
func TestMonitorLogQuarter(t *testing.T) {
	q := time.Unix(1_700_000_100, 0) // a quarter hour's start (1_700_000_100 = 1_888_889 * 900)
	if !q.Truncate(Window).Equal(q) {
		t.Fatal("not a quarter hour")
	}
	now := q.Add(2 * time.Minute)
	proc := t.TempDir()
	fakeProc(t, proc, 1000, 65536)
	var logs bytes.Buffer
	counts := map[string]map[string]map[string]int64{"nv": {}, "nv2": {}}
	read := func(svc string) func(context.Context) (Reading, error) {
		return func(context.Context) (Reading, error) {
			// A new answer each time, as a socket's.
			limits := map[string]map[string]int64{}
			for name, kinds := range counts[svc] {
				limits[name] = maps.Clone(kinds)
			}
			return Reading{Boot: "b", Age: time.Second, AgeKnown: true, Limits: limits}, nil
		}
	}
	m := &Monitor{Sources: func(context.Context) ([]Source, error) {
		return []Source{{Service: "nv", Read: read("nv")}, {Service: "nv2", Read: read("nv2")}}, nil
	}, Log: slog.New(slog.NewTextHandler(&logs, nil)), Proc: proc, Now: func() time.Time { return now }}
	round := func(at time.Duration) {
		now = q.Add(at)
		m.Round(context.Background())
	}
	round(2 * time.Minute)
	counts["nv"]["u9"] = map[string]int64{"tcp": 1}
	counts["nv"]["u5"] = map[string]int64{"rate": 2}
	round(3 * time.Minute)
	counts["nv2"]["u5"] = map[string]int64{"udp": 1}
	round(14*time.Minute + 45*time.Second)
	if logs.Len() != 0 {
		t.Fatalf("logged within the quarter hour:\n%s", logs.String())
	}
	// The next quarter hour's first round: one line; u7's refusal in this
	// very round waits for the next one.
	counts["nv"]["u7"] = map[string]int64{"tcp": 1}
	round(15*time.Minute + 10*time.Second)
	want := "conn-limit: at a limit in the last 15 min: u5 (nv, nv2), u9 (nv)"
	if strings.Count(logs.String(), "conn-limit:") != 1 || !strings.Contains(logs.String(), want) {
		t.Fatalf("want %q:\n%s", want, logs.String())
	}
	logs.Reset()
	counts["nv"]["u5"] = map[string]int64{"rate": 9} // still at it: not again within the hour
	round(20 * time.Minute)
	round(30*time.Minute + 5*time.Second)
	if got := logs.String(); !strings.Contains(got, "conn-limit: at a limit in the last 15 min: u7 (nv)\"") || strings.Contains(got, "u5") {
		t.Fatalf("the second quarter hour:\n%s", got)
	}
	logs.Reset()
	round(45*time.Minute + 5*time.Second)
	if logs.Len() != 0 {
		t.Fatalf("a quarter hour with no one new:\n%s", logs.String())
	}
}

// A rayd started anew, or one round whose services could not be listed,
// does not count a process's old refusals again: the first reading of a
// service is a baseline (unless the process itself is new), and a failed
// listing keeps the marks and the metrics' services.
func TestMonitorBaseline(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	proc := t.TempDir()
	fakeProc(t, proc, 1000, 65536)
	var logs bytes.Buffer
	age := 3 * time.Hour
	limits := map[string]map[string]int64{"u5": {"tcp": 1340}}
	var listErr error
	hb := &health.Board{Now: func() time.Time { return now }}
	m := &Monitor{
		Sources: func(context.Context) ([]Source, error) {
			if listErr != nil {
				return nil, listErr
			}
			return []Source{{Service: "nv", Read: func(context.Context) (Reading, error) {
				return Reading{Boot: "b1", Age: age, AgeKnown: true, Limits: limits}, nil
			}}}, nil
		},
		Health: hb, Log: slog.New(slog.NewTextHandler(&logs, nil)), Proc: proc, Now: func() time.Time { return now },
	}
	m.Round(context.Background())
	if s := m.Snapshot(); len(s.Users) != 0 || s.Refused[[2]string{"nv", "tcp"}] != 0 || len(s.Services) != 1 {
		t.Fatalf("a process of 3 h read first: %+v", s)
	}
	limits = map[string]map[string]int64{"u5": {"tcp": 1341}}
	now, age = now.Add(Every), age+Every
	m.Round(context.Background())
	if s := m.Snapshot(); s.Refused[[2]string{"nv", "tcp"}] != 1 || len(s.Users) != 1 || s.Users[0].Refused != 1 {
		t.Fatalf("after the baseline: %+v", s)
	}
	// The services cannot be listed: health hears, nothing else moves.
	listErr = errors.New("database is locked")
	now = now.Add(Every)
	m.Round(context.Background())
	s := m.Snapshot()
	if len(s.Services) != 1 || s.Refused[[2]string{"nv", "tcp"}] != 1 {
		t.Fatalf("a failed listing: %+v", s)
	}
	failed := false
	for _, l := range hb.Loops() {
		failed = failed || l.Name == "conn-limit" && l.Err != ""
	}
	if !failed {
		t.Fatalf("health not told: %+v", hb.Loops())
	}
	listErr = nil
	limits = map[string]map[string]int64{"u5": {"tcp": 1342}}
	now = now.Add(Every)
	m.Round(context.Background())
	if s := m.Snapshot(); s.Refused[[2]string{"nv", "tcp"}] != 2 {
		t.Fatalf("after a failed listing, counted again whole: %+v", s.Refused)
	}
	// A process that started since the last round: its refusals count.
	m2 := &Monitor{Sources: func(context.Context) ([]Source, error) {
		return []Source{{Service: "nv", Read: func(context.Context) (Reading, error) {
			return Reading{Boot: "b2", Age: 12 * time.Second, AgeKnown: true, Limits: limits}, nil
		}}}, nil
	}, Proc: proc, Now: func() time.Time { return now }}
	m2.Round(context.Background())
	if s := m2.Snapshot(); s.Refused[[2]string{"nv", "tcp"}] != 1342 {
		t.Fatalf("a fresh process: %+v", s.Refused)
	}
}

// The conntrack line: only at 70 % or more, with the guard on in the last
// day, or with drops in 15 minutes; the warning that the table was full
// once in 10 minutes.
func TestMonitorConntrack(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	proc := t.TempDir()
	var logs bytes.Buffer
	hb := &health.Board{Now: func() time.Time { return now }}
	m := &Monitor{Health: hb, Log: slog.New(slog.NewTextHandler(&logs, nil)), Proc: proc, Now: func() time.Time { return now }}
	line := func() (string, bool) {
		for _, l := range hb.Loops() {
			if l.Name == "conntrack" {
				return l.Detail, true
			}
		}
		return "", false
	}
	fakeProc(t, proc, 1000, 10000, cpu(5, 1), cpu(5, 1))
	m.Round(context.Background())
	if l, ok := line(); ok {
		t.Fatalf("a quiet table has a line: %q", l)
	}
	if s := m.Snapshot(); s.Conntrack.Dropped != 10 || s.Conntrack.EarlyDropped != 2 || s.Conntrack.DroppedRecent != 0 {
		t.Fatalf("table %+v", s.Conntrack)
	}
	fakeProc(t, proc, 7100, 10000, cpu(5, 1), cpu(5, 1))
	now = now.Add(Every)
	m.Round(context.Background())
	if l, _ := line(); l != "7100 of 10000 (71%)" {
		t.Fatalf("at 71 %%: %q", l)
	}
	m.SetGuard(Guard{On: true, Since: now.Add(-2 * time.Minute), LastOn: now.Add(-2 * time.Minute)})
	fakeProc(t, proc, 8900, 10000, cpu(105, 1), cpu(5, 1))
	now = now.Add(Every)
	m.Round(context.Background())
	if l, _ := line(); l != "8900 of 10000 (89%): guard on 2m15s — new data-plane connections refused; 100 connections dropped in 15 min: the table was full" {
		t.Fatalf("guard on, drops: %q", l)
	}
	if !strings.Contains(logs.String(), "the table was full") {
		t.Fatalf("no warning:\n%s", logs.String())
	}
	fakeProc(t, proc, 8900, 10000, cpu(205, 1), cpu(5, 1))
	now = now.Add(Every)
	m.Round(context.Background())
	if n := strings.Count(logs.String(), "the table was full"); n != 1 {
		t.Fatalf("warned %d times in 10 minutes", n)
	}
	// The guard off, a while ago; the table quiet and no drops for 15
	// minutes: the line stays for the day.
	m.SetGuard(Guard{On: false, Since: now, LastOn: now.Add(-time.Hour)})
	fakeProc(t, proc, 100, 10000, cpu(205, 1), cpu(5, 1))
	now = now.Add(Window + time.Minute)
	m.Round(context.Background())
	if l, _ := line(); !strings.Contains(l, "guard was on 1h") {
		t.Fatalf("a day: %q", l)
	}
	now = now.Add(24 * time.Hour)
	m.Round(context.Background())
	if l, ok := line(); ok {
		t.Fatalf("after a day: %q", l)
	}
}
