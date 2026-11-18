package stats

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// fake is a node whose series the test sets before each sample.
type fake struct {
	now    time.Time
	points []Point
	host   Host
}

func (f *fake) sampler() *Sampler {
	return &Sampler{
		Collect:  func(context.Context, time.Time) ([]Point, error) { return append([]Point(nil), f.points...), nil },
		ReadHost: func() Host { return f.host },
		Now:      func() time.Time { return f.now },
	}
}

// keep shows every series as it is.
func keep(_ string, labels []string) ([]string, bool) { return labels, true }

func counter(name string, v float64, labels ...string) Point {
	return Point{Name: name, Labels: labels, Value: v}
}

func findCounter(t *testing.T, r Report, name string) Counter {
	t.Helper()
	for _, c := range r.Counters {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no counter %s in %+v", name, r.Counters)
	return Counter{}
}

func findGauge(t *testing.T, r Report, name string) Gauge {
	t.Helper()
	for _, g := range r.Gauges {
		if g.Name == name {
			return g
		}
	}
	t.Fatalf("no gauge %s in %+v", name, r.Gauges)
	return Gauge{}
}

// A counter's increase is summed from sample to sample: a restart of what
// counts loses only the minute it happened in, and the report says so.
func TestReportCounters(t *testing.T) {
	ctx := context.Background()
	f := &fake{now: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)}
	s := f.sampler()
	s.Start()
	// 90 minutes of samples: requests grow by 10 a minute, the process
	// restarts at minute 70 (back to 5), sessions go up and down.
	for i := 0; i <= 90; i++ {
		req := float64(10 * i)
		if i >= 70 {
			req = float64(5 + 10*(i-70))
		}
		f.points = []Point{
			counter("x_requests_total", req, "service", "naive#1"),
			counter("x_sessions", float64(i%7), "service", "naive#1"),
		}
		if i >= 80 {
			f.points = append(f.points, counter("x_new_total", float64(i-80)))
		}
		if err := s.Take(ctx); err != nil {
			t.Fatal(err)
		}
		f.now = f.now.Add(time.Minute)
	}
	// The report's own sample, a minute after the last.
	f.points = []Point{counter("x_requests_total", 5+10*21, "service", "naive#1"), counter("x_sessions", 3, "service", "naive#1"),
		counter("x_new_total", 11)}
	r, err := s.Report(ctx, time.Hour, keep)
	if err != nil {
		t.Fatal(err)
	}
	if want := f.now.Add(-time.Hour); !r.From.Equal(want) || !r.To.Equal(f.now) {
		t.Fatalf("window %v..%v, want %v..%v", r.From, r.To, want, f.now)
	}
	// From minute 31 (310) to 69 (690): 380; the restart at 70 counts its
	// 5, then 10 a minute to 205 at 90 and 215 now: 380 + 5 + 210 = 595.
	c := findCounter(t, r, "x_requests_total")
	if c.Delta != 595 || !c.Reset || c.New || c.Labels["service"] != "naive#1" {
		t.Fatalf("requests: %+v", c)
	}
	if n := findCounter(t, r, "x_new_total"); n.Delta != 11 || !n.New {
		t.Fatalf("a counter born in the window: %+v", n)
	}
	g := findGauge(t, r, "x_sessions")
	if g.End != 3 || g.Min != 0 || g.Max != 6 {
		t.Fatalf("sessions: %+v", g)
	}
	if !r.Partial || len(r.Why) != 1 || !strings.Contains(r.Why[0], "went back") {
		t.Fatalf("a reset makes the report partial: %v %q", r.Partial, r.Why)
	}
	if r.V != Version || r.Kind != Kind || r.Side != "node" || r.Asked != "1h0m0s" {
		t.Fatalf("identity: %+v", r)
	}
}

// A rayd younger than the window reports from its first sample, and says
// so; before any sample there is no report.
func TestReportYoung(t *testing.T) {
	ctx := context.Background()
	f := &fake{now: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC), points: []Point{counter("a_total", 1)}}
	s := f.sampler()
	s.Start()
	if _, err := s.Report(ctx, time.Hour, keep); !errors.Is(err, ErrNoSamples) {
		t.Fatalf("no sample: %v", err)
	}
	for range 10 {
		if err := s.Take(ctx); err != nil {
			t.Fatal(err)
		}
		f.now = f.now.Add(time.Minute)
		f.points[0].Value += 2
	}
	r, err := s.Report(ctx, time.Hour, keep)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Partial || !strings.Contains(strings.Join(r.Why, ";"), "sampled for 10m0s") || r.From.Before(r.To.Add(-10*time.Minute)) {
		t.Fatalf("young: %+v", r)
	}
	if c := findCounter(t, r, "a_total"); c.Delta != 20 || c.New {
		t.Fatalf("young counter: %+v", c)
	}
	for _, bad := range []time.Duration{time.Minute, 3 * time.Hour} {
		if _, err := s.Report(ctx, bad, keep); err == nil {
			t.Errorf("window %v taken", bad)
		}
	}
}

// A sample missing for long (rayd stopped, the host asleep) is a gap the
// report names; a series one reading missed counts from its last reading.
func TestReportGapsAndMissedReads(t *testing.T) {
	ctx := context.Background()
	f := &fake{now: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)}
	s := f.sampler()
	s.Start()
	take := func(v float64, with bool) {
		f.points = nil
		if with {
			f.points = []Point{counter("dns_total", v)}
		}
		if err := s.Take(ctx); err != nil {
			t.Fatal(err)
		}
	}
	take(100, true) // before the window
	f.now = f.now.Add(10 * time.Minute)
	take(0, false) // the window's start: the socket timed out
	f.now = f.now.Add(10 * time.Minute)
	take(130, true)
	f.now = f.now.Add(30 * time.Minute) // a gap
	take(150, true)
	f.now = f.now.Add(time.Minute)
	f.points = []Point{counter("dns_total", 155)}
	r, err := s.Report(ctx, 50*time.Minute, keep)
	if err != nil {
		t.Fatal(err)
	}
	if c := findCounter(t, r, "dns_total"); c.Delta != 55 || c.New {
		t.Fatalf("missed read: %+v", c)
	}
	if !r.Partial || !strings.Contains(strings.Join(r.Why, ";"), "no sample for 30m0s") {
		t.Fatalf("gap: %v", r.Why)
	}
}

// The ring keeps Keep: old samples and the keys only they held go.
func TestSamplerKeeps(t *testing.T) {
	ctx := context.Background()
	f := &fake{now: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)}
	s := f.sampler()
	for i := range 200 {
		f.points = []Point{counter("a_total", float64(i)), counter("gone_total", 1, "service", "dnstt#"+string(rune('0'+i%3)))}
		if i > 50 {
			f.points = f.points[:1]
		}
		if err := s.Take(ctx); err != nil {
			t.Fatal(err)
		}
		f.now = f.now.Add(time.Minute)
	}
	if n := len(s.samples); n != 123 {
		t.Fatalf("%d samples kept, want two hours and two", n)
	}
	if len(s.series) != 1 {
		t.Fatalf("keys no sample holds are kept: %d", len(s.series))
	}
}

// The host: CPU from tick to tick, memory, network summed, a reboot (a
// counter that went back) left out.
func TestHostStats(t *testing.T) {
	h := func(busy, total uint64, avail uint64, rx uint64) Host {
		return Host{OK: true, CPUBusy: busy, CPUTotal: total, CPUs: 2, MemTotal: 4 << 30, MemAvailable: avail << 30,
			Load: [3]float64{0.5, 0.4, 0.3}, Net: NetCounters{RxBytes: rx, TxBytes: rx / 2}, DiskFree: 25, DiskTotal: 100, Uptime: 3600}
	}
	w := []Sample{{Host: h(100, 1000, 3, 1000)}, {Host: h(300, 2000, 2, 3000)}, {Host: h(10, 50, 1, 100)}, {Host: h(60, 150, 2, 600)}}
	got := hostStats(w, time.Minute)
	if got == nil || got.CPUs != 2 || got.MemTotalMB != 4096 || got.DiskFreePct != 25 || got.UptimeS != 3600 {
		t.Fatalf("host: %+v", got)
	}
	// Steps 1 and 3: 200/1000 and 50/100; the reboot step is out.
	if got.CPUBusyPct.Avg == nil || *got.CPUBusyPct.Avg != 22.7 || got.CPUBusyPct.Max != 50 || got.CPUBusyPct.Min != 20 {
		t.Fatalf("cpu: %+v avg %v", got.CPUBusyPct, *got.CPUBusyPct.Avg)
	}
	if got.MemUsedPct.End != 50 || got.MemUsedPct.Max != 75 || got.MemUsedPct.Min != 25 {
		t.Fatalf("memory: %+v", got.MemUsedPct)
	}
	if got.Net.RxBytes != 2500 || got.Net.TxBytes != 1250 {
		t.Fatalf("net: %+v", got.Net)
	}
	// The last step a second long (the report's sample just after a
	// minute's): in the mean, not in the end, least and most.
	t0 := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	w2 := []Sample{{At: t0, Host: h(0, 1000, 2, 0)}, {At: t0.Add(time.Minute), Host: h(100, 2000, 2, 0)}, {At: t0.Add(61 * time.Second), Host: h(110, 2010, 2, 0)}}
	if got := hostStats(w2, time.Minute); got.CPUBusyPct.End != 10 || got.CPUBusyPct.Max != 10 || *got.CPUBusyPct.Avg != 10.9 {
		t.Fatalf("short step: %+v avg %v", got.CPUBusyPct, *got.CPUBusyPct.Avg)
	}
	if hostStats([]Sample{{}}, time.Minute) != nil {
		t.Fatal("no host read: no host stats")
	}
}

// The JSON has the field names the spec gives, and no infinity.
func TestReportJSON(t *testing.T) {
	ctx := context.Background()
	f := &fake{now: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC), points: []Point{counter("g", 1)}}
	s := f.sampler()
	s.Start()
	for range 6 {
		if err := s.Take(ctx); err != nil {
			t.Fatal(err)
		}
		f.now = f.now.Add(time.Minute)
	}
	r, err := s.Report(ctx, 5*time.Minute, keep)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"v":1`, `"kind":"niko-stats"`, `"side":"node"`, `"from":"2026-11-18T12:01:00Z"`, `"gauges":[{"name":"g","end":1,"min":1,"max":1}]`, `"counters":[]`, `"clients_seen":[]`} {
		if !strings.Contains(string(b), field) {
			t.Errorf("no %s in %s", field, b)
		}
	}
}

func TestValidRun(t *testing.T) {
	for _, ok := range []string{"r-abc", "run_1.2-x", strings.Repeat("a", 64)} {
		if !ValidRun(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", strings.Repeat("a", 65), "a b", "a/b", "ä", "a\n"} {
		if ValidRun(bad) {
			t.Errorf("%q taken", bad)
		}
	}
}

func TestServiceIDs(t *testing.T) {
	ids := ServiceIDs([]ServiceRef{{ID: 5, Name: "late", Kind: "naive"}, {ID: 2, Name: "first", Kind: "naive"}, {ID: 3, Name: "sub", Kind: "subscription"}})
	if ids["first"] != "naive#1" || ids["late"] != "naive#2" || ids["sub"] != "subscription#1" {
		t.Fatalf("%v", ids)
	}
}

// Series the report shows as one are summed after each one's increase:
// one that goes away (a site deleted, its loop gone) takes no count back,
// and a series is followed by its own name whatever it shows as.
func TestReportCleanSums(t *testing.T) {
	ctx := context.Background()
	f := &fake{now: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)}
	s := f.sampler()
	s.Start()
	for i := 0; i <= 60; i++ {
		f.points = []Point{counter("runs_total", float64(1000+i), "loop", "acme a"), counter("fail", 1, "loop", "acme a")}
		if i < 30 {
			f.points = append(f.points, counter("runs_total", float64(500+i), "loop", "acme b"), counter("fail", 1, "loop", "acme b"))
		}
		if err := s.Take(ctx); err != nil {
			t.Fatal(err)
		}
		f.now = f.now.Add(time.Minute)
	}
	f.points = []Point{counter("runs_total", 1061, "loop", "acme a"), counter("fail", 1, "loop", "acme a")}
	byKind := func(_ string, l []string) ([]string, bool) {
		if len(l) == 2 && l[0] == "loop" {
			kind, _, _ := strings.Cut(l[1], " ")
			return []string{"loop", kind}, true
		}
		return l, true
	}
	r, err := s.Report(ctx, time.Hour, byKind)
	if err != nil {
		t.Fatal(err)
	}
	// From the sample at minute 1: a 1001..1061 (60); b 501..529 (28), then
	// gone.
	if c := findCounter(t, r, "runs_total"); c.Delta != 60+28 || c.Reset || c.New || c.Labels["loop"] != "acme" {
		t.Fatalf("summed: %+v", c)
	}
	if g := findGauge(t, r, "fail"); g.End != 1 || g.Max != 2 || g.Min != 1 {
		t.Fatalf("gauges summed by sample: %+v", g)
	}
	if r.Partial {
		t.Fatalf("partial: %q", r.Why)
	}
	drop := func(name string, l []string) ([]string, bool) { return l, name != "fail" }
	if r, _ := s.Report(ctx, time.Hour, drop); len(r.Gauges) != 0 {
		t.Fatalf("left out, still shown: %+v", r.Gauges)
	}
}

// A series first read inside the window counts from that reading: a
// counter of the kernel's since boot, read late, brings none of before.
func TestReportLateFirstReading(t *testing.T) {
	ctx := context.Background()
	f := &fake{now: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)}
	s := f.sampler()
	s.Start()
	for i := 0; i < 10; i++ {
		f.points = []Point{counter("a_total", float64(i))}
		if i > 0 {
			f.points = append(f.points, counter("since_boot_total", float64(5_000_000+i)))
		}
		if err := s.Take(ctx); err != nil {
			t.Fatal(err)
		}
		f.now = f.now.Add(time.Minute)
	}
	f.points = []Point{counter("a_total", 10), counter("since_boot_total", 5_000_029)}
	r, err := s.Report(ctx, 10*time.Minute, keep)
	if err != nil {
		t.Fatal(err)
	}
	if c := findCounter(t, r, "since_boot_total"); c.Delta != 28 || !c.New {
		t.Fatalf("late first reading: %+v", c)
	}
}

// A sample stored after the report's own began (a Take that ended while
// the report's collect was slow) is not part of its window.
func TestReportIgnoresLaterSamples(t *testing.T) {
	ctx := context.Background()
	f := &fake{now: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)}
	s := f.sampler()
	s.Start()
	for i := 0; i <= 10; i++ {
		f.points = []Point{counter("a_total", float64(100*i))}
		if err := s.Take(ctx); err != nil {
			t.Fatal(err)
		}
		f.now = f.now.Add(time.Minute)
	}
	// The report's sample at T, value 1050; a Take at T+5s, value 1100,
	// stored before the report reads the ring.
	reportAt := f.now
	s.Collect = func(context.Context, time.Time) ([]Point, error) {
		if f.now.Equal(reportAt) {
			f.now = reportAt.Add(5 * time.Second)
			if err := s.Take(ctx); err != nil {
				t.Fatal(err)
			}
			f.now = reportAt
			return []Point{counter("a_total", 1050)}, nil
		}
		return []Point{counter("a_total", 1100)}, nil
	}
	r, err := s.Report(ctx, 10*time.Minute, keep)
	if err != nil {
		t.Fatal(err)
	}
	if c := findCounter(t, r, "a_total"); c.Delta != 950 || c.Reset {
		t.Fatalf("a later sample in the window: %+v", c)
	}
}
