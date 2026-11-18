package stats

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"time"
)

// Report is a window of the node's statistics as rayctl stats writes it
// (spec/stats-v1.md): rayd fills what it samples, rayctl the run, the
// versions of the binaries and the journal.
type Report struct {
	V         int       `json:"v"`
	Kind      string    `json:"kind"`
	Side      string    `json:"side"`
	Run       string    `json:"run,omitempty"`
	Generated time.Time `json:"generated"`
	// The window: from the sample at or before now minus the window asked
	// (the oldest one when rayd is younger) to now.
	From    time.Time  `json:"from"`
	To      time.Time  `json:"to"`
	Asked   string     `json:"asked"`
	Partial bool       `json:"partial"`
	Why     []string   `json:"partial_why,omitempty"`
	Node    Node       `json:"node"`
	Host    *HostStats `json:"host,omitempty"`
	// Services by kind and number, never by name.
	Services []Service `json:"services,omitempty"`
	// Devices whose client the node recorded since ClientsSince, by
	// product and version (client-min-v1 §5). The node records a client
	// that did not change at most hourly, so the span is two hours at
	// least: a shorter one would miss devices that were there.
	ClientsSince time.Time    `json:"clients_since"`
	Clients      []ClientSeen `json:"clients_seen"`
	Counters     []Counter    `json:"counters"`
	Gauges       []Gauge      `json:"gauges"`
	// Journal entries in the window by unit and priority, counts only;
	// rayctl on the node as root.
	Journal []JournalCount `json:"journal,omitempty"`
}

// Report's identity.
const (
	Version = 1
	Kind    = "niko-stats"
)

// Node is the node's software and how long it has run.
type Node struct {
	Raycontrol  string `json:"raycontrol"`
	NikoServer  string `json:"niko_server,omitempty"`
	Xray        string `json:"xray,omitempty"`
	OS          string `json:"os,omitempty"`
	Kernel      string `json:"kernel,omitempty"`
	Arch        string `json:"arch,omitempty"`
	RaydUptimeS int64  `json:"rayd_uptime_s"`
}

// HostStats is the host over the window.
type HostStats struct {
	UptimeS     int64      `json:"uptime_s"` // since the host booted, at the end
	CPUs        int        `json:"cpus"`
	CPUBusyPct  Range      `json:"cpu_busy_pct"`
	Load        [3]float64 `json:"load"` // 1, 5 and 15 minutes, at the end
	MemTotalMB  uint64     `json:"mem_total_mb"`
	MemUsedPct  Range      `json:"mem_used_pct"`
	DiskFreePct float64    `json:"disk_free_pct"` // the node's state, at the end
	// Every interface but lo, the window's increase.
	Net NetCounters `json:"net"`
}

// Range is a value over the window: at its end, its least and most among
// the samples, and the mean where it means something (CPU: busy time over
// the whole window).
type Range struct {
	End float64  `json:"end"`
	Min float64  `json:"min"`
	Max float64  `json:"max"`
	Avg *float64 `json:"avg,omitempty"`
}

// Service is one service: its kind and number among the services of that
// kind (by creation), and its certificate's days left.
type Service struct {
	ID       string `json:"id"` // kind#n
	Kind     string `json:"kind"`
	Enabled  bool   `json:"enabled"`
	CertDays *int   `json:"cert_days,omitempty"`
}

// ClientSeen is how many devices last named a client in the window.
type ClientSeen struct {
	Product string `json:"product"`
	Version string `json:"version"`
	Devices int    `json:"devices"`
}

// Counter is a counter's increase over the window, summed from sample to
// sample so that a restart of what counts loses only its last minute.
type Counter struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	Delta  float64           `json:"delta"`
	// Reset: it went back at least once (its process restarted); New: it
	// was not there at the window's start.
	Reset bool `json:"reset,omitempty"`
	New   bool `json:"new,omitempty"`
}

// Gauge is a level over the window.
type Gauge struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	Range
}

// JournalCount is how many journal entries a unit wrote in the window at a
// priority.
type JournalCount struct {
	Unit     string `json:"unit"`
	Priority string `json:"priority"`
	Entries  int    `json:"entries"`
}

// ErrNoSamples is Report before the first sample.
var ErrNoSamples = errors.New("stats: no sample yet")

var runID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ValidRun reports whether s can be a run ID: letters, digits, '.', '-' and
// '_', at most 64 (the client's test run, RayTestRun).
func ValidRun(s string) bool { return runID.MatchString(s) }

// Report is the window of the last `last` (MinWindow to MaxWindow) up to
// a sample taken now.
func (s *Sampler) Report(ctx context.Context, last time.Duration) (Report, error) {
	if last < MinWindow || last > MaxWindow {
		return Report{}, fmt.Errorf("stats: the window is %v to %v, not %v", MinWindow, MaxWindow, last)
	}
	end, err := s.sample(ctx)
	if err != nil {
		return Report{}, err
	}
	s.mu.Lock()
	held := slices.Clone(s.samples)
	series := make(map[string]*meta, len(s.series))
	for k, m := range s.series {
		series[k] = m
	}
	started := s.started
	s.mu.Unlock()

	r := Report{V: Version, Kind: Kind, Side: "node", Generated: end.At.UTC(), To: end.At.UTC(), Asked: last.String(),
		Counters: []Counter{}, Gauges: []Gauge{}, Clients: []ClientSeen{}}
	from := end.At.Add(-last)
	// The window's samples: the last one at or before from, and every one
	// after it; the sample taken now closes them.
	first := -1
	for i, sm := range held {
		if !sm.At.After(from) {
			first = i
		}
	}
	if first < 0 {
		if len(held) == 0 {
			return Report{}, ErrNoSamples
		}
		first = 0
		r.Partial = true
		if !started.IsZero() {
			r.Why = append(r.Why, fmt.Sprintf("rayd has sampled for %v only", end.At.Sub(started).Round(time.Second)))
		} else {
			r.Why = append(r.Why, "fewer samples than the window")
		}
	}
	window := append(held[first:], end)
	r.From = window[0].At.UTC()
	for i := 1; i < len(window); i++ {
		if gap := window[i].At.Sub(window[i-1].At); gap > 3*s.every() {
			r.Partial = true
			r.Why = append(r.Why, fmt.Sprintf("no sample for %v before %s", gap.Round(time.Second), window[i].At.UTC().Format(time.RFC3339)))
		}
	}

	// Every series the window read, even one the last read missed (a
	// stats socket that timed out this minute).
	union := map[string]bool{}
	for _, sm := range window {
		for k := range sm.Values {
			union[k] = true
		}
	}
	keys := make([]string, 0, len(union))
	for k := range union {
		if _, ok := series[k]; !ok {
			series[k] = metaOfKey(k)
		}
		keys = append(keys, k)
	}
	slices.Sort(keys)
	resets := 0
	for _, k := range keys {
		m := series[k]
		labels := labelMap(m.labels)
		if (Point{Name: m.name}).Counter() {
			c := Counter{Name: m.name, Labels: labels}
			prev, seen := window[0].Values[k]
			// Not read at the window's start: its last reading before.
			for i := first - 1; !seen && i >= 0; i-- {
				prev, seen = held[i].Values[k]
			}
			c.New = !seen
			for _, sm := range window[1:] {
				v, ok := sm.Values[k]
				if !ok {
					continue // not read this minute: the next reading counts from the last
				}
				switch {
				case !seen:
					c.Delta += v // it began within the window
				case v >= prev:
					c.Delta += v - prev
				default:
					c.Delta += v // went back: counted again from zero
					c.Reset = true
				}
				prev, seen = v, true
			}
			if c.Reset {
				resets++
			}
			r.Counters = append(r.Counters, c)
			continue
		}
		g := Gauge{Name: m.name, Labels: labels, Range: Range{Min: math.Inf(1), Max: math.Inf(-1)}}
		for _, sm := range window {
			if v, ok := sm.Values[k]; ok {
				g.End, g.Min, g.Max = v, min(g.Min, v), max(g.Max, v)
			}
		}
		r.Gauges = append(r.Gauges, g)
	}
	if resets > 0 {
		r.Partial = true
		r.Why = append(r.Why, fmt.Sprintf("%d counters went back (a process restarted): their increase misses up to a sample each", resets))
	}
	r.Host = hostStats(window)
	return r, nil
}

// hostStats is the host over the window's samples; nil when none read it.
func hostStats(window []Sample) *HostStats {
	var hs []Host
	for _, sm := range window {
		if sm.Host.OK {
			hs = append(hs, sm.Host)
		}
	}
	if len(hs) == 0 {
		return nil
	}
	last := hs[len(hs)-1]
	out := &HostStats{UptimeS: int64(last.Uptime), CPUs: last.CPUs, Load: last.Load, MemTotalMB: last.MemTotal >> 20}
	if last.DiskTotal > 0 {
		out.DiskFreePct = round1(100 * float64(last.DiskFree) / float64(last.DiskTotal))
	}
	memUsed := func(h Host) float64 {
		if h.MemTotal == 0 || h.MemAvailable > h.MemTotal {
			return 0
		}
		return round1(100 * float64(h.MemTotal-h.MemAvailable) / float64(h.MemTotal))
	}
	out.MemUsedPct = Range{End: memUsed(last), Min: math.Inf(1), Max: math.Inf(-1)}
	for _, h := range hs {
		v := memUsed(h)
		out.MemUsedPct.Min, out.MemUsedPct.Max = min(out.MemUsedPct.Min, v), max(out.MemUsedPct.Max, v)
	}
	// CPU and network: from sample to sample, over the same boot only
	// (a counter that went back is a reboot: that step is left out).
	cpu := Range{Min: math.Inf(1), Max: math.Inf(-1)}
	var busy, total uint64
	steps := 0
	for i := 1; i < len(hs); i++ {
		a, b := hs[i-1], hs[i]
		if b.CPUTotal <= a.CPUTotal || b.CPUBusy < a.CPUBusy {
			continue
		}
		db, dt := b.CPUBusy-a.CPUBusy, b.CPUTotal-a.CPUTotal
		busy, total = busy+db, total+dt
		pct := round1(100 * float64(db) / float64(dt))
		cpu.Min, cpu.Max, cpu.End = min(cpu.Min, pct), max(cpu.Max, pct), pct
		steps++
		out.Net = out.Net.add(netStep(a.Net, b.Net))
	}
	if steps > 0 {
		avg := round1(100 * float64(busy) / float64(total))
		cpu.Avg = &avg
		out.CPUBusyPct = cpu
	}
	return out
}

// netStep is b minus a, field by field; a field that went back (a reboot,
// an interface gone) counts as nothing.
func netStep(a, b NetCounters) NetCounters {
	d := func(x, y uint64) uint64 {
		if y < x {
			return 0
		}
		return y - x
	}
	return NetCounters{
		RxBytes: d(a.RxBytes, b.RxBytes), RxPackets: d(a.RxPackets, b.RxPackets), RxErrors: d(a.RxErrors, b.RxErrors), RxDrops: d(a.RxDrops, b.RxDrops),
		TxBytes: d(a.TxBytes, b.TxBytes), TxPackets: d(a.TxPackets, b.TxPackets), TxErrors: d(a.TxErrors, b.TxErrors), TxDrops: d(a.TxDrops, b.TxDrops),
	}
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

func labelMap(pairs []string) map[string]string {
	if len(pairs) < 2 {
		return nil
	}
	m := make(map[string]string, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i]] = pairs[i+1]
	}
	return m
}

// metaOfKey takes a key apart (Point.Key).
func metaOfKey(k string) *meta {
	parts := splitKey(k)
	m := &meta{key: k, name: parts[0]}
	for _, kv := range parts[1:] {
		name, value, _ := cutByte(kv, '=')
		m.labels = append(m.labels, name, value)
	}
	return m
}

func splitKey(k string) []string {
	var out []string
	start := 0
	for i := 0; i < len(k); i++ {
		if k[i] == 0 {
			out = append(out, k[start:i])
			start = i + 1
		}
	}
	return append(out, k[start:])
}

func cutByte(s string, c byte) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

// SortClients orders the clients by product, then version, as the report
// lists them.
func SortClients(cs []ClientSeen) {
	slices.SortFunc(cs, func(a, b ClientSeen) int {
		return cmp.Or(cmp.Compare(a.Product, b.Product), cmp.Compare(a.Version, b.Version))
	})
}

// ServiceRef is what ServiceIDs needs of a service.
type ServiceRef struct {
	ID         int64
	Name, Kind string
}

// ServiceIDs names each service kind#n, n its place among the services of
// its kind by ID (creation): what a report says instead of the operator's
// names.
func ServiceIDs(services []ServiceRef) map[string]string {
	sorted := slices.Clone(services)
	slices.SortFunc(sorted, func(a, b ServiceRef) int { return cmp.Compare(a.ID, b.ID) })
	n := map[string]int{}
	ids := make(map[string]string, len(sorted))
	for _, svc := range sorted {
		n[svc.Kind]++
		ids[svc.Name] = fmt.Sprintf("%s#%d", svc.Kind, n[svc.Kind])
	}
	return ids
}
