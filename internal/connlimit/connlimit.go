// Package connlimit is rayd's view of the connection limits
// (docs/spec/conn-limit-v1.md §7): the refusals the processes count by
// user, read every 15 s with the traffic line; the conntrack table; and the
// guard as rayspa reports it. It is kept in memory only, never in the
// database, and it names users only by their number (u<id>), never with
// destinations, ports or addresses, and no finer than 15 minutes.
package connlimit

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/store"
)

// Kinds are the refusals a process counts (§2), in this order.
var Kinds = []string{"tcp", "rate", "failed", "udp", "evicted", "dest", "live", "lookup"}

// The loop's times (§7).
const (
	Every = 15 * time.Second
	// Window is how far back "at the limit" looks.
	Window = 15 * time.Minute
	// quietBefore: a user's first refusal after this long without one is
	// logged (rayd at info), with the others of its quarter hour in one
	// line at the quarter hour's end: no time finer than Window (§12, 3).
	quietBefore = time.Hour
	// logMax bounds the users one line names.
	logMax = 50
	// warnEvery bounds the warnings that the table was full.
	warnEvery = 10 * time.Minute
	// guardDay: the conntrack line shows a guard that was on this recently.
	guardDay = 24 * time.Hour
	first    = 5 * time.Second
	// freshWithin: a process that has run no longer than this when a
	// service is first read started since the last round could have read
	// it; its refusals are new. One that has run longer had them before.
	freshWithin = Every + 5*time.Second
)

// Source is a process that counts refusals.
type Source struct {
	Service string
	Read    func(ctx context.Context) (Reading, error)
}

// Reading is what a source gave at one poll: its run (a boot, random at
// each start), how long it has run where it says (AgeKnown), and each
// name's refusals by kind since it started.
type Reading struct {
	Boot     string
	Age      time.Duration
	AgeKnown bool
	Limits   map[string]map[string]int64
}

// Guard is rayspa's guard of the conntrack table, as it last reported.
type Guard struct {
	On                                bool
	Since, LastOn                     time.Time
	Switches, Refused                 uint64
	SweptUDP, SweptTCPOut, SweptTCPIn uint64
	Reported                          time.Time
}

// Conntrack is the table as rayd last read it.
type Conntrack struct {
	Count, Max            uint64
	Dropped, EarlyDropped uint64
	// DroppedRecent are the drops in the last Window.
	DroppedRecent uint64
}

// User is one at a limit in the last Window, on one service.
type User struct {
	ID      int64
	Service string
	Refused uint64
}

// Snapshot is what status, metrics and rayctl conn-limit show.
type Snapshot struct {
	Off       bool
	Conntrack *Conntrack // nil: not read
	Guard     *Guard     // nil: no report since rayd started
	Users     []User     // by ID, then service
	// Refused are the refusals since rayd started reading them, by
	// service and kind.
	Refused map[[2]string]uint64
	// Services are those read, for metrics with zeros.
	Services []string
}

// Monitor reads and keeps it all.
type Monitor struct {
	// Sources are the processes to read (naive services); Off says whether
	// the limits are off (the store's setting).
	Sources func(ctx context.Context) ([]Source, error)
	Off     func(ctx context.Context) (bool, error)
	Health  *health.Board
	Log     *slog.Logger
	// Proc is /proc (tests give another); Now is time.Now when nil.
	Proc string
	Now  func() time.Time

	mu      sync.Mutex
	marks   map[string]mark // by service
	totals  map[[2]string]uint64
	events  []event
	lastHit map[int64]time.Time
	// pending are the users newly at a limit since the last quarter hour,
	// by number, with their services; flushed is that quarter hour.
	pending  map[int64]map[string]bool
	flushed  time.Time
	guard    *Guard
	ct       *Conntrack
	drops    []dropSample
	warned   time.Time
	off      bool
	services []string
}

type mark struct {
	boot   string
	counts map[string]map[string]int64
}

type event struct {
	at      time.Time
	user    int64
	service string
	n       uint64
}

type dropSample struct {
	at      time.Time
	dropped uint64
}

func (m *Monitor) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Monitor) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Run reads every Every until ctx ends.
func (m *Monitor) Run(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(first):
	}
	t := time.NewTicker(Every)
	defer t.Stop()
	for {
		m.Round(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// SetGuard keeps rayspa's report.
func (m *Monitor) SetGuard(g Guard) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if g.Reported.IsZero() {
		g.Reported = m.now()
	}
	m.guard = &g
}

// Round is one reading of the sources and the table.
func (m *Monitor) Round(ctx context.Context) {
	if m == nil {
		return
	}
	var sources []Source
	var err error
	if m.Sources != nil {
		sources, err = m.Sources(ctx)
	}
	type result struct {
		r   Reading
		err error
	}
	results := make([]result, len(sources))
	var wg sync.WaitGroup
	for i, src := range sources {
		wg.Go(func() {
			r, err := src.Read(ctx)
			results[i] = result{r, err}
		})
	}
	wg.Wait()
	off := false
	if m.Off != nil {
		if o, oerr := m.Off(ctx); oerr == nil {
			off = o
		}
	}
	ct, ctErr := ReadConntrack(m.proc())

	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.off = off
	if m.marks == nil {
		m.marks, m.totals, m.lastHit = map[string]mark{}, map[[2]string]uint64{}, map[int64]time.Time{}
		m.pending = map[int64]map[string]bool{}
	}
	// Before this round's: those of the quarter hour that ended.
	m.flushLocked(now)
	// The services unknown this round (the store failed): the marks and the
	// metrics' services stay as they were, nothing is counted; a service
	// read anew would count its process's refusals since it started again.
	if err == nil {
		var services []string
		for i, src := range sources {
			services = append(services, src.Service)
			r := results[i]
			if r.err != nil {
				continue // not running, or too old to count: nothing new
			}
			m.take(src.Service, r.r, now)
		}
		for svc := range m.marks {
			if !slices.Contains(services, svc) {
				delete(m.marks, svc)
			}
		}
		slices.Sort(services)
		m.services = services
	}
	m.events = slices.DeleteFunc(m.events, func(e event) bool { return now.Sub(e.at) >= Window })
	if ctErr == nil {
		m.drops = append(m.drops, dropSample{now, ct.Dropped})
		m.drops = slices.DeleteFunc(m.drops, func(d dropSample) bool { return now.Sub(d.at) > Window })
		if ct.Dropped >= m.drops[0].dropped {
			ct.DroppedRecent = ct.Dropped - m.drops[0].dropped
		}
		m.ct = &ct
		if ct.DroppedRecent > 0 && now.Sub(m.warned) >= warnEvery {
			m.warned = now
			m.log().Warn("conntrack: the table was full, the kernel dropped new connections", "dropped", ct.DroppedRecent,
				"in", Window, "entries", ct.Count, "max", ct.Max)
		}
	} else {
		m.ct = nil
	}
	if err != nil {
		m.Health.Done("conn-limit", err)
	} else {
		m.Health.Report("conn-limit", m.limitLine(), nil)
	}
	if line := m.conntrackLine(now); line != "" {
		m.Health.Report("conntrack", line, nil)
	} else {
		m.Health.Retain("conntrack", nil)
	}
}

func (m *Monitor) proc() string {
	if m.Proc != "" {
		return m.Proc
	}
	return "/proc"
}

// take counts what a source's counters grew by since the last reading of
// the same run; a new run counts whole. A service with no reading before
// (rayd started anew, or the service is new to it) is a baseline, not
// counted: its counters are since its process started, which may be long
// before. Unless that process has run no longer than freshWithin: then
// its refusals are new.
func (m *Monitor) take(service string, r Reading, now time.Time) {
	boot, limits := r.Boot, r.Limits
	prev, ok := m.marks[service]
	same := ok && prev.boot == boot
	fresh := !ok && r.AgeKnown && r.Age <= freshWithin
	if !ok && !fresh {
		m.marks[service] = mark{boot: boot, counts: limits}
		return
	}
	for name, kinds := range limits {
		id, ok := store.TrafficUser(name)
		if !ok || name != "u"+strconv.FormatInt(id, 10) {
			continue // base names only: u<id>
		}
		var n uint64
		for kind, v := range kinds {
			if !slices.Contains(Kinds, kind) || v <= 0 {
				continue
			}
			d := v
			if same {
				if was := prev.counts[name][kind]; v >= was {
					d = v - was
				}
			}
			if d > 0 {
				m.totals[[2]string{service, kind}] += uint64(d)
				n += uint64(d)
			}
		}
		if n == 0 {
			continue
		}
		m.events = append(m.events, event{at: now, user: id, service: service, n: n})
		if last, ok := m.lastHit[id]; !ok || now.Sub(last) >= quietBefore || m.pending[id] != nil {
			if m.pending[id] == nil {
				m.pending[id] = map[string]bool{}
			}
			m.pending[id][service] = true
		}
		m.lastHit[id] = now
	}
	for id, last := range m.lastHit {
		if now.Sub(last) >= quietBefore {
			delete(m.lastHit, id)
		}
	}
	m.marks[service] = mark{boot: boot, counts: limits}
}

// flushLocked logs the users newly at a limit, in one line, once a quarter
// hour of the wall clock (Window) has ended: the line names users and
// services, never when within it. Under mu.
func (m *Monitor) flushLocked(now time.Time) {
	q := now.Truncate(Window)
	if !q.After(m.flushed) {
		return
	}
	m.flushed = q
	if len(m.pending) == 0 {
		return
	}
	ids := slices.Sorted(maps.Keys(m.pending))
	parts := make([]string, 0, min(len(ids), logMax+1))
	for i, id := range ids {
		if i == logMax {
			parts = append(parts, fmt.Sprintf("%d more", len(ids)-i))
			break
		}
		parts = append(parts, fmt.Sprintf("u%d (%s)", id, strings.Join(slices.Sorted(maps.Keys(m.pending[id])), ", ")))
	}
	m.log().Info("conn-limit: at a limit in the last 15 min: " + strings.Join(parts, ", "))
	clear(m.pending)
}

// users are those at a limit in the window, by ID then service. Under mu.
func (m *Monitor) users() []User {
	sum := map[[2]string]uint64{}
	for _, e := range m.events {
		sum[[2]string{strconv.FormatInt(e.user, 10), e.service}] += e.n
	}
	var out []User
	for k, n := range sum {
		id, _ := strconv.ParseInt(k[0], 10, 64)
		out = append(out, User{ID: id, Service: k[1], Refused: n})
	}
	slices.SortFunc(out, func(a, b User) int {
		if a.ID != b.ID {
			return int(a.ID - b.ID)
		}
		return strings.Compare(a.Service, b.Service)
	})
	return out
}

// limitLine is rayctl status's conn-limit line. Under mu.
func (m *Monitor) limitLine() string {
	if m.off {
		return "off: no per-user or per-address limits (rayctl conn-limit on)"
	}
	users := m.users()
	if len(users) == 0 {
		return "on; nobody at a limit in 15 min"
	}
	parts := make([]string, 0, len(users))
	for i, u := range users {
		if i == 10 {
			parts = append(parts, fmt.Sprintf("%d more", len(users)-i))
			break
		}
		parts = append(parts, fmt.Sprintf("u%d (%s: %d)", u.ID, u.Service, u.Refused))
	}
	return "at a limit in 15 min: " + strings.Join(parts, ", ")
}

// conntrackLine is rayctl status's conntrack line, "" when there is
// nothing to say: under 70 %, no guard in a day, no drops in the window.
// Under mu.
func (m *Monitor) conntrackLine(now time.Time) string {
	ct, g := m.ct, m.guard
	high := ct != nil && ct.Max > 0 && ct.Count*100 >= ct.Max*70
	guardDay := g != nil && (g.On || !g.LastOn.IsZero() && now.Sub(g.LastOn) < guardDay)
	drops := ct != nil && ct.DroppedRecent > 0
	if !high && !guardDay && !drops {
		return ""
	}
	var b strings.Builder
	if ct != nil && ct.Max > 0 {
		fmt.Fprintf(&b, "%d of %d (%d%%)", ct.Count, ct.Max, ct.Count*100/ct.Max)
	} else {
		b.WriteString("table not read")
	}
	switch {
	case g != nil && g.On:
		fmt.Fprintf(&b, ": guard on %s — new data-plane connections refused", now.Sub(g.Since).Round(time.Second))
	case guardDay:
		fmt.Fprintf(&b, ": guard was on %s ago", now.Sub(g.LastOn).Round(time.Minute))
	}
	if drops {
		fmt.Fprintf(&b, "; %d connections dropped in 15 min: the table was full", ct.DroppedRecent)
	}
	return b.String()
}

// Snapshot is the state for status, metrics and rayctl conn-limit.
func (m *Monitor) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Snapshot{Off: m.off, Users: m.users(), Refused: map[[2]string]uint64{}, Services: slices.Clone(m.services)}
	if m.ct != nil {
		ct := *m.ct
		s.Conntrack = &ct
	}
	if m.guard != nil {
		g := *m.guard
		s.Guard = &g
	}
	for k, v := range m.totals {
		s.Refused[k] = v
	}
	return s
}

// ReadConntrack reads the table under proc: its entries and size, and the
// drops summed over the CPUs (net/stat/nf_conntrack, hexadecimal, one line
// a CPU after the header).
func ReadConntrack(proc string) (Conntrack, error) {
	var ct Conntrack
	num := func(name string) (uint64, error) {
		b, err := os.ReadFile(filepath.Join(proc, "sys/net/netfilter", name)) //nolint:gosec // G304: /proc
		if err != nil {
			return 0, err
		}
		return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	}
	var err error
	if ct.Count, err = num("nf_conntrack_count"); err != nil {
		return ct, err
	}
	if ct.Max, err = num("nf_conntrack_max"); err != nil {
		return ct, err
	}
	b, err := os.ReadFile(filepath.Join(proc, "net/stat/nf_conntrack")) //nolint:gosec // G304: /proc
	if err != nil {
		return ct, nil // the counts alone
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) < 2 {
		return ct, nil
	}
	head := strings.Fields(lines[0])
	col := func(name string) int { return slices.Index(head, name) }
	drop, early := col("drop"), col("early_drop")
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		get := func(i int) uint64 {
			if i < 0 || i >= len(f) {
				return 0
			}
			v, _ := strconv.ParseUint(f[i], 16, 64)
			return v
		}
		ct.Dropped += get(drop)
		ct.EarlyDropped += get(early)
	}
	return ct, nil
}
