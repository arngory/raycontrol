package perimeter

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The guard of the conntrack table (spec/conn-limit-v1.md §6.3): on at 85 %
// of nf_conntrack_max, every new data-plane flow leaving the node is
// refused; off at 70 %, not before guardHold since it went on. While the
// table is 70 % full or more, the entries without a socket are swept once
// a minute. It is not under rayctl conn-limit: below 85 % it does nothing,
// and above it the other way is the kernel dropping everyone's new flows
// at 100 %, SSH's too.
const (
	guardOnPct  = 85
	guardOffPct = 70
	guardHold   = 2 * time.Minute
	// guardLogEvery bounds the guard's warnings: a switch logged, the next
	// within this only counted, and told with the next line: the next
	// switch's, or past this the next tick's, with the state as it is then
	// (else a guard that went off within it would never say so).
	guardLogEvery = 10 * time.Minute
	// guardReportEvery: the state goes to rayd at each switch and this
	// often, so a rayd started anew knows within it.
	guardReportEvery = time.Minute
	// sweepEvery is how often orphans are swept while the table is full.
	sweepEvery = time.Minute
)

// GuardState is what the guard reports to rayd.
type GuardState struct {
	On                                bool
	Since, LastOn                     time.Time
	Switches, Refused                 uint64
	SweptUDP, SweptTCPOut, SweptTCPIn uint64
}

// SweepResult is what one sweep removed.
type SweepResult struct {
	UDP, TCPOut, TCPIn uint64
}

// Guard is the guard's configuration and state. The gate drives it from
// Tick, under its lock; the sweep runs apart.
type Guard struct {
	// Read gives the table's entries and size (ReadConntrackTable when
	// nil): tests give a size of their own.
	Read func() (count, max uint64, err error)
	// Sweep removes the entries without a socket; nil: no sweep.
	Sweep func(ctx context.Context) (SweepResult, error)
	// Report gets the state at each switch and once a minute; it must not
	// block (rayspa sends it to rayd apart).
	Report func(GuardState)
	// Refused reads the guard's counter of the table as it is; nil: 0.
	Refused func() (uint64, error)
	Log     *slog.Logger

	on, applied        bool
	since, lastOn      time.Time
	switches           uint64
	logged             time.Time
	unlogged           int
	reported           time.Time
	refusedBase, lastC uint64

	sweepMu   sync.Mutex
	sweeping  bool
	swept     SweepResult
	lastSweep time.Time
}

// ReadConntrackTable reads nf_conntrack_count and nf_conntrack_max.
func ReadConntrackTable() (count, max uint64, err error) {
	read := func(name string) (uint64, error) {
		b, err := os.ReadFile("/proc/sys/net/netfilter/" + name) //nolint:gosec // G304: two names of this file
		if err != nil {
			return 0, err
		}
		return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	}
	if count, err = read("nf_conntrack_count"); err != nil {
		return 0, 0, err
	}
	max, err = read("nf_conntrack_max")
	return count, max, err
}

// EnableGuard gives the gate its guard: Tick switches it from then on.
func (g *Gate) EnableGuard(gd *Guard) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.guard = gd
}

// guardLocked is the guard's step in Tick: it reads the table, switches,
// puts the switch into the table (again after a restore), reports and
// starts a sweep. Under g.mu.
func (g *Gate) guardLocked(now time.Time) {
	gd := g.guard
	if gd == nil || g.restoring {
		return
	}
	read := gd.Read
	if read == nil {
		read = ReadConntrackTable
	}
	count, max, err := read()
	if err != nil || max == 0 {
		// No conntrack yet (the module not loaded): nothing to guard.
		g.guardApplyLocked(now)
		return
	}
	switched := false
	var onFor time.Duration
	switch {
	case !gd.on && count*100 >= max*guardOnPct:
		gd.on, gd.since, gd.lastOn = true, now, now
		switched = true
	case gd.on && count*100 <= max*guardOffPct && now.Sub(gd.since) >= guardHold:
		onFor = now.Sub(gd.since)
		gd.on, gd.since = false, now
		switched = true
	}
	if switched {
		gd.switches++
		g.guardLogLocked(now, count, max, onFor)
	} else if gd.unlogged > 0 && now.Sub(gd.logged) >= guardLogEvery {
		if !gd.on {
			onFor = gd.since.Sub(gd.lastOn)
		}
		g.guardLogLocked(now, count, max, onFor)
	}
	g.guardApplyLocked(now)
	if switched || now.Sub(gd.reported) >= guardReportEvery {
		gd.reported = now
		if gd.Report != nil {
			gd.Report(g.guardStateLocked())
		}
	}
	if count*100 >= max*guardOffPct && gd.Sweep != nil {
		g.sweepLocked(now)
	}
}

// guardApplyLocked puts the guard's state into the table if it is not
// there: a refusal is tried again at the next tick.
func (g *Gate) guardApplyLocked(time.Time) {
	gd := g.guard
	if gd.on == gd.applied {
		return
	}
	if err := g.fw.SetGuard(gd.on); err != nil {
		g.log.Warn("conntrack guard not switched, trying again", "on", gd.on, "err", err)
		return
	}
	gd.applied = gd.on
}

// guardLogLocked logs a switch, at most a line in guardLogEvery: the next
// line tells the switches between. Numbers only.
func (g *Gate) guardLogLocked(now time.Time, count, max uint64, onFor time.Duration) {
	gd := g.guard
	if !gd.logged.IsZero() && now.Sub(gd.logged) < guardLogEvery {
		gd.unlogged++
		return
	}
	attrs := []any{"entries", count, "max", max}
	if gd.unlogged > 0 {
		attrs = append(attrs, "switches_since_last_line", gd.unlogged)
	}
	gd.logged, gd.unlogged = now, 0
	st := g.guardStateLocked()
	if gd.on {
		g.log.Warn("conntrack guard on: new data-plane connections refused until the table is 70 % full or less", attrs...)
		return
	}
	attrs = append(attrs, "was_on", onFor.Round(time.Second), "refused", st.Refused, "swept", st.SweptUDP+st.SweptTCPOut+st.SweptTCPIn)
	g.log.Warn("conntrack guard off", attrs...)
}

// guardStateLocked is the state to report. Under g.mu.
func (g *Gate) guardStateLocked() GuardState {
	gd := g.guard
	st := GuardState{On: gd.on, Since: gd.since, LastOn: gd.lastOn, Switches: gd.switches}
	if gd.Refused != nil {
		if c, err := gd.Refused(); err == nil {
			if c < gd.lastC {
				gd.refusedBase += gd.lastC // a new table, a new counter
			}
			gd.lastC = c
		}
	}
	st.Refused = gd.refusedBase + gd.lastC
	gd.sweepMu.Lock()
	st.SweptUDP, st.SweptTCPOut, st.SweptTCPIn = gd.swept.UDP, gd.swept.TCPOut, gd.swept.TCPIn
	gd.sweepMu.Unlock()
	return st
}

// sweepLocked starts a sweep, once a minute at most and one at a time,
// apart from the gate: it takes a fraction of a second for a full table.
func (g *Gate) sweepLocked(now time.Time) {
	gd := g.guard
	gd.sweepMu.Lock()
	defer gd.sweepMu.Unlock()
	if gd.sweeping || now.Sub(gd.lastSweep) < sweepEvery {
		return
	}
	gd.sweeping, gd.lastSweep = true, now
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		r, err := gd.Sweep(ctx)
		gd.sweepMu.Lock()
		gd.sweeping = false
		gd.swept.UDP += r.UDP
		gd.swept.TCPOut += r.TCPOut
		gd.swept.TCPIn += r.TCPIn
		gd.sweepMu.Unlock()
		if err != nil {
			g.log.Warn("conntrack guard: sweep", "err", err)
		} else if n := r.UDP + r.TCPOut + r.TCPIn; n > 0 {
			g.log.Debug("conntrack guard: entries without a socket removed", "udp", r.UDP, "tcp_out", r.TCPOut, "tcp_in", r.TCPIn)
		}
	}()
}

// GuardOn reports whether the guard is on (tests, status).
func (g *Gate) GuardOn() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.guard != nil && g.guard.on
}
