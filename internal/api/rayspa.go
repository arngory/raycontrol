package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"connectrpc.com/connect"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
)

// rayspaWatch is what rayd knows of rayspa (docs/08-decisions.md, R4-40):
// whether it follows the perimeter feed, and where its table stands as it
// reports it (ReportGate). rayd cannot read the kernel's table (it has no
// CAP_NET_ADMIN). A rayspa that does not follow may have left its table
// (closed: no knock is answered) or none (a boot it did not come up in:
// the host is open); one that follows but cannot put its table in (a
// kernel refusing the ruleset) leaves the host open too, and says so. An
// older rayspa reports nothing: its table's state is unknown here, and
// rayctl status as root reads the table.
type rayspaWatch struct {
	mu            sync.Mutex
	watchers      int
	since         time.Time // the last feed ended, or the monitor started
	followedSince time.Time // the feed is followed since (watchers > 0)
	down          bool      // the outage is in the journal

	gate     *perimeterv1.Gate // the last report; nil: none
	gateAt   time.Time         // when it came
	notUp    time.Time         // reports say not current (gateCurrent) since; zero: current, or none
	gateDown bool              // the table's outage is in the journal
}

// gateCurrent reports whether a report is of a table up with rayd's newest
// snapshot: up, with a snapshot of the feed (not the one rayspa saved),
// the feed's newest not refused. Up on the saved snapshot, or on an
// earlier one, while rayspa follows the feed is a rayspa that takes none
// of rayd's snapshots: what changed since, a revocation, is not in force.
func gateCurrent(g *perimeterv1.Gate) bool {
	return g.GetState() == gateUp && g.GetFromRayd() && !g.GetRefused()
}

func (w *rayspaWatch) start(now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.watchers == 0 {
		w.followedSince = now
	}
	w.watchers++
}

func (w *rayspaWatch) end(now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.watchers--; w.watchers == 0 {
		w.since = now
	}
}

// report takes a rayspa's report of its table.
func (w *rayspaWatch) report(g *perimeterv1.Gate, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case gateCurrent(g):
		w.notUp = time.Time{}
	case w.notUp.IsZero() || w.gate == nil || now.Sub(w.gateAt) >= gateStale:
		// Not current since this report: the one before was, or there was
		// none for a while. A new process does not start the count again:
		// a rayspa that crashes and comes back every minute, its table
		// never in, would never fail the loop.
		w.notUp = now
	}
	w.gate, w.gateAt = g, now
}

// The states a rayspa reports (perimeterv1.Gate.state).
const (
	gateUp     = "up"
	gateBehind = "behind"
	gateNotIn  = "not_in"
	gateNone   = "no_snapshot"
)

// ReportGate takes rayspa's report of its table (R4-40).
func (p *PerimeterServer) ReportGate(ctx context.Context, req *connect.Request[perimeterv1.ReportGateRequest]) (*connect.Response[perimeterv1.ReportGateResponse], error) {
	if !p.rayspaPeer(ctx) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("only rayspa may report its table"))
	}
	g := req.Msg.GetGate()
	switch g.GetState() {
	case gateUp, gateBehind, gateNotIn, gateNone:
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("gate state %q", g.GetState()))
	}
	if len(g.GetVersion()) > 64 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("gate version too long"))
	}
	p.watch.report(g, time.Now())
	return connect.NewResponse(&perimeterv1.ReportGateResponse{}), nil
}

// RayspaLoop is the loop of rayctl status that says whether rayspa
// follows the perimeter, and whether its table is in.
const RayspaLoop = "perimeter"

// RayspaUnknown begins the loop's detail when rayspa follows but reports
// nothing of its table (an older rayspa): rayctl status says "unknown",
// not "ok".
const RayspaUnknown = "unknown: "

// rayspaGrace is how long rayspa may be away, or its table not in,
// before the loop fails: a restart takes seconds, and a rayspa started
// before rayd (at boot) asks again every 30 s at most.
const rayspaGrace = 90 * time.Second

// gateStale: a report older than this is not taken (rayspa reports every
// 30 s; a rayspa rolled back to a version that reports nothing).
const gateStale = 90 * time.Second

// gateFirst: a rayspa that reports does so within seconds of each feed's
// first snapshot; until then its table is not called unknown.
const gateFirst = 20 * time.Second

// MonitorRayspa reports every 10 s whether rayspa follows the perimeter
// feed and has its table in into the health board: an outage longer than
// rayspaGrace fails the loop and goes to the journal at error once, its
// end at info. Not for a node without rayspa (rayd serve -supervise).
func (p *PerimeterServer) MonitorRayspa(ctx context.Context, log *slog.Logger) {
	p.watch.mu.Lock()
	p.watch.since = time.Now()
	p.watch.mu.Unlock()
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			p.reportRayspa(now, log)
		}
	}
}

// reportRayspa is one round of MonitorRayspa: nothing while rayspa has
// been away, or its table not in, less than rayspaGrace (rayd's start,
// rayspa's).
func (p *PerimeterServer) reportRayspa(now time.Time, log *slog.Logger) {
	w := &p.watch
	w.mu.Lock()
	following, away, wasDown := w.watchers > 0, now.Sub(w.since), w.down
	followed := now.Sub(w.followedSince)
	var gate *perimeterv1.Gate
	if w.gate != nil && now.Sub(w.gateAt) < gateStale {
		gate = w.gate
	}
	notUp := time.Duration(0)
	if !w.notUp.IsZero() {
		notUp = now.Sub(w.notUp)
	}
	switch {
	case following:
		w.down = false
	case away >= rayspaGrace:
		w.down = true
	}
	down := w.down
	tableDown := following && gate != nil && !gateCurrent(gate) && notUp >= rayspaGrace
	wasTableDown := w.gateDown
	w.gateDown = tableDown
	w.mu.Unlock()

	switch {
	case following && gate == nil:
		if wasDown {
			log.Info("perimeter: rayspa follows the perimeter again")
		}
		if followed < gateFirst && !wasDown {
			return // a rayspa that reports does so with its first snapshot
		}
		p.Health.Report(RayspaLoop, RayspaUnknown+"rayspa follows the perimeter, its table is not reported "+
			"(a rayspa older than this rayd, or its reports do not arrive); rayctl status as root reads it", nil)
	case following && gateCurrent(gate):
		if wasDown {
			log.Info("perimeter: rayspa follows the perimeter again")
		}
		if wasTableDown {
			log.Info("perimeter: rayspa's table is in again")
		}
		p.Health.Report(RayspaLoop, "rayspa follows the perimeter, its table is in (rayspa "+gate.GetVersion()+")", nil)
	case tableDown:
		err := fmt.Errorf("rayspa follows the perimeter, but its table %s for %v: %s (journalctl -u rayspa -p warning)",
			gateText(gate), notUp.Round(time.Second), gateEffect(gate))
		if !wasTableDown {
			msg := "perimeter down"
			if gate.GetState() == gateUp {
				msg = "perimeter behind rayd"
			}
			log.Error(msg, "err", err)
		}
		p.Health.Done(RayspaLoop, err)
	case following:
		// Not current for less than rayspaGrace: the round before stands.
	case down:
		err := fmt.Errorf("rayspa has not followed the perimeter for %v: no knock opens a port, "+
			"and if it did not come up since a boot the host is open (rayctl status as root; journalctl -u rayspa)", away.Round(time.Second))
		if !wasDown {
			log.Error("perimeter down", "err", err)
		}
		p.Health.Done(RayspaLoop, err)
	}
}

// gateText says where a table that is not current stands.
func gateText(g *perimeterv1.Gate) string {
	switch {
	case g.GetState() == gateUp && !g.GetFromRayd():
		return "is up on the snapshot rayspa saved, not on rayd's (it takes none of rayd's)"
	case g.GetState() == gateUp:
		return "is up on an earlier snapshot of rayd's (it refused the newest)"
	case g.GetState() == gateBehind:
		return "is behind its snapshot (in, a part of the snapshot not)"
	case g.GetState() == gateNone:
		return "has no snapshot to put in (rayspa took none of rayd's)"
	}
	return "is not in"
}

// gateEffect says what a table that is not current means for the host.
func gateEffect(g *perimeterv1.Gate) string {
	switch {
	case g.GetState() == gateUp:
		return "what changed since (admin addresses, revocations, ports) is not in force"
	case g.GetState() == gateBehind:
		return "the last change of the perimeter (admin addresses, a revocation, ports) is not in force"
	case g.GetLeftOver():
		return "the table an earlier rayspa left is in force, frozen: no knock opens a port"
	}
	return "the host is open"
}
