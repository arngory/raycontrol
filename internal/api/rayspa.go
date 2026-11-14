package api

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// rayspaWatch is what rayd knows of rayspa (docs/08-decisions.md, R4-40):
// whether it follows the perimeter feed. rayd cannot read the kernel's
// table (it has no CAP_NET_ADMIN); a rayspa that follows has its table in
// within a second of the snapshot it gets at once. One that does not may
// have left its table (closed: no knock is answered) or none (a boot it
// did not come up in: the host is open). rayctl status as root says which.
type rayspaWatch struct {
	mu       sync.Mutex
	watchers int
	since    time.Time // the last feed ended, or the monitor started
	down     bool      // the outage is in the journal
}

func (w *rayspaWatch) start() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.watchers++
}

func (w *rayspaWatch) end(now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.watchers--; w.watchers == 0 {
		w.since = now
	}
}

// RayspaLoop is the loop of rayctl status that says whether rayspa
// follows the perimeter.
const RayspaLoop = "perimeter"

// rayspaGrace is how long rayspa may be away before the loop fails: a
// restart takes seconds, and a rayspa started before rayd (at boot) asks
// again every 30 s at most.
const rayspaGrace = 90 * time.Second

// MonitorRayspa reports every 10 s whether rayspa follows the perimeter
// feed into the health board: an outage longer than rayspaGrace fails the
// loop and goes to the journal at error once, its end at info. Not for a
// node without rayspa (rayd serve -supervise).
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
// been away less than rayspaGrace and never came (rayd's start).
func (p *PerimeterServer) reportRayspa(now time.Time, log *slog.Logger) {
	w := &p.watch
	w.mu.Lock()
	following, away, wasDown := w.watchers > 0, now.Sub(w.since), w.down
	switch {
	case following:
		w.down = false
	case away >= rayspaGrace:
		w.down = true
	}
	down := w.down
	w.mu.Unlock()
	switch {
	case following:
		if wasDown {
			log.Info("perimeter: rayspa follows the perimeter again")
		}
		p.Health.Report(RayspaLoop, "rayspa follows the perimeter", nil)
	case down:
		err := fmt.Errorf("rayspa has not followed the perimeter for %v: no knock opens a port, "+
			"and if it did not come up since a boot the host is open (rayctl status as root; journalctl -u rayspa)", away.Round(time.Second))
		if !wasDown {
			log.Error("perimeter down", "err", err)
		}
		p.Health.Done(RayspaLoop, err)
	}
}
