package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/roots"
)

// rootsReporter shows the roots of the node's own outbound TLS (R4-41) in
// rayctl status, as the loop tls-roots: which roots, and the connections
// they refused (roots.RefusalWindow, under these roots, not cleared by a
// connection to the same host since), with the last one's host (one of
// the node's own peers: never anything of a user's). A refused download
// the system store then let through (the releases) is a warning beside
// it, not a failure.
//
// The log has a line per host and minute at most, with the count of the
// connections refused since its previous line: a DoH upstream behind an
// interceptor is refused at the users' query rate.
type rootsReporter struct {
	hb  *health.Board
	log *slog.Logger
	now func() time.Time // time.Now when nil

	mu    sync.Mutex
	pool  *roots.Pool
	hosts map[string]*hostLog
}

// hostLog is what the log said of a host, and what it has not said yet.
type hostLog struct {
	said    time.Time // its last line
	pending uint64    // refused since
	err     string    // the last reason
}

// logEvery is how often, at most, the log has a line of one host.
const logEvery = time.Minute

func (r *rootsReporter) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

func (r *rootsReporter) report(s roots.Status) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.Pool != r.pool {
		r.pool = s.Pool
		if s.Pool.Err != nil {
			r.log.Warn("tls roots: the settings are not followed, the embedded list only", "err", s.Pool.Err)
		} else {
			r.log.Info("tls roots", "roots", s.Pool.String())
		}
	}
	if ev := s.Event; ev != nil && !ev.Rescued {
		// A rescued one is in the log already, by its download's warning.
		if r.hosts == nil {
			r.hosts = map[string]*hostLog{}
		}
		h := r.hosts[ev.Host]
		if h == nil {
			h = &hostLog{}
			r.hosts[ev.Host] = h
		}
		h.pending++
		h.err = ev.Err
		if now := r.clock(); now.Sub(h.said) >= logEvery {
			r.say(ev.Host, h, now)
		}
	}
	r.hb.Report("tls-roots", rootsDetail(s), rootsError(s))
}

// say writes host's line: the connections refused since its last one.
func (r *rootsReporter) say(host string, h *hostLog, now time.Time) {
	attrs := []any{"host", host, "err", h.err, "refused", h.pending}
	if !h.said.IsZero() {
		attrs = append(attrs, "since", h.said.Format(time.RFC3339))
	}
	r.log.Warn("outbound TLS refused by the node's roots", attrs...)
	h.said, h.pending = now, 0
}

// flush writes the lines held back, and forgets hosts quiet for an hour.
func (r *rootsReporter) flush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock()
	for host, h := range r.hosts {
		switch {
		case h.pending > 0 && now.Sub(h.said) >= logEvery:
			r.say(host, h, now)
		case h.pending == 0 && now.Sub(h.said) > time.Hour:
			delete(r.hosts, host)
		}
	}
}

// run reports t every minute, until ctx ends: refusals age out
// (roots.RefusalWindow) without a connection to tell, and the log's held
// back lines go out.
func (r *rootsReporter) run(ctx context.Context, t *roots.Trust) {
	tick := time.NewTicker(logEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			r.flush()
			r.report(t.Status())
		}
	}
}

// fetchLog is the log of rayd's release checks: the warning of a fallback
// to the system store (internal/release).
func fetchLog(log *slog.Logger) func(format string, args ...any) {
	return func(format string, args ...any) { log.Warn("update check: " + fmt.Sprintf(format, args...)) }
}

func connections(n uint64) string {
	if n == 1 {
		return "1 connection"
	}
	return fmt.Sprintf("%d connections", n)
}

// rootsDetail is the roots, and the warning of downloads the system store
// let through.
func rootsDetail(s roots.Status) string {
	d := s.Pool.String()
	if s.Rescued > 0 {
		d += fmt.Sprintf("; warning: %s to %s refused by these roots went through with the system store in the last %v "+
			"(a signed release download; behind a TLS-intercepting proxy: rayctl roots)",
			connections(s.Rescued), s.RescuedHost, roots.RefusalWindow)
	}
	return d
}

// rootsError is what status shows as failing: connections these roots
// refused in the last roots.RefusalWindow, to hosts not reached since, or
// settings that are not followed.
func rootsError(s roots.Status) error {
	switch {
	case s.Refused > 0:
		return fmt.Errorf("%s refused by these roots in the last %v, the last to %s: %s; %s (behind a TLS-intercepting proxy or with a private CA: rayctl roots)",
			connections(s.Refused), roots.RefusalWindow, s.LastHost, s.LastErr, s.Pool)
	case s.Pool.Err != nil:
		return fmt.Errorf("%s (rayctl roots)", s.Pool)
	}
	return nil
}
