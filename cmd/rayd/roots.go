package main

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/roots"
)

// rootsReporter shows the roots of the node's own outbound TLS (R4-41) in
// rayctl status, as the loop tls-roots: which roots, and the connections
// they refused since rayd started, with the last one's host (one of the
// node's own peers: never anything of a user's).
type rootsReporter struct {
	hb  *health.Board
	log *slog.Logger

	mu      sync.Mutex
	pool    *roots.Pool
	refused uint64
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
	if s.Refused > r.refused {
		r.refused = s.Refused
		r.log.Warn("outbound TLS refused by the node's roots", "host", s.LastHost, "err", s.LastErr, "since_start", s.Refused)
	}
	r.hb.Report("tls-roots", s.Pool.String(), rootsError(s))
}

// fetchLog is the log of rayd's release checks: the warning of a fallback
// to the system store (internal/release).
func fetchLog(log *slog.Logger) func(format string, args ...any) {
	return func(format string, args ...any) { log.Warn("update check: " + fmt.Sprintf(format, args...)) }
}

// rootsError is what status shows as failing: refused connections, or
// settings that are not followed.
func rootsError(s roots.Status) error {
	switch {
	case s.Refused > 0:
		n := "1 connection"
		if s.Refused > 1 {
			n = fmt.Sprintf("%d connections", s.Refused)
		}
		return fmt.Errorf("%s refused since rayd started, the last to %s: %s; %s (behind a TLS-intercepting proxy or with a private CA: rayctl roots)",
			n, s.LastHost, s.LastErr, s.Pool)
	case s.Pool.Err != nil:
		return fmt.Errorf("%s (rayctl roots)", s.Pool)
	}
	return nil
}
