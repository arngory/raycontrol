// Package dnsstats reads the counters of the DNS path, which niko-server
// (v0.11.0) gives on stats sockets: a dnstt backend's, and the DNS front's.
// It keeps an hour of a backend's: rayctl metrics shows the counters,
// rayctl status what happened in the last hour (refused session starts,
// dnsauth and seal refusals).
package dnsstats

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Snapshot is what a dnstt backend gives on its stats socket (niko-server
// dnsttserver.StatsSnapshot).
type Snapshot struct {
	Started          int64  `json:"started,omitempty"` // the backend's start, Unix seconds; 0: not said
	Queries          uint64 `json:"queries"`
	MemoHits         uint64 `json:"memo_hits"`
	Sessions         int    `json:"sessions"`
	Handshakes       int    `json:"handshakes"`
	SessionsAdmitted uint64 `json:"sessions_admitted"`
	// Session starts refused, by start packet: a client's retries count
	// again.
	RefusedFull       uint64 `json:"starts_refused_full"`
	RefusedRate       uint64 `json:"starts_refused_rate"`
	RefusedDevice     uint64 `json:"starts_refused_device"`
	SessionsEvicted   uint64 `json:"sessions_evicted"`
	HandshakeTimeouts uint64 `json:"handshake_timeouts"`
	StreamsRefused    uint64 `json:"streams_refused"`
	AuthValid         uint64 `json:"auth_valid"`
	AuthUntagged      uint64 `json:"auth_untagged"`
	AuthRefused       uint64 `json:"auth_refused"`
	AuthThrottled     uint64 `json:"auth_throttled"`
	SealOpened        uint64 `json:"seal_opened"`
	SealUnsealed      uint64 `json:"seal_unsealed"`
	SealRefused       uint64 `json:"seal_refused"`
}

// Read reads a backend's counters: one JSON line given to whoever
// connects, within 2 s and 64 KiB.
func Read(ctx context.Context, path string) (Snapshot, error) {
	var s Snapshot
	err := readJSON(ctx, path, &s)
	return s, err
}

// Front is what the DNS front gives on its stats socket (niko-server
// nikoserver.DNSFrontSnapshot, dns.stats_socket).
type Front struct {
	Started        int64             `json:"started"`
	Queries        map[string]uint64 `json:"queries"` // queries in a zone, by zone
	Malformed      uint64            `json:"malformed"`
	Refused        uint64            `json:"refused"` // outside the zones
	Apex           uint64            `json:"apex"`
	Probes         uint64            `json:"probes"`
	ProbesOverRate uint64            `json:"probes_over_rate"`
	Forwarded      uint64            `json:"forwarded"`
	BackendAway    uint64            `json:"backend_away"`
	Answers        uint64            `json:"answers"`
	Unmatched      uint64            `json:"unmatched"`
	Truncated      uint64            `json:"truncated"`
}

// ReadFront reads the DNS front's counters, as Read a backend's.
func ReadFront(ctx context.Context, path string) (Front, error) {
	var f Front
	err := readJSON(ctx, path, &f)
	return f, err
}

// readJSON reads one JSON value given to whoever connects to a unix
// socket at path, within 2 s and 64 KiB.
func readJSON(ctx context.Context, path string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return err
	}
	defer c.Close()
	if d, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(d)
	}
	return json.NewDecoder(io.LimitReader(c, 64<<10)).Decode(v)
}

// counters are a snapshot's counters, in one order, for Sub and restart.
func (s *Snapshot) counters() []*uint64 {
	return []*uint64{&s.Queries, &s.MemoHits, &s.SessionsAdmitted, &s.RefusedFull, &s.RefusedRate, &s.RefusedDevice,
		&s.SessionsEvicted, &s.HandshakeTimeouts, &s.StreamsRefused, &s.AuthValid, &s.AuthUntagged, &s.AuthRefused,
		&s.AuthThrottled, &s.SealOpened, &s.SealUnsealed, &s.SealRefused}
}

// Sub is what s counted since o: the counters' differences; Started and
// the gauges (sessions, handshakes) are s's.
func (s Snapshot) Sub(o Snapshot) Snapshot {
	d := s
	dc, oc := d.counters(), o.counters()
	for i := range dc {
		*dc[i] -= *oc[i]
	}
	return d
}

// restarted tells whether s comes from another run of the backend than o:
// another start, or a counter that went down.
func (s Snapshot) restarted(o Snapshot) bool {
	if s.Started != o.Started {
		return true
	}
	sc, oc := s.counters(), o.counters()
	for i := range sc {
		if *sc[i] < *oc[i] {
			return true
		}
	}
	return false
}

// Window keeps one backend's snapshots over Span (an hour when zero). Not
// safe for concurrent use.
type Window struct {
	Span   time.Duration
	points []point
}

type point struct {
	at time.Time
	s  Snapshot
}

func (w *Window) span() time.Duration {
	if w.Span > 0 {
		return w.Span
	}
	return time.Hour
}

// Add takes a snapshot read at now. A restart of the backend starts the
// window again.
func (w *Window) Add(now time.Time, s Snapshot) {
	if n := len(w.points); n > 0 && s.restarted(w.points[n-1].s) {
		w.points = w.points[:0]
	}
	w.points = append(w.points, point{now, s})
	// The oldest kept is the last one at least Span old: the window covers
	// the whole Span once it can.
	from := now.Add(-w.span())
	drop := 0
	for drop+1 < len(w.points) && !w.points[drop+1].at.After(from) {
		drop++
	}
	w.points = w.points[drop:]
}

// Delta is what the backend counted over the window and how long that is:
// from the window's oldest snapshot to its newest, or, with one snapshot,
// since the backend started when that was within Span. ok is false when
// there is nothing to tell yet.
func (w *Window) Delta() (d Snapshot, span time.Duration, ok bool) {
	n := len(w.points)
	if n == 0 {
		return d, 0, false
	}
	last := w.points[n-1]
	if n == 1 {
		if last.s.Started == 0 {
			return d, 0, false
		}
		since := last.at.Sub(time.Unix(last.s.Started, 0))
		if since < 0 || since > w.span() {
			return d, 0, false
		}
		return last.s, since, true
	}
	first := w.points[0]
	return last.s.Sub(first.s), last.at.Sub(first.at), true
}

// Summary says, on one line, how many sessions there are and what the
// backend did in the window (d over span, when ok): its queries and new
// sessions, and every refusal it counted.
func Summary(now Snapshot, d Snapshot, span time.Duration, ok bool) string {
	head := plural(now.Sessions, "session")
	if now.Handshakes > 0 {
		head += fmt.Sprintf(" (%d in handshake)", now.Handshakes)
	}
	if !ok {
		return head
	}
	parts := []string{plural64(d.Queries, "query", "queries"), plural64(d.SessionsAdmitted, "new session", "new sessions")}
	for _, e := range []struct {
		n    uint64
		what string
	}{
		{d.RefusedFull, "session starts refused (node full)"},
		{d.RefusedRate, "session starts refused (too fast)"},
		{d.RefusedDevice, "session starts refused (device's limit)"},
		{d.SessionsEvicted, "silent sessions replaced"},
		{d.HandshakeTimeouts, "handshakes timed out"},
		{d.StreamsRefused, "streams refused"},
		{d.AuthRefused, "refused by dnsauth"},
		{d.AuthUntagged, "taken without a dnsauth tag"},
		{d.SealRefused, "refused by the seal"},
		{d.SealUnsealed, "taken unsealed"},
	} {
		if e.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", e.n, e.what))
		}
	}
	return head + "; last " + short(span) + ": " + strings.Join(parts, ", ")
}

func plural(n int, one string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %ss", n, one)
}

func plural64(n uint64, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// short is d as 1h, 1h5m, 12m or 40s.
func short(d time.Duration) string {
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	d = d.Round(time.Minute)
	h, m := d/time.Hour, (d%time.Hour)/time.Minute
	switch {
	case h == 0:
		return fmt.Sprintf("%dm", m)
	case m == 0:
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}
