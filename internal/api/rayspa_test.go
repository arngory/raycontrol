package api

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/health"
)

// rayd's view of rayspa (R4-40): quiet while rayd starts, a failed loop and
// one error line once rayspa stays away, back to ok and one info line when
// it follows again.
func TestMonitorRayspa(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	board := &health.Board{}
	p := &PerimeterServer{Server: &Server{Health: board}}
	start := time.Unix(1767225600, 0)
	p.watch.since = start
	loop := func() (health.Loop, bool) {
		for _, l := range board.Loops() {
			if l.Name == RayspaLoop {
				return l, true
			}
		}
		return health.Loop{}, false
	}

	p.reportRayspa(start.Add(30*time.Second), log)
	if _, ok := loop(); ok || buf.Len() != 0 {
		t.Fatalf("within the grace: a loop, or %q", buf.String())
	}
	for i := range 3 {
		p.reportRayspa(start.Add(rayspaGrace+time.Duration(i)*10*time.Second), log)
	}
	l, ok := loop()
	if !ok || !l.Failing() || !strings.Contains(l.Err, "host is open") {
		t.Fatalf("away: %+v", l)
	}
	if n := strings.Count(buf.String(), "level=ERROR"); n != 1 {
		t.Fatalf("%d error lines:\n%s", n, buf.String())
	}

	p.watch.start(start.Add(3 * time.Minute))
	p.reportRayspa(start.Add(3*time.Minute), log)
	p.reportRayspa(start.Add(3*time.Minute+10*time.Second), log)
	// It reports nothing of its table (a rayspa before ReportGate): not
	// failed, not ok, unknown.
	if l, _ := loop(); l.Failing() || strings.Count(buf.String(), "level=INFO") != 1 || !strings.HasPrefix(l.Detail, RayspaUnknown) {
		t.Fatalf("back: %+v\n%s", l, buf.String())
	}
	// A restart: away again, but for less than the grace.
	p.watch.end(start.Add(4 * time.Minute))
	p.reportRayspa(start.Add(4*time.Minute+20*time.Second), log)
	if l, _ := loop(); l.Failing() || strings.Count(buf.String(), "level=ERROR") != 1 {
		t.Fatalf("a restart: %+v\n%s", l, buf.String())
	}
}

// rayspa follows the feed but its table is not in (a kernel refusing the
// ruleset at each try): the loop fails after the same grace, says the
// host is open, logs once; up again, ok. A report that stops coming (a
// rollback to a rayspa that sends none) reads as unknown, not as the last
// state.
func TestMonitorRayspaGate(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	board := &health.Board{}
	p := &PerimeterServer{Server: &Server{Health: board}}
	start := time.Unix(1767225600, 0)
	p.watch.since = start
	loop := func() health.Loop {
		for _, l := range board.Loops() {
			if l.Name == RayspaLoop {
				return l
			}
		}
		return health.Loop{}
	}
	at := func(d time.Duration) time.Time { return start.Add(d) }
	p.watch.start(at(time.Second))
	notIn := &perimeterv1.Gate{State: gateNotIn, Version: "v0.27.1", Pid: 77}
	for d := 2 * time.Second; d < rayspaGrace; d += 10 * time.Second {
		p.watch.report(notIn, at(d))
		p.reportRayspa(at(d), log)
	}
	if l := loop(); l.Failing() || buf.Len() != 0 {
		t.Fatalf("within the grace: %+v %q", l, buf.String())
	}
	for d := rayspaGrace + 2*time.Second; d < 3*time.Minute; d += 10 * time.Second {
		p.watch.report(notIn, at(d))
		p.reportRayspa(at(d), log)
	}
	if l := loop(); !l.Failing() || !strings.Contains(l.Err, "not in") || !strings.Contains(l.Err, "the host is open") {
		t.Fatalf("not in: %+v", l)
	}
	if n := strings.Count(buf.String(), "level=ERROR"); n != 1 {
		t.Fatalf("%d error lines:\n%s", n, buf.String())
	}
	left := &perimeterv1.Gate{State: gateNotIn, LeftOver: true, Pid: 77}
	p.watch.report(left, at(3*time.Minute))
	p.reportRayspa(at(3*time.Minute), log)
	if l := loop(); !l.Failing() || !strings.Contains(l.Err, "an earlier rayspa left") {
		t.Fatalf("left over: %+v", l)
	}

	up := &perimeterv1.Gate{State: gateUp, FromRayd: true, Version: "v0.27.1", Pid: 77}
	p.watch.report(up, at(4*time.Minute))
	p.reportRayspa(at(4*time.Minute), log)
	if l := loop(); l.Failing() || !strings.Contains(l.Detail, "its table is in") || !strings.Contains(buf.String(), "table is in again") {
		t.Fatalf("up: %+v\n%s", l, buf.String())
	}
	// No report for longer than gateStale.
	p.reportRayspa(at(4*time.Minute+gateStale), log)
	if l := loop(); l.Failing() || !strings.HasPrefix(l.Detail, RayspaUnknown) {
		t.Fatalf("stale: %+v", l)
	}

	// The handler: rayspa's (or root's) only, known states only.
	if _, err := p.ReportGate(context.Background(), connect.NewRequest(&perimeterv1.ReportGateRequest{Gate: up})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("no peer: %v", err)
	}
	ctx := context.WithValue(context.Background(), peerKey{}, &ucred{Uid: 0})
	if _, err := p.ReportGate(ctx, connect.NewRequest(&perimeterv1.ReportGateRequest{Gate: &perimeterv1.Gate{State: "open"}})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("a state rayd does not know: %v", err)
	}
	if _, err := p.ReportGate(ctx, connect.NewRequest(&perimeterv1.ReportGateRequest{Gate: up})); err != nil {
		t.Fatal(err)
	}
}

// monitor is a PerimeterServer whose rayspa loop is watched from start.
func monitor(t *testing.T) (p *PerimeterServer, loop func() health.Loop, log *slog.Logger, buf *bytes.Buffer) {
	t.Helper()
	buf = &bytes.Buffer{}
	log = slog.New(slog.NewTextHandler(buf, nil))
	board := &health.Board{}
	p = &PerimeterServer{Server: &Server{Health: board}}
	loop = func() health.Loop {
		for _, l := range board.Loops() {
			if l.Name == RayspaLoop {
				return l
			}
		}
		return health.Loop{}
	}
	return p, loop, log, buf
}

// A rayspa that crashes and comes back every minute, its table never in:
// each process reports not_in with a pid of its own, and follows the feed
// for a while. The count of not up is not restarted by a new pid, only by
// an up report or a gap of reports longer than gateStale: the loop fails.
func TestMonitorRayspaCrashLoop(t *testing.T) {
	p, loop, log, _ := monitor(t)
	start := time.Unix(1767225600, 0)
	p.watch.since = start
	at := func(d time.Duration) time.Time { return start.Add(d) }
	failedAt := time.Duration(0)
	for m := range 10 {
		run := time.Duration(m) * time.Minute
		p.watch.start(at(run + time.Second))
		for d := run; d < run+time.Minute; d += 10 * time.Second {
			if (d-run)%(30*time.Second) == 0 { // at its start, then every 30 s
				p.watch.report(&perimeterv1.Gate{State: gateNotIn, Version: "v0.27.1", Pid: uint32(100 + m)}, at(d+2*time.Second))
			}
			if d-run == 40*time.Second {
				p.watch.end(at(d)) // the crash
			}
			p.reportRayspa(at(d+3*time.Second), log)
			if failedAt == 0 && loop().Failing() {
				failedAt = d
			}
		}
	}
	if l := loop(); !l.Failing() || !strings.Contains(l.Err, "is not in") || failedAt > 3*time.Minute {
		t.Fatalf("a crash loop: failed at %v, %+v", failedAt, l)
	}
	// Up again, then a gap longer than gateStale: a new count.
	p.watch.start(at(11 * time.Minute))
	p.watch.report(&perimeterv1.Gate{State: gateUp, FromRayd: true, Pid: 200}, at(11*time.Minute))
	p.reportRayspa(at(11*time.Minute), log)
	if l := loop(); l.Failing() {
		t.Fatalf("up: %+v", l)
	}
	p.watch.report(&perimeterv1.Gate{State: gateNotIn, Pid: 200}, at(12*time.Minute))
	p.watch.report(&perimeterv1.Gate{State: gateNotIn, Pid: 201}, at(12*time.Minute+gateStale))
	p.reportRayspa(at(12*time.Minute+gateStale+time.Second), log)
	if l := loop(); l.Failing() {
		t.Fatalf("a new count after a gap: %+v", l)
	}
}

// rayspa up on its saved snapshot while every snapshot of rayd's fails
// its checks (from_rayd false), or up on an earlier snapshot of rayd's
// while it refuses the newest (refused): the table is in, but what changed
// since, a revocation, is not. For longer than the grace while rayspa
// follows the feed, the loop fails with its own reason; a snapshot of
// rayd's taken, ok again. At rayspa's start the saved snapshot is up for
// a moment: no failure within the grace.
func TestMonitorRayspaBehindRayd(t *testing.T) {
	for _, c := range []struct {
		name   string
		behind *perimeterv1.Gate
		reason string
	}{
		{"the saved snapshot", &perimeterv1.Gate{State: gateUp, Version: "v0.27.1", Pid: 7}, "up on the snapshot rayspa saved, not on rayd's"},
		{"an earlier snapshot", &perimeterv1.Gate{State: gateUp, FromRayd: true, Refused: true, Version: "v0.27.1", Pid: 7},
			"up on an earlier snapshot of rayd's (it refused the newest)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, loop, log, buf := monitor(t)
			start := time.Unix(1767225600, 0)
			p.watch.since = start
			at := func(d time.Duration) time.Time { return start.Add(d) }
			up := &perimeterv1.Gate{State: gateUp, FromRayd: true, Version: "v0.27.1", Pid: 7}
			p.watch.start(at(time.Second))
			p.watch.report(up, at(2*time.Second))
			p.reportRayspa(at(10*time.Second), log)
			for d := 20 * time.Second; d < 20*time.Second+rayspaGrace; d += 10 * time.Second {
				p.watch.report(c.behind, at(d))
				p.reportRayspa(at(d), log)
			}
			if l := loop(); l.Failing() || !strings.Contains(l.Detail, "its table is in") {
				t.Fatalf("within the grace: %+v", l)
			}
			for d := 20*time.Second + rayspaGrace; d < 4*time.Minute; d += 10 * time.Second {
				p.watch.report(c.behind, at(d))
				p.reportRayspa(at(d), log)
			}
			l := loop()
			if !l.Failing() || !strings.Contains(l.Err, c.reason) || !strings.Contains(l.Err, "revocations") || strings.Contains(l.Err, "host is open") {
				t.Fatalf("behind: %+v", l)
			}
			if n := strings.Count(buf.String(), "perimeter behind rayd"); n != 1 || strings.Contains(buf.String(), "perimeter down") {
				t.Fatalf("journal:\n%s", buf.String())
			}
			p.watch.report(up, at(4*time.Minute))
			p.reportRayspa(at(4*time.Minute), log)
			if l := loop(); l.Failing() {
				t.Fatalf("rayd's snapshot taken: %+v", l)
			}
		})
	}
}
