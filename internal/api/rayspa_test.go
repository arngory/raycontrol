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
