package api

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

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

	p.watch.start()
	p.reportRayspa(start.Add(3*time.Minute), log)
	p.reportRayspa(start.Add(3*time.Minute+10*time.Second), log)
	if l, _ := loop(); l.Failing() || strings.Count(buf.String(), "level=INFO") != 1 {
		t.Fatalf("back: %+v\n%s", l, buf.String())
	}
	// A restart: away again, but for less than the grace.
	p.watch.end(start.Add(4 * time.Minute))
	p.reportRayspa(start.Add(4*time.Minute+20*time.Second), log)
	if l, _ := loop(); l.Failing() || strings.Count(buf.String(), "level=ERROR") != 1 {
		t.Fatalf("a restart: %+v\n%s", l, buf.String())
	}
}
