package main

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/perimeter"
)

// rayspa's STATUS (R4-40): a table left over is one with an input chain,
// looked at on each call, so that a relay's hold (a table without one)
// reads as the open host it is, and a flush ruleset before the first
// snapshot shows. Every line names the process.
func TestStartStatus(t *testing.T) {
	gate := perimeter.NewGate(&perimeter.NFT{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	gate.SetupAtFirstSnapshot()
	input, calls := true, 0
	st := startState{gate: gate, pid: 4242, inForce: func() (bool, error) { calls++; return input, nil }}
	n := st.now()
	if !n.leftOver || !strings.HasPrefix(n.status(), "waiting for rayd: the table an earlier rayspa left is in force") {
		t.Fatalf("an earlier table: %+v %q", n, n.status())
	}
	// A flush ruleset, or a relay's hold only: no input chain.
	input = false
	m := st.now()
	if m == n || m.leftOver || !strings.HasPrefix(m.status(), "PERIMETER DOWN: the host is open until rayd answers") {
		t.Fatalf("no input chain: %+v %q", m, m.status())
	}
	if calls != 2 {
		t.Fatalf("the input chain looked up %d times, want each time", calls)
	}
	for _, s := range []string{n.status(), m.status()} {
		if !strings.HasSuffix(s, "; rayspa "+version+", pid 4242") {
			t.Errorf("%q does not name the process", s)
		}
	}

	up := stateNow{state: perimeter.GateUp, pid: 7}
	if s := up.status(); !strings.HasPrefix(s, "perimeter up: the saved snapshot") {
		t.Errorf("up from the saved snapshot: %q", s)
	}
	up.fromRayd = true
	if s := up.status(); s != "perimeter up: rayd's snapshot; rayspa "+version+", pid 7" {
		t.Errorf("up from rayd: %q", s)
	}
	behind := stateNow{state: perimeter.GateBehind, fromRayd: true, pid: 7}
	if s := behind.status(); !strings.HasPrefix(s, "perimeter behind") {
		t.Errorf("behind: %q", s)
	}
	notIn := stateNow{state: perimeter.GateNotIn, pid: 7}
	if s := notIn.status(); !strings.HasPrefix(s, "PERIMETER DOWN: the host is open, the table is not in") {
		t.Errorf("not in: %q", s)
	}
}

// A READY that cannot be sent is an error to log.
func TestNotifyError(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", t.TempDir()+"/none")
	if err := notify("READY=1"); err == nil {
		t.Fatal("no error from a notify socket that is not there")
	}
	t.Setenv("NOTIFY_SOCKET", "")
	if err := notify("READY=1"); err != nil {
		t.Fatalf("no socket asked for: %v", err)
	}
}
