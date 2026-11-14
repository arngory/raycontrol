package main

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/roots"
)

// TestRootsReporter: rayctl status shows which roots, then, once a
// connection is refused, the count since start and the last host.
func TestRootsReporter(t *testing.T) {
	hb := &health.Board{}
	r := &rootsReporter{hb: hb, log: slog.New(slog.DiscardHandler)}
	p := roots.Build(roots.Settings{}, nil)
	r.report(roots.Status{Pool: p})
	l := hb.Loops()[0]
	if l.Name != "tls-roots" || l.Failing() || l.Detail != "embedded 91 roots of 2026-11-14; system store not added; no extra file" {
		t.Fatalf("at start %+v", l)
	}
	r.report(roots.Status{Pool: p, Refused: 2, LastHost: "api.cloudflare.com", LastErr: "x509: certificate signed by unknown authority"})
	l = hb.Loops()[0]
	if !l.Failing() || !strings.Contains(l.Err, "2 connections refused since rayd started, the last to api.cloudflare.com: x509: certificate signed by unknown authority") ||
		!strings.Contains(l.Err, "rayctl roots") {
		t.Fatalf("refused %+v", l)
	}
	bad := roots.Build(roots.Settings{File: "/nonexistent/roots.pem"}, nil)
	if err := rootsError(roots.Status{Pool: bad}); err == nil || !strings.Contains(err.Error(), "not followed") {
		t.Fatalf("settings not followed: %v", err)
	}
}
