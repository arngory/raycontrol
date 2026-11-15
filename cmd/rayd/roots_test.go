package main

import (
	"bytes"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/roots"
)

// TestRootsReporter: rayctl status shows which roots, then, once a
// connection is refused, the count in the window and the last host; it
// recovers when the refusals are gone (aged out, cleared, a new pool). A
// download the system store let through is a warning, not a failure.
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
	if !l.Failing() || !strings.Contains(l.Err, "2 connections refused by these roots in the last 12h0m0s, the last to api.cloudflare.com: x509: certificate signed by unknown authority") ||
		!strings.Contains(l.Err, "rayctl roots") {
		t.Fatalf("refused %+v", l)
	}
	r.report(roots.Status{Pool: p, Total: 2})
	if l = hb.Loops()[0]; l.Failing() {
		t.Fatalf("no refusal left, still failing: %+v", l)
	}
	r.report(roots.Status{Pool: p, Total: 3, Rescued: 1, RescuedHost: "github.com"})
	if l = hb.Loops()[0]; l.Failing() || !strings.Contains(l.Detail, "warning: 1 connection to github.com refused by these roots went through with the system store") {
		t.Fatalf("rescued: %+v", l)
	}
	bad := roots.Build(roots.Settings{File: "/nonexistent/roots.pem"}, nil)
	if err := rootsError(roots.Status{Pool: bad}); err == nil || !strings.Contains(err.Error(), "not followed") {
		t.Fatalf("settings not followed: %v", err)
	}
}

// TestRootsReporterRecovers: through a trust, the loop fails at a refusal
// and is ok again once the same host is reached.
func TestRootsReporterRecovers(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	hb := &health.Board{}
	r := &rootsReporter{hb: hb, log: slog.New(slog.DiscardHandler)}
	tr := &roots.Trust{Fixed: &roots.Settings{System: true}, Report: r.report, System: func() (*x509.CertPool, error) {
		p := x509.NewCertPool()
		p.AddCert(srv.Certificate())
		return p, nil
	}}
	tr.Refused("127.0.0.1", errors.New("x509: certificate signed by unknown authority"))
	if l := hb.Loops()[0]; !l.Failing() {
		t.Fatalf("refused, not failing: %+v", l)
	}
	resp, err := tr.Client(0).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if l := hb.Loops()[0]; l.Failing() {
		t.Fatalf("reached, still failing: %+v", l)
	}
}

// TestRootsLog: one line per host and minute, with the count since the
// line before; the rest when the minute is over. The line names the
// peer's host and the reason, nothing of the request (a DoH question).
func TestRootsLog(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	var buf bytes.Buffer
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	r := &rootsReporter{hb: &health.Board{}, log: slog.New(slog.NewTextHandler(&buf, nil)), now: func() time.Time { return now }}
	tr := &roots.Trust{Fixed: &roots.Settings{}, Report: r.report}
	c := tr.Client(0)
	for range 50 {
		if resp, err := c.Get(srv.URL + "/dns-query?dns=AAABAAABAAAAAAAAB3NlY3JldAd1c2VyLWRvbWFpbgAAAQAB"); err == nil {
			_ = resp.Body.Close()
			t.Fatal("accepted")
		}
	}
	other := errors.New("x509: certificate signed by unknown authority")
	tr.Refused("dns.quad9.net", other)
	lines := func() []string {
		var out []string
		for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if strings.Contains(l, "outbound TLS refused") {
				out = append(out, l)
			}
		}
		return out
	}
	got := lines()
	if len(got) != 2 || !strings.Contains(got[0], "host=127.0.0.1") || !strings.Contains(got[0], "refused=1") || !strings.Contains(got[1], "host=dns.quad9.net") {
		t.Fatalf("first lines %q", got)
	}
	now = now.Add(30 * time.Second)
	r.flush()
	if len(lines()) != 2 {
		t.Fatalf("a line within the minute: %q", lines())
	}
	now = now.Add(31 * time.Second)
	r.flush()
	got = lines()
	if len(got) != 3 || !strings.Contains(got[2], "host=127.0.0.1") || !strings.Contains(got[2], "refused=49") || !strings.Contains(got[2], "since=2026-11-14T12:00:00Z") {
		t.Fatalf("after the minute %q", got)
	}
	for _, l := range got {
		if strings.Contains(l, "dns-query") || strings.Contains(l, "AAAB") || strings.Contains(l, srv.URL) {
			t.Errorf("the request in the log: %s", l)
		}
	}
	// Quiet for an hour: forgotten.
	now = now.Add(2 * time.Hour)
	r.flush()
	if len(r.hosts) != 0 {
		t.Fatalf("hosts kept: %v", r.hosts)
	}
}
