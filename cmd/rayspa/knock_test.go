package main

import (
	"bytes"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/perimeter"
	"github.com/arngory/raycontrol/internal/spa"
)

// A refused knock warns once a minute by kind, with the device's ID where
// there is one and never the source's address (R4-3).
func TestHandleKnockWarnings(t *testing.T) {
	var out bytes.Buffer
	log := slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelWarn}))
	warn := everyMinute()
	src := netip.MustParseAddr("198.51.100.77")
	for _, err := range []error{spa.ErrQuota, perimeter.ErrAddrs, spa.ErrBusy, perimeter.ErrFlood, spa.ErrAuth} {
		check := func(netip.Addr, netip.Addr, []byte) (spa.Grant, error) { return spa.Grant{DeviceID: "d7"}, err }
		for range 3 {
			handleKnock(log, warn, check, src, netip.Addr{}, nil)
		}
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("%d warnings, want one of each of four kinds:\n%s", len(lines), out.String())
	}
	if strings.Contains(out.String(), src.String()) {
		t.Fatalf("the source's address in the journal:\n%s", out.String())
	}
	for _, l := range lines[:2] {
		if !strings.Contains(l, "device=d7") {
			t.Errorf("no device ID: %s", l)
		}
	}
}
