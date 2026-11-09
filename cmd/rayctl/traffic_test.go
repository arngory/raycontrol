package main

import (
	"testing"
	"time"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

func TestTrafficColumns(t *testing.T) {
	for n, want := range map[int64]string{0: "0", 512: "512", 1536: "1.5K", 12 << 30: "12.0G", 1<<40 + 1<<39: "1.5T"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
	now := time.Now()
	u := &nodev1.User{Name: "a", Enabled: true}
	if usedOf(u) != "-" || stateOf(u, now) != "active" {
		t.Fatalf("no limit: %q %q", usedOf(u), stateOf(u, now))
	}
	u.TrafficLimitBytes, u.TrafficUsedBytes, u.TrafficPeriod, u.TrafficResetDay = 50<<30, 12<<30, "monthly", 15
	if usedOf(u) != "12.0G/50G" || periodOf(u) != "monthly, day 15" {
		t.Fatalf("%q %q", usedOf(u), periodOf(u))
	}
	u.TrafficExhausted = true
	if usedOf(u) != "12.0G/50G (over)" || stateOf(u, now) != "exhausted" {
		t.Fatalf("%q %q", usedOf(u), stateOf(u, now))
	}
	u.TrafficExhausted, u.Enabled = false, false
	if stateOf(u, now) != "disabled" {
		t.Fatal(stateOf(u, now))
	}
	u.Enabled, u.ExpiresAt = true, now.Unix()-1
	if stateOf(u, now) != "expired" {
		t.Fatal(stateOf(u, now))
	}
	u.TrafficPeriod = "none"
	if periodOf(u) != "none" || whenUTC(0) != "-" || whenUTC(1767225600) != "2026-01-01 00:00Z" {
		t.Fatalf("%q %q", periodOf(u), whenUTC(1767225600))
	}
}
