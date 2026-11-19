package main

import (
	"strings"
	"testing"
	"time"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

func TestStaleAllow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	day := int64(24 * 3600)
	devices := []*nodev1.Device{
		{Id: "fresh", Role: "billing", Allow: []string{"198.51.100.7/32"}, CreatedAt: now.Unix() - 60*day, LastCall: now.Unix() - day},
		{Id: "quiet", Role: "billing", Allow: []string{"198.51.100.7/32"}, CreatedAt: now.Unix() - 60*day, LastCall: now.Unix() - 31*day},
		{Id: "never", Role: "support", Allow: []string{"198.51.100.8/32", "2001:db8::/64"}, CreatedAt: now.Unix() - 40*day},
		{Id: "new", Role: "support", Allow: []string{"198.51.100.9/32"}, CreatedAt: now.Unix() - day},
		{Id: "spa", Role: "billing", CreatedAt: now.Unix() - 90*day},
		{Id: "revoked", Role: "billing", Allow: []string{"198.51.100.7/32"}, CreatedAt: now.Unix() - 90*day, RevokedAt: now.Unix() - 50*day},
	}
	got := staleAllow(devices, now)
	if len(got) != 2 || !strings.HasPrefix(got[0], "quiet ") || !strings.Contains(got[0], "no call for 30 days") ||
		!strings.HasPrefix(got[1], "never ") || !strings.Contains(got[1], "never called") || !strings.Contains(got[1], "static (2)") {
		t.Fatalf("stale: %q", got)
	}
}

func TestAccessOf(t *testing.T) {
	if accessOf(nil) != "spa" || accessOf([]string{"198.51.100.7/32"}) != "static (1)" {
		t.Fatal(accessOf(nil), accessOf([]string{"x"}))
	}
}
