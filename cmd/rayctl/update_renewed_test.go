package main

import (
	"strings"
	"testing"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// After an update, one line for the users the migration renewed (R4-36):
// only the audit lines since the update began count, and an update that
// renewed nobody prints nothing.
func TestRenewedText(t *testing.T) {
	line := func(ts int64, action string) *nodev1.AuditEntry {
		return &nodev1.AuditEntry{Time: ts, Action: action, Target: "x: 1 credentials new"}
	}
	const since = 1000
	if got := renewedText(nil, since, 1000); got != "" {
		t.Errorf("no audit: %q", got)
	}
	// Newest first; one renewal before the update does not count.
	old := []*nodev1.AuditEntry{line(1001, "apply"), line(999, "user.renew:revoked-before")}
	if got := renewedText(old, since, 1000); got != "" {
		t.Errorf("nobody renewed: %q", got)
	}
	entries := []*nodev1.AuditEntry{line(1002, "apply"), line(1001, "user.renew:revoked-before"),
		line(1001, "user.renew:revoked-before"), line(1000, "user.renew"), line(999, "user.renew:revoked-before")}
	got := renewedText(entries, since, 1000)
	if !strings.HasPrefix(got, "2 users have new credentials: each had a device revoked before v0.27.0") ||
		!strings.Contains(got, "reconnect by themselves at their next connection check") {
		t.Errorf("%q", got)
	}
	if got := renewedText(entries[:2], since, 1000); !strings.HasPrefix(got, "1 user has new credentials") {
		t.Errorf("one: %q", got)
	}
	// The list full with lines of the update: a lower bound.
	if got := renewedText(entries[:4], since, 4); !strings.HasPrefix(got, "at least 2 users have") {
		t.Errorf("full list: %q", got)
	}
}
