package main

import (
	"strings"
	"testing"
	"time"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// -overlap is refused before anything is revoked on a node of a release
// before v0.31.0, which would revoke without it; a later release or a dev
// build goes on (review N2).
func TestOverlapKnown(t *testing.T) {
	for v, ok := range map[string]bool{"v0.30.2": false, "v0.27.0": false, "v0.31.0": true, "v0.32.1": true, "dev": true, "": true} {
		err := overlapKnown(v)
		if (err == nil) != ok {
			t.Errorf("%q: %v", v, err)
		}
		if err != nil && (!strings.Contains(err.Error(), "Nothing revoked") || !strings.Contains(err.Error(), v)) {
			t.Errorf("%q: %v", v, err)
		}
	}
}

// What rayctl says besides the answer: the older node's note (for -json on
// stderr too), the user's last device, a device revoked with overlap
// before whose secret is still accepted (review N2, N3, N6).
func TestRevokeNotes(t *testing.T) {
	until := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC).Unix()
	older := &nodev1.RevokeDeviceResponse{User: "alice", Device: "phone", Credentials: 3}
	if got := revokeNote(true, older); !strings.Contains(got, "older than v0.31.0") {
		t.Errorf("%q", got)
	}
	for _, r := range []*nodev1.RevokeDeviceResponse{
		{User: "alice", Device: "phone", Credentials: 3, SwitchAt: until - 3600, Until: until},
		{User: "alice", Device: "phone", Already: true},
		{Invite: true},
		{User: "carol", Device: "tv"},
	} {
		if got := revokeNote(true, r); got != "" {
			t.Errorf("%v: %q", r, got)
		}
	}
	if got := revokeNote(false, older); got != "" {
		t.Errorf("without overlap: %q", got)
	}
	last := lastDeviceWarning("d1", &nodev1.RevokeDeviceResponse{User: "alice", Until: until})
	for _, want := range []string{"d1 was alice's last active device", "until 2026-11-21 12:00 UTC", "rayctl user renew alice"} {
		if !strings.Contains(last, want) {
			t.Errorf("no %q in %q", want, last)
		}
	}
	again := revokeText("d1", false, &nodev1.RevokeDeviceResponse{User: "alice", Device: "phone", Already: true, Until: until})
	for _, want := range []string{"revoked already, with overlap", "still\naccepted until 2026-11-21 12:00 UTC", "rayctl user renew alice"} {
		if !strings.Contains(again, want) {
			t.Errorf("no %q in %q", want, again)
		}
	}
}
