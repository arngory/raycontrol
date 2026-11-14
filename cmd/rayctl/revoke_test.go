package main

import (
	"strings"
	"testing"
	"time"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/store"
)

// rayctl device revoke says that the user's credentials are new and that
// the user's other devices reconnect after their next fetch (R4-36), and
// says nothing of the kind where nothing changed.
func TestRevokeText(t *testing.T) {
	for _, c := range []struct {
		r          *nodev1.RevokeDeviceResponse
		want, none string
	}{
		{&nodev1.RevokeDeviceResponse{User: "alice", Device: "phone", Credentials: 3},
			"alice's credentials are new (3 services)", ""},
		{&nodev1.RevokeDeviceResponse{User: "alice", Device: "phone", Credentials: 3},
			"other devices are cut too, until they fetch", ""},
		{&nodev1.RevokeDeviceResponse{User: "alice", Device: "phone", Already: true}, "revoked already: nothing changed", "are new"},
		{&nodev1.RevokeDeviceResponse{User: "alice", Device: "phone", Already: true}, "rayctl user renew alice", ""},
		{&nodev1.RevokeDeviceResponse{Invite: true}, "invite d1 withdrawn", "credentials"},
		{&nodev1.RevokeDeviceResponse{User: "carol", Device: "tv"}, "carol has no credentials yet", "cut"},
		{&nodev1.RevokeDeviceResponse{}, "older than v0.27.0", "new"},
	} {
		got := revokeText("d1", c.r)
		if !strings.Contains(got, c.want) || (c.none != "" && strings.Contains(got, c.none)) {
			t.Errorf("%v: %q", c.r, got)
		}
	}
}

// rayctl user renew says what changed and that the user's devices
// reconnect after their next fetch.
func TestRenewText(t *testing.T) {
	if got := renewText(&nodev1.RenewUserResponse{Name: "alice", Credentials: 2}); !strings.Contains(got, "alice's credentials are new (2 credentials)") ||
		!strings.Contains(got, "cut until they fetch") {
		t.Errorf("%q", got)
	}
	if got := renewText(&nodev1.RenewUserResponse{Name: "carol"}); !strings.Contains(got, "nothing to renew") {
		t.Errorf("%q", got)
	}
}

// rayctl restore lists what it kept revoked, and warns of what it cannot
// know: the devices this node's database has no record of.
func TestRestoreCarryText(t *testing.T) {
	made := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	if got := restoreCarryText(nil, nil, made); got != "" {
		t.Errorf("nothing to say: %q", got)
	}
	got := restoreCarryText([]store.CarriedDevice{{ID: "d1", User: "alice", Name: "phone"}},
		[]store.CarriedDevice{{ID: "d2", User: "bob", Name: "tv"}}, made)
	for _, want := range []string{"d1  alice/phone", "credentials are new", "warning: this node's database has no record of 1 devices",
		"2026-11-01T12:00:00Z cannot be known", "d2  bob/tv"} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
}
