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
			"alice's credentials are new (3 credentials)", "services"},
		{&nodev1.RevokeDeviceResponse{User: "alice", Device: "phone", Credentials: 3},
			"other devices are cut too, until they fetch", ""},
		{&nodev1.RevokeDeviceResponse{User: "alice", Device: "phone", Already: true}, "revoked already: nothing changed", "are new"},
		{&nodev1.RevokeDeviceResponse{User: "alice", Device: "phone", Already: true}, "rayctl user renew alice", ""},
		{&nodev1.RevokeDeviceResponse{Invite: true}, "invite d1 withdrawn", "credentials"},
		{&nodev1.RevokeDeviceResponse{User: "carol", Device: "tv"}, "carol has no credentials yet", "cut"},
		{&nodev1.RevokeDeviceResponse{}, "older than v0.27.0", "new"},
	} {
		got := revokeText("d1", false, c.r)
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
	if got := restoreCarryText(store.Restored{}, made); got != "" {
		t.Errorf("nothing to say: %q", got)
	}
	got := restoreCarryText(store.Restored{
		Kept:    7,
		Carried: []store.CarriedDevice{{ID: "d1", User: "alice", Name: "phone"}},
		Unknown: []store.CarriedDevice{{ID: "d2", User: "bob", Name: "tv"}},
		New:     []store.Renewal{{User: "carol", Why: "deleted here since the backup"}, {User: "dave", Why: "a device added and revoked here since the backup"}},
		Added: []store.AddedDevice{{CarriedDevice: store.CarriedDevice{ID: "d3", User: "dave", Name: "watch"}, Revoked: true},
			{CarriedDevice: store.CarriedDevice{ID: "d4", User: "erin", Name: "tablet"}}},
	}, made)
	for _, want := range []string{"stay as they are on this node now for 7 users", "d1  alice/phone", "credentials are new",
		"added here since the backup, so not in it: gone with the restore", "d3  dave/watch (revoked here already)\n", "d4  erin/tablet\n",
		"warning: this node's database has no record of 1 devices", "(users deleted here since)",
		"2026-11-01T12:00:00Z cannot be known", "d2  bob/tv", "  carol: deleted here since the backup",
		"  dave: a device added and revoked here since the backup"} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
	got = restoreCarryText(store.Restored{Foreign: true, Unknown: []store.CarriedDevice{{ID: "d2", User: "bob", Name: "tv"}}}, made)
	if !strings.Contains(got, "another node's: a new host") || strings.Contains(got, "stay as they are") {
		t.Errorf("a new host:\n%s", got)
	}
	got = restoreCarryText(store.Restored{Foreign: true, Newer: "device d2 bob/tv is revoked in the backup and active here",
		Unknown: []store.CarriedDevice{{ID: "d1", User: "alice", Name: "phone"}}}, made)
	for _, want := range []string{
		"the backup is newer than this node's database: nothing carried (device d2 bob/tv is revoked in the backup and active here)\n",
		"warning: this node's database is no later state of the backup (a new host with this node's identity,\n",
		"restored here): it says nothing of the 1 devices the backup has active:\n",
		"d1  alice/phone",
	} {
		if !strings.Contains(got, want) || strings.Contains(got, "another node's") {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
}

// rayctl device revoke -overlap says that the user's credentials rotate,
// when the switch is and when the old ones stop working, and what to do
// for a stolen device (R4-43); a node before v0.31.0, which does not read
// overlap, made them new at once, and rayctl says so.
func TestRevokeOverlapText(t *testing.T) {
	switchAt := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC).Unix()
	until := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC).Unix()
	rotating := &nodev1.RevokeDeviceResponse{User: "alice", Device: "phone", Credentials: 3, SwitchAt: switchAt, Until: until}
	older := &nodev1.RevokeDeviceResponse{User: "alice", Device: "phone", Credentials: 3}
	for _, c := range []struct {
		r          *nodev1.RevokeDeviceResponse
		want, none string
	}{
		{rotating, "revoked with overlap. alice's credentials rotate (3 credentials)", "are new"},
		{rotating, "other devices get them with their next subscription fetch and switch to them\nat 2026-11-19 12:00 UTC", "devices are cut too,"},
		{rotating, "The old ones, which the revoked device knew, stop working at 2026-11-21 12:00 UTC", ""},
		{rotating, "For a stolen device revoke without\n-overlap; to cut this one off now: rayctl user renew alice", ""},
		{older, "older than v0.31.0: it knows no -overlap", "rotate"},
		{older, "alice's credentials are new (3 credentials)", ""},
		{&nodev1.RevokeDeviceResponse{User: "carol", Device: "tv"}, "carol has no credentials yet", "overlap"},
		{&nodev1.RevokeDeviceResponse{User: "alice", Device: "phone", Already: true}, "revoked already: nothing changed", "rotate"},
	} {
		got := revokeText("d1", true, c.r)
		if !strings.Contains(got, c.want) || (c.none != "" && strings.Contains(got, c.none)) {
			t.Errorf("%v: %q", c.r, got)
		}
	}
	// Without -overlap, switch_at is not looked at.
	if got := revokeText("d1", false, rotating); !strings.Contains(got, "credentials are new") || strings.Contains(got, "older than v0.31.0") {
		t.Errorf("%q", got)
	}
}

// rayctl restore says which revocations it carried with their rotation
// going on (with overlap) and which gave new credentials.
func TestRestoreCarryTextOverlap(t *testing.T) {
	made := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	got := restoreCarryText(store.Restored{
		Kept:    2,
		Carried: []store.CarriedDevice{{ID: "d1", User: "alice", Name: "phone"}, {ID: "d2", User: "bob", Name: "tv", Rotating: true}},
		Added:   []store.AddedDevice{{CarriedDevice: store.CarriedDevice{ID: "d3", User: "carol", Name: "watch", Rotating: true}, Revoked: true}},
	}, made)
	for _, want := range []string{
		"their users' credentials are new, and the users'\nother devices reconnect after their next subscription fetch:\n  d1  alice/phone\n",
		"revoked here with overlap since the backup", "the rotation the revocation began going on to its switch and grace:\n  d2  bob/tv\n",
		"  d3  carol/watch (revoked here already, with overlap)\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
}
