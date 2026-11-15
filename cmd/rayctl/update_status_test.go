package main

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
)

// updateNode answers GetUpdateStatus with its answer.
type updateNode struct {
	nodev1connect.NodeServiceClient
	m *nodev1.GetUpdateStatusResponse
}

func (n updateNode) GetUpdateStatus(context.Context, *connect.Request[nodev1.GetUpdateStatusRequest]) (*connect.Response[nodev1.GetUpdateStatusResponse], error) {
	return connect.NewResponse(n.m), nil
}

// rayctl update status says when the latest release is a new minor or
// major version, which the auto update leaves, and what takes it; a patch
// release, or none newer, adds nothing.
func TestUpdateStatusNewer(t *testing.T) {
	for _, c := range []struct {
		latest, auto, remote string
		want                 string // the line after latest; "": none
	}{
		{"v0.27.0", "patch", "off", "newer      v0.27.0 is a new minor version: the auto update takes patch releases only; rayctl update takes it"},
		{"v0.27.0", "patch", "on", "newer      v0.27.0 is a new minor version: the auto update takes patch releases only; rayctl update takes it (or an admin's phone)"},
		{"v1.0.0", "off", "off", "newer      v1.0.0 is a new major version: rayctl update takes it"},
		{"v0.26.2", "patch", "off", ""},
		{"v0.26.1", "patch", "off", ""},
		{"", "patch", "off", ""},
	} {
		m := &nodev1.GetUpdateStatusResponse{Installed: "v0.26.1", Latest: c.latest, Auto: c.auto, Remote: c.remote, Window: "03:00-05:00",
			Timezone: "UTC +00:00"}
		out, err := captureStdout(t, func() error { return (&cli{c: updateNode{m: m}}).updateStatus(context.Background()) })
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(out, "\n")
		next := lines[2]
		if got := strings.HasPrefix(next, "newer"); got != (c.want != "") || (c.want != "" && next != c.want) {
			t.Errorf("latest %q auto %s remote %s:\n%s", c.latest, c.auto, c.remote, out)
		}
	}
}

// On the exit rayctl update status ends with a line for each relay in
// front of it (spec/relay-update-remote-v1.md §9.2): its version and where
// its update by the node's word stands, failures with their code and
// text, nothing a terminal would act on; -json has them as rayd sends
// them. A node without relays, or one before them, adds none.
func TestUpdateStatusRelays(t *testing.T) {
	at := time.Date(2026, 11, 20, 3, 41, 12, 0, time.UTC).Unix()
	m := &nodev1.GetUpdateStatusResponse{Installed: "v0.28.0", Remote: "on", Auto: "off", Window: "03:00-05:00", Timezone: "UTC +00:00",
		Status: &nodev1.UpdateStatus{Id: "6f1c0e2a9b3d4c5e", State: "done", From: "v0.27.0", To: "v0.28.0", By: "rayctl on the node", Kind: "local", EndedAt: at - 600},
		Relays: []*nodev1.RelayUpdateStatus{
			{Name: "r1", Version: "v0.28.0", State: "done", Target: "v0.28.0", UpdateId: "6f1c0e2a9b3d4c5e", ChangedAt: at, SeenAt: at, Remote: true},
			{Name: "r2", Version: "v0.27.0", State: "off", Target: "v0.28.0", UpdateId: "6f1c0e2a9b3d4c5e", ChangedAt: at},
			{Name: "r3", Version: "v0.27.0", State: "running", Target: "v0.28.0", UpdateId: "6f1c0e2a9b3d4c5e", ChangedAt: at, Remote: true},
			{Name: "r4", Version: "v0.27.0", State: "waiting", Target: "v0.28.0", UpdateId: "6f1c0e2a9b3d4c5e", ChangedAt: at, Remote: true},
			{Name: "r5", State: "unknown"},
			{Name: "r6", Version: "v0.27.0", State: "rolled_back", Target: "v0.28.0", UpdateId: "6f1c0e2a9b3d4c5e", Reason: "check",
				Error: "rayspa did not come back\x1b[2J", ChangedAt: at, Remote: true},
			{Name: "r7", Version: "v0.26.0", State: "failed", Target: "v0.27.0", UpdateId: "0a", Reason: "no_word", ChangedAt: at},
			{Name: "r8", Version: "v0.29.0", State: "current", Target: "v0.28.0", UpdateId: "6f1c0e2a9b3d4c5e", ChangedAt: at},
			{Name: "r9", Version: "v0.27.0", State: "paused", ChangedAt: at},
		}}
	out, err := captureStdout(t, func() error { return (&cli{c: updateNode{m: m}}).updateStatus(context.Background()) })
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	want := []string{
		"last       done: v0.27.0 → v0.28.0, by rayctl on the node, 2026-11-20T03:31:12Z",
		"relay      r1: v0.28.0, done (v0.27.0 → v0.28.0), 2026-11-20T03:41:12Z",
		"relay      r2: v0.27.0, off: root on r2 has not allowed it (rayctl update remote on there)",
		"relay      r3: v0.27.0, running (v0.27.0 → v0.28.0), 2026-11-20T03:41:12Z",
		"relay      r4: v0.27.0, waiting for r3",
		"relay      r5: unknown: no word from it (an older relay, or its rayd relay does not run)",
		"relay      r6: v0.27.0, rolled_back (v0.27.0 → v0.28.0), 2026-11-20T03:41:12Z, check: rayspa did not come back?[2J",
		"relay      r7: v0.26.0, failed (→ v0.27.0), 2026-11-20T03:41:12Z, no_word",
		"relay      r8: v0.29.0, current",
		"relay      r9: v0.27.0, paused, 2026-11-20T03:41:12Z",
	}
	if len(lines) < len(want) || !slices.Equal(lines[len(lines)-len(want):], want) {
		t.Fatalf("got\n%s\nwant the end\n%s", out, strings.Join(want, "\n"))
	}
	// Nobody given the offer: waiting for its turn, as when nothing ran.
	m.Status, m.Relays = nil, []*nodev1.RelayUpdateStatus{{Name: "r1", Version: "v0.27.0", State: "waiting", Target: "v0.28.0"}, {Name: "r2", State: "offered",
		Target: "v0.28.0", ChangedAt: at}}
	out, _ = captureStdout(t, func() error { return (&cli{c: updateNode{m: m}}).updateStatus(context.Background()) })
	if !strings.HasSuffix(out, "last       none\nrelay      r1: v0.27.0, waiting for r2\nrelay      r2: offered v0.28.0, 2026-11-20T03:41:12Z\n") {
		t.Fatalf("no update of its own:\n%s", out)
	}
	m.Relays = m.Relays[:1]
	out, _ = captureStdout(t, func() error { return (&cli{c: updateNode{m: m}}).updateStatus(context.Background()) })
	if !strings.HasSuffix(out, "relay      r1: v0.27.0, waiting for its turn\n") {
		t.Fatalf("its turn:\n%s", out)
	}
	// The relay the others wait for: the one holding its turn, or the one
	// whose update began last, not one before it whose turn ran out while
	// it still says it runs; else one at an earlier update.
	id := "6f1c0e2a9b3d4c5e"
	ran := &nodev1.RelayUpdateStatus{Name: "r1", Version: "v0.27.0", State: "running", Target: "v0.28.0", UpdateId: id, ChangedAt: at - 3600}
	waits := &nodev1.RelayUpdateStatus{Name: "r4", Version: "v0.27.0", State: "waiting", Target: "v0.28.0", UpdateId: id}
	for _, c := range []struct {
		relays []*nodev1.RelayUpdateStatus
		want   string
	}{
		{[]*nodev1.RelayUpdateStatus{ran, {Name: "r2", State: "offered", Target: "v0.28.0", UpdateId: id, ChangedAt: at}, waits}, "r2"},
		{[]*nodev1.RelayUpdateStatus{ran, {Name: "r2", Version: "v0.27.0", State: "requested", Target: "v0.28.0", UpdateId: id, ChangedAt: at}, waits}, "r2"},
		{[]*nodev1.RelayUpdateStatus{{Name: "r1", Version: "v0.26.0", State: "running", Target: "v0.27.0", UpdateId: "0a", ChangedAt: at}, ran, waits}, "r1"},
		{[]*nodev1.RelayUpdateStatus{{Name: "r1", Version: "v0.26.0", State: "running", Target: "v0.27.0", UpdateId: "0a", ChangedAt: at}, waits}, "r1"},
	} {
		m.Relays = c.relays
		out, _ = captureStdout(t, func() error { return (&cli{c: updateNode{m: m}}).updateStatus(context.Background()) })
		if !strings.HasSuffix(out, "relay      r4: v0.27.0, waiting for "+c.want+"\n") {
			t.Errorf("waiting for %s:\n%s", c.want, out)
		}
	}
	m.Relays = nil
	if out, _ = captureStdout(t, func() error { return (&cli{c: updateNode{m: m}}).updateStatus(context.Background()) }); strings.Contains(out, "relay") {
		t.Fatalf("no relays:\n%s", out)
	}
	m.Relays = []*nodev1.RelayUpdateStatus{{Name: "r1", Version: "v0.28.0", State: "done", Target: "v0.28.0", UpdateId: "6f1c0e2a9b3d4c5e", ChangedAt: at, Remote: true}}
	out, err = captureStdout(t, func() error { return (&cli{c: updateNode{m: m}, json: true}).updateStatus(context.Background()) })
	var back nodev1.GetUpdateStatusResponse
	if err != nil || !strings.Contains(out, `"relays"`) || protojson.Unmarshal([]byte(out), &back) != nil || !proto.Equal(back.Relays[0], m.Relays[0]) {
		t.Fatalf("-json: %v\n%s", err, out)
	}
}

// With a new minor version out, rayctl update status names the newest
// patch release of the node's own (latest_patch) and what takes it;
// without a check, it says that nothing was checked, never a release.
func TestUpdateStatusPatch(t *testing.T) {
	for _, c := range []struct {
		latest, patch, auto string
		want                []string // the lines after installed
	}{
		{"v0.27.0", "v0.26.2", "patch", []string{"latest     v0.27.0",
			"patch      v0.26.2, the newest patch release of v0.26.0: the auto update takes it in its window",
			"newer      v0.27.0 is a new minor version: the auto update takes patch releases only; rayctl update takes it"}},
		{"v0.27.0", "v0.26.2", "off", []string{"latest     v0.27.0",
			"patch      v0.26.2, the newest patch release of v0.26.0: rayctl update -version v0.26.2 takes it",
			"newer      v0.27.0 is a new minor version: rayctl update takes it"}},
		// The latest release is the patch: one line for it.
		{"v0.26.2", "v0.26.2", "patch", []string{"latest     v0.26.2", "remote     off"}},
		// A patch line from a stale answer, older than the node: none.
		{"v0.27.0", "v0.25.9", "off", []string{"latest     v0.27.0", "newer      v0.27.0 is a new minor version: rayctl update takes it"}},
		{"", "", "off", []string{"latest     not checked: rayd asks GitHub only with rayctl update auto patch or rayd -update-check; rayctl update -check asks now",
			"remote     off"}},
		{"", "", "patch", []string{"latest     not known yet: rayd asks GitHub every ~6 h (rayctl status, loop auto-update, says why not); rayctl update -check asks now",
			"remote     off"}},
	} {
		m := &nodev1.GetUpdateStatusResponse{Installed: "v0.26.0", Latest: c.latest, LatestPatch: c.patch, Auto: c.auto, Remote: "off",
			Window: "03:00-05:00", Timezone: "UTC +00:00"}
		out, err := captureStdout(t, func() error { return (&cli{c: updateNode{m: m}}).updateStatus(context.Background()) })
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(out, "\n")
		if len(lines) < 1+len(c.want) || !slices.Equal(lines[1:1+len(c.want)], c.want) {
			t.Errorf("latest %q patch %q auto %s:\n%s", c.latest, c.patch, c.auto, out)
		}
	}
}
