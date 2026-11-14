package main

import (
	"context"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

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
