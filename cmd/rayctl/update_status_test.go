package main

import (
	"context"
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
		next := lines[1]
		if c.latest != "" {
			next = lines[2]
		}
		if got := strings.HasPrefix(next, "newer"); got != (c.want != "") || (c.want != "" && next != c.want) {
			t.Errorf("latest %q auto %s remote %s:\n%s", c.latest, c.auto, c.remote, out)
		}
	}
}
