package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/nodeupdate"
)

// The update by request (spec/node-update-v1.md §2): taken once root has
// remote updates on, for a release newer than the node, one at a time;
// the request lands where the root unit looks.
func TestStartUpdate(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	dir := t.TempDir()
	unit := filepath.Join(dir, "raycontrol-update.path")
	srv.NodeUpdate = &NodeUpdate{Request: filepath.Join(dir, "update-request"), Status: filepath.Join(dir, "status.json"), Unit: unit,
		Latest: func() string { return "v0.19.2" }}
	start := func(v string) error {
		_, err := c.StartUpdate(ctx, connect.NewRequest(&nodev1.StartUpdateRequest{Version: v}))
		return err
	}
	want := func(err error, code connect.Code, text string) {
		t.Helper()
		if connect.CodeOf(err) != code || !strings.Contains(err.Error(), text) {
			t.Fatalf("%v, want %v %q", err, code, text)
		}
	}
	want(start(""), connect.CodeFailedPrecondition, "remote updates are off")
	if _, err := c.SetUpdatePolicy(ctx, connect.NewRequest(&nodev1.SetUpdatePolicyRequest{Remote: "on"})); err != nil {
		t.Fatal(err)
	}
	want(start(""), connect.CodeFailedPrecondition, "not a release") // Version "test"
	srv.Version = "v0.19.0"
	want(start(""), connect.CodeFailedPrecondition, "no update unit")
	os.WriteFile(unit, []byte("[Path]\n"), 0o644)
	want(start("v0.19"), connect.CodeInvalidArgument, "latest or vX.Y.Z")
	want(start("v0.18.1"), connect.CodeInvalidArgument, "never goes back")
	want(start("v0.19.0"), connect.CodeInvalidArgument, "never goes back")

	r, err := c.StartUpdate(ctx, connect.NewRequest(&nodev1.StartUpdateRequest{Version: "v0.19.1"}))
	if err != nil || r.Msg.Status.State != nodeupdate.Requested || r.Msg.Status.Target != "v0.19.1" || r.Msg.Status.From != "v0.19.0" {
		t.Fatalf("start: %+v %v", r, err)
	}
	req, ok := nodeupdate.PeekRequest(srv.NodeUpdate.Request)
	if !ok || req.Kind != nodeupdate.Remote || req.Version != "v0.19.1" || req.ID != r.Msg.Status.Id || req.Check("v0.19.0") != nil {
		t.Fatalf("the request %+v %v", req, ok)
	}
	want(start(""), connect.CodeFailedPrecondition, "requested already")
	st, err := c.GetUpdateStatus(ctx, connect.NewRequest(&nodev1.GetUpdateStatusRequest{}))
	if err != nil || st.Msg.Status.State != nodeupdate.Requested || st.Msg.Latest != "v0.19.2" || st.Msg.Remote != "on" ||
		st.Msg.Auto != "off" || st.Msg.Window != nodeupdate.DefaultWindow || st.Msg.Installed != "v0.19.0" {
		t.Fatalf("status %+v %v", st, err)
	}

	// Root's unit took it and runs it: still one at a time; then done.
	os.Remove(srv.NodeUpdate.Request)
	s := nodeupdate.Status{ID: req.ID, State: nodeupdate.Running, From: "v0.19.0", To: "v0.19.1", Target: "v0.19.1", Started: time.Now()}
	nodeupdate.WriteStatus(srv.NodeUpdate.Status, s)
	want(start(""), connect.CodeFailedPrecondition, "running already")
	s.State, s.Ended = nodeupdate.Done, time.Now()
	nodeupdate.WriteStatus(srv.NodeUpdate.Status, s)
	if st, _ := c.GetUpdateStatus(ctx, connect.NewRequest(&nodev1.GetUpdateStatusRequest{})); st.Msg.Status.State != nodeupdate.Done || st.Msg.Status.EndedAt == 0 {
		t.Fatalf("after: %+v", st.Msg.Status)
	}
	if err := start("latest"); err != nil {
		t.Fatalf("the next one: %v", err)
	}

	// The policy: checked, kept, audited.
	for _, bad := range []*nodev1.SetUpdatePolicyRequest{{Remote: "yes"}, {Auto: "minor"}, {Window: "3-5"}, {Window: "03:00-03:00"}} {
		if _, err := c.SetUpdatePolicy(ctx, connect.NewRequest(bad)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	if _, err := c.SetUpdatePolicy(ctx, connect.NewRequest(&nodev1.SetUpdatePolicyRequest{Auto: "patch", Window: "23:30-01:00"})); err != nil {
		t.Fatal(err)
	}
	if st, _ := c.GetUpdateStatus(ctx, connect.NewRequest(&nodev1.GetUpdateStatusRequest{})); st.Msg.Auto != "patch" || st.Msg.Window != "23:30-01:00" || st.Msg.Remote != "on" {
		t.Fatalf("policy %+v", st.Msg)
	}
	entries, _ := srv.Store.ListAudit(ctx, 30)
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action+" "+e.Result)
	}
	if !strings.Contains(strings.Join(actions, "\n"), "update.start v0.19.1 ok") || !strings.Contains(strings.Join(actions, "\n"), "update.policy ok") {
		t.Fatalf("audit %v", actions)
	}
}
