package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/sys/unix"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/nodeupdate"
)

// The update by request (spec/node-update-v1.md §2): taken once root has
// remote updates on (root's file, not rayd's database), for a release
// newer than the node, one at a time; the request lands where the root
// unit looks.
func TestStartUpdate(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	dir := t.TempDir()
	unit := filepath.Join(dir, "raycontrol-update.path")
	latest := "v0.19.2"
	srv.NodeUpdate = &NodeUpdate{Request: filepath.Join(dir, "update-request"), Status: filepath.Join(dir, "status.json"),
		Policy: filepath.Join(dir, "policy.json"), Unit: unit, Latest: func() string { return latest }}
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
	// On the node's socket it is root's: the raycontrol group may not.
	as := func(uid uint32) context.Context {
		return context.WithValue(context.WithValue(ctx, peerKey{}, &unix.Ucred{Uid: uid}), actorKey{}, "test")
	}
	if _, err := srv.StartUpdate(as(1000), connect.NewRequest(&nodev1.StartUpdateRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("a member of the group: %v", err)
	}
	// rayd's own settings do not turn it on.
	srv.Store.SetSetting(ctx, "update_remote", []byte("on"))
	want(start(""), connect.CodeFailedPrecondition, "remote updates are off")
	if err := nodeupdate.WritePolicy(srv.NodeUpdate.Policy, nodeupdate.Policy{Remote: "on", Auto: "off", Window: nodeupdate.DefaultWindow}); err != nil {
		t.Fatal(err)
	}
	want(start(""), connect.CodeFailedPrecondition, "not a release") // Version "test"
	srv.Version = "v0.19.0"
	want(start(""), connect.CodeFailedPrecondition, "no update unit")
	os.WriteFile(unit, []byte("[Path]\n"), 0o644)
	want(start("v0.19"), connect.CodeInvalidArgument, "latest or vX.Y.Z")
	want(start("v0.18.1"), connect.CodeInvalidArgument, "never goes back")
	want(start("v0.19.0"), connect.CodeInvalidArgument, "never goes back")
	latest = "v0.19.0"
	want(start("latest"), connect.CodeFailedPrecondition, "the latest release")
	latest = "v0.19.2"

	r, err := c.StartUpdate(ctx, connect.NewRequest(&nodev1.StartUpdateRequest{Version: "v0.19.1"}))
	if err != nil || r.Msg.Status.State != nodeupdate.Requested || r.Msg.Status.Target != "v0.19.1" || r.Msg.Status.From != "v0.19.0" {
		t.Fatalf("start: %+v %v", r, err)
	}
	req, ok := nodeupdate.PeekRequest(srv.NodeUpdate.Request)
	if !ok || req.Kind != nodeupdate.Remote || req.Version != "v0.19.1" || req.ID != r.Msg.Status.Id || req.Check("v0.19.0", time.Now()) != nil ||
		req.Tried() != "v0.19.1" {
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
	// latest names the release rayd saw, for the auto update to hold.
	if w, _ := nodeupdate.PeekRequest(srv.NodeUpdate.Request); w.Version != "latest" || w.Release != "v0.19.2" || w.Tried() != "v0.19.2" {
		t.Fatalf("latest: %+v", w)
	}

	// A run whose runner died with no word is no longer under way.
	os.Remove(srv.NodeUpdate.Request)
	s.State, s.Started, s.Ended = nodeupdate.Running, time.Now().Add(-nodeupdate.Stale), time.Time{}
	nodeupdate.WriteStatus(srv.NodeUpdate.Status, s)
	if st, _ := c.GetUpdateStatus(ctx, connect.NewRequest(&nodev1.GetUpdateStatusRequest{})); st.Msg.Status.State != nodeupdate.Failed ||
		!strings.Contains(st.Msg.Status.Error, "interrupted") {
		t.Fatalf("a dead run: %+v", st.Msg.Status)
	}
	if err := start(""); err != nil {
		t.Fatalf("after a dead run: %v", err)
	}
	// A request the unit never took (its path unit stopped): failed after
	// an hour, and the next one is taken.
	w, _ := nodeupdate.PeekRequest(srv.NodeUpdate.Request)
	srv.NodeUpdate.Now = func() time.Time { return w.At.Add(nodeupdate.Stale) }
	if st, _ := c.GetUpdateStatus(ctx, connect.NewRequest(&nodev1.GetUpdateStatusRequest{})); st.Msg.Status.State != nodeupdate.Failed ||
		st.Msg.Status.Id != w.ID || !strings.Contains(st.Msg.Status.Error, "not taken") {
		t.Fatalf("a request never taken: %+v", st.Msg.Status)
	}
	if err := start("v0.19.2"); err != nil {
		t.Fatalf("after a request never taken: %v", err)
	}
	if st, _ := c.GetUpdateStatus(ctx, connect.NewRequest(&nodev1.GetUpdateStatusRequest{})); st.Msg.Status.Release != "v0.19.2" {
		t.Fatalf("the release asked for: %+v", st.Msg.Status)
	}

	entries, _ := srv.Store.ListAudit(ctx, 30)
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action+" "+e.Result)
	}
	if all := strings.Join(actions, "\n"); !strings.Contains(all, "update.start v0.19.1 ok") || !strings.Contains(all, "update.start error: remote updates are off") {
		t.Fatalf("audit %v", actions)
	}
}
