package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
	"github.com/arngory/raycontrol/internal/nodeupdate"
)

type updateNode struct {
	nodev1connect.NodeServiceClient
	remote, auto, version string
}

func (n *updateNode) GetUpdateStatus(context.Context, *connect.Request[nodev1.GetUpdateStatusRequest]) (*connect.Response[nodev1.GetUpdateStatusResponse], error) {
	return connect.NewResponse(&nodev1.GetUpdateStatusResponse{Remote: n.remote, Auto: n.auto}), nil
}

func (n *updateNode) GetStatus(context.Context, *connect.Request[nodev1.GetStatusRequest]) (*connect.Response[nodev1.GetStatusResponse], error) {
	if n.version == "" {
		return nil, errors.New("down")
	}
	return connect.NewResponse(&nodev1.GetStatusResponse{Version: n.version}), nil
}

// rayctl update -request (spec/node-update-v1.md §3): the request checked
// again on root's side, the update by the installed rayctl, its outcome in
// the status file.
func TestUpdateRequest(t *testing.T) {
	saved := version
	t.Cleanup(func() { version = saved })
	version = "v0.19.0"
	dir := t.TempDir()
	reqFile, statFile := filepath.Join(dir, "update-request"), filepath.Join(dir, "status", "status.json")
	fake := func(script string) string {
		p := filepath.Join(t.TempDir(), "rayctl")
		os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755)
		return p
	}
	run := func(n *updateNode, r nodeupdate.Request, rayctl string) (nodeupdate.Status, error) {
		t.Helper()
		if r.ID != "" {
			if err := nodeupdate.WriteRequest(reqFile, r); err != nil {
				t.Fatal(err)
			}
		}
		err := (&cli{c: n}).updateRequest(context.Background(), reqFile, statFile, rayctl)
		if _, serr := os.Stat(reqFile); !os.IsNotExist(serr) {
			t.Fatal("the request stays: the path unit would fire again")
		}
		return nodeupdate.ReadStatus(statFile), err
	}
	req := func(kind, v string) nodeupdate.Request {
		return nodeupdate.Request{ID: nodeupdate.NewID(), Kind: kind, Version: v, By: "alice/phone (remote)", At: time.Now().UTC()}
	}
	never := fake(`echo ran >&2; exit 9`)

	// No request: nothing.
	if err := (&cli{c: &updateNode{}}).updateRequest(context.Background(), reqFile, statFile, never); err != nil {
		t.Fatal(err)
	}
	// Refused: the policy off now, going back, an auto update past a patch.
	for _, c := range []struct {
		n    *updateNode
		r    nodeupdate.Request
		want string
	}{
		{&updateNode{remote: "off"}, req(nodeupdate.Remote, "latest"), "remote updates are off"},
		{&updateNode{remote: "on", auto: "off"}, req(nodeupdate.Auto, "v0.19.1"), "auto updates are off"},
		{&updateNode{remote: "on"}, req(nodeupdate.Remote, "v0.18.1"), "never goes back"},
		{&updateNode{auto: "patch"}, req(nodeupdate.Auto, "v0.20.0"), "patch releases"},
	} {
		st, err := run(c.n, c.r, never)
		if err == nil || !strings.Contains(err.Error(), c.want) || st.State != nodeupdate.Failed || st.ID != c.r.ID || !strings.Contains(st.Error, c.want) {
			t.Errorf("%+v: %v, status %+v", c.r, err, st)
		}
	}
	// Done: the installed rayctl updated, rayd answers with the new version.
	args := filepath.Join(dir, "args")
	ok := fake(`echo "$@" > ` + args + `; echo "raycontrol v0.19.1 is running"`)
	st, err := run(&updateNode{remote: "on", version: "v0.19.1"}, req(nodeupdate.Remote, "latest"), ok)
	if b, _ := os.ReadFile(args); err != nil || st.State != nodeupdate.Done || st.From != "v0.19.0" || st.To != "v0.19.1" || st.Target != "latest" ||
		strings.TrimSpace(string(b)) != "update -yes -version latest" || st.Ended.IsZero() {
		t.Fatalf("done: %+v %v %q", st, err, b)
	}
	// Rolled back: the cause the update gave.
	back := fake(`echo "update failed: niko-front.service exited"; echo "rayctl: update failed, the previous version runs again: niko-front.service exited" >&2; exit 1`)
	st, err = run(&updateNode{remote: "on", version: "v0.19.0"}, req(nodeupdate.Remote, "v0.19.1"), back)
	if err == nil || st.State != nodeupdate.RolledBack || st.Error != "niko-front.service exited" || st.To != "v0.19.0" || st.Target != "v0.19.1" {
		t.Fatalf("rolled back: %+v %v", st, err)
	}
	// Failed otherwise: the last line.
	broken := fake(`echo "rayctl: SHA256SUMS: minisign: signed with another key" >&2; exit 1`)
	st, _ = run(&updateNode{remote: "on", version: "v0.19.0"}, req(nodeupdate.Remote, "v0.19.1"), broken)
	if st.State != nodeupdate.Failed || st.Error != "SHA256SUMS: minisign: signed with another key" {
		t.Fatalf("failed: %+v", st)
	}
	if fi, err := os.Stat(statFile); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("status file %v %v", fi, err)
	}
}
