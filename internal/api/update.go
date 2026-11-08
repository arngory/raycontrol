package api

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/release"
)

// NodeUpdate is where the update by request lives (spec/node-update-v1.md);
// the zero value is the node's.
type NodeUpdate struct {
	Request, Status, Policy string // nodeupdate.RequestFile, StatusFile, PolicyFile
	Unit                    string // the path unit's file: the node runs requests
	// Latest is the latest release rayd's checks saw ("" when none).
	Latest func() string
	Now    func() time.Time
}

func (u *NodeUpdate) request() string {
	if u == nil || u.Request == "" {
		return nodeupdate.RequestFile
	}
	return u.Request
}

func (u *NodeUpdate) status() string {
	if u == nil || u.Status == "" {
		return nodeupdate.StatusFile
	}
	return u.Status
}

// policy is root's: rayd reads it and cannot change it.
func (u *NodeUpdate) policy() nodeupdate.Policy {
	if u == nil || u.Policy == "" {
		return nodeupdate.ReadPolicy(nodeupdate.PolicyFile)
	}
	return nodeupdate.ReadPolicy(u.Policy)
}

func (u *NodeUpdate) unit() string {
	if u == nil || u.Unit == "" {
		return "/etc/systemd/system/" + nodeupdate.PathUnit
	}
	return u.Unit
}

func (u *NodeUpdate) latest() string {
	if u == nil || u.Latest == nil {
		return ""
	}
	return u.Latest()
}

func (u *NodeUpdate) now() time.Time {
	if u == nil || u.Now == nil {
		return time.Now()
	}
	return u.Now()
}

// current is the last status as it stands now, and the request waiting.
// The request first: root writes the status before it removes the
// request, so one of the two shows an update taken.
func (u *NodeUpdate) current(now time.Time) (st nodeupdate.Status, req nodeupdate.Request, waiting bool) {
	req, waiting = nodeupdate.PeekRequest(u.request())
	st = nodeupdate.Settled(nodeupdate.ReadStatus(u.status()), now)
	return st, req, waiting
}

// StartUpdate asks for an update of the node (spec/node-update-v1.md §2).
func (s *Server) StartUpdate(ctx context.Context, req *connect.Request[nodev1.StartUpdateRequest]) (*connect.Response[nodev1.StartUpdateResponse], error) {
	u := s.NodeUpdate
	fail := func(code connect.Code, err error) (*connect.Response[nodev1.StartUpdateResponse], error) {
		_ = s.Store.Audit(ctx, actorFrom(ctx), "update.start", "node", "error: "+err.Error())
		return nil, connect.NewError(code, err)
	}
	if isLocal(ctx) && !isOwner(ctx) {
		// On the node it is root's rayctl update; the group may not.
		return fail(connect.CodePermissionDenied, errors.New("on the node: rayctl update, as root"))
	}
	if u.policy().Remote != "on" {
		return fail(connect.CodeFailedPrecondition, errors.New("remote updates are off on this node (root on it: rayctl update remote on)"))
	}
	if !release.IsRelease(s.Version) {
		return fail(connect.CodeFailedPrecondition, fmt.Errorf("the node runs %s, not a release: it updates by hand", s.Version))
	}
	if _, err := os.Stat(u.unit()); err != nil {
		return fail(connect.CodeFailedPrecondition, errors.New("the node has no update unit (root on it: rayctl apply)"))
	}
	v := cmp.Or(req.Msg.Version, "latest")
	switch latest := u.latest(); {
	case !nodeupdate.ValidVersion(v):
		return fail(connect.CodeInvalidArgument, fmt.Errorf("version %q: latest or vX.Y.Z", nodeupdate.Printable(v)))
	case v != "latest" && !release.Newer(v, s.Version):
		return fail(connect.CodeInvalidArgument, fmt.Errorf("%s is not newer than the node's %s: an update by request never goes back", v, s.Version))
	case v == "latest" && latest != "" && !release.Newer(latest, s.Version):
		return fail(connect.CodeFailedPrecondition, fmt.Errorf("the node runs %s, the latest release", s.Version))
	}
	now := u.now()
	if st, w, waiting := u.current(now); nodeupdate.Busy(st, w, waiting, now) {
		state := st.State
		if waiting {
			state = nodeupdate.Requested
		}
		return fail(connect.CodeFailedPrecondition, fmt.Errorf("an update is %s already", state))
	}
	r := nodeupdate.Request{ID: nodeupdate.NewID(), Kind: nodeupdate.Remote, Version: v, By: actorFrom(ctx), At: now.UTC()}
	switch err := nodeupdate.WriteRequest(u.request(), r, now); {
	case errors.Is(err, nodeupdate.ErrWaiting):
		return fail(connect.CodeFailedPrecondition, err)
	case err != nil:
		return nil, s.done(ctx, "update.start "+v, "node", err)
	}
	if err := s.done(ctx, "update.start "+v, "node", nil); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.StartUpdateResponse{Status: requestedPB(r, s.Version)}), nil
}

// GetUpdateStatus reports the last update by request, or the one under
// way, and root's policy.
func (s *Server) GetUpdateStatus(_ context.Context, _ *connect.Request[nodev1.GetUpdateStatusRequest]) (*connect.Response[nodev1.GetUpdateStatusResponse], error) {
	u := s.NodeUpdate
	now := u.now()
	st, r, waiting := u.current(now)
	p := u.policy()
	out := &nodev1.GetUpdateStatusResponse{
		Status:    statusPB(st),
		Installed: s.Version,
		Latest:    u.latest(),
		Remote:    p.Remote,
		Auto:      p.Auto,
		Window:    p.Window,
		Timezone:  now.Format("MST -07:00"),
	}
	if waiting && r.ID != st.ID {
		out.Status = requestedPB(r, s.Version)
		if now.Sub(r.At) >= nodeupdate.Stale {
			out.Status.State = nodeupdate.Failed
			out.Status.Error = "not taken within " + nodeupdate.Stale.String() + ": the update unit does not run (systemctl status " + nodeupdate.PathUnit + ")"
		}
	}
	return connect.NewResponse(out), nil
}

func requestedPB(r nodeupdate.Request, from string) *nodev1.UpdateStatus {
	st := &nodev1.UpdateStatus{Id: r.ID, State: nodeupdate.Requested, From: from, To: r.Version, Target: r.Version, By: r.By, Kind: r.Kind,
		RequestedAt: unixOf(r.At)}
	if r.Version != "latest" {
		st.Release = r.Version
	}
	return st
}

func statusPB(st nodeupdate.Status) *nodev1.UpdateStatus {
	return &nodev1.UpdateStatus{Id: st.ID, State: st.State, From: st.From, To: st.To, Target: st.Target, Release: st.Release, By: st.By, Kind: st.Kind,
		Error: st.Error, RequestedAt: unixOf(st.Requested), StartedAt: unixOf(st.Started), EndedAt: unixOf(st.Ended)}
}
