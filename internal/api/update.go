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
	Request, Status string // nodeupdate.RequestFile, nodeupdate.StatusFile
	Unit            string // the path unit's file: the node runs requests
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

func (u *NodeUpdate) unit() string {
	if u == nil || u.Unit == "" {
		return "/etc/systemd/system/" + nodeupdate.PathUnit
	}
	return u.Unit
}

func (u *NodeUpdate) now() time.Time {
	if u == nil || u.Now == nil {
		return time.Now()
	}
	return u.Now()
}

// current is the last status, or the request waiting when it is newer.
func (u *NodeUpdate) current() (st nodeupdate.Status, req nodeupdate.Request, waiting bool) {
	st = nodeupdate.ReadStatus(u.status())
	req, waiting = nodeupdate.PeekRequest(u.request())
	return st, req, waiting
}

func (s *Server) setting(ctx context.Context, key, def string) string {
	v, err := s.Store.GetSetting(ctx, key)
	if err != nil || len(v) == 0 {
		return def
	}
	return string(v)
}

// StartUpdate asks for an update of the node (spec/node-update-v1.md §2).
func (s *Server) StartUpdate(ctx context.Context, req *connect.Request[nodev1.StartUpdateRequest]) (*connect.Response[nodev1.StartUpdateResponse], error) {
	u := s.NodeUpdate
	fail := func(code connect.Code, err error) (*connect.Response[nodev1.StartUpdateResponse], error) {
		_ = s.Store.Audit(ctx, actorFrom(ctx), "update.start", "node", "error: "+err.Error())
		return nil, connect.NewError(code, err)
	}
	if s.setting(ctx, nodeupdate.SettingRemote, "off") != "on" {
		return fail(connect.CodeFailedPrecondition, errors.New("remote updates are off on this node (root on it: rayctl update remote on)"))
	}
	if !release.IsRelease(s.Version) {
		return fail(connect.CodeFailedPrecondition, fmt.Errorf("the node runs %s, not a release: it updates by hand", s.Version))
	}
	if _, err := os.Stat(u.unit()); err != nil {
		return fail(connect.CodeFailedPrecondition, errors.New("the node has no update unit (root on it: rayctl apply)"))
	}
	v := cmp.Or(req.Msg.Version, "latest")
	switch {
	case !nodeupdate.ValidVersion(v):
		return fail(connect.CodeInvalidArgument, fmt.Errorf("version %q: latest or vX.Y.Z", v))
	case v != "latest" && !release.Newer(v, s.Version):
		return fail(connect.CodeInvalidArgument, fmt.Errorf("%s is not newer than the node's %s: an update by request never goes back", v, s.Version))
	}
	now := u.now()
	if st, w, waiting := u.current(); nodeupdate.Busy(st, w, waiting, now) {
		state := st.State
		if waiting {
			state = nodeupdate.Requested
		}
		return fail(connect.CodeFailedPrecondition, fmt.Errorf("an update is %s already", state))
	}
	r := nodeupdate.Request{ID: nodeupdate.NewID(), Kind: nodeupdate.Remote, Version: v, By: actorFrom(ctx), At: now.UTC()}
	err := nodeupdate.WriteRequest(u.request(), r)
	if err := s.done(ctx, "update.start "+v, "node", err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.StartUpdateResponse{Status: requestedPB(r, s.Version)}), nil
}

// GetUpdateStatus reports the last update by request, or the one under
// way, and the node's policy.
func (s *Server) GetUpdateStatus(ctx context.Context, _ *connect.Request[nodev1.GetUpdateStatusRequest]) (*connect.Response[nodev1.GetUpdateStatusResponse], error) {
	u := s.NodeUpdate
	st, r, waiting := u.current()
	out := &nodev1.GetUpdateStatusResponse{
		Status:    statusPB(st),
		Installed: s.Version,
		Remote:    s.setting(ctx, nodeupdate.SettingRemote, "off"),
		Auto:      s.setting(ctx, nodeupdate.SettingAuto, "off"),
		Window:    s.setting(ctx, nodeupdate.SettingWindow, nodeupdate.DefaultWindow),
		Timezone:  u.now().Format("MST -07:00"),
	}
	if waiting && r.ID != st.ID {
		out.Status = requestedPB(r, s.Version)
	}
	if u != nil && u.Latest != nil {
		out.Latest = u.Latest()
	}
	return connect.NewResponse(out), nil
}

// SetUpdatePolicy is root's on the node (nodeOnly): whether admins may
// update it over the API, and the auto update of patch releases.
func (s *Server) SetUpdatePolicy(ctx context.Context, req *connect.Request[nodev1.SetUpdatePolicyRequest]) (*connect.Response[nodev1.SetUpdatePolicyResponse], error) {
	m := req.Msg
	var err error
	switch {
	case m.Remote != "" && m.Remote != "on" && m.Remote != "off":
		err = fmt.Errorf("remote %q: on or off", m.Remote)
	case m.Auto != "" && m.Auto != "off" && m.Auto != "patch":
		err = fmt.Errorf("auto %q: off or patch", m.Auto)
	case m.Window != "":
		_, _, err = nodeupdate.ParseWindow(m.Window)
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	for key, v := range map[string]string{nodeupdate.SettingRemote: m.Remote, nodeupdate.SettingAuto: m.Auto, nodeupdate.SettingWindow: m.Window} {
		if v == "" || err != nil {
			continue
		}
		err = s.Store.SetSetting(ctx, key, []byte(v))
	}
	target := fmt.Sprintf("remote=%s auto=%s window=%s", m.Remote, m.Auto, m.Window)
	if err := s.done(ctx, "update.policy", target, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetUpdatePolicyResponse{}), nil
}

func requestedPB(r nodeupdate.Request, from string) *nodev1.UpdateStatus {
	return &nodev1.UpdateStatus{Id: r.ID, State: nodeupdate.Requested, From: from, To: r.Version, Target: r.Version, By: r.By, Kind: r.Kind,
		RequestedAt: unixOf(r.At)}
}

func statusPB(st nodeupdate.Status) *nodev1.UpdateStatus {
	return &nodev1.UpdateStatus{Id: st.ID, State: st.State, From: st.From, To: st.To, Target: st.Target, By: st.By, Kind: st.Kind, Error: st.Error,
		RequestedAt: unixOf(st.Requested), StartedAt: unixOf(st.Started), EndedAt: unixOf(st.Ended)}
}
