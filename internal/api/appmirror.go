package api

import (
	"context"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/appmirror"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

func (s *Server) appMirror() *appmirror.Mirror {
	if s.AppMirror != nil {
		return s.AppMirror
	}
	return &appmirror.Mirror{Store: s.Store}
}

// GetAppMirror reports the mirror of the client's releases
// (spec/app-update-v1.md).
func (s *Server) GetAppMirror(ctx context.Context, _ *connect.Request[nodev1.GetAppMirrorRequest]) (*connect.Response[nodev1.GetAppMirrorResponse], error) {
	st := s.appMirror().Status(ctx)
	resp := &nodev1.GetAppMirrorResponse{Enabled: st.Enabled, Error: st.Err}
	if !st.Checked.IsZero() {
		resp.Checked = st.Checked.Unix()
	}
	for _, r := range st.Releases {
		resp.Releases = append(resp.Releases, &nodev1.AppRelease{App: appmirror.App, Tag: r.Tag, Prerelease: r.Prerelease,
			Bytes: r.Bytes(), Files: uint32(len(r.Files)), Verified: r.Verified.Unix()})
	}
	return connect.NewResponse(resp), nil
}

// SetAppMirror turns the mirror on, with room for it, or off; rayd's loop
// follows at once.
func (s *Server) SetAppMirror(ctx context.Context, req *connect.Request[nodev1.SetAppMirrorRequest]) (*connect.Response[nodev1.SetAppMirrorResponse], error) {
	m := s.appMirror()
	err := m.SetEnabled(ctx, req.Msg.Enabled)
	target := "off"
	if req.Msg.Enabled {
		target = "on"
	}
	if err := s.done(ctx, "app-mirror.set", target, err); err != nil {
		return nil, err
	}
	m.Kick()
	return connect.NewResponse(&nodev1.SetAppMirrorResponse{}), nil
}
