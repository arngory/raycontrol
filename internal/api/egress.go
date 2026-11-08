package api

import (
	"context"
	"errors"
	"os"
	"strings"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/store"
)

// GetEgress returns the node's egress policy (spec/egress-policy-v1.md).
// Root and the group see it on the node's socket; there is no remote
// method (remote.go, nodeOnly).
func (s *Server) GetEgress(ctx context.Context, _ *connect.Request[nodev1.GetEgressRequest]) (*connect.Response[nodev1.GetEgressResponse], error) {
	if !isLocal(ctx) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("the egress policy: on the node only"))
	}
	e, err := s.Store.Egress(ctx)
	if err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&nodev1.GetEgressResponse{Egress: egressPB(e), Uids: s.egressUIDs()}), nil
}

// SetEgress blocks or allows BitTorrent and SMTP on every profile: root on
// the node only, each change in the audit log. rayspa takes it from the
// next perimeter snapshot, sent at once.
func (s *Server) SetEgress(ctx context.Context, req *connect.Request[nodev1.SetEgressRequest]) (*connect.Response[nodev1.SetEgressResponse], error) {
	if !isRoot(ctx) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("the egress policy: root on the node only"))
	}
	var change []string
	for _, p := range []struct {
		name  string
		block *bool
	}{{"bittorrent", req.Msg.Bittorrent}, {"smtp", req.Msg.Smtp}} {
		if p.block != nil {
			change = append(change, map[bool]string{true: "block ", false: "allow "}[*p.block]+p.name)
		}
	}
	if len(change) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("nothing to change: bittorrent or smtp"))
	}
	e, err := s.Store.SetEgress(ctx, req.Msg.Bittorrent, req.Msg.Smtp)
	if err := s.done(ctx, "egress.set", strings.Join(change, ", "), err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetEgressResponse{Egress: egressPB(e)}), nil
}

func egressPB(e store.Egress) *nodev1.Egress {
	return &nodev1.Egress{Bittorrent: e.BitTorrent, Smtp: e.SMTP}
}

// egressUIDs are the processes the egress policy covers besides the data
// plane's UIDs: rayd's own where it runs the data plane as its children
// (rayd serve -supervise), which the fixed UIDs do not catch.
func (s *Server) egressUIDs() []uint32 {
	if !s.Paths.Supervised {
		return nil
	}
	return []uint32{uint32(os.Getuid())}
}
