package api

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/connlimit"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
)

// GetConnLimit says whether the connection limits are on
// (spec/conn-limit-v1.md §8), with the table, the guard and the users at a
// limit. Root and the group see it on the node's socket; there is no
// remote method (remote.go, nodeOnly).
func (s *Server) GetConnLimit(ctx context.Context, _ *connect.Request[nodev1.GetConnLimitRequest]) (*connect.Response[nodev1.GetConnLimitResponse], error) {
	if !isLocal(ctx) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("the connection limits: on the node only"))
	}
	off, err := s.Store.ConnLimitOff(ctx)
	if err != nil {
		return nil, toConnect(err)
	}
	resp := &nodev1.GetConnLimitResponse{Off: off}
	snap := s.ConnLimit.Snapshot()
	if ct := snap.Conntrack; ct != nil {
		resp.Conntrack = &nodev1.Conntrack{Count: ct.Count, Max: ct.Max, Dropped: ct.Dropped, EarlyDropped: ct.EarlyDropped,
			DroppedRecent: ct.DroppedRecent}
	}
	if g := snap.Guard; g != nil {
		resp.Guard = &nodev1.ConnGuard{On: g.On, Since: unixOf(g.Since), LastOn: unixOf(g.LastOn), Switches: g.Switches,
			Refused: g.Refused, SweptUdp: g.SweptUDP, SweptTcpOut: g.SweptTCPOut, SweptTcpIn: g.SweptTCPIn, Reported: unixOf(g.Reported)}
	}
	for _, u := range snap.Users {
		resp.Users = append(resp.Users, &nodev1.ConnLimitUser{Id: u.ID, Service: u.Service, Refused: u.Refused})
	}
	keys := make([][2]string, 0, len(snap.Refused))
	for k := range snap.Refused {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b [2]string) int { return strings.Compare(a[0]+"\x00"+a[1], b[0]+"\x00"+b[1]) })
	for _, k := range keys {
		resp.Refused = append(resp.Refused, &nodev1.ConnLimitRefused{Service: k[0], Kind: k[1], Total: snap.Refused[k]})
	}
	return connect.NewResponse(resp), nil
}

// SetConnLimit turns the limits on or off: root on the node only, each
// change in the audit log. rayspa takes the per-address limit from the
// next perimeter snapshot, naive its limits from its rendered file, both
// within seconds.
func (s *Server) SetConnLimit(ctx context.Context, req *connect.Request[nodev1.SetConnLimitRequest]) (*connect.Response[nodev1.SetConnLimitResponse], error) {
	if !isRoot(ctx) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("the connection limits: root on the node only"))
	}
	off, err := s.Store.SetConnLimitOff(ctx, req.Msg.Off)
	if err := s.done(ctx, "conn_limit.set", map[bool]string{true: "off", false: "on"}[req.Msg.Off], err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetConnLimitResponse{Off: off}), nil
}

// ReportGuard takes the guard's state from rayspa (spec/conn-limit-v1.md
// §6.3): only the rayspa user and root may report.
func (p *PerimeterServer) ReportGuard(ctx context.Context, req *connect.Request[perimeterv1.ReportGuardRequest]) (*connect.Response[perimeterv1.ReportGuardResponse], error) {
	if !p.rayspaPeer(ctx) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("only rayspa may report the guard"))
	}
	g := req.Msg.GetGuard()
	if g == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("no guard"))
	}
	p.ConnLimit.SetGuard(connlimit.Guard{On: g.On, Since: timeOf(g.Since), LastOn: timeOf(g.LastOn), Switches: g.Switches,
		Refused: g.Refused, SweptUDP: g.SweptUdp, SweptTCPOut: g.SweptTcpOut, SweptTCPIn: g.SweptTcpIn})
	return connect.NewResponse(&perimeterv1.ReportGuardResponse{}), nil
}

// timeOf is unix seconds as a time, zero for 0.
func timeOf(unix int64) time.Time {
	if unix <= 0 {
		return time.Time{}
	}
	return time.Unix(unix, 0)
}
