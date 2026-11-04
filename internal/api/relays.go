package api

import (
	"context"
	"fmt"
	"net/netip"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/store"
)

// AddRelay lets a relay's address in on the service ports (relay-v1, R6-a).
func (s *Server) AddRelay(ctx context.Context, req *connect.Request[nodev1.AddRelayRequest]) (*connect.Response[nodev1.AddRelayResponse], error) {
	addr, err := netip.ParseAddr(req.Msg.Address)
	if err != nil {
		err = fmt.Errorf("%w relay address %q: one IP", store.ErrInvalid, req.Msg.Address)
	}
	var r store.Relay
	if err == nil {
		r, err = s.Store.CreateRelay(ctx, req.Msg.Name, addr)
	}
	if err := s.done(ctx, "relay.add "+req.Msg.Address, req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.AddRelayResponse{Relay: relayPB(r)}), nil
}

func (s *Server) ListRelays(ctx context.Context, _ *connect.Request[nodev1.ListRelaysRequest]) (*connect.Response[nodev1.ListRelaysResponse], error) {
	rs, err := s.Store.ListRelays(ctx)
	if err != nil {
		return nil, toConnect(err)
	}
	resp := &nodev1.ListRelaysResponse{}
	for _, r := range rs {
		resp.Relays = append(resp.Relays, relayPB(r))
	}
	return connect.NewResponse(resp), nil
}

func (s *Server) RemoveRelay(ctx context.Context, req *connect.Request[nodev1.RemoveRelayRequest]) (*connect.Response[nodev1.RemoveRelayResponse], error) {
	err := s.Store.DeleteRelay(ctx, req.Msg.Name)
	if err := s.done(ctx, "relay.remove", req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.RemoveRelayResponse{}), nil
}

func relayPB(r store.Relay) *nodev1.Relay {
	return &nodev1.Relay{Name: r.Name, Address: r.Address.String(), CreatedAt: r.CreatedAt.Unix()}
}
