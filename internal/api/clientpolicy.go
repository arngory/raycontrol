package api

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/clientver"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/node"
)

// ClientWindow is how far back GetClientPolicy counts devices by the client
// they last named (client-min-v1 §5).
const ClientWindow = 30 * 24 * time.Hour

// GetClientPolicy returns the node's minimum client version and the devices
// by client.
func (s *Server) GetClientPolicy(ctx context.Context, _ *connect.Request[nodev1.GetClientPolicyRequest]) (*connect.Response[nodev1.GetClientPolicyResponse], error) {
	p, err := node.ClientPolicy(ctx, s.Store)
	if err != nil {
		return nil, toConnect(err)
	}
	counts, err := s.Store.ClientCounts(ctx, time.Now().Add(-ClientWindow))
	if err != nil {
		return nil, toConnect(err)
	}
	resp := &nodev1.GetClientPolicyResponse{Policy: policyMsg(p)}
	for _, c := range counts {
		resp.Clients = append(resp.Clients, &nodev1.ClientCount{Client: c.Client, Devices: uint32(c.Devices)}) //nolint:gosec // G115: a count of devices
	}
	return connect.NewResponse(resp), nil
}

// SetClientPolicy sets the node's minimum client version, or takes it away:
// it goes out with the next subscription a client fetches.
func (s *Server) SetClientPolicy(ctx context.Context, req *connect.Request[nodev1.SetClientPolicyRequest]) (*connect.Response[nodev1.SetClientPolicyResponse], error) {
	in := req.Msg.GetPolicy()
	p, err := node.SetClientPolicy(ctx, s.Store, clientver.Policy{Min: in.GetMin(), From: in.GetFrom(), RefuseUnknown: in.GetRefuseUnknown()})
	target := "none"
	if len(p.Min) > 0 {
		target = fmt.Sprintf("min %v from %d refuse_unknown %v", p.Min, p.From, p.RefuseUnknown)
	}
	if err := s.done(ctx, "client min", target, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetClientPolicyResponse{Policy: policyMsg(p)}), nil
}

func policyMsg(p clientver.Policy) *nodev1.ClientPolicy {
	return &nodev1.ClientPolicy{Min: p.Min, From: p.From, RefuseUnknown: p.RefuseUnknown}
}
