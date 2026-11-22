package api

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/clientver"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
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
	want := clientver.Policy{Min: in.GetMin(), From: in.GetFrom(), RefuseUnknown: in.GetRefuseUnknown()}
	var p clientver.Policy
	err := s.zonesFit(ctx, want)
	if err == nil {
		p, err = node.SetClientPolicy(ctx, s.Store, want)
	}
	// The audit names only a policy as checked: an invalid one may hold
	// anything the caller sent.
	target := "none"
	switch {
	case err != nil:
		target = "invalid"
	case len(p.Min) > 0:
		target = fmt.Sprintf("min %s from %d refuse_unknown %v", minList(p.Min), p.From, p.RefuseUnknown)
	}
	if err := s.done(ctx, "client min", target, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetClientPolicyResponse{Policy: policyMsg(p)}), nil
}

// minList is a policy's minimums in a stable order: "niko 1.59.0, …".
func minList(min map[string]string) string {
	out := make([]string, 0, len(min))
	for product, v := range min {
		out = append(out, product+" "+v)
	}
	slices.Sort(out)
	return strings.Join(out, ", ")
}

func policyMsg(p clientver.Policy) *nodev1.ClientPolicy {
	return &nodev1.ClientPolicy{Min: p.Min, From: p.From, RefuseUnknown: p.RefuseUnknown}
}

// zonesFit refuses a policy under which a DNS tunnel's zone would be too
// long (docs/spec/dns-zone-length-v1.md): one taken because older clients
// were kept out, which this policy would let back in.
func (s *Server) zonesFit(ctx context.Context, p clientver.Policy) error {
	if _, err := p.Check(); err != nil {
		return nil // node.SetClientPolicy says why
	}
	all, err := s.Store.ListServices(ctx)
	if err != nil {
		return err
	}
	// As it holds now: one that starts later lets older clients in until
	// then.
	if long := provision.ZonesTooLong(all, p, time.Now()); len(long) > 0 {
		return fmt.Errorf("%w: under this client minimum these zones are too long for their clients: %s; keep a minimum of niko %s, or give the services shorter zones first",
			store.ErrInvalid, strings.Join(long, ", "), provision.LongZoneClient)
	}
	return nil
}
