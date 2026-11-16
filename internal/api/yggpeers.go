package api

import (
	"cmp"
	"context"
	"encoding/hex"
	"fmt"
	"slices"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/render"
)

// GetYggdrasilPeerKeys lists the keys a Yggdrasil service lets in, the
// list its users file is made of (render.YggdrasilPeers), and the node's
// own key: what a peer of the operator's own that keeps to
// AllowedPublicKeys must let in, the node peering with it and clients
// taking it as their fallback path (niko-ygg-via). Public keys only.
//
// Who may list the devices may ask (ListDevices: root, the group, admin
// devices through the remote API): the answer names the same users and
// devices, and the keys are those their links already carry, from which
// nothing of a device's secret follows. Not audited, as ListDevices.
func (s *Server) GetYggdrasilPeerKeys(ctx context.Context, req *connect.Request[nodev1.GetYggdrasilPeerKeysRequest]) (*connect.Response[nodev1.GetYggdrasilPeerKeysResponse], error) {
	svc, err := s.Store.ServiceByName(ctx, req.Msg.Service)
	if err != nil {
		return nil, toConnect(err)
	}
	if svc.Kind != "yggdrasil" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("service %s is %s: peer keys are a Yggdrasil service's", svc.Name, svc.Kind))
	}
	if !svc.Enabled {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("service %s is disabled: it lets no one in (rayctl service enable %s)", svc.Name, svc.Name))
	}
	// The model the users file is rendered from, the devices with it.
	m, err := render.CollectForRender(ctx, s.Store)
	if err != nil {
		return nil, toConnect(err)
	}
	var ygg, inner *render.Service
	for i := range m.Services {
		switch {
		case m.Services[i].ID == svc.ID:
			ygg = &m.Services[i]
		case m.Services[i].Kind == "inner":
			inner = &m.Services[i]
		}
	}
	if ygg == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("service %s is disabled: it lets no one in", svc.Name))
	}
	if inner == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("service %s needs the inner stage, which is missing or disabled", svc.Name))
	}
	_, nodeKey, err := render.YggdrasilNode(*ygg)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	devices, err := s.Store.ListDevices(ctx, "")
	if err != nil {
		return nil, toConnect(err)
	}
	names := map[string]string{}
	for _, d := range devices {
		names[d.ID] = d.Name
	}
	resp := &nodev1.GetYggdrasilPeerKeysResponse{Service: svc.Name, NodeKey: hex.EncodeToString(nodeKey),
		NodeAddress: render.YggdrasilAddress(nodeKey).String()}
	for _, p := range render.YggdrasilPeers(m, *ygg, *inner) {
		k := &nodev1.YggdrasilPeerKey{PublicKey: hex.EncodeToString(p.Key), Address: render.YggdrasilAddress(p.Key).String(),
			User: p.User, DeviceId: p.Device, Device: names[p.Device], Credential: p.Credential}
		if !p.From.IsZero() {
			k.From = p.From.Unix()
		}
		if !p.Until.IsZero() {
			k.Until = p.Until.Unix()
		}
		resp.Keys = append(resp.Keys, k)
	}
	// By user, the user's own keys first, then the devices by name; each
	// current, next, previous (YggdrasilPeers' order, kept).
	slices.SortStableFunc(resp.Keys, func(a, b *nodev1.YggdrasilPeerKey) int {
		own := func(k *nodev1.YggdrasilPeerKey) int {
			if k.DeviceId == "" {
				return 0
			}
			return 1
		}
		return cmp.Or(cmp.Compare(a.User, b.User), cmp.Compare(own(a), own(b)), cmp.Compare(a.Device, b.Device), cmp.Compare(a.DeviceId, b.DeviceId))
	})
	return connect.NewResponse(resp), nil
}
