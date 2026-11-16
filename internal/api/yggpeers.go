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
// taking it as their fallback path (niko-ygg-via). Public keys only, each
// with its label in the users file; the users' and devices' names only
// when the request asks (names): the keys go into a config on a host
// outside the node, which should name nobody (lan-v1 §4.3).
//
// Who may list the devices may ask (ListDevices: root, the group, admin
// devices through the remote API): the answer names the same users and
// devices, and the keys are those their links already carry, from which
// nothing of a device's secret follows. Not audited, as ListDevices. The
// model is Collect's and the devices' keys (CollectYggdrasil), nothing of
// the DNS tunnels' keys that CollectForRender derives too.
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
	// The model the users file is rendered from, its devices with it.
	m, err := render.CollectYggdrasil(ctx, s.Store)
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
	names := map[string]string{}
	if req.Msg.Names {
		devices, err := s.Store.ListDevices(ctx, "")
		if err != nil {
			return nil, toConnect(err)
		}
		for _, d := range devices {
			names[d.ID] = d.Name
		}
	}
	var rows []peerKeyRow
	for _, p := range render.YggdrasilPeers(m, *ygg, *inner) {
		k := &nodev1.YggdrasilPeerKey{PublicKey: hex.EncodeToString(p.Key), Address: render.YggdrasilAddress(p.Key).String(),
			DeviceId: p.Device, Credential: p.Credential, Label: p.Label}
		if !p.From.IsZero() {
			k.From = p.From.Unix()
		}
		if !p.Until.IsZero() {
			k.Until = p.Until.Unix()
		}
		if req.Msg.Names {
			k.User, k.Device = p.User, names[p.Device]
		}
		rows = append(rows, peerKeyRow{pb: k, userID: p.UserID})
	}
	slices.SortFunc(rows, comparePeerKeys)
	resp := &nodev1.GetYggdrasilPeerKeysResponse{Service: svc.Name, NodeKey: hex.EncodeToString(nodeKey),
		NodeAddress: render.YggdrasilAddress(nodeKey).String()}
	for _, r := range rows {
		resp.Keys = append(resp.Keys, r.pb)
	}
	return connect.NewResponse(resp), nil
}

// peerKeyRow is a key of GetYggdrasilPeerKeys' answer with its user's
// number, which the answer does not carry but in its label.
type peerKeyRow struct {
	pb     *nodev1.YggdrasilPeerKey
	userID int64
}

// credentialOrder puts a user's keys of one device in the order of the
// rotation: current, next, previous.
var credentialOrder = map[string]int{"current": 0, "next": 1, "previous": 2}

// comparePeerKeys orders the answer: by user (by name with names, else by
// number), the user's own keys first, then the devices' (by name with
// names, else by ID), each current, next, previous. The names are empty
// without names, so the numbers decide then.
func comparePeerKeys(a, b peerKeyRow) int {
	own := func(r peerKeyRow) int {
		if r.pb.DeviceId == "" {
			return 0
		}
		return 1
	}
	return cmp.Or(cmp.Compare(a.pb.User, b.pb.User), cmp.Compare(a.userID, b.userID), cmp.Compare(own(a), own(b)),
		cmp.Compare(a.pb.Device, b.pb.Device), cmp.Compare(a.pb.DeviceId, b.pb.DeviceId),
		cmp.Compare(credentialOrder[a.pb.Credential], credentialOrder[b.pb.Credential]))
}
