package api

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/store"
)

// relayFeed serves RelayService on the remote API.
type relayFeed struct{ r *Remote }

var errNotRelay = connect.NewError(connect.CodeNotFound, errors.New("not found"))

// WatchRelay streams a relay's perimeter: the current snapshot at once and a
// new one after every change. The caller is the relay whose client
// certificate this is, calling from the relay's address; anyone else gets
// what a wrong path gets. A relay removed or given a new certificate is cut
// off at the next change.
func (f *relayFeed) WatchRelay(ctx context.Context, req *connect.Request[perimeterv1.WatchRelayRequest], stream *connect.ServerStream[perimeterv1.WatchRelayResponse]) error {
	p := f.r.Perimeter
	pin := pinFrom(ctx)
	relay, err := p.Store.RelayByCertPin(ctx, pin)
	if err != nil {
		return errNotRelay
	}
	from, err := netip.ParseAddrPort(req.Peer().Addr)
	if err != nil || from.Addr().Unmap() != relay.Address {
		f.r.Log.Warn("relay certificate from another address", "relay", relay.Name, "from", req.Peer().Addr)
		return errNotRelay
	}
	refresh := p.Refresh
	if refresh <= 0 {
		refresh = time.Minute
	}
	var last []byte
	for {
		rev, wake := p.changes()
		if r, err := p.Store.RelayByCertPin(ctx, pin); err != nil || r.Name != relay.Name {
			return errNotRelay
		}
		snap, err := p.RelaySnapshot(ctx, relay.Name)
		if errors.Is(err, store.ErrNotFound) {
			return errNotRelay
		}
		if err != nil {
			return toConnect(err)
		}
		body, err := proto.MarshalOptions{Deterministic: true}.Marshal(snap)
		if err != nil {
			return err
		}
		if string(body) != string(last) {
			snap.Revision = rev
			if err := stream.Send(&perimeterv1.WatchRelayResponse{Snapshot: snap}); err != nil {
				return err
			}
			last = body
		}
		select {
		case <-ctx.Done():
			return nil
		case <-wake:
		case <-time.After(refresh):
		}
	}
}
