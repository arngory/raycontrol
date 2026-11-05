package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/summary"
)

// relayFeed serves RelayService on the remote API.
type relayFeed struct{ r *Remote }

var errNotRelay = connect.NewError(connect.CodeNotFound, errors.New("not found"))

// maxRelayStreams bounds the WatchRelay streams of one relay at once: its
// rayspa and its rayd relay (relay-v1 §9.1).
const maxRelayStreams = 2

// maxRelayReports bounds the Report calls of one relay at once.
const maxRelayReports = 4

// relayFrom is the relay calling: the one whose client certificate this is,
// calling from the relay's address. Anyone else gets what a wrong path gets.
func (f *relayFeed) relayFrom(ctx context.Context, peer string) (store.Relay, error) {
	relay, err := f.r.Perimeter.Store.RelayByCertPin(ctx, pinFrom(ctx))
	if err != nil {
		return store.Relay{}, errNotRelay
	}
	from, err := netip.ParseAddrPort(peer)
	if err != nil || from.Addr().Unmap() != relay.Address {
		f.r.Log.Warn("relay certificate from another address", "relay", relay.Name, "from", peer)
		return store.Relay{}, errNotRelay
	}
	return relay, nil
}

// Report takes a client summary report a relay passes on (relay-v1 §9.3):
// for a device the relay knows, about the client's network (a /24 or a
// /48), with path "relay". A refusal says why in its code, which the relay
// turns into its answer to the client: FailedPrecondition for summaries off
// (404), ResourceExhausted for a network already counted today (429),
// InvalidArgument for a bad report (400), PermissionDenied for a device the
// relay does not know (404, as for an unknown device), Unavailable for too
// many calls at once (503).
func (f *relayFeed) Report(ctx context.Context, req *connect.Request[perimeterv1.ReportRequest]) (*connect.Response[perimeterv1.ReportResponse], error) {
	relay, err := f.relayFrom(ctx, req.Peer().Addr)
	if err != nil {
		return nil, err
	}
	if f.r.RelayReport == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, summary.ErrDisabled)
	}
	network, err := netip.ParsePrefix(req.Msg.Network)
	wantBits := 48
	if network.Addr().Is4() {
		wantBits = 24
	}
	if err != nil || network != network.Masked() || !network.Addr().IsGlobalUnicast() || network.Bits() != wantBits {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the client's network is a /24 or a /48 of a unicast address"))
	}
	if len(req.Msg.Body) > summary.MaxBody {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("a report is at most %d bytes", summary.MaxBody))
	}
	f.r.relayMu.Lock()
	if f.r.relayReports == nil {
		f.r.relayReports = map[string]int{}
	}
	if f.r.relayReports[relay.Name] >= maxRelayReports {
		f.r.relayMu.Unlock()
		// Later, not a refusal: the relay answers 503 (relay-v1 §9.3).
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("too many reports at once from this relay"))
	}
	f.r.relayReports[relay.Name]++
	f.r.relayMu.Unlock()
	defer func() {
		f.r.relayMu.Lock()
		f.r.relayReports[relay.Name]--
		f.r.relayMu.Unlock()
	}()
	// A relay passes on its own devices' reports only: the ones it has
	// K_relay for.
	known, err := f.r.Perimeter.RelayKnows(ctx, relay.Name, req.Msg.Device)
	if err != nil {
		return nil, toConnect(err)
	}
	if !known {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("a device this relay does not know"))
	}
	err = f.r.RelayReport(ctx, req.Msg.Device, network, bytes.NewReader(req.Msg.Body))
	switch {
	case err == nil:
		return connect.NewResponse(&perimeterv1.ReportResponse{}), nil
	case errors.Is(err, summary.ErrDisabled):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, summary.ErrRepeated):
		return nil, connect.NewError(connect.CodeResourceExhausted, err)
	case errors.Is(err, summary.ErrInvalid):
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, store.ErrNotFound):
		// Revoked since the relay's last snapshot.
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("a device this relay does not know"))
	}
	f.r.Log.Warn("relay report", "relay", relay.Name, "err", err)
	return nil, connect.NewError(connect.CodeInternal, errors.New("report not taken"))
}

// WatchRelay streams a relay's perimeter: the current snapshot at once and a
// new one after every change. The caller is the relay whose client
// certificate this is, calling from the relay's address; anyone else gets
// what a wrong path gets. A relay removed or given a new certificate is cut
// off at the next change.
func (f *relayFeed) WatchRelay(ctx context.Context, req *connect.Request[perimeterv1.WatchRelayRequest], stream *connect.ServerStream[perimeterv1.WatchRelayResponse]) error {
	p := f.r.Perimeter
	pin := pinFrom(ctx)
	relay, err := f.relayFrom(ctx, req.Peer().Addr)
	if err != nil {
		return err
	}
	// One relay runs one rayspa: a second stream may overlap a reconnect,
	// more is a relay doing work it has no need for.
	f.r.relayMu.Lock()
	if f.r.relayStreams == nil {
		f.r.relayStreams = map[string]int{}
	}
	if f.r.relayStreams[relay.Name] >= maxRelayStreams {
		f.r.relayMu.Unlock()
		return connect.NewError(connect.CodeResourceExhausted, errors.New("too many feeds for this relay"))
	}
	f.r.relayStreams[relay.Name]++
	probe := req.Msg.Probe
	if probe {
		if f.r.relayProbes == nil {
			f.r.relayProbes, f.r.relayProbeAt = map[string]int{}, map[string]time.Time{}
		}
		f.r.relayProbes[relay.Name]++
	}
	f.r.relayMu.Unlock()
	defer func() {
		f.r.relayMu.Lock()
		f.r.relayStreams[relay.Name]--
		if probe {
			f.r.relayProbes[relay.Name]--
			f.r.relayProbeAt[relay.Name] = f.r.clock()
		}
		f.r.relayMu.Unlock()
	}()
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
