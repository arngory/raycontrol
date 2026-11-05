package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
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

// IssueRelayBundle makes a relay its client certificate, its SPA parameters
// if it has none, and the bundle its host installs (relay-v1 §3). The
// certificate before stops working at once.
func (s *Server) IssueRelayBundle(ctx context.Context, req *connect.Request[nodev1.IssueRelayBundleRequest]) (*connect.Response[nodev1.IssueRelayBundleResponse], error) {
	bundle, err := s.issueRelayBundle(ctx, req.Msg)
	// The audit log names the relay, never the bundle: it holds a key.
	if err := s.done(ctx, "relay.bundle", req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.IssueRelayBundleResponse{Bundle: bundle}), nil
}

func (s *Server) issueRelayBundle(ctx context.Context, req *nodev1.IssueRelayBundleRequest) (string, error) {
	relay, err := s.Store.RelayByName(ctx, req.Name)
	if err != nil {
		return "", err
	}
	if req.SshPort > 65535 {
		return "", fmt.Errorf("%w ssh port %d", store.ErrInvalid, req.SshPort)
	}
	exit, err := s.exitAddress(ctx, req.ExitAddress)
	if err != nil {
		return "", err
	}
	// The relay takes its perimeter from the remote API.
	apiSvc, err := s.apiEndpoint(ctx)
	if err != nil {
		return "", err
	}
	if apiSvc == nil {
		return "", fmt.Errorf("%w: the relay takes its perimeter from the remote API: enable the api service first", store.ErrInvalid)
	}
	if _, err := provision.RelayParams(ctx, s.Store, relay.Name); err != nil {
		return "", err
	}
	if req.SshPort != 0 {
		if err := s.Store.SetRelaySSHPort(ctx, relay.Name, uint16(req.SshPort)); err != nil {
			return "", err
		}
	}
	cert, err := NewClientCertificate()
	if err != nil {
		return "", err
	}
	pem, err := EncodeClientCertificate(cert)
	if err != nil {
		return "", err
	}
	if err := s.Store.SetRelayCertPin(ctx, relay.Name, CertPin(cert.Leaf)); err != nil {
		return "", err
	}
	return node.RelayBundle{Version: 1, Name: relay.Name, Exit: exit, API: apiSvc.endpoint, Cert: string(pem)}.Encode()
}

// exitAddress is the exit's IP for a relay's DNAT: the one given, or the
// node's host if it is an IP or resolves to one.
func (s *Server) exitAddress(ctx context.Context, given string) (netip.Addr, error) {
	host := given
	if host == "" {
		h, err := node.Host(ctx, s.Store)
		if err != nil {
			return netip.Addr{}, err
		}
		host = h
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap(), nil
	}
	if given != "" || host == "" {
		return netip.Addr{}, fmt.Errorf("%w exit address %q: one IP (rayctl relay bundle -exit)", store.ErrInvalid, host)
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(rctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return netip.Addr{}, errors.Join(fmt.Errorf("%w: the node's host %s does not resolve: give the exit's IP (-exit)", store.ErrInvalid, host), err)
	}
	return addrs[0].Unmap(), nil
}
