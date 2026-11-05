package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
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
	if err == nil {
		// An admin address reaches SSH: a relay there would too.
		var admin []netip.Prefix
		if admin, err = node.AdminAccess(ctx, s.Store); err == nil {
			for _, p := range admin {
				if p.Contains(addr.Unmap()) {
					err = fmt.Errorf("%w relay address %s: inside the admin prefix %s, it would reach SSH", store.ErrInvalid, addr, p)
				}
			}
		}
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
	if !isRoot(ctx) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("a relay's bundle holds its private key: root only"))
	}
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
	exit, err := s.exitAddress(ctx, req.ExitAddress, relay.Address)
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
	admin := relay.Admin
	if len(req.Admin) > 0 {
		ps, err := node.ParsePrefixes(req.Admin)
		if err != nil {
			return "", err
		}
		admin = nil
		for _, p := range ps {
			if p.Bits() < node.MinAdminBits(p.Addr()) {
				return "", fmt.Errorf("%w admin prefix %s: wider than /%d", store.ErrInvalid, p, node.MinAdminBits(p.Addr()))
			}
			admin = append(admin, p.String())
		}
	}
	services, err := s.Store.ListServices(ctx)
	if err != nil {
		return "", err
	}
	// Someone must be able to reach the relay host's SSH: its admin
	// addresses, or the devices allowed the exit's SSH, by SPA.
	if len(admin) == 0 && !slices.ContainsFunc(services, func(svc store.Service) bool { return svc.Kind == "ssh" && svc.Enabled }) {
		return "", fmt.Errorf("%w: the relay host's SSH would open for nobody: give admin addresses (-admin) or enable the ssh service", store.ErrInvalid)
	}
	sshPort := relay.SSHPort
	if req.SshPort != 0 {
		sshPort = uint16(req.SshPort)
	}
	// New SPA parameters with every bundle: the keys of the devices for the
	// relay change with them, so a bundle replaced because its host was
	// lost takes the old keys with it.
	params, err := provision.RekeyRelay(ctx, s.Store, relay.Name)
	if err != nil {
		return "", err
	}
	// The relay forwards the service ports to the exit and answers SPA on
	// its range: its own SSH must be neither.
	ssh := store.Port{Proto: "tcp", Num: sshPort}
	if int(sshPort) >= int(params.PortBase) && int(sshPort) < int(params.PortBase)+int(params.PortRange) {
		return "", fmt.Errorf("%w ssh port %d: in the relay's SPA range", store.ErrInvalid, sshPort)
	}
	for _, svc := range services {
		if ports, err := svc.Ports(); err == nil && svc.Kind != "ssh" && slices.Contains(ports, ssh) {
			return "", fmt.Errorf("%w ssh port %d: %s's, which the relay forwards", store.ErrInvalid, sshPort, svc.Name)
		}
	}
	if err := s.Store.SetRelaySSHPort(ctx, relay.Name, sshPort); err != nil {
		return "", err
	}
	if err := s.Store.SetRelayAdmin(ctx, relay.Name, admin); err != nil {
		return "", err
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

// exitAddress is the exit's IP for a relay's DNAT, of the relay's family
// (the relay forwards one family and calls the exit's API from its own
// address): the one given, or the node's host if it is an IP or resolves
// to one.
func (s *Server) exitAddress(ctx context.Context, given string, relay netip.Addr) (netip.Addr, error) {
	host := given
	if host == "" {
		h, err := node.Host(ctx, s.Store)
		if err != nil {
			return netip.Addr{}, err
		}
		host = h
	}
	sameFamily := func(a netip.Addr) bool { return a.Unmap().Is4() == relay.Is4() }
	if a, err := netip.ParseAddr(host); err == nil {
		if !sameFamily(a) {
			return netip.Addr{}, fmt.Errorf("%w exit address %s: the relay %s is of the other family (-exit)", store.ErrInvalid, a, relay)
		}
		return a.Unmap(), nil
	}
	if given != "" || host == "" {
		return netip.Addr{}, fmt.Errorf("%w exit address %q: one IP (rayctl relay bundle -exit)", store.ErrInvalid, host)
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(rctx, "ip", host)
	if err != nil {
		return netip.Addr{}, errors.Join(fmt.Errorf("%w: the node's host %s does not resolve: give the exit's IP (-exit)", store.ErrInvalid, host), err)
	}
	for _, a := range addrs {
		if sameFamily(a) {
			return a.Unmap(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%w: the node's host %s has no address of the relay's family: give the exit's IP (-exit)", store.ErrInvalid, host)
}

// relaysOutside refuses admin prefixes that hold a relay's address: the
// relay would reach SSH, past SPA.
func (s *Server) relaysOutside(ctx context.Context, cidrs []string) error {
	ps, err := node.ParsePrefixes(cidrs)
	if err != nil {
		return err
	}
	relays, err := s.Store.ListRelays(ctx)
	if err != nil {
		return err
	}
	for _, p := range ps {
		for _, r := range relays {
			if p.Contains(r.Address) {
				return fmt.Errorf("%w admin prefix %s holds the relay %s (%s), which would reach SSH", store.ErrInvalid, p, r.Name, r.Address)
			}
		}
	}
	return nil
}
