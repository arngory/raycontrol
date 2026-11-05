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
	// The relay host forwards IPv4 (net.ipv4.ip_forward); IPv6 relays later.
	if !relay.Address.Is4() {
		return "", fmt.Errorf("%w relay %s: a relay host is IPv4 for now", store.ErrInvalid, relay.Address)
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
	sshPort, admin, err := relayAccess(relay, req.SshPort, req.Admin)
	if err != nil {
		return "", err
	}
	services, err := s.Store.ListServices(ctx)
	if err != nil {
		return "", err
	}
	forwarded, err := relayForwarded(services, sshPort)
	if err != nil {
		return "", err
	}
	// New SPA parameters with every bundle, clear of the ports the relay
	// forwards or serves: the keys of the devices for the relay change with
	// them. Nothing is written before every check has passed.
	_, spaJSON, err := provision.NewRelayParams(append(forwarded, store.Port{Proto: "tcp", Num: sshPort}))
	if err != nil {
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
	if err := s.Store.IssueRelay(ctx, relay.Name, store.RelayIssue{SPA: spaJSON, SSHPort: sshPort, Admin: admin, CertPin: CertPin(cert.Leaf)}); err != nil {
		return "", err
	}
	return node.RelayBundle{Version: 1, Name: relay.Name, Exit: exit, API: apiSvc.endpoint, Cert: string(pem)}.Encode()
}

// relayAccess checks the relay host's SSH port and admin list asked for,
// keeping the relay's own where none is given. The list must not be empty:
// the devices allowed SSH have no way yet to knock at a relay with their
// K_relay (rayctl knock does not), so the list is the only way in.
func relayAccess(relay store.Relay, port uint32, cidrs []string) (uint16, []string, error) {
	if port > 65535 {
		return 0, nil, fmt.Errorf("%w ssh port %d", store.ErrInvalid, port)
	}
	sshPort := relay.SSHPort
	if port != 0 {
		sshPort = uint16(port)
	}
	admin := relay.Admin
	if len(cidrs) > 0 {
		ps, err := node.ParsePrefixes(cidrs)
		if err != nil {
			return 0, nil, err
		}
		admin = nil
		for _, p := range ps {
			if p.Bits() < node.MinAdminBits(p.Addr()) {
				return 0, nil, fmt.Errorf("%w admin prefix %s: wider than /%d", store.ErrInvalid, p, node.MinAdminBits(p.Addr()))
			}
			admin = append(admin, p.String())
		}
	}
	if len(admin) == 0 {
		return 0, nil, fmt.Errorf("%w: the relay host's SSH needs admin addresses (-admin): run from an SSH session or give them", store.ErrInvalid)
	}
	return sshPort, admin, nil
}

// relayForwarded are the ports a relay forwards (every enabled service's,
// not SSH's, not public ones'); the relay host's own SSH must not be one.
func relayForwarded(services []store.Service, sshPort uint16) ([]store.Port, error) {
	ssh := store.Port{Proto: "tcp", Num: sshPort}
	var out []store.Port
	for _, svc := range services {
		if svc.Kind == "ssh" || svc.Public() || !svc.Enabled {
			continue
		}
		ports, err := svc.Ports()
		if err != nil {
			continue
		}
		if slices.Contains(ports, ssh) {
			return nil, fmt.Errorf("%w ssh port %d: %s's, which the relay forwards", store.ErrInvalid, sshPort, svc.Name)
		}
		out = append(out, ports...)
	}
	return out, nil
}

// SetRelayAccess changes the relay host's SSH port and admin list without a
// new bundle: the running relay takes them with its next snapshot, its SPA
// and certificate stay.
func (s *Server) SetRelayAccess(ctx context.Context, req *connect.Request[nodev1.SetRelayAccessRequest]) (*connect.Response[nodev1.SetRelayAccessResponse], error) {
	err := func() error {
		relay, err := s.Store.RelayByName(ctx, req.Msg.Name)
		if err != nil {
			return err
		}
		sshPort, admin, err := relayAccess(relay, req.Msg.SshPort, req.Msg.Admin)
		if err != nil {
			return err
		}
		services, err := s.Store.ListServices(ctx)
		if err != nil {
			return err
		}
		if _, err := relayForwarded(services, sshPort); err != nil {
			return err
		}
		if params, err := provision.RelayParams(ctx, s.Store, relay.Name); err == nil &&
			int(sshPort) >= int(params.PortBase) && int(sshPort) < int(params.PortBase)+int(params.PortRange) {
			return fmt.Errorf("%w ssh port %d: in the relay's SPA range", store.ErrInvalid, sshPort)
		}
		return s.Store.SetRelayAccess(ctx, relay.Name, sshPort, admin)
	}()
	if err := s.done(ctx, "relay.access", req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetRelayAccessResponse{}), nil
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
