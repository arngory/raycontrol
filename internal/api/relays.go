package api

import (
	"context"
	"encoding/json"
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
	} else if addr = addr.Unmap(); !addr.Is4() {
		// The relay host forwards IPv4 (net.ipv4.ip_forward); IPv6 later.
		err = fmt.Errorf("%w relay address %s: a relay host is IPv4 for now", store.ErrInvalid, addr)
	}
	if err == nil {
		// An admin address reaches SSH: a relay there would too.
		var admin []netip.Prefix
		if admin, err = node.AdminAccess(ctx, s.Store); err == nil {
			for _, p := range admin {
				if p.Contains(addr) {
					err = fmt.Errorf("%w relay address %s: inside the admin prefix %s, it would reach SSH", store.ErrInvalid, addr, p)
				}
			}
		}
	}
	if err == nil {
		// An integration's address lets in only its device
		// (integrations-v1 §3.3): a relay there would lose every device
		// behind it.
		var lists []store.AllowEntry
		if lists, err = s.Store.AllowLists(ctx); err == nil {
			for _, e := range lists {
				if store.AllowCovers(e.Allow, addr) {
					err = fmt.Errorf("%w relay address %s: inside an integration's addresses (rayctl device list)", store.ErrInvalid, addr)
					break
				}
			}
		}
	}
	var r store.Relay
	if err == nil {
		r, err = s.addRelay(ctx, req.Msg.Name, addr)
	}
	if err := s.done(ctx, "relay.add "+req.Msg.Address, req.Msg.Name, err); err != nil {
		return nil, err
	}
	pb := relayPB(r)
	// As stored, its SSH port's default with it.
	if stored, err := s.Store.RelayByName(ctx, r.Name); err == nil {
		if services, err := s.Store.ListServices(ctx); err == nil {
			pb.Ports = relayPorts(stored, services, false) // no bundle yet, no names
		}
	}
	return connect.NewResponse(&nodev1.AddRelayResponse{Relay: pb}), nil
}

func (s *Server) ListRelays(ctx context.Context, _ *connect.Request[nodev1.ListRelaysRequest]) (*connect.Response[nodev1.ListRelaysResponse], error) {
	rs, err := s.Store.ListRelays(ctx)
	if err != nil {
		return nil, toConnect(err)
	}
	services, err := s.Store.ListServices(ctx)
	if err != nil {
		return nil, toConnect(err)
	}
	names, err := s.relayNames(ctx, services)
	if err != nil {
		return nil, toConnect(err)
	}
	cf, err := s.hasDNSProvider(ctx)
	if err != nil {
		return nil, toConnect(err)
	}
	resp := &nodev1.ListRelaysResponse{}
	for _, r := range rs {
		pb := relayPB(r)
		pb.Ports = relayPorts(r, services, !cf && len(names[r.Name]) > 0)
		pb.Names = names[r.Name]
		resp.Relays = append(resp.Relays, pb)
	}
	return connect.NewResponse(resp), nil
}

// hasDNSProvider reports whether the node has Cloudflare: its sites'
// certificates are wildcards then, and its relays forward no TCP 80 for
// them (relay-names-v1 §5, §6).
func (s *Server) hasDNSProvider(ctx context.Context) (bool, error) {
	c, _, err := provision.Cloudflare(ctx, s.Store)
	return c != nil, err
}

// acmePort80 reports whether a relay host takes TCP 80 for this node's
// ACME windows (relay-names-v1 §6): the node has no DNS provider and the
// relay has names, which its sites' certificates take under HTTP-01.
func (s *Server) acmePort80(ctx context.Context, relay string) (bool, error) {
	if cf, err := s.hasDNSProvider(ctx); err != nil || cf {
		return false, err
	}
	names, err := provision.RelayNames(ctx, s.Store)
	return slices.ContainsFunc(names, func(rn provision.RelayName) bool { return rn.Relay == relay }), err
}

// relayNames are the relays' names (relay-names-v1 §3), by relay, with
// whether clients may be given each as rayd's check last found it.
func (s *Server) relayNames(ctx context.Context, services []store.Service) (map[string][]*nodev1.RelayName, error) {
	names, err := provision.RelayNames(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	out := map[string][]*nodev1.RelayName{}
	for _, rn := range names {
		pb := &nodev1.RelayName{Name: rn.Name, Problem: "not checked yet"}
		if i := slices.IndexFunc(services, func(svc store.Service) bool { return svc.ID == rn.Service }); i >= 0 {
			pb.Service = services[i].Name
		}
		if s.RelayNameStatus != nil {
			pb.Ready, pb.Problem = s.RelayNameStatus(rn.Name)
		}
		out[rn.Relay] = append(out[rn.Relay], pb)
	}
	return out, nil
}

// relayPorts are the ports a relay host takes from outside, for a
// provider's firewall in front of it (rayctl relay ports), from what its
// perimeter is made of (RelaySnapshot): its own SSH for its admin
// addresses (AdminPorts), its SPA range for everyone, its probe endpoint
// and the exit's ports it forwards (relayServicesOf) after a knock. The
// SPA range and the probe endpoint only once a bundle is out (CertPin, as
// the subscription has it, sub.addRelays): the SPA parameters a relay may
// have before (SetRelayAccess draws them to check its SSH port) are
// replaced by the bundle's, and a firewall opened for them would be
// opened for the wrong range. acme80: TCP 80 too, which the relay forwards
// to the exit while it orders the relay's names (acmePort80).
func relayPorts(relay store.Relay, services []store.Service, acme80 bool) []*nodev1.RelayPort {
	out := []*nodev1.RelayPort{{Name: "ssh", Protos: []string{"tcp"}, From: uint32(relay.SSHPort), To: uint32(relay.SSHPort), Access: "admin"}}
	bundled := relay.CertPin != ""
	if bundled && len(relay.SPA) > 0 {
		var j node.SPAParams
		if json.Unmarshal(relay.SPA, &j) == nil {
			if p, err := j.Params(); err == nil && p.PortRange > 0 {
				out = append(out, &nodev1.RelayPort{Name: "spa", Protos: []string{"tcp", "udp"}, From: uint32(p.PortBase),
					To: uint32(p.PortBase) + uint32(p.PortRange) - 1, Access: "everyone"})
			}
		}
	}
	forwarded, scoped := relayServicesOf(relay, services)
	if bundled && relay.ProbePort != 0 && !scoped[provision.RelayProbeSvc] {
		out = append(out, &nodev1.RelayPort{Name: "probe", Protos: []string{"tcp", "udp"}, From: uint32(relay.ProbePort),
			To: uint32(relay.ProbePort), Access: "spa"})
	}
	byID := map[uint32]store.Service{}
	for _, svc := range services {
		byID[uint32(svc.ID)] = svc
	}
	for _, ps := range forwarded {
		if ps.Local {
			continue // the relay host's SSH, above
		}
		svc := byID[ps.Id]
		name := svc.Name
		switch svc.Kind {
		case "subscription":
			name = "sub"
		case "api":
			name = "api"
		}
		// One line a port number, its protocols together (GetPorts).
		byNum := map[uint32]*nodev1.RelayPort{}
		for _, p := range ps.Ports {
			rp := byNum[p.Port]
			if rp == nil {
				rp = &nodev1.RelayPort{Name: name, From: p.Port, To: p.Port, Forwarded: true, Access: "spa"}
				byNum[p.Port] = rp
				out = append(out, rp)
			}
			if !slices.Contains(rp.Protos, p.Proto) {
				rp.Protos = append(rp.Protos, p.Proto)
				slices.Sort(rp.Protos)
			}
		}
	}
	if acme80 {
		// From any address, but only while an order is under way: the
		// relay's table forwards it for the window alone.
		out = append(out, &nodev1.RelayPort{Name: "acme", Protos: []string{"tcp"}, From: 80, To: 80, Forwarded: true, Access: "acme"})
	}
	return out
}

func (s *Server) RemoveRelay(ctx context.Context, req *connect.Request[nodev1.RemoveRelayRequest]) (*connect.Response[nodev1.RemoveRelayResponse], error) {
	err := s.removeRelay(ctx, req.Msg.Name)
	if err := s.done(ctx, "relay.remove", req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.RemoveRelayResponse{}), nil
}

// addRelay creates the relay. A new relay by an old one's name has none
// of its reports nor its turn (relay-update-remote-v1 §8.3): neither a
// record a removal could not delete, nor what the exit keeps of the old
// one in memory. Against a look at the queue (turnMu): none gives the old
// relay's turn to the new one.
func (s *Server) addRelay(ctx context.Context, name string, addr netip.Addr) (store.Relay, error) {
	s.relayUpd.turnMu.Lock()
	defer s.relayUpd.turnMu.Unlock()
	r, err := s.Store.CreateRelay(ctx, name, addr)
	if err != nil {
		return r, err
	}
	_ = s.Store.DeleteSetting(ctx, relayUpdateKey+r.Name)
	s.relayUpd.forget(r.Name)
	// Nor the names of a relay of its name before (relay-names-v1 §3),
	// should its removal have left them.
	_ = provision.ForgetRelayNames(ctx, s.Store, r.Name)
	return r, nil
}

// removeRelay deletes the relay and its update reports
// (relay-update-remote-v1 §8.3), as one against a report taken meanwhile,
// which then finds no relay, and against a look at the queue, which gives
// it no turn after. The relay is gone once its row is: a record left
// behind (the store failed in between) is nobody's, and AddRelay clears it
// for a new relay of the name.
func (s *Server) removeRelay(ctx context.Context, name string) error {
	s.relayUpd.turnMu.Lock()
	defer s.relayUpd.turnMu.Unlock()
	s.relayUpd.saveMu.Lock()
	defer s.relayUpd.saveMu.Unlock()
	if err := s.Store.DeleteRelay(ctx, name); err != nil {
		return err
	}
	s.relayUpd.forget(name)
	_ = s.Store.DeleteSetting(ctx, relayUpdateKey+name)
	_ = provision.ForgetRelayNames(ctx, s.Store, name)
	return nil
}

func relayPB(r store.Relay) *nodev1.Relay {
	return &nodev1.Relay{Name: r.Name, Address: r.Address.String(), CreatedAt: r.CreatedAt.Unix(), ProbePort: uint32(r.ProbePort)}
}

// IssueRelayBundle makes a relay its client certificate, its SPA parameters
// if it has none, and the bundle its host installs (relay-v1 §3). The
// certificate before stops working at once.
func (s *Server) IssueRelayBundle(ctx context.Context, req *connect.Request[nodev1.IssueRelayBundleRequest]) (*connect.Response[nodev1.IssueRelayBundleResponse], error) {
	if !isRoot(ctx) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("a relay's bundle holds its private key: root only"))
	}
	resp, err := s.issueRelayBundle(ctx, req.Msg)
	// The audit log names the relay, never the bundle: it holds a key.
	if err := s.done(ctx, "relay.bundle", req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

func (s *Server) issueRelayBundle(ctx context.Context, req *nodev1.IssueRelayBundleRequest) (*nodev1.IssueRelayBundleResponse, error) {
	relay, err := s.Store.RelayByName(ctx, req.Name)
	if err != nil {
		return nil, err
	}
	// The relay host forwards IPv4 (net.ipv4.ip_forward); IPv6 relays later.
	if !relay.Address.Is4() {
		return nil, fmt.Errorf("%w relay %s: a relay host is IPv4 for now", store.ErrInvalid, relay.Address)
	}
	exit, err := s.exitAddress(ctx, req.ExitAddress, relay.Address)
	if err != nil {
		return nil, err
	}
	// The relay takes its perimeter from the remote API.
	apiSvc, err := s.apiEndpoint(ctx)
	if err != nil {
		return nil, err
	}
	if apiSvc == nil {
		return nil, fmt.Errorf("%w: the relay takes its perimeter from the remote API: enable the api service first", store.ErrInvalid)
	}
	cidrs := req.Admin
	kept := len(cidrs) == 0 && len(relay.Admin) > 0
	if len(cidrs) == 0 && !kept {
		cidrs = req.AdminIfNone
	}
	sshPort, admin, err := relayAccess(relay, req.SshPort, cidrs)
	if err != nil {
		return nil, err
	}
	services, err := s.Store.ListServices(ctx)
	if err != nil {
		return nil, err
	}
	forwarded, err := relayForwarded(services, sshPort)
	if err != nil {
		return nil, err
	}
	// New SPA parameters with every bundle, clear of the ports the relay
	// forwards or serves: the keys of the devices for the relay change with
	// them. Nothing is written before every check has passed.
	served := append(slices.Clone(forwarded), store.Port{Proto: "tcp", Num: sshPort})
	params, spaJSON, err := provision.NewRelayParams(served)
	if err != nil {
		return nil, err
	}
	cert, err := NewClientCertificate()
	if err != nil {
		return nil, err
	}
	pem, err := EncodeClientCertificate(cert)
	if err != nil {
		return nil, err
	}
	// The relay's probe endpoint (relay-v1 §9.1): a port of its own, new
	// with every bundle like its certificate.
	probePort, err := provision.RelayProbePort(served, params)
	if err != nil {
		return nil, err
	}
	probeKey, probeCert, err := provision.SelfSigned(relay.Name)
	if err != nil {
		return nil, err
	}
	probePin, err := provision.SPKIPin(probeCert)
	if err != nil {
		return nil, err
	}
	probePEM := append(encodePEM("CERTIFICATE", probeCert), encodePEM("PRIVATE KEY", probeKey)...)
	bundle, err := node.RelayBundle{Version: 1, Name: relay.Name, Exit: exit, API: apiSvc.endpoint, Cert: string(pem),
		Probe: &node.RelayProbe{Port: probePort, Cert: string(probePEM)}}.Encode()
	if err != nil {
		return nil, err
	}
	certPin := CertPin(cert.Leaf)
	if err := s.Store.IssueRelay(ctx, relay.Name, store.RelayIssue{SPA: spaJSON, SSHPort: sshPort, Admin: admin, CertPin: certPin,
		ProbePort: probePort, ProbePin: probePin}); err != nil {
		return nil, err
	}
	// The relay as the bundle makes it: its ports for its host's firewall.
	relay.SPA, relay.SSHPort, relay.Admin, relay.ProbePort, relay.CertPin = spaJSON, sshPort, admin, probePort, certPin
	acme80, err := s.acmePort80(ctx, relay.Name)
	if err != nil {
		return nil, err
	}
	return &nodev1.IssueRelayBundleResponse{Bundle: bundle, SshPort: uint32(sshPort), Admin: admin, AdminKept: kept, ProbePort: uint32(probePort),
		Ports: relayPorts(relay, services, acme80)}, nil
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
		return 0, nil, fmt.Errorf("%w: the relay host's SSH needs admin addresses (-admin): give them, or run from an SSH session", store.ErrInvalid)
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
		if sshPort == relay.ProbePort {
			return fmt.Errorf("%w ssh port %d: the relay's probe endpoint", store.ErrInvalid, sshPort)
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
		if a.Zone() != "" {
			// The relay refuses it (node.DecodeRelayBundle): a zone is
			// any text after "%", and rayspa writes the exit into nft.
			return netip.Addr{}, fmt.Errorf("%w exit address %q: an IP without a zone (-exit)", store.ErrInvalid, host)
		}
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
