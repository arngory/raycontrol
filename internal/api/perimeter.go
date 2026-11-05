package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1/perimeterv1connect"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
)

// PerimeterServer feeds rayspa. Its snapshots carry device keys, so only the
// rayspa user and root may watch.
type PerimeterServer struct {
	*Server
	RayspaUID  int
	DefaultTTL time.Duration
	MaxTTL     time.Duration
	TCPCarrier bool
	// Refresh re-reads the store this often even without changes, so that
	// expiring users drop out on time.
	Refresh time.Duration
}

var _ perimeterv1connect.PerimeterServiceHandler = (*PerimeterServer)(nil)

// Handler returns the HTTP handler for the perimeter service.
func (p *PerimeterServer) Handler() (string, http.Handler) {
	return perimeterv1connect.NewPerimeterServiceHandler(p)
}

func (p *PerimeterServer) WatchPerimeter(ctx context.Context, _ *connect.Request[perimeterv1.WatchPerimeterRequest], stream *connect.ServerStream[perimeterv1.WatchPerimeterResponse]) error {
	cred, _ := ctx.Value(peerKey{}).(*unix.Ucred)
	if cred == nil || (cred.Uid != 0 && int(cred.Uid) != p.RayspaUID) {
		return connect.NewError(connect.CodePermissionDenied, errors.New("only rayspa may watch the perimeter"))
	}
	var last []byte
	for {
		rev, wake := p.changes()
		snap, err := p.snapshot(ctx)
		if err != nil {
			return toConnect(err)
		}
		body, err := proto.MarshalOptions{Deterministic: true}.Marshal(snap)
		if err != nil {
			return err
		}
		if string(body) != string(last) {
			snap.Revision = rev
			if err := stream.Send(&perimeterv1.WatchPerimeterResponse{Snapshot: snap}); err != nil {
				return err
			}
			last = body
		}
		select {
		case <-ctx.Done():
			return nil
		case <-wake:
		case <-time.After(p.Refresh):
		}
	}
}

// snapshot builds the perimeter state from the store. Revision is left 0 so
// that equal states marshal equally.
func (p *PerimeterServer) snapshot(ctx context.Context) (*perimeterv1.Snapshot, error) {
	snap := &perimeterv1.Snapshot{Spa: p.spaPB(p.Params), DebugUntil: unixOf(debugUntil(ctx, p.Store))}

	devices, err := p.Store.SPADevices(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range devices {
		pd := &perimeterv1.Device{Id: d.ID, Key: d.Key[:]}
		for _, id := range d.Allowed {
			pd.Allowed = append(pd.Allowed, uint32(id))
		}
		snap.Devices = append(snap.Devices, pd)
	}

	services, err := p.Store.ListServices(ctx)
	if err != nil {
		return nil, err
	}
	public := map[string]bool{}
	ssh := provision.SSHPorts(services)
	for _, svc := range services {
		if !svc.Enabled {
			continue
		}
		ports, err := provision.ServicePorts(svc, ssh)
		if err != nil {
			// Settings from before a check (S-3): the service is not
			// rendered either (render.ServiceErrors), so it gets no port;
			// the others keep theirs.
			continue
		}
		if svc.Public() || realityOpen(svc) {
			if !svc.Public() {
				// Its TCP ports public, and still a service for SPA scopes.
				ps := &perimeterv1.Service{Id: uint32(svc.ID)}
				for _, port := range ports {
					ps.Ports = append(ps.Ports, &perimeterv1.Port{Proto: port.Proto, Port: uint32(port.Num)})
				}
				snap.Services = append(snap.Services, ps)
			}
			for _, port := range ports {
				// "open" makes TCP 443 public, never another port the
				// service was given (tcp/22 would take SSH out from
				// behind SPA).
				if !svc.Public() && port != openPort {
					continue
				}
				if !public[port.String()] {
					public[port.String()] = true
					snap.PublicPorts = append(snap.PublicPorts, &perimeterv1.Port{Proto: port.Proto, Port: uint32(port.Num)})
				}
			}
			continue
		}
		ps := &perimeterv1.Service{Id: uint32(svc.ID)}
		var udp uint16
		for _, port := range ports {
			ps.Ports = append(ps.Ports, &perimeterv1.Port{Proto: port.Proto, Port: uint32(port.Num)})
			if port.Proto == "udp" && udp == 0 {
				udp = port.Num
			}
		}
		if rot, ok := provision.ServiceRotation(svc); ok && udp != 0 {
			secrets, err := p.Store.ServiceSecrets(ctx, svc.ID)
			if err != nil {
				return nil, err
			}
			ps.Rotation = &perimeterv1.Rotation{PortKey: secrets[provision.SecretPortKey],
				PortBase: uint32(rot.Base), PortRange: uint32(rot.Range), TargetPort: uint32(udp)}
		}
		snap.Services = append(snap.Services, ps)
	}
	if port, until := p.acmeWindow(); port != 0 && until.After(time.Now()) {
		snap.Acme = &perimeterv1.AcmeWindow{Port: uint32(port), Until: until.Unix()}
	}
	admin, err := node.AdminAccess(ctx, p.Store)
	if err != nil {
		return nil, err
	}
	for _, a := range admin {
		snap.AdminPrefixes = append(snap.AdminPrefixes, a.String())
	}
	// Relays (relay-v1): their addresses reach the ports of every enabled
	// service that is not SSH and not public anyway; never the admin ports.
	relays, err := p.Store.ListRelays(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range relays {
		// A relay host is IPv4 (relay-v1 §3.1): an IPv6 relay a branch
		// build added cannot get a bundle, so its address reaches nothing.
		if a := r.Address.Unmap(); a.Is4() {
			snap.RelayPrefixes = append(snap.RelayPrefixes, netip.PrefixFrom(a, 32).String())
		}
	}
	if len(snap.RelayPrefixes) > 0 {
		seen := map[string]bool{}
		for _, svc := range services {
			if !svc.Enabled || svc.Kind == "ssh" || svc.Public() {
				continue
			}
			ports, _ := provision.ServicePorts(svc, ssh)
			for _, port := range ports {
				if !seen[port.String()] {
					seen[port.String()] = true
					snap.RelayPorts = append(snap.RelayPorts, &perimeterv1.Port{Proto: port.Proto, Port: uint32(port.Num)})
				}
			}
		}
	}
	for _, svc := range services {
		if svc.Enabled && svc.Kind == "ssh" {
			ports, _ := svc.Ports()
			for _, port := range ports {
				snap.AdminPorts = append(snap.AdminPorts, &perimeterv1.Port{Proto: port.Proto, Port: uint32(port.Num)})
			}
		}
	}
	return snap, nil
}

// spaPB is the SPA part of a snapshot for a parameter set.
func (p *PerimeterServer) spaPB(pr spa.Params) *perimeterv1.SPAParams {
	return &perimeterv1.SPAParams{
		NodeId:      pr.NodeID[:],
		EpochLenS:   uint32(pr.EpochLen / time.Second),
		SlotLenS:    uint32(pr.SlotLen / time.Second),
		PortKey:     pr.PortKey[:],
		PortBase:    uint32(pr.PortBase),
		PortRange:   uint32(pr.PortRange),
		LenMin:      uint32(pr.LenMin),
		LenMax:      uint32(pr.LenMax),
		DefaultTtlS: uint32(p.DefaultTTL / time.Second),
		MaxTtlS:     uint32(p.MaxTTL / time.Second),
		TcpCarrier:  p.TCPCarrier,
	}
}

// RelaySnapshot is the perimeter of a relay in front of this node, as its
// rayspa takes it (relay-v1 §3.1): the relay's own SPA; each device with its
// key for this relay (spa.RelayKey), never its own; the services the relay
// forwards, with the same IDs and ports (SPA scopes stay as they are), but
// not SSH, not the public ones, and no UDP port rotation (§4); the relay
// host's own SSH as a local service in the scope of the exit's SSH, so the
// devices allowed SSH there open it here by SPA, and for the relay's own
// admin addresses (never the exit's).
func (p *PerimeterServer) RelaySnapshot(ctx context.Context, name string) (*perimeterv1.Snapshot, error) {
	relay, err := p.Store.RelayByName(ctx, name)
	if err != nil {
		return nil, err
	}
	params, err := provision.RelayParams(ctx, p.Store, name)
	if err != nil {
		return nil, err
	}
	snap := &perimeterv1.Snapshot{Spa: p.spaPB(params)}
	var scoped map[uint16]bool
	snap.Services, scoped, err = p.relayServices(ctx, relay)
	if err != nil {
		return nil, err
	}
	// The relay's probe endpoint (relay-v1 §9.1): served there, open to
	// every device the relay knows.
	probe := relay.ProbePort != 0 && !scoped[provision.RelayProbeSvc]
	if probe {
		snap.Services = append(snap.Services, &perimeterv1.Service{Id: uint32(provision.RelayProbeSvc), Local: true,
			Ports: []*perimeterv1.Port{{Proto: "tcp", Port: uint32(relay.ProbePort)}, {Proto: "udp", Port: uint32(relay.ProbePort)}}})
	}
	devices, err := p.Store.SPADevices(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range devices {
		var allowed []uint32
		for _, id := range d.Allowed {
			if scoped[id] {
				allowed = append(allowed, uint32(id))
			}
		}
		if len(allowed) == 0 {
			continue
		}
		if probe {
			allowed = append(allowed, uint32(provision.RelayProbeSvc))
		}
		k := spa.RelayKey(d.Key, p.Params.NodeID, params.NodeID, relay.Name)
		snap.Devices = append(snap.Devices, &perimeterv1.Device{Id: d.ID, Key: k[:], Allowed: allowed})
	}
	snap.AdminPrefixes = slices.Clone(relay.Admin)
	snap.AdminPorts = []*perimeterv1.Port{{Proto: "tcp", Port: uint32(relay.SSHPort)}}
	return snap, nil
}

// relayServices are the services a relay forwards to this node and its own
// SSH (local), and their IDs.
func (p *PerimeterServer) relayServices(ctx context.Context, relay store.Relay) ([]*perimeterv1.Service, map[uint16]bool, error) {
	var out []*perimeterv1.Service
	services, err := p.Store.ListServices(ctx)
	if err != nil {
		return nil, nil, err
	}
	scoped := map[uint16]bool{}
	ssh := provision.SSHPorts(services)
	sshPort := store.Port{Proto: "tcp", Num: relay.SSHPort}
	for _, svc := range services {
		if !svc.Enabled || svc.Public() {
			continue
		}
		if svc.Kind == "ssh" {
			if !scoped[uint16(svc.ID)] {
				out = append(out, &perimeterv1.Service{Id: uint32(svc.ID), Local: true,
					Ports: []*perimeterv1.Port{{Proto: sshPort.Proto, Port: uint32(sshPort.Num)}}})
				scoped[uint16(svc.ID)] = true
			}
			continue
		}
		ports, err := provision.RelayPorts(relay, svc, ssh)
		if err != nil {
			continue
		}
		if len(ports) == 0 {
			continue
		}
		ps := &perimeterv1.Service{Id: uint32(svc.ID)}
		for _, port := range ports {
			ps.Ports = append(ps.Ports, &perimeterv1.Port{Proto: port.Proto, Port: uint32(port.Num)})
		}
		out = append(out, ps)
		scoped[uint16(svc.ID)] = true
	}
	return out, scoped, nil
}

// RelayKnows reports whether a relay knows the device: whether it may
// reach a service the relay forwards (the devices of RelaySnapshot).
func (p *PerimeterServer) RelayKnows(ctx context.Context, name, device string) (bool, error) {
	relay, err := p.Store.RelayByName(ctx, name)
	if err != nil {
		return false, err
	}
	_, scoped, err := p.relayServices(ctx, relay)
	if err != nil {
		return false, err
	}
	devices, err := p.Store.SPADevices(ctx)
	if err != nil {
		return false, err
	}
	for _, d := range devices {
		if d.ID == device {
			return slices.ContainsFunc(d.Allowed, func(id uint16) bool { return scoped[id] }), nil
		}
	}
	return false, nil
}

// openPort is the one port "open" makes public.
var openPort = store.Port{Proto: "tcp", Num: 443}

// realityOpen reports a REALITY service with "open": TCP 443 to everyone
// (RAYCONTROL.md §22.2.2).
func realityOpen(svc store.Service) bool {
	if svc.Kind != "reality" {
		return false
	}
	var st struct {
		Open bool `json:"open"`
	}
	_ = json.Unmarshal([]byte(svc.Settings), &st)
	return st.Open
}
