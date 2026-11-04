package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1/perimeterv1connect"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
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
	pr := p.Params
	snap := &perimeterv1.Snapshot{Spa: &perimeterv1.SPAParams{
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
	}}

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
	for _, svc := range services {
		if !svc.Enabled {
			continue
		}
		ports, err := svc.Ports()
		if err != nil {
			return nil, fmt.Errorf("service %s: %w", svc.Name, err)
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
	if len(relays) > 0 {
		for _, r := range relays {
			snap.RelayPrefixes = append(snap.RelayPrefixes, netip.PrefixFrom(r.Address, r.Address.BitLen()).String())
		}
		seen := map[string]bool{}
		for _, svc := range services {
			if !svc.Enabled || svc.Kind == "ssh" || svc.Public() {
				continue
			}
			ports, _ := svc.Ports()
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
