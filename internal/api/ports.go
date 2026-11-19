package api

import (
	"context"
	"slices"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/spa"
)

// GetPorts lists the node's ports for a provider's firewall (rayctl
// ports): SPA, the enabled services', their rotation ranges with the port
// of this slot, TCP 80 while certificates come through HTTP-01. The same
// ports the perimeter has (snapshot), named, and how each was set.
func (s *Server) GetPorts(ctx context.Context, _ *connect.Request[nodev1.GetPortsRequest]) (*connect.Response[nodev1.GetPortsResponse], error) {
	chosen, err := provision.Ports(ctx, s.Store)
	if err != nil {
		return nil, toConnect(err)
	}
	services, err := s.Store.ListServices(ctx)
	if err != nil {
		return nil, toConnect(err)
	}
	now := time.Now()
	source := func(ok bool) string {
		if ok {
			return "chosen"
		}
		return "random"
	}
	p := s.Params
	spaPort := &nodev1.NodePort{Name: "spa", Protos: []string{"tcp", "udp"}, From: uint32(p.PortBase), To: uint32(p.PortBase) + uint32(p.PortRange) - 1,
		Source: source(chosen.SPA == provision.Span{Base: p.PortBase, Range: p.PortRange}), Access: "everyone"}
	spaPort.Current, spaPort.CurrentUntil = slotNow(p, now)
	out := []*nodev1.NodePort{spaPort}
	ssh := provision.SSHPorts(services)
	site := false
	allow, err := s.Store.AllowPrefixes(ctx)
	if err != nil {
		return nil, toConnect(err)
	}
	integ := len(allow) > 0
	for _, svc := range services {
		if !svc.Enabled {
			continue
		}
		site = site || svc.Kind == "site"
		ports, err := provision.ServicePorts(svc, ssh)
		if err != nil {
			continue // not in the perimeter either (snapshot)
		}
		byProto := map[uint16][]string{}
		var order []uint16
		for _, port := range ports {
			if _, ok := byProto[port.Num]; !ok {
				order = append(order, port.Num)
			}
			byProto[port.Num] = append(byProto[port.Num], port.Proto)
		}
		for _, n := range order {
			np := &nodev1.NodePort{Name: svc.Name, Protos: byProto[n], From: uint32(n), To: uint32(n), Source: "fixed", Access: "spa"}
			switch svc.Kind {
			case "ssh":
				np.Source, np.Access = "sshd", "admin"
			case "subscription":
				np.Name, np.Source = "sub", source(chosen.Sub == n)
			case "api":
				np.Name, np.Source = "api", source(chosen.API == n)
				// Integrations' servers reach it without a knock
				// (integrations-v1 §3.2), TCP only.
				if slices.Contains(byProto[n], "tcp") && integ {
					np.Access = "spa,static"
				}
			}
			if svc.Public() || realityOpen(svc) && n == 443 {
				np.Access = "everyone"
			}
			out = append(out, np)
		}
		if rot, ok := provision.ServiceRotation(svc); ok {
			secrets, err := s.Store.ServiceSecrets(ctx, svc.ID)
			if err != nil {
				return nil, toConnect(err)
			}
			sched := p
			copy(sched.PortKey[:], secrets[provision.SecretPortKey])
			sched.PortBase, sched.PortRange = rot.Base, rot.Range
			inPool := chosen.Rotation.Range > 0 && rot.Base >= chosen.Rotation.Base &&
				int(rot.Base)+int(rot.Range) <= int(chosen.Rotation.Base)+int(chosen.Rotation.Range)
			np := &nodev1.NodePort{Name: svc.Name + " rotation", Protos: []string{"udp"}, From: uint32(rot.Base),
				To: uint32(rot.Base) + uint32(rot.Range) - 1, Source: source(inPool), Access: "spa"}
			np.Current, np.CurrentUntil = slotNow(sched, now)
			out = append(out, np)
		}
	}
	if site {
		// HTTP-01: TCP 80 is redirected to rayd's responder for a few
		// minutes per certificate; with a DNS provider, DNS-01 instead.
		if c, _, err := provision.Cloudflare(ctx, s.Store); err == nil && c == nil {
			out = append(out, &nodev1.NodePort{Name: "acme", Protos: []string{"tcp"}, From: 80, To: 80, Source: "fixed", Access: "acme"})
		}
	}
	return connect.NewResponse(&nodev1.GetPortsResponse{Ports: out}), nil
}

// slotNow is the port of p's schedule now and when it changes.
func slotNow(p spa.Params, now time.Time) (uint32, int64) {
	slot := p.Slot(now)
	return uint32(p.Port(slot)), int64((slot + 1) * uint64(p.SlotLen/time.Second))
}
