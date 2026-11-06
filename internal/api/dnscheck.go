package api

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/dnscheck"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// CheckDNSZones gives the last periodic check of the node's DNS tunnel
// zones, or checks them now (dnscheck.Monitor: callers at the same time
// share a check, a forced one comes at most once per 30 s). Not for root
// only: the answer holds no key, and the node's own pace bounds what it
// sends to resolvers.
func (s *Server) CheckDNSZones(ctx context.Context, req *connect.Request[nodev1.CheckDNSZonesRequest]) (*connect.Response[nodev1.CheckDNSZonesResponse], error) {
	m := s.DNSCheck
	if m == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("this rayd does not check DNS zones"))
	}
	var resolvers []dnscheck.Resolver
	if len(req.Msg.Resolvers) > 0 {
		var err error
		if resolvers, err = dnscheck.ParseResolvers(req.Msg.Resolvers); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		// Over the remote API, only resolvers the node may well ask: the
		// named ones and public addresses on port 53.
		if !isLocal(ctx) {
			for _, r := range resolvers {
				if !r.Public() {
					return nil, connect.NewError(connect.CodeInvalidArgument,
						fmt.Errorf("resolver %s: over the remote API only the named ones or a public address on port 53", r.Name))
				}
			}
		}
	}
	if !req.Msg.Now && len(resolvers) == 0 {
		resp := &nodev1.CheckDNSZonesResponse{}
		if rep, ok := m.Last(); ok {
			resp = DNSReportPB(rep)
		}
		resp.NextAt = unixOf(m.Next())
		return connect.NewResponse(resp), nil
	}
	rep, err := m.Run(ctx, dnscheck.RunOptions{Resolvers: resolvers, Forced: true})
	var soon dnscheck.TooSoon
	switch {
	case errors.As(err, &soon):
		return nil, connect.NewError(connect.CodeResourceExhausted, err)
	case err != nil && ctx.Err() != nil:
		return nil, connect.NewError(connect.CodeCanceled, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	resp := DNSReportPB(rep)
	resp.NextAt = unixOf(m.Next())
	return connect.NewResponse(resp), nil
}

// DNSReportPB is a check of DNS zones as the API gives it: what the
// check found, none of the keys it used.
func DNSReportPB(rep dnscheck.Report) *nodev1.CheckDNSZonesResponse {
	out := &nodev1.CheckDNSZonesResponse{CheckedAt: unixOf(rep.End), Limited: rep.Limited,
		DurationMs: uint32(max(rep.End.Sub(rep.Start).Milliseconds(), 0))}
	for _, r := range rep.Resolvers {
		out.Resolvers = append(out.Resolvers, r.String())
	}
	for _, z := range rep.Zones {
		zc := &nodev1.DNSZoneCheck{Service: z.Zone.Service, Kind: z.Zone.Kind, Zone: z.Zone.Name, Ns: z.Zone.NS,
			State: z.State().String(), Summary: z.Summary(), Delegated: z.Delegated,
			Parent: dnsStepPB(z.Parent), Front: dnsStepPB(z.Front), Backend: dnsStepPB(z.Backend)}
		if err := z.Err(); err != nil {
			zc.Error = err.Error()
		}
		for _, r := range z.Resolvers {
			rc := &nodev1.DNSResolverCheck{Resolver: r.Resolver.String(), Network: r.Resolver.Net, WarnOnly: r.Resolver.WarnOnly,
				Soa: dnsStepPB(r.SOA), Small: dnsStepPB(r.Small), Large: dnsStepPB(r.Large), Edns: uint32(max(r.EDNS, 0)), CaseRandomized: r.Mixed}
			if r.Egress.IsValid() {
				rc.Egress = r.Egress.String()
			}
			zc.Resolvers = append(zc.Resolvers, rc)
		}
		out.Zones = append(out.Zones, zc)
	}
	return out
}

func dnsStepPB(s dnscheck.Step) *nodev1.DNSCheckStep {
	return &nodev1.DNSCheckStep{State: s.State.String(), Detail: s.Detail, Fix: s.Fix, RttMs: uint32(max(s.RTT.Milliseconds(), 0))}
}
