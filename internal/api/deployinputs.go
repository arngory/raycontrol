package api

import (
	"fmt"

	"github.com/arngory/raycontrol/internal/deploy"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/provision"
)

// DeployInputsProto is in as GetDeployInputs returns it.
func DeployInputsProto(in deploy.Inputs) *nodev1.GetDeployInputsResponse {
	r := &nodev1.GetDeployInputsResponse{
		FrontTcp: in.FrontTCP, FrontRendered: in.Front, FrontDns: in.FrontDNS, DnsProbeKey: in.DNSProbeKey,
		SubscriptionPort: uint32(max(in.SubscriptionPort, 0)), //nolint:gosec // G115: a port, 0-65535
		HostPorts:        portRanges(in.HostPorts), OutsidePorts: portRanges(in.OutsidePorts), Warnings: in.Warnings,
	}
	for _, s := range in.Services {
		ps := &nodev1.DeployService{Kind: s.Kind, Name: s.Name, Uid: uint32(max(s.UID, 0)), //nolint:gosec // G115: a UID
			Answer: s.Answer, Site: s.Site, PublicPeers: s.PublicPeers, Salamander: s.Salamander, Icmp: s.ICMP}
		if s.Kind == "slipstream" {
			ps.Slipstream = &nodev1.DeploySlipstream{Zone: s.Slipstream.Zone, QuicAlpn: s.Slipstream.ALPN, QuicSni: s.Slipstream.SNI,
				MaxConnections:    uint32(max(s.Slipstream.MaxConnections, 0)),    //nolint:gosec // G115: checked by ParseSlipstream
				DeviceConnections: uint32(max(s.Slipstream.DeviceConnections, 0)), //nolint:gosec // G115: checked by ParseSlipstream
				Error:             s.SlipstreamError}
		}
		r.Services = append(r.Services, ps)
	}
	return r
}

// DeployInputs reads GetDeployInputs's answer, as root does: it comes from
// rayd, which root does not trust. A number that does not fit is an error,
// never cut down to fit (a port of 65536+22 is not port 22); the rest is
// for deploy.Inputs.Check and deploy.CheckService.
func DeployInputs(r *nodev1.GetDeployInputsResponse) (deploy.Inputs, error) {
	if len(r.GetServices()) > deploy.MaxInputServices {
		return deploy.Inputs{}, fmt.Errorf("%d services: at most %d", len(r.GetServices()), deploy.MaxInputServices)
	}
	in := deploy.Inputs{FrontTCP: r.GetFrontTcp(), Front: r.GetFrontRendered(), FrontDNS: r.GetFrontDns(), DNSProbeKey: r.GetDnsProbeKey(),
		SubscriptionPort: int(r.GetSubscriptionPort()), Warnings: r.GetWarnings()}
	if n := len(in.Warnings); n > deploy.MaxWarnings {
		in.Warnings = append(in.Warnings[:deploy.MaxWarnings:deploy.MaxWarnings], fmt.Sprintf("%d more of rayd's warnings not shown", n-deploy.MaxWarnings))
	}
	var err error
	if in.HostPorts, err = portsOf(r.GetHostPorts()); err != nil {
		return deploy.Inputs{}, fmt.Errorf("host ports: %w", err)
	}
	if in.OutsidePorts, err = portsOf(r.GetOutsidePorts()); err != nil {
		return deploy.Inputs{}, fmt.Errorf("outside ports: %w", err)
	}
	for _, s := range r.GetServices() {
		si := deploy.ServiceInput{Kind: s.GetKind(), Name: s.GetName(), UID: int(s.GetUid()), Answer: s.GetAnswer(), Site: s.GetSite(),
			PublicPeers: s.GetPublicPeers(), Salamander: s.GetSalamander(), ICMP: s.GetIcmp()}
		if ss := s.GetSlipstream(); ss != nil {
			si.Slipstream = provision.SlipstreamSettings{Zone: ss.GetZone(), ALPN: ss.GetQuicAlpn(), SNI: ss.GetQuicSni(),
				MaxConnections: int(ss.GetMaxConnections()), DeviceConnections: int(ss.GetDeviceConnections())}
			si.SlipstreamError = ss.GetError()
		} else if s.GetKind() == "slipstream" {
			si.SlipstreamError = fmt.Sprintf("service %q: rayd gave no settings", s.GetName())
		}
		in.Services = append(in.Services, si)
	}
	return in, nil
}

// portsOf reads port ranges back; a port above 65535 or 0 is an error.
func portsOf(rs []*nodev1.PortRange) ([]deploy.PortRange, error) {
	var out []deploy.PortRange
	for _, r := range rs {
		from, err := deploy.Port(r.GetFrom())
		if err != nil {
			return nil, err
		}
		to, err := deploy.Port(r.GetTo())
		if err != nil {
			return nil, err
		}
		out = append(out, deploy.PortRange{Proto: r.GetProto(), From: from, To: to})
	}
	return out, nil
}

// portRanges are port ranges as the API gives them.
func portRanges(rs []deploy.PortRange) []*nodev1.PortRange {
	var out []*nodev1.PortRange
	for _, r := range rs {
		out = append(out, &nodev1.PortRange{Proto: r.Proto, From: uint32(r.From), To: uint32(r.To)})
	}
	return out
}
