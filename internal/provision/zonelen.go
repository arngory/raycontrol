package provision

import (
	"context"
	"fmt"
	"time"

	"github.com/arngory/raycontrol/internal/clientver"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/store"
)

// The longest zone, in characters, each DNS tunnel takes (docs/spec/
// dns-zone-length-v1.md). Measured on loopback with the real binaries
// (2026-11): a query's name holds 253 characters, the zone's among them,
// and what is left is a tunnel's upstream payload. Past these the client
// refuses to start or sends nothing, whatever the resolvers.
const (
	// ZoneLenBase is the zone length every tunnel takes with every client:
	// the domain of the node at most 16 characters, newZone's 4 before it.
	ZoneLenBase = 20

	// dnstt: Niko's core wants 80 bytes of KCP payload a query before
	// 1.66, 50 (kcp-go's own floor) since.
	MaxDNSTTZone     = 72
	MaxDNSTTZoneLong = 120

	// slipstream: the server's picoquic drops an Initial under 129 bytes;
	// Niko before 1.66 sizes its packets (240-L)/1.6-8 (129 at 20), since
	// 1.66 as its encoder fits them (129 at 29).
	MaxSlipstreamZoneShort = 20
	MaxSlipstreamZone      = 29

	// masterdns: the client's MIN_UPLOAD_MTU, 38 bytes, at 116; past
	// WarnMasterDNSZone a query carries under half of a short zone's.
	MaxMasterDNSZone  = 116
	WarnMasterDNSZone = 100
)

// LongZoneClient is the Niko release whose clients take the longer zones
// of dnstt and slipstream.
const LongZoneClient = "1.66.0"

// LongZoneClients reports whether the node's client policy keeps Niko
// older than LongZoneClient out now: a minimum for niko of LongZoneClient
// or later, in force. Clients that name no version are not asked to be
// refused as well: released Niko up to 1.58, which names none, deletes the
// node's profiles when refused (rayctl client min -yes), and such a client
// loses only the tunnels with a long zone.
func LongZoneClients(p clientver.Policy, now time.Time) bool {
	if !p.Active(now) {
		return false
	}
	min, ok := p.Min["niko"]
	if !ok {
		return false
	}
	mv, err := clientver.ParseVersion(min)
	want, _ := clientver.ParseVersion(LongZoneClient)
	return err == nil && clientver.Compare(mv, want) >= 0
}

// ZoneMax is the longest zone of a kind under a client policy at now; 0
// for a kind that is not a DNS tunnel.
func ZoneMax(kind string, p clientver.Policy, now time.Time) int {
	long := LongZoneClients(p, now)
	switch kind {
	case "dnstt":
		if long {
			return MaxDNSTTZoneLong
		}
		return MaxDNSTTZone
	case "slipstream":
		if long {
			return MaxSlipstreamZone
		}
		return MaxSlipstreamZoneShort
	case "masterdns":
		return MaxMasterDNSZone
	}
	return 0
}

// longPolicy is a policy that keeps Niko older than LongZoneClient out.
var longPolicy = clientver.Policy{Min: map[string]string{"niko": LongZoneClient}}

// zoneLenError says why a zone is too long for a kind, and what would do.
func zoneLenError(kind, zone string, max int) error {
	more := ""
	if longMax := ZoneMax(kind, longPolicy, time.Now()); longMax > max {
		more = fmt.Sprintf("; with clients from Niko %s only (rayctl client min niko %s), %d", LongZoneClient, LongZoneClient, longMax)
	}
	return fmt.Errorf("%w zone %s: %d characters, %s takes at most %d%s (docs/spec/dns-zone-length-v1.md): give zone=<a shorter name delegated to the node>; %d characters or fewer works for every tunnel and client",
		store.ErrInvalid, zone, len(zone), kind, max, more, ZoneLenBase)
}

// checkZoneLen refuses a zone of a DNS tunnel longer than ZoneMax under the
// node's client policy now.
func checkZoneLen(ctx context.Context, st *store.Store, kind, zone string) error {
	p, err := node.ClientPolicy(ctx, st)
	if err != nil {
		return err
	}
	now := time.Now()
	if max := ZoneMax(kind, p, now); max > 0 && len(zone) > max {
		return zoneLenError(kind, zone, max)
	}
	return nil
}

// ZonesTooLong lists the zones of all that a client policy would make too
// long (a policy set after them that lets older clients in): "<service>
// <zone> (<n> > <max>)".
func ZonesTooLong(all []store.Service, p clientver.Policy, now time.Time) []string {
	var out []string
	for _, svc := range all {
		max := ZoneMax(svc.Kind, p, now)
		if max == 0 {
			continue
		}
		for _, z := range Zones(svc) {
			if z = canonicalZone(z); len(z) > max {
				out = append(out, fmt.Sprintf("%s %s (%d > %d)", svc.Name, z, len(z), max))
			}
		}
	}
	return out
}

// ZoneWarnings are the enabled DNS tunnels whose zone the node's clients
// may not take, or take slowly: a zone longer than ZoneMax under the
// policy now (one made before raycontrol v0.36.0 checked, or with a
// longer limit then), and a masterdns zone past WarnMasterDNSZone.
func ZoneWarnings(all []store.Service, p clientver.Policy, now time.Time) []string {
	var out []string
	for _, svc := range all {
		max := ZoneMax(svc.Kind, p, now)
		if !svc.Enabled || max == 0 {
			continue
		}
		for _, z := range Zones(svc) {
			z = canonicalZone(z)
			switch {
			case len(z) > max:
				out = append(out, fmt.Sprintf("%s %s: zone %s is %d characters, more than the %d its clients take (docs/spec/dns-zone-length-v1.md): they do not start; give it a zone of %d or fewer",
					svc.Kind, svc.Name, z, len(z), max, ZoneLenBase))
			case svc.Kind == "masterdns" && len(z) > WarnMasterDNSZone:
				out = append(out, fmt.Sprintf("masterdns %s: zone %s is %d characters: a query carries under half of what a zone of %d does upstream",
					svc.Name, z, len(z), ZoneLenBase))
			}
		}
	}
	return out
}
