package provision

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/arngory/raycontrol/internal/cloudflare"
	"github.com/arngory/raycontrol/internal/dnscheck"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
)

// The node's DNS provider (docs/08-decisions.md, R4-10). The token is a
// secret (class P2) like the node's keys: it lives in the database only.
const (
	settingDNSProvider = "dns_provider"
	settingCFToken     = "cloudflare_token" //nolint:gosec // G101: a name
	settingCFZone      = "cloudflare_zone"
	settingNSName      = "dns_ns_name"
)

// CloudflareAPI is the API the node talks to (a test seam).
var CloudflareAPI = cloudflare.API

// Cloudflare returns the node's Cloudflare client and zone; a nil client
// when the node has no DNS provider.
func Cloudflare(ctx context.Context, st *store.Store) (*cloudflare.Client, cloudflare.Zone, error) {
	var zone cloudflare.Zone
	p, err := st.GetSetting(ctx, settingDNSProvider)
	if errors.Is(err, store.ErrNotFound) {
		return nil, zone, nil
	}
	if err != nil {
		return nil, zone, err
	}
	if string(p) != "cloudflare" {
		return nil, zone, fmt.Errorf("unknown DNS provider %q", p)
	}
	token, err := st.GetSetting(ctx, settingCFToken)
	if err != nil {
		return nil, zone, err
	}
	z, err := st.GetSetting(ctx, settingCFZone)
	if err != nil {
		return nil, zone, err
	}
	if err := json.Unmarshal(z, &zone); err != nil {
		return nil, zone, err
	}
	return &cloudflare.Client{Token: string(token), BaseURL: CloudflareAPI}, zone, nil
}

// SetCloudflare checks the token, finds the zone of the node's domain and
// keeps both.
func SetCloudflare(ctx context.Context, st *store.Store, token string) (cloudflare.Zone, error) {
	domain, err := Domain(ctx, st)
	if err != nil {
		return cloudflare.Zone{}, err
	}
	if domain == "" {
		return cloudflare.Zone{}, fmt.Errorf("%w: the node has no domain (rayd init -domain)", store.ErrInvalid)
	}
	token = strings.TrimSpace(token)
	c := &cloudflare.Client{Token: token, BaseURL: CloudflareAPI}
	if err := c.Verify(ctx); err != nil {
		return cloudflare.Zone{}, fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	zone, err := c.ZoneFor(ctx, domain)
	if err != nil {
		return zone, fmt.Errorf("%w: %w", store.ErrInvalid, err)
	}
	z, err := json.Marshal(zone)
	if err != nil {
		return zone, err
	}
	for k, v := range map[string][]byte{settingCFToken: []byte(token), settingCFZone: z, settingDNSProvider: []byte("cloudflare")} {
		if err := st.SetSetting(ctx, k, v); err != nil {
			return zone, err
		}
	}
	return zone, nil
}

// DNSRecords are the records the node needs in its zone: the wildcard every
// subdomain resolves through (the decoy site and REALITY's names, those it
// moves to included), and for DNS tunnels a name server name and the NS
// delegation of each tunnel zone to it. warnings say what cannot be made.
func DNSRecords(ctx context.Context, st *store.Store) (records []cloudflare.Record, warnings []string, err error) {
	domain, err := Domain(ctx, st)
	if err != nil || domain == "" {
		return nil, nil, err
	}
	host, err := node.Host(ctx, st)
	if err != nil {
		return nil, nil, err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return nil, []string{fmt.Sprintf("the node's host %q is a name, not an address: no records can point to it", host)}, nil
	}
	typ := "A"
	if addr.Is6() && !addr.Is4In6() {
		typ = "AAAA"
	}
	records = append(records, cloudflare.Record{Type: typ, Name: "*." + domain, Content: addr.Unmap().String()})

	all, err := st.ListServices(ctx)
	if err != nil {
		return nil, nil, err
	}
	var zones []string
	for _, s := range all {
		if (s.Kind == "dnstt" || s.Kind == "masterdns") && s.Enabled {
			if z := Zone(s); z != "" && !slices.Contains(zones, z) {
				zones = append(zones, z)
			}
		}
	}
	if len(zones) == 0 {
		return records, nil, nil
	}
	ns, err := nsName(ctx, st, all)
	if err != nil {
		return nil, nil, err
	}
	records = append(records, cloudflare.Record{Type: typ, Name: ns, Content: addr.Unmap().String()})
	slices.Sort(zones)
	for _, z := range zones {
		records = append(records, cloudflare.Record{Type: "NS", Name: z, Content: ns})
	}
	return records, nil, nil
}

// NSName is the name DNS tunnel zones are delegated to, as DNSRecords
// asks for it (chosen once, here or there): the front answers SOA and NS at
// the apex of dnstt zones with it (niko-server v0.9.0). "" when DNSRecords
// would ask for no delegation: no DNS tunnel, no domain, or a host that is
// a name. Then the delegation, if any, is the operator's own, and the
// front must not name another server.
func NSName(ctx context.Context, st *store.Store) (string, error) {
	domain, err := Domain(ctx, st)
	if err != nil || domain == "" {
		return "", err
	}
	host, err := node.Host(ctx, st)
	if err != nil {
		return "", err
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return "", nil
	}
	all, err := st.ListServices(ctx)
	if err != nil {
		return "", err
	}
	if !slices.ContainsFunc(all, func(s store.Service) bool {
		return (s.Kind == "dnstt" || s.Kind == "masterdns") && s.Enabled && Zone(s) != ""
	}) {
		return "", nil
	}
	return nsName(ctx, st, all)
}

// DNSCheckDevice names the node's own line in the dnsauth-v1 keys of a
// dnstt service (render.CollectForRender): the check from the node tags
// its polls with it, so that where auth is required a backend without the
// service's current seal key still shows as such, not as alive (review 8).
// Device IDs are hex: this one is no device's.
const DNSCheckDevice = "node-check"

// DNSCheckAuthKey is the dnsauth-v1 key of the node's own check on a
// service: derived as a device's (spa.DNSAuthKey) from the node's check
// key (store.DNSCheckKey), which no subscription carries.
func DNSCheckAuthKey(checkKey []byte, nodeID [spa.NodeIDSize]byte, svcID int64) ([spa.KeySize]byte, error) {
	if len(checkKey) != spa.KeySize {
		return [spa.KeySize]byte{}, fmt.Errorf("%w: a check key of %d bytes", store.ErrInvalid, len(checkKey))
	}
	return spa.DNSAuthKey([spa.KeySize]byte(checkKey), nodeID, uint16(svcID)), nil
}

// DNSCheckTargets are the zones the node checks from itself (dnscheck,
// rayd -dns-check): those of the enabled dnstt and masterdns services, as
// DNSRecords selects them, with what the check needs. The parent should
// delegate each to NSName and so to the node's host; a dnstt zone has the
// node's probe key, its service's seal mode and current seal key (its poll
// is sealed as a client's would be), and dnsauth's mode with the node's
// own key where auth is on (DNSCheckDevice).
func DNSCheckTargets(ctx context.Context, st *store.Store) ([]dnscheck.Zone, error) {
	host, err := node.Host(ctx, st)
	if err != nil {
		return nil, err
	}
	ns, err := NSName(ctx, st)
	if err != nil {
		return nil, err
	}
	all, err := st.ListServices(ctx)
	if err != nil {
		return nil, err
	}
	var zones []dnscheck.Zone
	var probeKey, checkKey []byte
	var params spa.Params
	for _, s := range all {
		zone := Zone(s)
		if !s.Enabled || (s.Kind != "dnstt" && s.Kind != "masterdns") || zone == "" {
			continue
		}
		z := dnscheck.Zone{Service: s.Name, Kind: s.Kind, Name: zone, NS: ns, Host: host, SvcID: uint16(s.ID)}
		if s.Kind == "dnstt" {
			if probeKey == nil {
				if probeKey, err = st.DNSProbeKey(ctx); err != nil {
					return nil, err
				}
			}
			z.ProbeKey, z.Seal, z.Auth = probeKey, DNSSealMode(s), DNSAuthMode(s)
			if z.Auth != "off" {
				if checkKey == nil {
					if params, err = node.LoadParams(ctx, st); err != nil {
						return nil, err
					}
					if checkKey, err = st.DNSCheckKey(ctx); err != nil {
						return nil, err
					}
				}
				k, err := DNSCheckAuthKey(checkKey, params.NodeID, s.ID)
				if err != nil {
					return nil, err
				}
				z.AuthKey = k[:]
			}
			if z.Seal != "off" {
				secrets, err := st.ServiceSecrets(ctx, s.ID)
				if err != nil {
					return nil, err
				}
				z.SealKey = secrets[SecretSealKey]
			}
		}
		zones = append(zones, z)
	}
	return zones, nil
}

// nsName is the name DNS tunnel zones are delegated to: a random label of
// the node's domain, chosen once.
func nsName(ctx context.Context, st *store.Store, all []store.Service) (string, error) {
	if b, err := st.GetSetting(ctx, settingNSName); err == nil {
		return string(b), nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	name, err := newZone(ctx, st, all)
	if err != nil {
		return "", err
	}
	// Render, the DNS sync and the API may ask at once the first time:
	// all of them take the name stored first, so the front and the
	// delegation never name two servers.
	stored, err := st.InitSetting(ctx, settingNSName, []byte(name))
	return string(stored), err
}

// SyncDNS brings the zone in line with DNSRecords. Without a DNS provider
// it does nothing.
func SyncDNS(ctx context.Context, st *store.Store) (changes, problems []string, err error) {
	c, zone, err := Cloudflare(ctx, st)
	if err != nil || c == nil {
		return nil, nil, err
	}
	records, problems, err := DNSRecords(ctx, st)
	if err != nil {
		return nil, problems, err
	}
	changes, conflicts, err := cloudflare.Sync(ctx, c, zone.ID, records)
	return changes, append(problems, conflicts...), err
}

// RemoveDNS forgets the DNS provider and, unless keep, first deletes every
// record raycontrol created in the zone.
func RemoveDNS(ctx context.Context, st *store.Store, keep bool) ([]string, error) {
	c, zone, err := Cloudflare(ctx, st)
	if err != nil || c == nil {
		return nil, err
	}
	var removed []string
	if !keep {
		if removed, err = cloudflare.RemoveOwn(ctx, c, zone.ID); err != nil {
			return removed, err
		}
	}
	for _, k := range []string{settingDNSProvider, settingCFToken, settingCFZone} {
		if err := st.DeleteSetting(ctx, k); err != nil {
			return removed, err
		}
	}
	return removed, nil
}
