package provision

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/arngory/raycontrol/internal/store"
)

// MaxSlipstreamZone is the longest zone of a slipstream service
// (spec/slipstream-v1.md §3): a client's packets carry (240 - len(zone)) /
// 1.6 bytes, 8 of them the dnsauth-v2 field, and a QUIC Initial needs 129.
const MaxSlipstreamZone = 20

// DNSTunnel reports whether a kind is a DNS tunnel: a zone delegated to the
// node, answered by the front on UDP 53, its clients' queries tagged with a
// device's key (dnsauth).
func DNSTunnel(kind string) bool {
	return kind == "dnstt" || kind == "masterdns" || kind == "slipstream"
}

// SlipstreamSettings are a slipstream service's (spec/slipstream-v1.md §3):
// its zone, and the ALPN and server name its QUIC handshake carries, random
// per service (they are in every Initial, so no mark is shared). Not "sni":
// that is a name of the node (sites, REALITY), this one is not.
type SlipstreamSettings struct {
	Zone string `json:"zone"`
	ALPN string `json:"quic_alpn"`
	SNI  string `json:"quic_sni"`
}

var (
	slipALPN = regexp.MustCompile(`^[a-z0-9]{8,12}$`)
	slipSNI  = regexp.MustCompile(`^[a-z][a-z0-9]{2,9}\.[a-z]{2,6}$`)
)

// ParseSlipstream reads a slipstream service's settings, checked.
func ParseSlipstream(svc store.Service) (SlipstreamSettings, error) {
	var s SlipstreamSettings
	if err := json.Unmarshal([]byte(svc.Settings), &s); err != nil {
		return s, err
	}
	switch {
	case !zoneName.MatchString(s.Zone) || len(s.Zone) > MaxSlipstreamZone:
		return s, fmt.Errorf("zone %q: a DNS name of two labels or more, at most %d characters", s.Zone, MaxSlipstreamZone)
	case !slipALPN.MatchString(s.ALPN):
		return s, fmt.Errorf("quic_alpn %q: 8 to 12 of a-z and 0-9", s.ALPN)
	case !slipSNI.MatchString(s.SNI):
		return s, fmt.Errorf("quic_sni %q: <label>.<label>", s.SNI)
	}
	return s, nil
}

// slipstreamTLDs end the server names a slipstream service gets.
var slipstreamTLDs = []string{"com", "net", "org", "io", "app", "dev", "cloud", "tech"}

// slipstreamService fills in a new slipstream service: its zone (given, or
// a short one under the node's domain), a random ALPN and server name, and
// a self-signed P-256 certificate for the name, whose key clients pin
// (SPKI). It takes no options of the other DNS tunnels: the front checks
// every query's dnsauth-v2 tag (required from the first day: no old
// clients), the server has no seal and one zone.
func slipstreamService(ctx context.Context, st *store.Store, all []store.Service, settings map[string]any, secrets map[string][]byte) error {
	for _, k := range []string{"auth", "auth_hint", "seal", "spare_zones", "quic_alpn", "quic_sni"} {
		if _, ok := settings[k]; ok {
			return fmt.Errorf("%w: slipstream takes no %s (spec/slipstream-v1.md: dnsauth-v2 required, one zone; the ALPN and name are its own)", store.ErrInvalid, k)
		}
	}
	// Clients sign slipstream's queries with v2 whatever the subscription's
	// dnsauth.v says, which is for dnstt and masterdns alone (Niko 1.37):
	// a tunnel beside it with auth_hint=off is no conflict.
	if z, ok := settings["zone"]; !ok {
		zone, err := newZone(ctx, st, all)
		if err != nil {
			return err
		}
		if len(zone) > MaxSlipstreamZone {
			return fmt.Errorf("%w: a zone under the node's domain would be %d characters, slipstream takes at most %d (spec/slipstream-v1.md §3): give zone=<a shorter name delegated to the node>", store.ErrInvalid, len(zone), MaxSlipstreamZone)
		}
		settings["zone"] = zone
	} else if zs, isString := z.(string); !isString || !zoneName.MatchString(strings.TrimSuffix(zs, ".")) || len(canonicalZone(zs)) > MaxSlipstreamZone {
		return fmt.Errorf("%w zone %v: a DNS name of two labels or more, at most %d characters (spec/slipstream-v1.md §3)", store.ErrInvalid, z, MaxSlipstreamZone)
	} else if other := zoneConflict(canonicalZone(zs), all); other != "" {
		return fmt.Errorf("%w zone %v: the same as, or nested with, the zone of %s", store.ErrInvalid, z, other)
	} else if name, err := nodeNameClash(ctx, st, all, canonicalZone(zs)); err != nil {
		return err
	} else if name != "" {
		return fmt.Errorf("%w zone %v: it would take %s", store.ErrInvalid, z, name)
	} else {
		settings["zone"] = canonicalZone(zs)
	}

	alpn, err := randomLabel("abcdefghijklmnopqrstuvwxyz0123456789", 8, 12)
	if err != nil {
		return err
	}
	label, err := randomLabel("abcdefghijklmnopqrstuvwxyz", 4, 10)
	if err != nil {
		return err
	}
	tld, err := randInt(0, len(slipstreamTLDs)-1)
	if err != nil {
		return err
	}
	sni := label + "." + slipstreamTLDs[tld]
	key, cert, err := selfSigned(sni)
	if err != nil {
		return err
	}
	settings["quic_alpn"], settings["quic_sni"] = alpn, sni
	secrets[SecretTLSKey], secrets[SecretTLSCert] = key, cert
	return nil
}

// randomLabel is a random string of lo to hi characters of alphabet.
func randomLabel(alphabet string, lo, hi int) (string, error) {
	n, err := randInt(lo, hi)
	if err != nil {
		return "", err
	}
	b := make([]byte, n)
	for i := range b {
		j, err := randInt(0, len(alphabet)-1)
		if err != nil {
			return "", err
		}
		b[i] = alphabet[j]
	}
	return string(b), nil
}

// dnsTunnelKinds are the DNS tunnel kinds, for lists.
var dnsTunnelKinds = []string{"dnstt", "masterdns", "slipstream"}

// DNSTunnelKinds lists them.
func DNSTunnelKinds() []string { return slices.Clone(dnsTunnelKinds) }
