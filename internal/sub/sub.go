// Package sub builds, signs and serves subscriptions (docs/spec/subscription-v1.md).
package sub

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"github.com/arngory/raycontrol/internal/appmirror"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/summary"
)

const (
	signLabel = "raycontrol-sub-v1"
	authLabel = "raycontrol-sub-v1 auth"
	// AuthScheme prefixes the Authorization header value.
	AuthScheme = "RC1"
	// Lifetime is how long a subscription stays valid.
	Lifetime = 72 * time.Hour
	// MaxClockSkew bounds the minute in the auth token.
	MaxClockSkew = 2 // minutes
)

// Profile is one way to connect.
type Profile struct {
	Svc  uint16 `json:"svc"`
	Name string `json:"name"`
	Link string `json:"link"`
	Next *Next  `json:"next,omitempty"`
	// Via names the relays the profile also goes through (relay-v1 §4): the
	// same link with the relay's host, knocked at the relay with K_relay.
	Via []string `json:"via,omitempty"`
}

// Next is the credential that replaces Link from a given time (R4).
type Next struct {
	Link string `json:"link"`
	From int64  `json:"from"`
}

// Payload is the signed content.
type Payload struct {
	V      int    `json:"v"`
	NodeID string `json:"node_id"`
	// Name is the node's name (rayctl node name), for the client to show
	// with its address; checked by node.CleanName. None: no field.
	Name string `json:"name,omitempty"`
	// Note is what the node's owner tells its users (rayctl node note): one
	// line of plain text, at most 200 code points, checked by
	// node.CleanNote. None: no field.
	Note     string    `json:"note,omitempty"`
	Seq      uint64    `json:"seq"`
	Time     int64     `json:"time"`
	Issued   int64     `json:"issued"`
	Expires  int64     `json:"expires"`
	Profiles []Profile `json:"profiles"`
	// Probe says the endpoint serves channel probes (spec/probe-v1.md).
	Probe *ProbeHint `json:"probe,omitempty"`
	// Hints is a starting order of the profiles for the network the
	// subscription was asked from, out of the client summaries (R4-21,
	// probe-v1 §6.2); only with enough reports from that network.
	Hints *summary.Hints `json:"hints,omitempty"`
	// SPA lists the carriers the node takes (spa-v2 §10, §10.1): a client
	// skips what is not there instead of trying it. Nodes before v0.10.1
	// do not send it.
	SPA *SPAHint `json:"spa,omitempty"`
	// Relays in front of the node (relay-v1 §4).
	Relays []RelayHint `json:"relays,omitempty"`
	// DNSProbe is the key of dnsprobe-v1 (spec/dnsprobe-v1.md), for a
	// user with a dnstt profile: the client checks resolvers with it in
	// the dnstt zones.
	DNSProbe *DNSProbeHint `json:"dns_probe,omitempty"`
	// DNSAuth is the dnsauth versions the node takes on the user's DNS
	// tunnels that check tags (spec/dnsauth-v2.md §4): a client that
	// knows v2 signs with it when 2 is here, otherwise with v1. No field:
	// no such tunnel, or a node before v0.15.0 (v1 only).
	DNSAuth *DNSAuthVersions `json:"dnsauth,omitempty"`
	// App lists the client's releases the node serves at /app/v1
	// (spec/app-update-v1.md §1): only while the administrator has the
	// mirror on and it holds a verified release.
	App *appmirror.Hint `json:"app,omitempty"`
	// Traffic is the user's traffic limit and its count
	// (spec/traffic-limit-v1.md §4): only for a user with a limit.
	Traffic *TrafficHint `json:"traffic,omitempty"`
	// LAN is the user's devices over Yggdrasil (spec/lan-v1.md §1.2): only
	// for a user the administrator lets have it, with a Yggdrasil profile;
	// its password and devices only for a device that shows itself.
	LAN *LAN `json:"lan,omitempty"`
}

// TrafficHint is a user's traffic limit: Used bytes (up + down, as the
// node last wrote them, a minute behind at most) of Limit since Since
// (Unix seconds), the next reset at Reset (0: none, the period is the
// user's whole time). Exhausted: the node took the user off its profiles
// for the limit (the node decides; the answer has no profiles then).
type TrafficHint struct {
	V         int   `json:"v"`
	Used      int64 `json:"used"`
	Limit     int64 `json:"limit"`
	Since     int64 `json:"since"`
	Reset     int64 `json:"reset"`
	Exhausted bool  `json:"exhausted,omitempty"`
}

// ExhaustedJitter spreads the clients of a user over the limit after the
// reset (spec/traffic-limit-v1.md §4).
const (
	ExhaustedJitter   = 10 * time.Minute
	exhaustedLifetime = time.Hour
)

// ExhaustedExpiry is when the answer to a user over the limit expires: an
// hour on at most, and no later than the next reset (zero: none) plus
// jitter, so that the client learns of the reset, or a raised limit, by
// itself.
func ExhaustedExpiry(now, reset time.Time, jitter time.Duration) time.Time {
	exp := now.Add(exhaustedLifetime)
	if !reset.IsZero() {
		if r := reset.Add(min(max(jitter, 0), ExhaustedJitter)); r.Before(exp) {
			exp = r
		}
	}
	return exp
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// DNSAuthVersions lists dnsauth versions: 1, 2 or both.
type DNSAuthVersions struct {
	V []int `json:"v"`
}

// DNSProbeHint carries the node's dnsprobe-v1 key, base64url without
// padding.
type DNSProbeHint struct {
	V   int    `json:"v"`
	Key string `json:"key"`
}

// RelayHint is a relay in front of the node (relay-v1 §4): its address and
// its own SPA, at which a device knocks with its K_relay (spa.RelayKey with
// the relay's ID), and its probe endpoint when rayd relay serves one.
type RelayHint struct {
	ID    string          `json:"id"`
	Host  string          `json:"host"`
	SPA   node.SPAParams  `json:"spa"`
	Probe *RelayProbeHint `json:"probe,omitempty"`
}

// RelayProbeHint is a relay's probe-v1 endpoint (relay-v1 §9.2): at
// host:port, its certificate by pin, RC1 with the device's K_relay. Svc
// names it in an explicit knock scope; Report: it takes reports (§9.3).
type RelayProbeHint struct {
	V      int    `json:"v"`
	Port   uint16 `json:"port"`
	Pin    string `json:"pin"`
	Svc    uint16 `json:"svc"`
	UDP    bool   `json:"udp"`
	Report bool   `json:"report"`
}

// RelayKinds are the kinds a relay forwards to (relay-v1 §4): the DNS
// tunnels and Yggdrasil have paths of their own.
func RelayKinds(kind string) bool {
	return !slices.Contains([]string{"dnstt", "masterdns", "slipstream", "yggdrasil", "ssh", "subscription", "api"}, kind)
}

// SPAHint: "udp", "tcp" (bare, §10), "tls" (ClientHello, §10.1).
type SPAHint struct {
	Carriers []string `json:"carriers"`
}

// ProbeHint: probe-v1 on the subscription endpoint; UDP: the echo on the
// same port number; Tunnel: the name that leads to the endpoint through the
// tunnels of the services in TunnelSvc.
type ProbeHint struct {
	V   int  `json:"v"`
	UDP bool `json:"udp"`
	// Report lists the optional report fields the node takes (probe-v1
	// §6): a client sends one only when it is here.
	Report    []string `json:"report,omitempty"`
	Tunnel    string   `json:"tunnel,omitempty"`
	TunnelSvc []uint16 `json:"tunnel_svc,omitempty"`
}

// ProbeTunnels are the kinds whose exits send the probe name to the
// endpoint: Xray (inner behind the DNS tunnels and Yggdrasil, REALITY),
// rayd naive and the Hysteria2 backends (niko-server v0.5).
var ProbeTunnels = []string{"dnstt", "masterdns", "slipstream", "yggdrasil", "reality", "naive", "hy2-masq", "hy2-obfs"}

// Envelope is what the endpoint returns.
type Envelope struct {
	Payload string            `json:"payload"`
	Sig     map[string]string `json:"sig"`
}

func message(payload []byte) []byte { return append([]byte(signLabel), payload...) }

// Sign wraps a payload with both signatures.
func Sign(p Payload, keys provision.NodeKeys) (Envelope, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return Envelope{}, err
	}
	msg := message(body)
	mlsig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(keys.MLDSA65, msg, nil, true, mlsig); err != nil {
		return Envelope{}, err
	}
	enc := base64.RawURLEncoding
	return Envelope{
		Payload: enc.EncodeToString(body),
		Sig: map[string]string{
			"ed25519": enc.EncodeToString(ed25519.Sign(keys.Ed25519, msg)),
			"mldsa65": enc.EncodeToString(mlsig),
		},
	}, nil
}

// Verify checks both signatures with the public keys from node_keys and
// returns the payload. Clients do the same.
func Verify(e Envelope, nodeKeys map[string]string) (Payload, error) {
	var p Payload
	enc := base64.RawURLEncoding
	body, err := enc.DecodeString(e.Payload)
	if err != nil {
		return p, err
	}
	msg := message(body)
	edPub, err := hexKey(nodeKeys["ed25519"], ed25519.PublicKeySize)
	if err != nil {
		return p, fmt.Errorf("ed25519 key: %w", err)
	}
	edSig, err := enc.DecodeString(e.Sig["ed25519"])
	if err != nil || !ed25519.Verify(edPub, msg, edSig) {
		return p, errors.New("ed25519 signature does not verify")
	}
	mlRaw, err := enc.DecodeString(nodeKeys["mldsa65"])
	if err != nil {
		return p, err
	}
	var mlPub mldsa65.PublicKey
	if err := mlPub.UnmarshalBinary(mlRaw); err != nil {
		return p, err
	}
	mlSig, err := enc.DecodeString(e.Sig["mldsa65"])
	if err != nil || !mldsa65.Verify(&mlPub, msg, nil, mlSig) {
		return p, errors.New("ml-dsa-65 signature does not verify")
	}
	return p, json.Unmarshal(body, &p)
}

func hexKey(s string, n int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != n {
		return nil, fmt.Errorf("want %d bytes, got %d", n, len(b))
	}
	return b, nil
}

// AuthToken is the Authorization header value a device sends in a minute.
func AuthToken(deviceKey [spa.KeySize]byte, minute int64) string {
	return AuthScheme + " " + strconv.FormatInt(minute, 10) + "." + base64.RawURLEncoding.EncodeToString(authMAC(deviceKey, minute))
}

func authMAC(deviceKey [spa.KeySize]byte, minute int64) []byte {
	m := hmac.New(sha256.New, deviceKey[:])
	m.Write([]byte(authLabel))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(minute))
	m.Write(b[:])
	return m.Sum(nil)
}

// CheckAuth verifies an Authorization header value for the device at now.
func CheckAuth(header string, deviceKey [spa.KeySize]byte, now time.Time) bool {
	rest, ok := strings.CutPrefix(header, AuthScheme+" ")
	if !ok {
		return false
	}
	minStr, macStr, ok := strings.Cut(rest, ".")
	if !ok {
		return false
	}
	minute, err := strconv.ParseInt(minStr, 10, 64)
	if err != nil {
		return false
	}
	if d := minute - now.Unix()/60; d > MaxClockSkew || d < -MaxClockSkew {
		return false
	}
	mac, err := base64.RawURLEncoding.DecodeString(macStr)
	return err == nil && hmac.Equal(mac, authMAC(deviceKey, minute))
}

// Profiles builds the profiles of a user from the rendered model: those
// that could be made, and an error naming each service whose profile could
// not. One service's broken settings do not take the user's others away.
func Profiles(m render.Model, u render.User) ([]Profile, error) { return DeviceProfiles(m, u, nil) }

// DeviceProfiles are the profiles of a user's device, given by its SPA key:
// links that differ by device (Yggdrasil's key) are that device's. Without
// a device they are the user's (rayctl user export).
func DeviceProfiles(m render.Model, u render.User, device []byte) ([]Profile, error) {
	var inner *render.Service
	for i := range m.Services {
		if m.Services[i].Kind == "inner" {
			inner = &m.Services[i]
		}
	}
	var out []Profile
	var errs []error
	for _, s := range m.Services {
		if !slices.Contains(u.Services, s.ID) {
			continue
		}
		p, err := serviceProfile(m, u, s, inner, device)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("service %s: %w", s.Name, err))
		case p != nil:
			out = append(out, *p)
		}
	}
	return out, errors.Join(errs...)
}

// serviceProfile is a user's profile of one service, nil when the user has
// none there (no credential yet, no inner stage).
func serviceProfile(m render.Model, u render.User, s render.Service, inner *render.Service, device []byte) (*Profile, error) {
	switch s.Kind {
	case "dnstt", "masterdns", "slipstream":
		if inner == nil || m.Inner[u.ID] == "" {
			return nil, nil
		}
		_, encryption, err := render.VLESSEncryption(inner.Secrets[provision.SecretMLKEMSeed])
		if err != nil {
			return nil, err
		}
		q := url.Values{}
		q.Set("type", "raw")
		q.Set("encryption", encryption)
		q.Set("niko-node", m.NodeID)
		q.Set("niko-svc", strconv.FormatInt(s.ID, 10))
		zone := provision.Zone(s.Service)
		switch s.Kind {
		case "slipstream":
			// spec/slipstream-v1.md §4: the zone and the service's ID; the
			// server's key by its pin, the ALPN and name of its handshake.
			ss, err := provision.ParseSlipstream(s.Service)
			if err != nil {
				return nil, err
			}
			pin, err := provision.SPKIPin(s.Secrets[provision.SecretTLSCert])
			if err != nil {
				return nil, fmt.Errorf("certificate: %w", err)
			}
			q.Set("niko-dns", "slipstream;;"+ss.Zone+";"+strconv.FormatInt(s.ID, 10))
			q.Set("niko-slip", "v1;"+pin+";"+ss.ALPN+";"+ss.SNI)
		case "dnstt":
			pub, err := render.DNSTTPublicKey(s)
			if err != nil {
				return nil, err
			}
			q.Set("niko-dns", "dnstt;;"+zone+";"+pub)
			// dnsseal-v1: the zone's key when the seal is on.
			if render.DNSSealMode(s.Service) != "off" && len(s.Secrets[provision.SecretSealKey]) == 32 {
				q.Set("niko-dnsseal", "v1;"+base64.RawURLEncoding.EncodeToString(s.Secrets[provision.SecretSealKey]))
			}
		default:
			var settings struct {
				Method int `json:"encryption_method"`
			}
			_ = json.Unmarshal([]byte(s.Settings), &settings)
			q.Set("niko-dns", "masterdns;;"+zone+";"+strconv.Itoa(settings.Method))
			q.Set("niko-dnskey", string(s.Secrets[provision.SecretMasterDNSKey]))
			// mdseal-v1 (spec/mdseal-v1.md §6): the answers sealed with
			// niko-dnskey; with required the client drops open ones.
			switch render.DNSSealMode(s.Service) {
			case "optional":
				q.Set("niko-mdseal", "v1")
			case "required":
				q.Set("niko-mdseal", "v1;required")
			}
		}
		// Sign the queries with the device's key (spec/dnsauth-v1.md,
		// spec/dnsauth-masterdns.md, slipstream: always, dnsauth-v2): K
		// from niko-node and niko-svc.
		if render.DNSAuthMode(s.Service) != "off" {
			q.Set("niko-dnsauth", "v1")
		}
		// Spare zones (spec/dnszones-v1.md §2), in the order clients
		// try them; the same keys as the main zone. slipstream has one
		// zone (the server knows one, slipstream-v1 §3).
		if spares := provision.SpareZones(s.Service); len(spares) > 0 && s.Kind != "slipstream" {
			q.Set("niko-dns-spare", strings.Join(spares, ","))
		}
		link := func(uuid string) string {
			return "vless://" + uuid + "@inner:1?" + q.Encode() + "#" + url.PathEscape(s.Name)
		}
		p := Profile{Svc: uint16(s.ID), Name: s.Name, Link: link(m.Inner[u.ID])}
		if set := m.Sets[inner.ID][u.ID]; set.Next != "" {
			p.Next = &Next{Link: link(set.Next), From: set.NextFrom.Unix()}
		}
		return &p, nil
	case "yggdrasil":
		if inner == nil || m.Inner[u.ID] == "" {
			return nil, nil
		}
		link, err := YggdrasilLink(m, s, *inner, m.Inner[u.ID], device)
		if err != nil {
			return nil, err
		}
		p := Profile{Svc: uint16(s.ID), Name: s.Name, Link: link}
		if set := m.Sets[inner.ID][u.ID]; set.Next != "" {
			next, err := YggdrasilLink(m, s, *inner, set.Next, device)
			if err != nil {
				return nil, err
			}
			p.Next = &Next{Link: next, From: set.NextFrom.Unix()}
		}
		return &p, nil
	case "doh":
		token := m.Creds[s.ID][u.ID]
		if token == "" {
			return nil, nil
		}
		p := Profile{Svc: uint16(s.ID), Name: s.Name, Link: DoHLink(m, s, token)}
		if set := m.Sets[s.ID][u.ID]; set.Next != "" {
			p.Next = &Next{Link: DoHLink(m, s, set.Next), From: set.NextFrom.Unix()}
		}
		return &p, nil
	case "naive":
		password := m.Creds[s.ID][u.ID]
		if password == "" {
			return nil, nil
		}
		p := Profile{Svc: uint16(s.ID), Name: s.Name, Link: NaiveLink(m, s, password)}
		if set := m.Sets[s.ID][u.ID]; set.Next != "" {
			p.Next = &Next{Link: NaiveLink(m, s, set.Next), From: set.NextFrom.Unix()}
		}
		return &p, nil
	case "hy2-masq", "hy2-obfs":
		password := m.Creds[s.ID][u.ID]
		if password == "" {
			return nil, nil
		}
		p := Profile{Svc: uint16(s.ID), Name: s.Name, Link: HysteriaLink(m, s, password)}
		if set := m.Sets[s.ID][u.ID]; set.Next != "" {
			p.Next = &Next{Link: HysteriaLink(m, s, set.Next), From: set.NextFrom.Unix()}
		}
		return &p, nil
	case "reality":
		link, err := RealityLink(m, s, u.ID)
		if err != nil {
			return nil, err
		}
		if link != "" {
			p := Profile{Svc: uint16(s.ID), Name: s.Name, Link: link}
			// One next per profile: the earliest switch, the user's
			// credential (R4-1) or the service's keys (R4-7).
			set := m.Sets[s.ID][u.ID]
			if set.Next != "" {
				next, err := realityLink(m, s, set.Next, u.ID)
				if err != nil {
					return nil, err
				}
				p.Next = &Next{Link: next, From: set.NextFrom.Unix()}
			}
			if ns, from, ok := render.NextReality(s); ok && (p.Next == nil || from.Unix() <= p.Next.From) {
				// The next credential is accepted from its publication on,
				// so it goes with the next keys when there is one.
				uuid := m.Creds[s.ID][u.ID]
				if set.Next != "" {
					uuid = set.Next
				}
				next, err := realityLink(m, ns, uuid, u.ID)
				if err != nil {
					return nil, err
				}
				p.Next = &Next{Link: next, From: from.Unix()}
			}
			return &p, nil
		}
	}
	return nil, nil
}

// YggdrasilLink is a user's Yggdrasil profile (spec/subscription-v1.md §4):
// VLESS with ML-KEM-768 to inner at the node's mesh address and exit port,
// carried by Yggdrasil with one peer, the node itself, over a TLS link to
// the node's address under the service's name (sni): the client knows the
// node by its address (SPA goes there) and resolves no name, as for naive. niko-ygg is "<peer URI>;<the user's key>", the
// key (a 32-byte ed25519 seed, hex) derived from the same inner UUID; each
// niko-ygg-via is a public peer of the node, when it has them.
func YggdrasilLink(m render.Model, s, inner render.Service, uuid string, device []byte) (string, error) {
	st, nodeKey, err := render.YggdrasilNode(s)
	if err != nil {
		return "", err
	}
	_, encryption, err := render.VLESSEncryption(inner.Secrets[provision.SecretMLKEMSeed])
	if err != nil {
		return "", err
	}
	peer := url.URL{Scheme: "tls", Host: net.JoinHostPort(m.Host, "443"),
		RawQuery: url.Values{"sni": {st.SNI}, "key": {hex.EncodeToString(nodeKey)}}.Encode()}
	q := url.Values{}
	q.Set("type", "raw")
	q.Set("encryption", encryption)
	q.Set("niko-node", m.NodeID)
	q.Set("niko-svc", strconv.FormatInt(s.ID, 10))
	q.Set("niko-ygg", peer.String()+";"+hex.EncodeToString(render.YggdrasilDeviceKey(uuid, device).Seed()))
	// Public peers (R4-18): a fallback path through the mesh when the node
	// cannot be reached directly.
	for _, p := range st.Peers {
		// QUIC peers by address only (set before that rule: left out).
		if u, err := url.Parse(p); err == nil && u.Scheme == "quic" && net.ParseIP(u.Hostname()) == nil {
			continue
		}
		q.Add("niko-ygg-via", p)
	}
	host := net.JoinHostPort(render.YggdrasilAddress(nodeKey).String(), strconv.Itoa(st.ExitPort))
	return "vless://" + uuid + "@" + host + "?" + q.Encode() + "#" + url.PathEscape(s.Name), nil
}

// setSitePins adds niko-pin to the line of a service that answers with its
// site's certificate (spec/cert-pin-v1.md §2): the pins of the key of the
// leaf in use and of the next key, from the stored keys. The client takes
// a leaf with one of these keys only, whatever CA signed it. No parameter
// where the node cannot promise the key of the next certificate
// (provision.SiteKeyPins): the operator's own certificate, no certificate
// manager.
func setSitePins(q url.Values, m render.Model, s render.Service) {
	for _, x := range m.Services {
		if x.Kind == "site" && x.Name == provision.SiteOf(s.Service) {
			if pins := provision.SiteKeyPins(x.Service, x.Secrets); len(pins) > 0 {
				q.Set("niko-pin", strings.Join(pins, ","))
			}
		}
	}
}

// DoHLink is the DoH endpoint of a user (spec/subscription-v1.md §4): the
// standard https://<name>/dns-query/<token> with the Niko parameters, which
// the client drops before it asks.
func DoHLink(m render.Model, s render.Service, token string) string {
	var st struct {
		SNI string `json:"sni"`
	}
	_ = json.Unmarshal([]byte(s.Settings), &st)
	q := url.Values{}
	q.Set("niko-node", m.NodeID)
	q.Set("niko-svc", strconv.FormatInt(s.ID, 10))
	setSitePins(q, m, s)
	return "https://" + st.SNI + "/dns-query/" + url.PathEscape(token) + "?" + q.Encode() + "#" + url.PathEscape(s.Name)
}

// NaiveLink is the naive endpoint of a user (spec/subscription-v1.md §4):
// naive+https://niko:<password>@<node address>:443?sni=<name> with the Niko
// parameters, like hysteria2:// and vless://: the client needs no lookup of
// the name in its network and finds the node by its address. The server
// checks the password only.
func NaiveLink(m render.Model, s render.Service, password string) string {
	var st struct {
		SNI string `json:"sni"`
	}
	_ = json.Unmarshal([]byte(s.Settings), &st)
	q := url.Values{}
	q.Set("sni", st.SNI)
	q.Set("niko-node", m.NodeID)
	q.Set("niko-svc", strconv.FormatInt(s.ID, 10))
	// UDP over TCP v2 (spec/naive-uot-v1.md): without it the client sends
	// no UDP through naive.
	q.Set("uot", "2")
	// ping and traceroute (spec/icmp-v1.md): only where the node carries
	// them; without it the client sends no ICMP to the node.
	if provision.NaiveICMP(s.Service) {
		q.Set("icmp", "1")
	}
	setSitePins(q, m, s)
	return "naive+https://" + url.UserPassword("niko", password).String() + "@" + net.JoinHostPort(m.Host, "443") + "?" + q.Encode() + "#" + url.PathEscape(s.Name)
}

// HysteriaLink is the share link of a Hysteria2 service with a user's
// password (spec/subscription-v1.md §4): the standard hysteria2:// form,
// salamander for hy2-obfs, and the Niko parameters.
func HysteriaLink(m render.Model, s render.Service, password string) string {
	var st struct {
		SNI string `json:"sni"`
	}
	_ = json.Unmarshal([]byte(s.Settings), &st)
	port := 443
	if ports, err := s.Ports(); err == nil {
		for _, p := range ports {
			if p.Proto == "udp" {
				port = int(p.Num)
			}
		}
	}
	q := url.Values{}
	q.Set("sni", st.SNI)
	// No insecure parameter at all, not even 0: Niko rejects a line that
	// has one (RAYCONTROL.md §22), and the certificate is checked anyway.
	if s.Kind == "hy2-obfs" {
		q.Set("obfs", "salamander")
		q.Set("obfs-password", string(s.Secrets[provision.SecretObfsPassword]))
		// A self-signed certificate: Niko pins its key (niko-pin), other
		// clients its hash (pinSHA256).
		cert := s.Secrets[provision.SecretTLSCert]
		if pin, err := provision.SPKIPin(cert); err == nil {
			q.Set("niko-pin", pin)
		}
		sum := sha256.Sum256(cert)
		q.Set("pinSHA256", hex.EncodeToString(sum[:]))
	} else {
		// hy2-masq: the site's certificate, its keys pinned (cert-pin-v1);
		// no pinSHA256, which names one certificate and would break at
		// every renewal.
		setSitePins(q, m, s)
	}
	q.Set("niko-node", m.NodeID)
	q.Set("niko-svc", strconv.FormatInt(s.ID, 10))
	// niko-server >= v0.14.1 sends a stream's TCP response right after the
	// dial, before the destination speaks, so the client may hold the app's
	// SYN-ACK until then (subscription-v1 §4). TestNikoAckPin keeps the
	// pinned niko-server at that version or later.
	q.Set("niko-ack", "1")
	host := net.JoinHostPort(m.Host, strconv.Itoa(port))
	return "hysteria2://" + url.PathEscape(password) + "@" + host + "/?" + q.Encode() + "#" + url.PathEscape(s.Name)
}

// RealityLink is the share link of a REALITY service for a user, "" if the
// user has no credential there (spec/subscription-v1.md §4).
func RealityLink(m render.Model, s render.Service, userID int64) (string, error) {
	uuid := m.Creds[s.ID][userID]
	if uuid == "" {
		return "", nil
	}
	return realityLink(m, s, uuid, userID)
}

func realityLink(m render.Model, s render.Service, uuid string, userID int64) (string, error) {
	var rs render.RealitySettings
	if err := json.Unmarshal([]byte(s.Settings), &rs); err != nil {
		return "", err
	}
	pbk, pqv, err := render.RealityKeys(s)
	if err != nil {
		return "", err
	}
	_, encryption, err := render.VLESSEncryption(s.Secrets[provision.SecretMLKEMSeed])
	if err != nil {
		return "", err
	}
	port := 443
	if !m.FrontTCP {
		ports, err := s.Ports()
		if err != nil {
			return "", err
		}
		for _, p := range ports {
			if p.Proto == "tcp" {
				port = int(p.Num)
			}
		}
	}
	q := url.Values{}
	q.Set("type", "raw")
	q.Set("security", "reality")
	q.Set("encryption", encryption)
	q.Set("flow", render.RealityFlow)
	q.Set("sni", rs.SNI)
	q.Set("fp", rs.Fingerprint)
	q.Set("pbk", pbk)
	q.Set("sid", render.ShortID(s, userID))
	q.Set("pqv", pqv)
	q.Set("niko-node", m.NodeID)
	q.Set("niko-svc", strconv.FormatInt(s.ID, 10))
	host := net.JoinHostPort(m.Host, strconv.Itoa(port))
	return "vless://" + uuid + "@" + host + "?" + q.Encode() + "#" + url.PathEscape(s.Name), nil
}
