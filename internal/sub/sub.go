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
	V        int       `json:"v"`
	NodeID   string    `json:"node_id"`
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
	// user with a DNS tunnel: the client checks resolvers with it.
	DNSProbe *DNSProbeHint `json:"dns_probe,omitempty"`
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
	return !slices.Contains([]string{"dnstt", "masterdns", "yggdrasil", "ssh", "subscription", "api"}, kind)
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
var ProbeTunnels = []string{"dnstt", "masterdns", "yggdrasil", "reality", "naive", "hy2-masq", "hy2-obfs"}

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

// Profiles builds the profiles of a user from the rendered model.
func Profiles(m render.Model, u render.User) ([]Profile, error) {
	var inner *render.Service
	for i := range m.Services {
		if m.Services[i].Kind == "inner" {
			inner = &m.Services[i]
		}
	}
	var out []Profile
	for _, s := range m.Services {
		allowed := false
		for _, id := range u.Services {
			allowed = allowed || id == s.ID
		}
		if !allowed {
			continue
		}
		switch s.Kind {
		case "dnstt", "masterdns":
			if inner == nil || m.Inner[u.ID] == "" {
				continue
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
			if s.Kind == "dnstt" {
				pub, err := render.DNSTTPublicKey(s)
				if err != nil {
					return nil, err
				}
				q.Set("niko-dns", "dnstt;;"+zone+";"+pub)
				// Sign the queries with the device's key (spec/dnsauth-v1.md).
				if render.DNSAuthMode(s.Service) != "off" {
					q.Set("niko-dnsauth", "v1")
				}
			} else {
				var settings struct {
					Method int `json:"encryption_method"`
				}
				_ = json.Unmarshal([]byte(s.Settings), &settings)
				q.Set("niko-dns", "masterdns;;"+zone+";"+strconv.Itoa(settings.Method))
				q.Set("niko-dnskey", string(s.Secrets[provision.SecretMasterDNSKey]))
			}
			link := func(uuid string) string {
				return "vless://" + uuid + "@inner:1?" + q.Encode() + "#" + url.PathEscape(s.Name)
			}
			p := Profile{Svc: uint16(s.ID), Name: s.Name, Link: link(m.Inner[u.ID])}
			if set := m.Sets[inner.ID][u.ID]; set.Next != "" {
				p.Next = &Next{Link: link(set.Next), From: set.NextFrom.Unix()}
			}
			out = append(out, p)
		case "yggdrasil":
			if inner == nil || m.Inner[u.ID] == "" {
				continue
			}
			link, err := YggdrasilLink(m, s, *inner, m.Inner[u.ID])
			if err != nil {
				return nil, err
			}
			p := Profile{Svc: uint16(s.ID), Name: s.Name, Link: link}
			if set := m.Sets[inner.ID][u.ID]; set.Next != "" {
				next, err := YggdrasilLink(m, s, *inner, set.Next)
				if err != nil {
					return nil, err
				}
				p.Next = &Next{Link: next, From: set.NextFrom.Unix()}
			}
			out = append(out, p)
		case "doh":
			token := m.Creds[s.ID][u.ID]
			if token == "" {
				continue
			}
			p := Profile{Svc: uint16(s.ID), Name: s.Name, Link: DoHLink(m, s, token)}
			if set := m.Sets[s.ID][u.ID]; set.Next != "" {
				p.Next = &Next{Link: DoHLink(m, s, set.Next), From: set.NextFrom.Unix()}
			}
			out = append(out, p)
		case "naive":
			password := m.Creds[s.ID][u.ID]
			if password == "" {
				continue
			}
			p := Profile{Svc: uint16(s.ID), Name: s.Name, Link: NaiveLink(m, s, password)}
			if set := m.Sets[s.ID][u.ID]; set.Next != "" {
				p.Next = &Next{Link: NaiveLink(m, s, set.Next), From: set.NextFrom.Unix()}
			}
			out = append(out, p)
		case "hy2-masq", "hy2-obfs":
			password := m.Creds[s.ID][u.ID]
			if password == "" {
				continue
			}
			p := Profile{Svc: uint16(s.ID), Name: s.Name, Link: HysteriaLink(m, s, password)}
			if set := m.Sets[s.ID][u.ID]; set.Next != "" {
				p.Next = &Next{Link: HysteriaLink(m, s, set.Next), From: set.NextFrom.Unix()}
			}
			out = append(out, p)
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
				out = append(out, p)
			}
		}
	}
	return out, nil
}

// YggdrasilLink is a user's Yggdrasil profile (spec/subscription-v1.md §4):
// VLESS with ML-KEM-768 to inner at the node's mesh address and exit port,
// carried by Yggdrasil with one peer, the node itself, over a TLS link
// under the service's name. niko-ygg is "<peer URI>;<the user's key>", the
// key (a 32-byte ed25519 seed, hex) derived from the same inner UUID; each
// niko-ygg-via is a public peer of the node, when it has them.
func YggdrasilLink(m render.Model, s, inner render.Service, uuid string) (string, error) {
	st, nodeKey, err := render.YggdrasilNode(s)
	if err != nil {
		return "", err
	}
	_, encryption, err := render.VLESSEncryption(inner.Secrets[provision.SecretMLKEMSeed])
	if err != nil {
		return "", err
	}
	peer := url.URL{Scheme: "tls", Host: net.JoinHostPort(st.SNI, "443"),
		RawQuery: url.Values{"sni": {st.SNI}, "key": {hex.EncodeToString(nodeKey)}}.Encode()}
	q := url.Values{}
	q.Set("type", "raw")
	q.Set("encryption", encryption)
	q.Set("niko-node", m.NodeID)
	q.Set("niko-svc", strconv.FormatInt(s.ID, 10))
	q.Set("niko-ygg", peer.String()+";"+hex.EncodeToString(render.YggdrasilKey(uuid).Seed()))
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
	}
	q.Set("niko-node", m.NodeID)
	q.Set("niko-svc", strconv.FormatInt(s.ID, 10))
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
