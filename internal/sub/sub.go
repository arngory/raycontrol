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
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/spa"
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
}

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
	q.Set("insecure", "0")
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
