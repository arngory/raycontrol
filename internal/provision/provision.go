// Package provision creates what a node and its services need beyond the
// database rows: node signing keys, the subscription endpoint, tunnel keys
// and zones.
package provision

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/site"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
)

const (
	settingDomain  = "domain"
	settingEd25519 = "node_ed25519_seed"
	settingMLDSA   = "node_mldsa65_seed"

	// MasterDnsVPN method 5 is AES-256-GCM. Method 2 (its default) is a bare
	// ChaCha20 stream without authentication; the node allows AEAD only.
	masterdnsMethod = 5
)

// Secret names, shared with the renderer (names, not secrets).
const (
	SecretNoisePrivate  = "noise_private"        // dnstt, X25519
	SecretMasterDNSKey  = "encryption_key"       // MasterDnsVPN, hex text
	SecretMLKEMSeed     = "mlkem768_seed"        //nolint:gosec // G101: a name; inner, VLESS encryption
	SecretTLSKey        = "tls_key"              // subscription, PKCS#8 DER
	SecretTLSCert       = "tls_cert"             // subscription, DER
	SecretPortKey       = "port_key"             // UDP port rotation schedule
	SecretRealityKey    = "reality_x25519"       //nolint:gosec // G101: a name; REALITY, X25519 private key
	SecretRealityMLDSA  = "reality_mldsa65_seed" //nolint:gosec // G101: a name; REALITY, ML-DSA-65 seed
	SecretShortIDs      = "short_ids"            // REALITY, comma-separated hex
	SecretSiteSeed      = "site_seed"            // decoy site content
	SecretTLSChain      = "tls_chain"            // ACME certificate chain, PEM
	SecretObfsPassword  = "obfs_password"        //nolint:gosec // G101: a name; hy2-obfs, salamander
	SecretYggdrasilSeed = "yggdrasil_seed"       // the node's Yggdrasil key, an ed25519 seed
	SubscriptionService = "subscription"
)

// RealityShortIDs is how many shortIds a REALITY service gets; clients use
// one each (render.ShortID), so users do not all send the same one.
const RealityShortIDs = 4

// Options are the node-wide settings given at init.
type Options struct {
	Host   string // address clients use
	Domain string // base domain for service subdomains; may be empty
}

// NodeKeys are the node's signing keys (subscription signatures).
type NodeKeys struct {
	Ed25519 ed25519.PrivateKey
	MLDSA65 *mldsa65.PrivateKey
}

// PublicJSON is the node_keys field of the device bundle.
func (k NodeKeys) PublicJSON() map[string]string {
	pub, _ := k.MLDSA65.Public().(*mldsa65.PublicKey).MarshalBinary()
	return map[string]string{
		"ed25519": hex.EncodeToString(k.Ed25519.Public().(ed25519.PublicKey)),
		"mldsa65": base64.RawURLEncoding.EncodeToString(pub),
	}
}

// Init prepares a node: SPA parameters, signing keys, the subscription
// service. Repeating it keeps everything already created.
func Init(ctx context.Context, st *store.Store, o Options) (spa.Params, error) {
	params, err := node.Init(ctx, st, o.Host)
	if err != nil {
		return params, err
	}
	if o.Domain != "" {
		if err := st.SetSetting(ctx, settingDomain, []byte(strings.ToLower(o.Domain))); err != nil {
			return params, err
		}
	}
	for _, name := range []string{settingEd25519, settingMLDSA} {
		if _, err := st.GetSetting(ctx, name); errors.Is(err, store.ErrNotFound) {
			seed := make([]byte, 32)
			if _, err := rand.Read(seed); err != nil {
				return params, err
			}
			if err := st.SetSetting(ctx, name, seed); err != nil {
				return params, err
			}
		} else if err != nil {
			return params, err
		}
	}
	if _, err := st.ServiceByName(ctx, SubscriptionService); errors.Is(err, store.ErrNotFound) {
		host, err := node.Host(ctx, st)
		if err != nil {
			return params, err
		}
		svc, err := subscriptionService(params, host)
		if err != nil {
			return params, err
		}
		if _, err := st.CreateService(ctx, svc); err != nil {
			return params, err
		}
	} else if err != nil {
		return params, err
	}
	return params, nil
}

// LoadNodeKeys returns the signing keys created by Init.
func LoadNodeKeys(ctx context.Context, st *store.Store) (NodeKeys, error) {
	ed, err := st.GetSetting(ctx, settingEd25519)
	if err != nil {
		return NodeKeys{}, err
	}
	ml, err := st.GetSetting(ctx, settingMLDSA)
	if err != nil {
		return NodeKeys{}, err
	}
	var seed [mldsa65.SeedSize]byte
	copy(seed[:], ml)
	_, sk := mldsa65.NewKeyFromSeed(&seed)
	return NodeKeys{Ed25519: ed25519.NewKeyFromSeed(ed), MLDSA65: sk}, nil
}

// Domain returns the base domain or "" if none was set.
func Domain(ctx context.Context, st *store.Store) (string, error) {
	b, err := st.GetSetting(ctx, settingDomain)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	return string(b), err
}

func randInt(lo, hi int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(hi-lo+1)))
	if err != nil {
		return 0, err
	}
	return lo + int(n.Int64()), nil
}

// subscriptionService picks a random port outside the SPA range and a
// self-signed certificate; clients pin its key (spec/subscription-v1.md).
func subscriptionService(p spa.Params, host string) (store.Service, error) {
	var port int
	for {
		n, err := randInt(20000, 60999)
		if err != nil {
			return store.Service{}, err
		}
		if n < int(p.PortBase) || n >= int(p.PortBase)+int(p.PortRange) {
			port = n
			break
		}
	}
	key, cert, err := selfSigned(host)
	if err != nil {
		return store.Service{}, err
	}
	// The UDP port of the same number: the echo of channel probes (R4-16).
	settings, _ := json.Marshal(map[string][]string{"ports": {fmt.Sprintf("tcp/%d", port), fmt.Sprintf("udp/%d", port)}})
	return store.Service{
		Kind: "subscription", Name: SubscriptionService, Enabled: true, Settings: string(settings),
		Secrets: map[string][]byte{SecretTLSKey: key, SecretTLSCert: cert},
	}, nil
}

// SubscriptionUDP gives the subscription service the UDP port of its TCP
// port's number, for the echo of channel probes (R4-16), on nodes set up
// before it.
func SubscriptionUDP(ctx context.Context, st *store.Store) error {
	svc, err := st.ServiceByName(ctx, SubscriptionService)
	if err != nil {
		return err
	}
	ports, err := svc.Ports()
	if err != nil || len(ports) == 0 {
		return fmt.Errorf("subscription service has no port: %w", err)
	}
	want := store.Port{Proto: "udp", Num: ports[0].Num}
	if slices.Contains(ports, want) {
		return nil
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(svc.Settings), &settings); err != nil {
		return err
	}
	list := make([]string, 0, len(ports)+1)
	for _, p := range ports {
		list = append(list, p.String())
	}
	settings["ports"] = append(list, want.String())
	b, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	return st.UpdateService(ctx, svc.ID, store.ServiceUpdate{Settings: string(b)})
}

// SelfSigned makes a self-signed ECDSA P-256 certificate for host.
func SelfSigned(host string) (keyDER, certDER []byte, err error) { return selfSigned(host) }

func selfSigned(host string) (keyDER, certDER []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if certDER, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key); err != nil {
		return nil, nil, err
	}
	keyDER, err = x509.MarshalPKCS8PrivateKey(key)
	return keyDER, certDER, err
}

// SPKIPin returns base64url(SHA-256(SubjectPublicKeyInfo)) of a DER certificate.
func SPKIPin(certDER []byte) (string, error) {
	c, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// kindsNeedingInner send their traffic to the inner stage.
var kindsNeedingInner = []string{"dnstt", "masterdns", "olcrtc", "openflux", "yggdrasil"}

// NeedsInner reports whether a kind exits through the inner stage.
func NeedsInner(kind string) bool { return slices.Contains(kindsNeedingInner, kind) }

// CreateService fills in defaults and secrets, stores the service and, if
// it needs the inner stage and there is none yet, creates "inner" too.
func CreateService(ctx context.Context, st *store.Store, svc store.Service) (store.Service, error) {
	all, err := st.ListServices(ctx)
	if err != nil {
		return svc, err
	}
	if svc.Settings == "" {
		svc.Settings = "{}"
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(svc.Settings), &settings); err != nil {
		return svc, fmt.Errorf("%w settings: %w", store.ErrInvalid, err)
	}
	svc.Secrets = map[string][]byte{}

	switch svc.Kind {
	case "dnstt", "masterdns":
		if _, ok := settings["zone"]; !ok {
			zone, err := newZone(ctx, st, all)
			if err != nil {
				return svc, err
			}
			settings["zone"] = zone
		}
		if svc.Kind == "dnstt" {
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return svc, err
			}
			svc.Secrets[SecretNoisePrivate] = key.Bytes()
		} else {
			settings["encryption_method"] = masterdnsMethod
			raw := make([]byte, 16)
			if _, err := rand.Read(raw); err != nil {
				return svc, err
			}
			svc.Secrets[SecretMasterDNSKey] = []byte(hex.EncodeToString(raw)) // 32 hex chars, as MasterDnsVPN expects
		}
	case "inner":
		seed := make([]byte, 64)
		if _, err := rand.Read(seed); err != nil {
			return svc, err
		}
		svc.Secrets[SecretMLKEMSeed] = seed
	case "site":
		answer, _ := settings["answer"].(string)
		if answer == "" {
			answer = site.Answer404
		}
		if !slices.Contains(site.Answers, answer) {
			return svc, fmt.Errorf("%w site answer %q: want one of %s", store.ErrInvalid, answer, strings.Join(site.Answers, ", "))
		}
		settings["answer"] = answer
		if _, ok := settings["sni"]; !ok {
			name, err := newZone(ctx, st, all)
			if err != nil {
				return svc, err
			}
			settings["sni"] = name
		}
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return svc, err
		}
		svc.Secrets[SecretSiteSeed] = seed
	case "hy2-masq":
		// Hysteria2 with masquerade (R3-1): a random name of the node's
		// domain under the certificate of its site.
		site, err := siteFor(ctx, st, all)
		if err != nil {
			return svc, err
		}
		if all, err = st.ListServices(ctx); err != nil {
			return svc, err
		}
		settings["site"] = site.Name
		if _, ok := settings["sni"]; !ok {
			name, err := newZone(ctx, st, all)
			if err != nil {
				return svc, err
			}
			settings["sni"] = name
		}
	case "doh", "naive", "yggdrasil":
		// DoH (R3-2), naive (R2-14) and Yggdrasil (R4-15) share TCP 443 behind
		// the front (R2-15) under names of the node's domain, with the
		// certificate of the site REALITY steals from (unknown names go to
		// REALITY, which answers as that site).
		site := ""
		for _, s := range all {
			if s.Kind == "reality" && s.Enabled && siteOf(s) != "" {
				site = siteOf(s)
			}
		}
		if site == "" {
			return svc, fmt.Errorf("%w %s shares TCP 443 with REALITY under the node's own site: add reality first (rayctl service add reality reality)", store.ErrInvalid, svc.Kind)
		}
		settings["site"] = site
		if _, ok := settings["sni"]; !ok {
			name, err := newZone(ctx, st, all)
			if err != nil {
				return svc, err
			}
			settings["sni"] = name
		}
		if _, ok := settings["ports"]; !ok {
			// TCP 443 and, for DoH3 and naive-quic, UDP 443: both behind the
			// front (R2-15, R3-5). Yggdrasil links are TLS over TCP only.
			settings["ports"] = []string{"tcp/443", "udp/443"}
			if svc.Kind == "yggdrasil" {
				settings["ports"] = []string{"tcp/443"}
			}
		}
		if svc.Kind == "yggdrasil" {
			if peers, ok := settings["peers"]; ok {
				list, _ := peers.([]any)
				var uris []string
				for _, p := range list {
					s, _ := p.(string)
					uris = append(uris, s)
				}
				if len(uris) != len(list) || len(uris) == 0 {
					return svc, fmt.Errorf("%w yggdrasil peers: a list of peer URIs", store.ErrInvalid)
				}
				if _, err := YggdrasilPeers(strings.Join(uris, ",")); err != nil {
					return svc, err
				}
			}
			// The node's key, and the port of its mesh address that leads to
			// inner: random per node, like everything a scan could match.
			seed := make([]byte, 32)
			if _, err := rand.Read(seed); err != nil {
				return svc, err
			}
			svc.Secrets[SecretYggdrasilSeed] = seed
			if _, ok := settings["exit_port"]; !ok {
				port, err := randInt(1024, 65535)
				if err != nil {
					return svc, err
				}
				settings["exit_port"] = port
			}
		}
	case "api":
		// The remote API (R3-3): one per node, its own random TCP port behind
		// SPA, a self-signed certificate clients pin like the subscription's.
		for _, s := range all {
			if s.Kind == "api" {
				return svc, fmt.Errorf("%w the node has its API already: %s", store.ErrInvalid, s.Name)
			}
		}
		host, err := node.Host(ctx, st)
		if err != nil {
			return svc, err
		}
		key, cert, err := selfSigned(host)
		if err != nil {
			return svc, err
		}
		svc.Secrets[SecretTLSKey], svc.Secrets[SecretTLSCert] = key, cert
		if _, ok := settings["ports"]; !ok {
			port, err := freePort(ctx, st, all)
			if err != nil {
				return svc, err
			}
			settings["ports"] = []string{fmt.Sprintf("tcp/%d", port)}
		}
	case "hy2-obfs":
		// Hysteria2 inside salamander (R3-1): nothing of it shows outside,
		// so its certificate is its own, self-signed, pinned by clients
		// (niko-pin) and never in DNS or CT logs.
		if _, ok := settings["sni"]; !ok {
			label := make([]byte, 6)
			if _, err := rand.Read(label); err != nil {
				return svc, err
			}
			settings["sni"] = hex.EncodeToString(label) + ".invalid"
		}
		sni, _ := settings["sni"].(string)
		key, cert, err := selfSigned(sni)
		if err != nil {
			return svc, err
		}
		svc.Secrets[SecretTLSKey], svc.Secrets[SecretTLSCert] = key, cert
		pw := make([]byte, 24)
		if _, err := rand.Read(pw); err != nil {
			return svc, err
		}
		svc.Secrets[SecretObfsPassword] = []byte(base64.RawURLEncoding.EncodeToString(pw))
		// UDP 443 like hy2-masq: the front tells them apart by salamander
		// (udpmux, R3-4).
	case "reality":
		if _, ok := settings["target"]; !ok {
			// Self-steal: the node's own decoy site answers non-clients.
			site, err := siteFor(ctx, st, all)
			if err != nil {
				return svc, err
			}
			settings["site"] = site.Name
			settings["sni"] = SiteName(site)
		}
		if err := realitySettings(settings); err != nil {
			return svc, err
		}
		if err := realitySecrets(svc.Secrets); err != nil {
			return svc, err
		}
	}

	if rotates(svc.Kind) {
		// This service's own ports count as taken too.
		b, err := json.Marshal(settings)
		if err != nil {
			return svc, err
		}
		if _, ok := settings["udp_rotation"]; !ok && hasUDP(store.Service{Kind: svc.Kind, Settings: string(b)}) {
			rot, key, err := newRotation(ctx, st, append(slices.Clone(all), store.Service{Kind: svc.Kind, Settings: string(b)}))
			if err != nil {
				return svc, err
			}
			settings["udp_rotation"] = rot
			svc.Secrets[SecretPortKey] = key
		}
	}

	b, err := json.Marshal(settings)
	if err != nil {
		return svc, err
	}
	svc.Settings = string(b)
	if NeedsInner(svc.Kind) && !slices.ContainsFunc(all, func(s store.Service) bool { return s.Kind == "inner" }) {
		if _, err := CreateService(ctx, st, store.Service{Kind: "inner", Name: "inner", Enabled: true}); err != nil {
			return svc, fmt.Errorf("creating inner: %w", err)
		}
	}
	return st.CreateService(ctx, svc)
}

// RealityTarget returns the target and server name of REALITY settings.
// The target answers everyone who is not a client (probes included):
// "site:<name>" is the node's own decoy site (self-steal, the default with
// a domain); otherwise a foreign TLS 1.3 site the name belongs to
// (CheckRealityTarget), the name defaulting to the target's host.
func RealityTarget(settings map[string]any) (target, sni string, err error) {
	if site, _ := settings["site"].(string); site != "" {
		sni, _ = settings["sni"].(string)
		return "site:" + site, sni, nil
	}
	target, _ = settings["target"].(string)
	if target == "" {
		return "", "", fmt.Errorf("%w reality needs a target or the node's decoy site: "+
			`-settings '{"target":"www.example.org:443"}'`, store.ErrInvalid)
	}
	host := ""
	if !strings.HasPrefix(target, "/") {
		h, port, err := net.SplitHostPort(target)
		if err != nil || h == "" || port == "" {
			return "", "", fmt.Errorf("%w reality target %q: use host:port or a unix socket path", store.ErrInvalid, target)
		}
		host = h
	}
	sni, _ = settings["sni"].(string)
	if sni == "" {
		if host == "" || net.ParseIP(host) != nil {
			return "", "", fmt.Errorf("%w reality: set sni, the name the target has a certificate for", store.ErrInvalid)
		}
		sni = host
	}
	return target, sni, nil
}

// realitySettings checks the target and fills the server name and the
// client fingerprint.
func realitySettings(settings map[string]any) error {
	_, sni, err := RealityTarget(settings)
	if err != nil {
		return err
	}
	settings["sni"] = sni
	if fp, _ := settings["fingerprint"].(string); fp == "" {
		settings["fingerprint"] = "chrome"
	}
	return nil
}

// realitySecrets makes the REALITY keys (X25519, ML-DSA-65 seed), the
// shortIds (random lengths, so that installs differ) and the seed of the
// second layer, VLESS encryption with ML-KEM-768.
func realitySecrets(secrets map[string][]byte) error {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	secrets[SecretRealityKey] = key.Bytes()
	for name, n := range map[string]int{SecretRealityMLDSA: 32, SecretMLKEMSeed: 64} {
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		secrets[name] = b
	}
	ids := make([]string, RealityShortIDs)
	for i := range ids {
		n, err := randInt(2, 8) // bytes: 4 to 16 hex characters
		if err != nil {
			return err
		}
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		ids[i] = hex.EncodeToString(b)
	}
	secrets[SecretShortIDs] = []byte(strings.Join(ids, ","))
	return nil
}

// siteFor returns the decoy site, creating it with the first REALITY
// service in self-steal mode.
func siteFor(ctx context.Context, st *store.Store, all []store.Service) (store.Service, error) {
	for _, s := range all {
		if s.Kind == "site" {
			return s, nil
		}
	}
	domain, err := Domain(ctx, st)
	if err != nil {
		return store.Service{}, err
	}
	if domain == "" {
		return store.Service{}, fmt.Errorf("%w reality: without a node domain give a foreign target: "+
			`-settings '{"target":"www.example.org:443"}'`, store.ErrInvalid)
	}
	return CreateService(ctx, st, store.Service{Kind: "site", Name: "site", Enabled: true})
}

// SetServiceOption changes a setting that may change after creation: the
// answer of a site, whether REALITY moves its server name (R4-7, R4-8).
func SetServiceOption(ctx context.Context, st *store.Store, name, key, value string) (store.Service, error) {
	svc, err := st.ServiceByName(ctx, name)
	if err != nil {
		return svc, err
	}
	var v any
	switch {
	case svc.Kind == "site" && key == "answer":
		if !slices.Contains(site.Answers, value) {
			return svc, fmt.Errorf("%w site answer %q: want one of %s", store.ErrInvalid, value, strings.Join(site.Answers, ", "))
		}
		v = value
	case svc.Kind == "reality" && key == "rotate_sni":
		b, err := strconv.ParseBool(value)
		if err != nil {
			return svc, fmt.Errorf("%w rotate_sni: true or false", store.ErrInvalid)
		}
		v = b
	case (svc.Kind == "hy2-masq" || svc.Kind == "hy2-obfs") && (key == "up_mbps" || key == "down_mbps"):
		// The ceilings of the server's Brutal per connection (R4-16): up is
		// what the node sends a client at most (the node's channel or its
		// tariff), down what a client may send it; 0 removes the ceiling.
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 || n > 100000 {
			return svc, fmt.Errorf("%w %s: Mbit/s, 0 to 100000 (0: none)", store.ErrInvalid, key)
		}
		v = n
	case svc.Kind == "yggdrasil" && key == "peers":
		// Public peers (P-14, R4-18): off unless set; none removes them.
		v = 0
		if value != "" && value != "none" {
			peers, err := YggdrasilPeers(value)
			if err != nil {
				return svc, err
			}
			v = peers
		}
	default:
		return svc, fmt.Errorf("%w: %s has no option %q (site: answer; reality: rotate_sni; hy2-*: up_mbps, down_mbps; yggdrasil: peers)", store.ErrInvalid, name, key)
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(svc.Settings), &settings); err != nil {
		return svc, err
	}
	settings[key] = v
	if v == 0 {
		delete(settings, key)
	}
	b, err := json.Marshal(settings)
	if err != nil {
		return svc, err
	}
	if err := st.UpdateService(ctx, svc.ID, store.ServiceUpdate{Settings: string(b)}); err != nil {
		return svc, err
	}
	svc.Settings = string(b)
	return svc, nil
}

// MaxYggdrasilPeers bounds the public peers of a Yggdrasil service.
const MaxYggdrasilPeers = 8

// YggdrasilPeers parses the public peers of a Yggdrasil service (P-14,
// R4-18): comma-separated peer URIs as yggdrasil-go takes them, over TLS,
// QUIC, WebSocket or plain TCP, with a host and a port. The node peers with
// them, and clients get them as a fallback path to the node.
func YggdrasilPeers(value string) ([]string, error) {
	var peers []string
	for p := range strings.SplitSeq(value, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		u, err := url.Parse(p)
		if err != nil || u.Host == "" || u.Port() == "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return nil, fmt.Errorf("%w yggdrasil peer %q: want a URI like tls://host:port", store.ErrInvalid, p)
		}
		if !slices.Contains([]string{"tls", "quic", "wss", "ws", "tcp"}, u.Scheme) {
			return nil, fmt.Errorf("%w yggdrasil peer %q: scheme tls, quic, wss, ws or tcp", store.ErrInvalid, p)
		}
		if port, err := strconv.Atoi(u.Port()); err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("%w yggdrasil peer %q: bad port", store.ErrInvalid, p)
		}
		if ip := net.ParseIP(u.Hostname()); ip != nil && (!ip.IsGlobalUnicast() || ip.IsPrivate()) {
			return nil, fmt.Errorf("%w yggdrasil peer %q: a public address, or a name", store.ErrInvalid, p)
		}
		if !slices.Contains(peers, p) {
			peers = append(peers, p)
		}
	}
	if len(peers) == 0 || len(peers) > MaxYggdrasilPeers {
		return nil, fmt.Errorf("%w yggdrasil peers: 1 to %d peer URIs, comma-separated", store.ErrInvalid, MaxYggdrasilPeers)
	}
	return peers, nil
}

// SiteAnswer returns what a decoy site answers (site.Answer404 when unset,
// as for sites created before the setting).
func SiteAnswer(svc store.Service) string {
	var s struct {
		Answer string `json:"answer"`
	}
	_ = json.Unmarshal([]byte(svc.Settings), &s)
	if s.Answer == "" {
		return site.Answer404
	}
	return s.Answer
}

// SiteName returns the server name of a decoy site.
func SiteName(svc store.Service) string {
	var s struct {
		SNI string `json:"sni"`
	}
	_ = json.Unmarshal([]byte(svc.Settings), &s)
	return s.SNI
}

const settingACMEPort = "acme_port"

// ACMEPort is the port of rayd's HTTP-01 responder: random per install,
// outside the SPA range, the rotation ranges and the service ports, so
// host firewalls can let it through for good (the perimeter opens it only
// during an order).
func ACMEPort(ctx context.Context, st *store.Store) (uint16, error) {
	if b, err := st.GetSetting(ctx, settingACMEPort); err == nil {
		p, err := strconv.Atoi(string(b))
		return uint16(p), err
	} else if !errors.Is(err, store.ErrNotFound) {
		return 0, err
	}
	params, err := node.LoadParams(ctx, st)
	if err != nil {
		return 0, err
	}
	all, err := st.ListServices(ctx)
	if err != nil {
		return 0, err
	}
	free := func(p int) bool {
		if p >= int(params.PortBase) && p < int(params.PortBase)+int(params.PortRange) {
			return false
		}
		for _, s := range all {
			if r, ok := ServiceRotation(s); ok && p >= int(r.Base) && p < int(r.Base)+int(r.Range) {
				return false
			}
			ports, _ := s.Ports()
			if slices.ContainsFunc(ports, func(sp store.Port) bool { return int(sp.Num) == p }) {
				return false
			}
		}
		return true
	}
	for range 1000 {
		p, err := randInt(20000, 60999)
		if err != nil {
			return 0, err
		}
		if free(p) {
			return uint16(p), st.SetSetting(ctx, settingACMEPort, []byte(strconv.Itoa(p)))
		}
	}
	return 0, errors.New("no free port for the ACME responder")
}

// newZone returns "<label>.<domain>" with a random label not used yet.
func newZone(ctx context.Context, st *store.Store, all []store.Service) (string, error) {
	domain, err := Domain(ctx, st)
	if err != nil {
		return "", err
	}
	if domain == "" {
		return "", fmt.Errorf("%w: this service needs the node domain (rayd init -domain)", store.ErrInvalid)
	}
	// Nor the name DNS tunnel zones are delegated to.
	ns, _ := st.GetSetting(ctx, settingNSName)
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	for {
		label := make([]byte, 3)
		for i := range label {
			n, err := randInt(0, len(alphabet)-1)
			if err != nil {
				return "", err
			}
			label[i] = alphabet[n]
		}
		zone := string(label) + "." + domain
		if zone != string(ns) && !slices.ContainsFunc(all, func(s store.Service) bool { return strings.Contains(s.Settings, `"`+zone+`"`) }) {
			return zone, nil
		}
	}
}

// Zone returns the "zone" setting of a DNS tunnel service.
func Zone(svc store.Service) string {
	var s struct {
		Zone string `json:"zone"`
	}
	_ = json.Unmarshal([]byte(svc.Settings), &s)
	return s.Zone
}

// Rotation is the UDP port schedule of a service (spa-v2.md §11).
type Rotation struct {
	Base  uint16 `json:"base"`
	Range uint16 `json:"range"`
}

// rotates lists the kinds whose UDP port follows a schedule: everything the
// front serves on UDP 443.
func rotates(kind string) bool {
	return slices.Contains([]string{"hy2-masq", "hy2-obfs", "naive", "doh"}, kind)
}

// ServiceRotation returns the schedule of a service, if it has one and a
// UDP port for it to lead to: DoH and naive serve TCP 443 only until a
// udpmux (DoH3, naive-quic), and clients must not be told otherwise.
func ServiceRotation(svc store.Service) (Rotation, bool) {
	var s struct {
		Rot *Rotation `json:"udp_rotation"`
	}
	if json.Unmarshal([]byte(svc.Settings), &s) != nil || s.Rot == nil || s.Rot.Range == 0 || !hasUDP(svc) {
		return Rotation{}, false
	}
	return *s.Rot, true
}

func hasUDP(svc store.Service) bool {
	ports, err := svc.Ports()
	return err == nil && slices.ContainsFunc(ports, func(p store.Port) bool { return p.Proto == "udp" })
}

// freePort picks a random port that no SPA range, rotation range, service
// port or the ACME responder uses.
func freePort(ctx context.Context, st *store.Store, all []store.Service) (int, error) {
	params, err := node.LoadParams(ctx, st)
	if err != nil {
		return 0, err
	}
	acme := -1
	if b, err := st.GetSetting(ctx, settingACMEPort); err == nil {
		acme, _ = strconv.Atoi(string(b))
	}
	for range 1000 {
		p, err := randInt(20000, 60999)
		if err != nil {
			return 0, err
		}
		taken := p == acme || (p >= int(params.PortBase) && p < int(params.PortBase)+int(params.PortRange))
		for _, s := range all {
			if r, ok := ServiceRotation(s); ok && p >= int(r.Base) && p < int(r.Base)+int(r.Range) {
				taken = true
			}
			ports, _ := s.Ports()
			taken = taken || slices.ContainsFunc(ports, func(x store.Port) bool { return int(x.Num) == p })
		}
		if !taken {
			return p, nil
		}
	}
	return 0, errors.New("no free port")
}

// newRotation picks a port range that overlaps neither the SPA range, nor
// other schedules, nor any fixed service port, and a fresh key.
func newRotation(ctx context.Context, st *store.Store, all []store.Service) (Rotation, []byte, error) {
	params, err := node.LoadParams(ctx, st)
	if err != nil {
		return Rotation{}, nil, err
	}
	type span struct{ lo, hi int } // [lo, hi)
	taken := []span{{int(params.PortBase), int(params.PortBase) + int(params.PortRange)}}
	if b, err := st.GetSetting(ctx, settingACMEPort); err == nil {
		if p, err := strconv.Atoi(string(b)); err == nil {
			taken = append(taken, span{p, p + 1})
		}
	}
	for _, s := range all {
		if r, ok := ServiceRotation(s); ok {
			taken = append(taken, span{int(r.Base), int(r.Base) + int(r.Range)})
		}
		ports, _ := s.Ports()
		for _, p := range ports {
			taken = append(taken, span{int(p.Num), int(p.Num) + 1})
		}
	}
	for range 1000 {
		rng, err := randInt(1024, 4096)
		if err != nil {
			return Rotation{}, nil, err
		}
		base, err := randInt(20000, 60999-rng)
		if err != nil {
			return Rotation{}, nil, err
		}
		if !slices.ContainsFunc(taken, func(t span) bool { return base < t.hi && t.lo < base+rng }) {
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				return Rotation{}, nil, err
			}
			return Rotation{Base: uint16(base), Range: uint16(rng)}, key, nil
		}
	}
	return Rotation{}, nil, errors.New("no free port range for UDP rotation")
}
