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
	"regexp"
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
	SecretSealKey       = "seal_key"             // dnstt, dnsseal-v1, 32 bytes
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
		// As the zones are kept: lower case, no final dot (review 15: a
		// domain given with one made the NS name end in a dot, and a zone
		// holding it passed the checks, which compared names as written).
		if err := st.SetSetting(ctx, settingDomain, []byte(canonicalZone(o.Domain))); err != nil {
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
var kindsNeedingInner = []string{"dnstt", "masterdns", "slipstream", "olcrtc", "openflux", "yggdrasil"}

// NeedsInner reports whether a kind exits through the inner stage.
func NeedsInner(kind string) bool { return slices.Contains(kindsNeedingInner, kind) }

// CreateService fills in defaults and secrets, stores the service and, if
// it needs the inner stage and there is none yet, creates "inner" too.
func CreateService(ctx context.Context, st *store.Store, svc store.Service) (store.Service, error) {
	// Taken as service set takes it: two creates at once each checked
	// their zone and name against a list without the other's (review 13).
	settingsMu.Lock()
	defer settingsMu.Unlock()
	return createService(ctx, st, svc)
}

// createService is CreateService under settingsMu, which it holds when it
// makes the services another needs (inner, the site).
func createService(ctx context.Context, st *store.Store, svc store.Service) (store.Service, error) {
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
	if err := sshPortsApart(svc, all); err != nil {
		return svc, err
	}

	switch svc.Kind {
	case "dnstt", "masterdns":
		if a, ok := settings["auth"]; ok && !slices.Contains([]any{"off", "optional", "required"}, a) {
			return svc, fmt.Errorf("%w auth %v: off, optional or required (spec/dnsauth-v1.md)", store.ErrInvalid, a)
		} else if !ok && svc.Kind == "dnstt" {
			// A new dnstt service takes signed queries only (Niko 1.27
			// and later sign): without, anyone can start sessions and
			// hold its new ones back (niko-server's load test, review 7).
			// Older clients: rayctl service set NAME auth=optional.
			settings["auth"] = "required"
		} else if !ok {
			// masterdns (spec/dnsauth-masterdns.md §4, niko-server
			// v0.11.0): the session of a device that signs is bound to
			// it; clients that do not sign keep working.
			settings["auth"] = "optional"
		}
		// dnsauth-v2 (spec/dnsauth-v2.md §4): optional when unset
		// (DNSAuthHint); required takes no v1 tag, so it needs auth
		// required, as niko-server does.
		if h, ok := settings["auth_hint"]; ok && !slices.Contains([]any{"off", "optional", "required"}, h) {
			return svc, fmt.Errorf("%w auth_hint %v: off, optional or required (spec/dnsauth-v2.md)", store.ErrInvalid, h)
		} else if ok && h == "required" && settings["auth"] != "required" {
			return svc, fmt.Errorf("%w auth_hint required needs auth required: a dnsauth-v1 tag would pass as untagged", store.ErrInvalid)
		}
		if a, ok := settings["seal"]; ok && !slices.Contains([]any{"off", "optional", "required"}, a) {
			return svc, fmt.Errorf("%w seal %v: off, optional or required (spec/dnsseal-v1.md, spec/mdseal-v1.md)", store.ErrInvalid, a)
		} else if !ok {
			// Sealed for the clients that ask (Niko 1.35 seals dnstt;
			// masterdns, mdseal-v1, Niko 1.36), as before for
			// the others: optional costs them nothing.
			settings["seal"] = "optional"
		}
		if z, ok := settings["zone"]; !ok {
			zone, err := newZone(ctx, st, all)
			if err != nil {
				return svc, err
			}
			settings["zone"] = zone
		} else if zs, isString := z.(string); !isString || !zoneName.MatchString(strings.TrimSuffix(zs, ".")) || len(zs) > 253 {
			// niko-server refuses a config with another (its dnsName).
			return svc, fmt.Errorf("%w zone %v: a DNS name of two labels or more", store.ErrInvalid, z)
		} else if other := zoneConflict(canonicalZone(zs), all); other != "" {
			// The front takes no zone twice, nor one inside another
			// (niko-server v0.11.0): a name under both would be either's.
			return svc, fmt.Errorf("%w zone %v: the same as, or nested with, the zone of %s", store.ErrInvalid, z, other)
		} else if name, err := nodeNameClash(ctx, st, all, canonicalZone(zs)); err != nil {
			return svc, err
		} else if name != "" {
			return svc, fmt.Errorf("%w zone %v: it would take %s", store.ErrInvalid, z, name)
		} else {
			// As the front and the delegation compare it.
			settings["zone"] = canonicalZone(zs)
		}
		if raw, ok := settings["spare_zones"]; ok {
			// As service set takes them: a number, or the zones.
			var value string
			switch x := raw.(type) {
			case float64:
				value = strconv.FormatFloat(x, 'f', -1, 64)
			case []any:
				for i, z := range x {
					zs, ok := z.(string)
					if !ok {
						return svc, fmt.Errorf("%w spare_zones: a number or a list of zones", store.ErrInvalid)
					}
					if i > 0 {
						value += ","
					}
					value += zs
				}
			default:
				return svc, fmt.Errorf("%w spare_zones: a number or a list of zones", store.ErrInvalid)
			}
			main, _ := json.Marshal(map[string]any{"zone": settings["zone"]})
			spares, err := spareZones(ctx, st, store.Service{Name: svc.Name, Settings: string(main)}, all, value)
			if err != nil {
				return svc, err
			}
			delete(settings, "spare_zones")
			if len(spares) > 0 {
				settings["spare_zones"] = spares
			}
		}
		if svc.Kind == "dnstt" {
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return svc, err
			}
			svc.Secrets[SecretNoisePrivate] = key.Bytes()
			// dnsseal-v1: the zone's key, made with the service whatever
			// the mode: the unit copies it from the first deploy, so the
			// seal can be turned on later through the API.
			seal := make([]byte, 32)
			if _, err := rand.Read(seal); err != nil {
				return svc, err
			}
			svc.Secrets[SecretSealKey] = seal
		} else {
			settings["encryption_method"] = masterdnsMethod
			raw := make([]byte, 16)
			if _, err := rand.Read(raw); err != nil {
				return svc, err
			}
			svc.Secrets[SecretMasterDNSKey] = []byte(hex.EncodeToString(raw)) // 32 hex chars, as MasterDnsVPN expects
		}
	case "slipstream":
		if err := slipstreamService(ctx, st, all, settings, svc.Secrets); err != nil {
			return svc, err
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
		if v, ok := settings["icmp"]; ok && svc.Kind == "naive" {
			if _, ok := v.(bool); !ok {
				return svc, fmt.Errorf(`%w naive icmp: true or false (rayctl service set <naive> icmp=on|off)`, store.ErrInvalid)
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
	if svc.Enabled {
		// siteFor may have just made the site: read the list again.
		if all, err = st.ListServices(ctx); err != nil {
			return svc, err
		}
		if err := requirements(svc, all, true); err != nil {
			return svc, err
		}
	}
	if NeedsInner(svc.Kind) && !slices.ContainsFunc(all, func(s store.Service) bool { return s.Kind == "inner" }) {
		if _, err := createService(ctx, st, store.Service{Kind: "inner", Name: "inner", Enabled: true}); err != nil {
			return svc, fmt.Errorf("creating inner: %w", err)
		}
	}
	return st.CreateService(ctx, svc)
}

// sshPortsApart refuses a service that shares a port with SSH: an SPA grant
// or a relay for the other service would reach sshd past the admin rules.
// Services on the front share their ports by design; SSH shares none.
func sshPortsApart(svc store.Service, all []store.Service) error {
	ports, err := svc.Ports()
	if err != nil {
		return err
	}
	for _, other := range all {
		if (svc.Kind == "ssh") == (other.Kind == "ssh") {
			continue
		}
		theirs, err := other.Ports()
		if err != nil {
			continue
		}
		for _, p := range ports {
			if slices.Contains(theirs, p) {
				return fmt.Errorf("%w port %s of %s: %s uses it, and SSH shares no port", store.ErrInvalid, p, svc.Name, other.Name)
			}
		}
	}
	return nil
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
	return createService(ctx, st, store.Service{Kind: "site", Name: "site", Enabled: true})
}

// SetServiceOption changes a setting that may change after creation: the
// answer of a site, whether REALITY moves its server name (R4-7, R4-8).
func SetServiceOption(ctx context.Context, st *store.Store, name, key, value string) (store.Service, error) {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	svc, err := st.ServiceByName(ctx, name)
	if err != nil {
		return svc, err
	}
	var v any
	also := map[string]any{} // other settings the change makes
	switch {
	case (svc.Kind == "dnstt" || svc.Kind == "masterdns") && key == "spare_zones":
		// Spare zones of the tunnel (spec/dnszones-v1.md §5): delegated
		// and served as the main zone, in the links so that clients move
		// to them by themselves when the main one is blocked.
		all, err := st.ListServices(ctx)
		if err != nil {
			return svc, err
		}
		spares, err := spareZones(ctx, st, svc, all, value)
		if err != nil {
			return svc, err
		}
		v = 0
		if len(spares) > 0 {
			v = spares
		}
	case (svc.Kind == "dnstt" || svc.Kind == "masterdns") && key == "zone":
		// A spare zone becomes the main one, and the main one leaves
		// (§5): clients have the new main zone already, as a spare, and
		// lose the old one with their next subscription.
		z := canonicalZone(value)
		spares := SpareZones(svc)
		i := slices.Index(spares, z)
		if i < 0 {
			return svc, fmt.Errorf("%w zone %s: not a spare zone of %s (spare zones: %s); clients must have a zone before it becomes the main one",
				store.ErrInvalid, value, svc.Name, strings.Join(spares, ", "))
		}
		v = z
		also["spare_zones"] = 0
		if rest := slices.Delete(slices.Clone(spares), i, i+1); len(rest) > 0 {
			also["spare_zones"] = rest
		}
	case svc.Kind == "slipstream" && (key == "max_connections" || key == "device_connections"):
		// The server's limits (spec/slipstream-v1.md §3): a restart of
		// it, its clients reconnect.
		n, err := strconv.Atoi(value)
		if err != nil {
			return svc, fmt.Errorf("%w %s: a number (0: the default)", store.ErrInvalid, key)
		}
		ss, _ := ParseSlipstream(svc)
		total, device := ss.MaxConnections, ss.DeviceConnections
		if key == "max_connections" {
			total = n
		} else {
			device = n
		}
		if err := slipstreamLimits(total, device); err != nil {
			return svc, fmt.Errorf("%w: %w", store.ErrInvalid, err)
		}
		v = n
	case svc.Kind == "naive" && key == "icmp":
		// ping and traceroute through naive (spec/icmp-v1.md): off by
		// default; the node sends the clients' echoes itself.
		switch value {
		case "on":
			v = true
		case "off":
			v = 0
		default:
			return svc, fmt.Errorf("%w icmp: on or off", store.ErrInvalid)
		}
	case svc.Kind == "site" && key == "answer":
		if !slices.Contains(site.Answers, value) {
			return svc, fmt.Errorf("%w site answer %q: want one of %s", store.ErrInvalid, value, strings.Join(site.Answers, ", "))
		}
		v = value
	case svc.Kind == "reality" && key == "open":
		// TCP 443 open to everyone, not behind SPA (RAYCONTROL.md §22.2.2):
		// a host silent on 443 while TLS sessions go to it stands out, and
		// REALITY answers the unauthenticated as its site. The other
		// services on the front's TCP 443 become reachable too.
		b, err := strconv.ParseBool(value)
		if err != nil {
			return svc, fmt.Errorf("%w open: true or false", store.ErrInvalid)
		}
		v = b
		if !b {
			v = 0
		} else if ports, err := svc.Ports(); err != nil || !slices.Contains(ports, store.Port{Proto: "tcp", Num: 443}) {
			// Only TCP 443 opens; a REALITY moved off it has nothing to open.
			return svc, fmt.Errorf("%w open: %s does not listen on tcp/443", store.ErrInvalid, svc.Name)
		}
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
	case svc.Kind == "yggdrasil" && key == "lan_relay":
		// The ceiling of LAN traffic through the node (lan-v1 §4.4), Mbit/s
		// a user, its bytes in the traffic limit; 0: the devices meet
		// directly in one Wi-Fi only. Kept as set, 0 too (a number, not a
		// removal): unset is niko-server's LANRelayDefault.
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 || n > 100000 {
			return svc, fmt.Errorf("%w lan_relay: Mbit/s a user, 0 to 100000 (0: directly in one Wi-Fi only; %d unless set)", store.ErrInvalid, LANRelayDefault)
		}
		v = json.Number(strconv.Itoa(n))
	case (svc.Kind == "dnstt" || svc.Kind == "masterdns") && key == "auth_hint":
		// dnsauth-v2 (spec/dnsauth-v2.md §4): optional finds a v2 tag by
		// its hint and still scans for v1; required takes no v1 tag at
		// all, once every client signs v2 (dnsauth.v in the
		// subscription). Kept as set, off too: unset is optional.
		if !slices.Contains([]string{"off", "optional", "required"}, value) {
			return svc, fmt.Errorf("%w auth_hint: off, optional or required", store.ErrInvalid)
		}
		if value == "required" && DNSAuthMode(svc) != "required" {
			return svc, fmt.Errorf("%w auth_hint required needs auth required (now %s): a dnsauth-v1 tag would pass as untagged", store.ErrInvalid, DNSAuthMode(svc))
		}
		// The subscription says one dnsauth version for all of a user's
		// tunnels (dnsauth.v): required (v2 only) beside off (v1 only)
		// would leave one of them refusing every query of a client (review).
		if value == "required" || value == "off" {
			others, err := st.ListServices(ctx)
			if err != nil {
				return svc, err
			}
			for _, o := range others {
				// slipstream signs v2 whatever dnsauth.v says: not one of them.
				if o.ID == svc.ID || !DNSTunnel(o.Kind) || o.Kind == "slipstream" {
					continue
				}
				if h := DNSAuthHint(o); (value == "required" && h == "off") || (value == "off" && h == "required") {
					return svc, fmt.Errorf("%w auth_hint %s: %s has auth_hint %s, and a client signs one version for all the tunnels (set it to optional first)", store.ErrInvalid, value, o.Name, h)
				}
			}
		}
		v = value
	case (svc.Kind == "dnstt" || svc.Kind == "masterdns") && (key == "auth" || key == "seal"):
		// dnsauth-v1 (spec/dnsauth-v1.md §5, spec/dnsauth-masterdns.md
		// §4): required on a new dnstt service, optional on a new
		// masterdns one, optional or off for clients that do not sign;
		// the seal (dnsseal-v1, mdseal-v1 §5): optional on a new service,
		// required once every client seals.
		if !slices.Contains([]string{"off", "optional", "required"}, value) {
			return svc, fmt.Errorf("%w %s: off, optional or required", store.ErrInvalid, key)
		}
		if key == "auth" && value != "required" && DNSAuthHint(svc) == "required" {
			return svc, fmt.Errorf("%w auth %s: %s has auth_hint required, which needs auth required (auth_hint=optional first)", store.ErrInvalid, value, name)
		}
		if svc.Kind == "masterdns" && key == "auth" && value != "off" {
			// Methods 0 to 2 leave the query unauthenticated: a tag under
			// them means nothing (spec/dnsauth-masterdns.md §3). The node
			// sets 5: only a service changed by hand gets here.
			var md struct {
				Method int `json:"encryption_method"`
			}
			_ = json.Unmarshal([]byte(svc.Settings), &md)
			if md.Method < 3 {
				return svc, fmt.Errorf("%w auth: %s has encryption_method %d, dnsauth needs 3 to 5 (AES-GCM)", store.ErrInvalid, name, md.Method)
			}
		}
		v = value
		if value == "off" {
			v = 0
		}
	default:
		return svc, fmt.Errorf("%w: %s has no option %q (site: answer; reality: rotate_sni, open; hy2-*: up_mbps, down_mbps; naive: icmp; yggdrasil: peers, lan_relay; dnstt, masterdns: auth, auth_hint, seal, spare_zones, zone; slipstream: max_connections, device_connections)", store.ErrInvalid, name, key)
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(svc.Settings), &settings); err != nil {
		return svc, err
	}
	also[key] = v
	for k, x := range also {
		settings[k] = x
		if x == 0 { // the int 0 only: json.Number("0") is kept
			delete(settings, k)
		}
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

// LANRelayDefault is niko-server's ceiling of LAN traffic through the node
// (lan-v1 §4.4), Mbit/s a user, when a Yggdrasil backend's options leave
// lan_relay_mbps out.
const LANRelayDefault = 20

// LANRelay is a Yggdrasil service's ceiling of device-to-device traffic
// through the node, Mbit/s a user (rayctl service set NAME lan_relay=N):
// LANRelayDefault unless set; 0: none, directly in one Wi-Fi only.
func LANRelay(s store.Service) int {
	r, _ := LANRelaySet(s)
	return r
}

// LANRelaySet is LANRelay, and whether the administrator set it: render
// writes a set value as it is, the default too, so that the node keeps
// what was set whatever niko-server's own default.
func LANRelaySet(s store.Service) (int, bool) {
	var st struct {
		Relay *int `json:"lan_relay"`
	}
	if json.Unmarshal([]byte(s.Settings), &st) != nil || st.Relay == nil || *st.Relay < 0 {
		return LANRelayDefault, false
	}
	return *st.Relay, true
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
		ip := net.ParseIP(u.Hostname())
		if ip != nil && (!ip.IsGlobalUnicast() || ip.IsPrivate()) {
			return nil, fmt.Errorf("%w yggdrasil peer %q: a public address, or a name", store.ErrInvalid, p)
		}
		// yggdrasil-go resolves a quic:// name itself, with the system
		// resolver: on a client that means past its own DNS, in clear on the
		// network where the direct path fails. QUIC peers go by address.
		if ip == nil && u.Scheme == "quic" {
			return nil, fmt.Errorf("%w yggdrasil peer %q: a quic peer needs an IP address, not a name", store.ErrInvalid, p)
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

// NaiveICMP reports whether a naive service carries ping and traceroute
// (spec/icmp-v1.md): off unless rayctl service set <naive> icmp=on.
func NaiveICMP(svc store.Service) bool {
	var s struct {
		ICMP bool `json:"icmp"`
	}
	_ = json.Unmarshal([]byte(svc.Settings), &s)
	return svc.Kind == "naive" && s.ICMP
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

// newZone returns "<label>.<domain>" with a random label not used yet, by
// all nor among taken (zones chosen in the same change).
func newZone(ctx context.Context, st *store.Store, all []store.Service, taken ...string) (string, error) {
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
	// Bounded (review 13): a zone stored at or above the domain, as v0.13
	// took, clashes with every name under it, and the search went on
	// forever, the render and the DNS sync with it.
	for range 10000 {
		label := make([]byte, 3)
		for i := range label {
			n, err := randInt(0, len(alphabet)-1)
			if err != nil {
				return "", err
			}
			label[i] = alphabet[n]
		}
		zone := string(label) + "." + domain
		if zone != string(ns) && zoneConflict(zone, all) == "" && !slices.ContainsFunc(taken, func(t string) bool { return zonesClash(zone, t) }) &&
			!slices.ContainsFunc(all, func(s store.Service) bool { return strings.Contains(s.Settings, `"`+zone+`"`) }) {
			return zone, nil
		}
	}
	other := ""
	for _, svc := range all {
		for _, z := range Zones(svc) {
			if z == domain || strings.HasSuffix(domain, "."+z) {
				other = ": the zone of " + svc.Name + " holds the domain itself"
			}
		}
	}
	return "", fmt.Errorf("%w: no free name under %s%s", store.ErrInvalid, domain, other)
}

// nodeNameClash says which of the node's own names a DNS tunnel zone would
// take from it, "" when none: the node's domain (a zone at or above it
// would delegate every name of the node away), the name the zones are
// delegated to (delegating it breaks every tunnel's delegation), a
// service's server name (the site and the services under it would go
// with it). A zone under such a name takes nothing.
func nodeNameClash(ctx context.Context, st *store.Store, all []store.Service, zone string) (string, error) {
	domain, err := Domain(ctx, st)
	if err != nil {
		return "", err
	}
	// Names as niko-server compares them: lower case, no final dot (a
	// domain stored before Init canonicalized it may end in one).
	holds := func(name string) bool {
		name = canonicalZone(name)
		return name != "" && (name == zone || strings.HasSuffix(name, "."+zone))
	}
	if holds(domain) {
		return "the node's domain " + domain, nil
	}
	if ns, err := st.GetSetting(ctx, settingNSName); err == nil && holds(string(ns)) {
		return "the name the zones are delegated to, " + string(ns), nil
	}
	for _, svc := range all {
		var names struct {
			SNI     string `json:"sni"`
			SNINext string `json:"sni_next"`
		}
		_ = json.Unmarshal([]byte(svc.Settings), &names)
		for _, n := range []string{names.SNI, names.SNINext} {
			if holds(canonicalZone(n)) {
				return "the server name of " + svc.Name + ", " + n, nil
			}
		}
	}
	return "", nil
}

// zoneConflict names the DNS tunnel service among all one of whose zones
// (the main one or a spare) is zone, or holds it, or lies within it; ""
// when none does. The front refuses such zones (niko-server v0.11.0): a
// name under both is either's, and a tunnel's last label of data can
// spell the inner zone.
func zoneConflict(zone string, all []store.Service) string {
	for _, svc := range all {
		if !DNSTunnel(svc.Kind) {
			continue
		}
		for _, other := range Zones(svc) {
			if zonesClash(zone, other) {
				return svc.Name
			}
		}
	}
	return ""
}

// ZonesClash reports whether two zones are one, or one holds the other:
// the front refuses them together (niko-server v0.11.0).
func ZonesClash(a, b string) bool { return zonesClash(a, b) }

// CanonicalZone is a name as zones are kept and niko-server compares them:
// lower case, no final dot.
func CanonicalZone(z string) string { return canonicalZone(z) }

// zonesClash reports whether two zones are one, or one holds the other.
func zonesClash(a, b string) bool {
	return a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

// Zone returns the "zone" setting of a DNS tunnel service as the front,
// the parent zone and clients compare it: lower case, no final dot (a
// service made before v0.13.0 may keep it written otherwise).
func Zone(svc store.Service) string {
	var s struct {
		Zone string `json:"zone"`
	}
	_ = json.Unmarshal([]byte(svc.Settings), &s)
	return canonicalZone(s.Zone)
}

// MaxSpareZones is how many spare zones a DNS tunnel takes (niko-server's
// options.zones, spec/dnszones-v1.md §2).
const MaxSpareZones = 4

// SpareZones returns the spare zones of a DNS tunnel service
// (spec/dnszones-v1.md), in the order clients try them.
func SpareZones(svc store.Service) []string {
	var s struct {
		Spare []string `json:"spare_zones"`
	}
	_ = json.Unmarshal([]byte(svc.Settings), &s)
	var out []string
	for _, z := range s.Spare {
		if z = canonicalZone(z); z != "" {
			out = append(out, z)
		}
	}
	return out
}

// Zones is a DNS tunnel service's main zone and its spares; none without
// a main zone. The node delegates and serves each the same way.
func Zones(svc store.Service) []string {
	z := Zone(svc)
	if z == "" {
		return nil
	}
	return append([]string{z}, SpareZones(svc)...)
}

// spareZones reads the spare zones asked for a service: none ("", "0",
// "none"), a number of zones made up in the node's domain as a main zone
// is (those it has stay, the first ones), or the operator's own, comma
// separated. Each must be a DNS name, none twice, none clashing with the
// service's main zone, another service's zones or the name the zones are
// delegated to.
func spareZones(ctx context.Context, st *store.Store, svc store.Service, all []store.Service, value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "0" || value == "none" {
		return nil, nil
	}
	main := Zone(svc)
	var others []store.Service
	for _, o := range all {
		if o.ID != svc.ID {
			others = append(others, o)
		}
	}
	ns, _ := st.GetSetting(ctx, settingNSName)
	if n, err := strconv.Atoi(value); err == nil {
		if n < 0 || n > MaxSpareZones {
			return nil, fmt.Errorf("%w spare_zones=%d: 0 to %d", store.ErrInvalid, n, MaxSpareZones)
		}
		out := SpareZones(svc)
		if len(out) > n {
			return out[:n], nil
		}
		for len(out) < n {
			z, err := newZone(ctx, st, all, append([]string{main}, out...)...)
			if err != nil {
				return nil, err
			}
			out = append(out, z)
		}
		return out, nil
	}
	var out []string
	for _, raw := range strings.Split(value, ",") {
		z := canonicalZone(strings.TrimSpace(raw))
		switch {
		case !zoneName.MatchString(z) || len(z) > 253:
			return nil, fmt.Errorf("%w spare zone %q: a DNS name of two labels or more", store.ErrInvalid, raw)
		case zonesClash(z, main) || slices.ContainsFunc(out, func(o string) bool { return zonesClash(z, o) }):
			return nil, fmt.Errorf("%w spare zone %s: the same as, or nested with, another zone of %s", store.ErrInvalid, z, svc.Name)
		case len(ns) > 0 && zonesClash(z, string(ns)):
			return nil, fmt.Errorf("%w spare zone %s: the name the zones are delegated to is %s", store.ErrInvalid, z, ns)
		}
		if other := zoneConflict(z, others); other != "" {
			return nil, fmt.Errorf("%w spare zone %s: the same as, or nested with, a zone of %s", store.ErrInvalid, z, other)
		}
		if name, err := nodeNameClash(ctx, st, all, z); err != nil {
			return nil, err
		} else if name != "" {
			return nil, fmt.Errorf("%w spare zone %s: it would take %s", store.ErrInvalid, z, name)
		}
		out = append(out, z)
	}
	if len(out) > MaxSpareZones {
		return nil, fmt.Errorf("%w spare_zones: %d zones, %d at most", store.ErrInvalid, len(out), MaxSpareZones)
	}
	return out, nil
}

func canonicalZone(z string) string { return strings.ToLower(strings.TrimSuffix(z, ".")) }

// zoneName is a DNS name of two labels or more, as niko-server takes a
// zone (its config's dnsName).
var zoneName = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

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

// EnsureSealKey gives a dnstt service made before dnsseal-v1 its key: made
// once, whoever asks first (render, at every collect). It returns the key.
func EnsureSealKey(ctx context.Context, st *store.Store, svc store.Service, secrets map[string][]byte) ([]byte, error) {
	if k := secrets[SecretSealKey]; len(k) == 32 || svc.Kind != "dnstt" {
		return k, nil
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return st.InitServiceSecret(ctx, svc.ID, SecretSealKey, k)
}
