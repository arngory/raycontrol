// Package render turns the node state into the files the data plane reads:
// niko-server configs (CONFIG.md schema 1 in arngory/niko), the Xray config
// of the inner stage and the secret files systemd copies to the services.
package render

import (
	"context"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/sys/unix"

	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
)

// Fixed UIDs (docs/08-decisions.md, R1-6).
const (
	FrontUID  = 9100
	RaydUID   = 9190
	RayspaUID = 9191
)

// Schema is the niko-server config schema version raycontrol writes.
const Schema = 1

// Paths are the directories the renderer refers to.
type Paths struct {
	Rendered string // written by rayd
	Run      string // runtime directories of the data plane
}

// DefaultPaths are the paths on an installed node.
var DefaultPaths = Paths{
	Rendered: "/var/lib/raycontrol/rendered",
	Run:      "/run/niko",
}

// Service is a service with its secrets.
type Service struct {
	store.Service
	Secrets map[string][]byte
}

// User is an active user.
type User struct {
	ID       int64
	Name     string
	Services []int64
}

// Model is everything the renderer needs.
type Model struct {
	NodeID   string
	Host     string
	Domain   string
	Services []Service // enabled only
	Users    []User    // enabled and not expired
	// Inner maps user ID to the VLESS UUID at the inner stage.
	Inner map[int64]string
	// IPv6 is false on hosts without IPv6 sockets (ipv6.disable=1): the
	// front must not ask for [::] there, or it does not start at all.
	IPv6 bool
	// Creds maps service ID and user ID to the user's UUID for services
	// whose users are Xray clients (REALITY).
	Creds map[int64]map[int64]string
	// FrontTCP puts TCP services behind the niko-server front (tcpmux,
	// CONFIG.md). niko-server v0.1.1 has no TCP front yet, so REALITY binds
	// its TCP port itself until then (docs/08-decisions.md, R2-7).
	FrontTCP bool
}

// HostIPv6 reports whether this host can open IPv6 sockets.
func HostIPv6() bool {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return false
	}
	_ = unix.Close(fd)
	return true
}

// Collect reads the model from the store and creates missing inner
// credentials for users who reach a service behind the inner stage.
func Collect(ctx context.Context, st *store.Store) (Model, error) {
	m := Model{IPv6: HostIPv6()}
	params, err := node.LoadParams(ctx, st)
	if err != nil {
		return m, err
	}
	m.NodeID = hex.EncodeToString(params.NodeID[:])
	if m.Host, err = node.Host(ctx, st); err != nil {
		return m, err
	}
	if m.Domain, err = provision.Domain(ctx, st); err != nil {
		return m, err
	}
	services, err := st.ListServices(ctx)
	if err != nil {
		return m, err
	}
	var inner *Service
	for _, s := range services {
		if !s.Enabled {
			continue
		}
		secrets, err := st.ServiceSecrets(ctx, s.ID)
		if err != nil {
			return m, err
		}
		m.Services = append(m.Services, Service{s, secrets})
	}
	for i := range m.Services {
		if m.Services[i].Kind == "inner" {
			inner = &m.Services[i]
		}
	}

	users, err := st.ListUsers(ctx)
	if err != nil {
		return m, err
	}
	now := time.Now()
	var needInner []int64
	for _, u := range users {
		if !u.Enabled || (u.ExpiresAt != nil && !u.ExpiresAt.After(now)) {
			continue
		}
		m.Users = append(m.Users, User{ID: u.ID, Name: u.Name, Services: u.Services})
		if slices.ContainsFunc(m.Services, func(s Service) bool {
			return provision.NeedsInner(s.Kind) && slices.Contains(u.Services, s.ID)
		}) {
			needInner = append(needInner, u.ID)
		}
	}
	m.Creds = map[int64]map[int64]string{}
	for _, svc := range m.Services {
		if svc.Kind != "reality" {
			continue
		}
		var ids []int64
		for _, u := range m.Users {
			if slices.Contains(u.Services, svc.ID) {
				ids = append(ids, u.ID)
			}
		}
		all, err := st.Credentials(ctx, svc.ID, ids, newUUID)
		if err != nil {
			return m, err
		}
		m.Creds[svc.ID] = map[int64]string{}
		for _, id := range ids {
			m.Creds[svc.ID][id] = all[id]
		}
	}
	if inner != nil {
		all, err := st.Credentials(ctx, inner.ID, needInner, newUUID)
		if err != nil {
			return m, err
		}
		m.Inner = map[int64]string{}
		for _, id := range needInner {
			m.Inner[id] = all[id]
		}
	}
	return m, nil
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// File is one rendered file.
type File struct {
	Path    string
	Mode    uint32
	Group   string // readable by this group
	Content []byte
	// Service is the service whose process reads the file ("front" for the
	// front); a change restarts that process.
	Service string
}

// UnitName is the systemd unit of a service's process.
func UnitName(service string) string { return "niko-" + service + ".service" }

// GroupName is the system user and group of a service's process.
func GroupName(service string) string { return "niko-" + service }

func (p Paths) socket(service, kind string) string { return path.Join(p.Run, service, kind+".sock") }

// Credential is where a process finds a secret: systemd (root) copies it
// from the rendered file into the service's runtime directory before the
// start, readable by the service user only (docs/08-decisions.md, R2-9).
func (p Paths) Credential(service, name string) string {
	return path.Join(p.Run, service, name)
}

// APISocket is the gRPC API socket of an Xray process (inner, REALITY). Its
// directory belongs to the service user and the rayd group only: the
// tunnels that reach the inner VLESS socket must not reach the API.
func (p Paths) APISocket(service string) string {
	return path.Join(p.Run, service+"-api", "api.sock")
}

// XrayKinds run on Xray and get their users through its API.
var XrayKinds = []string{"inner", "reality"}

// IsXray reports whether the service runs on Xray.
func IsXray(kind string) bool { return slices.Contains(XrayKinds, kind) }

// XrayUsers returns the inbound tag and the users (email -> UUID) of an Xray
// service, as rayd syncs them through the API.
func XrayUsers(m Model, s Service) (tag string, users map[string]string) {
	creds := m.Inner
	tag = InnerTag
	if s.Kind == "reality" {
		creds, tag = m.Creds[s.ID], RealityTag
	}
	users = make(map[string]string, len(creds))
	for id, uuid := range creds {
		users[InnerEmail(id)] = uuid
	}
	return tag, users
}

// InnerSocket is the VLESS socket of the inner stage.
func (p Paths) InnerSocket(inner string) string { return p.socket(inner, "vless") }

func jsonFile(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	return append(b, '\n'), err
}

// Render returns all files for the model. Kinds the renderer does not
// handle yet are skipped and named in the second result.
func Render(m Model, p Paths) ([]File, []string, error) {
	var files []File
	var skipped []string
	var inner *Service
	for i := range m.Services {
		if m.Services[i].Kind == "inner" {
			inner = &m.Services[i]
		}
	}

	type route struct {
		Zone    string `json:"zone"`
		Backend string `json:"backend"`
	}
	type backendRef struct {
		Socket string `json:"socket"`
		Mode   string `json:"mode"`
		UID    int    `json:"uid"`
	}
	type tcpRoute struct {
		SNI     []string `json:"sni"`
		Backend string   `json:"backend"`
	}
	var zones []route
	var tcpRoutes []tcpRoute
	backends := map[string]backendRef{}

	for _, s := range m.Services {
		switch s.Kind {
		case "dnstt", "masterdns":
			if inner == nil {
				return nil, nil, fmt.Errorf("service %s needs the inner stage, which is missing or disabled", s.Name)
			}
			zone := provision.Zone(s.Service)
			zones = append(zones, route{Zone: zone, Backend: s.Name})
			backends[s.Name] = backendRef{Socket: p.socket(s.Name, "packet"), Mode: "packet", UID: s.UID}
			f, secret, err := dnsBackend(s, zone, inner.Name, p)
			if err != nil {
				return nil, nil, err
			}
			files = append(files, f, secret)
		case "inner":
			f, err := innerConfig(s, m, p)
			if err != nil {
				return nil, nil, err
			}
			files = append(files, f)
		case "reality":
			f, err := realityConfig(s, m, p)
			if err != nil {
				return nil, nil, err
			}
			files = append(files, f)
			if m.FrontTCP {
				backends[s.Name] = backendRef{Socket: p.socket(s.Name, "reality"), Mode: "proxy-v2", UID: s.UID}
				var rs RealitySettings
				_ = json.Unmarshal([]byte(s.Settings), &rs)
				tcpRoutes = append(tcpRoutes, tcpRoute{SNI: []string{rs.SNI}, Backend: s.Name})
			}
		case "ssh", "subscription", "api":
			// Not data-plane processes.
		default:
			skipped = append(skipped, s.Name+" ("+s.Kind+")")
		}
	}

	if len(backends) > 0 {
		sort.Slice(zones, func(i, j int) bool { return zones[i].Zone < zones[j].Zone })
		front := map[string]any{
			"schema":   Schema,
			"role":     "front",
			"log":      map[string]string{"level": "warn"},
			"backends": backends,
		}
		if len(zones) > 0 {
			listen := []string{"0.0.0.0:53"}
			if m.IPv6 {
				listen = append(listen, "[::]:53")
			}
			front["dns"] = map[string]any{"listen": listen, "zones": zones}
		}
		if len(tcpRoutes) > 0 {
			listen := []string{"0.0.0.0:443"}
			if m.IPv6 {
				listen = append(listen, "[::]:443")
			}
			// Unknown SNI goes to the first REALITY service: its target
			// answers like the site it stands for.
			front["tcp"] = map[string]any{"listen": listen, "sniff_timeout": "5s", "routes": tcpRoutes, "default": tcpRoutes[0].Backend}
		}
		b, err := jsonFile(front)
		if err != nil {
			return nil, nil, err
		}
		files = append(files, File{Path: path.Join(p.Rendered, "front", "front.json"), Mode: 0o640, Group: GroupName("front"), Content: b, Service: "front"})
	}
	return files, skipped, nil
}

func dnsBackend(s Service, zone, inner string, p Paths) (cfg, secret File, err error) {
	opts := map[string]any{}
	var secretName string
	var secretValue []byte
	switch s.Kind {
	case "dnstt":
		secretName, secretValue = "noise.key", []byte(hex.EncodeToString(s.Secrets[provision.SecretNoisePrivate])+"\n")
		opts["zone"] = zone
		opts["private_key_file"] = p.Credential(s.Name, secretName)
	case "masterdns":
		var settings struct {
			Method int `json:"encryption_method"`
		}
		_ = json.Unmarshal([]byte(s.Settings), &settings)
		secretName, secretValue = "encryption.key", s.Secrets[provision.SecretMasterDNSKey]
		opts["zones"] = []string{zone}
		opts["encryption_method"] = settings.Method
		opts["encryption_key_file"] = p.Credential(s.Name, secretName)
	}
	if len(s.Secrets) == 0 || len(secretValue) == 0 {
		return cfg, secret, fmt.Errorf("service %s has no key", s.Name)
	}
	b, err := jsonFile(map[string]any{
		"schema":    Schema,
		"role":      "backend",
		"kind":      s.Kind,
		"log":       map[string]string{"level": "warn"},
		"socket":    p.socket(s.Name, "packet"),
		"front_uid": FrontUID,
		"options":   opts,
		"inner":     p.InnerSocket(inner),
	})
	if err != nil {
		return cfg, secret, err
	}
	dir := path.Join(p.Rendered, s.Name)
	cfg = File{Path: path.Join(dir, "backend.json"), Mode: 0o640, Group: GroupName(s.Name), Content: b, Service: s.Name}
	// Secrets are read by systemd (root), which gives the process its own
	// copy (Paths.Credential), so the file needs no group access.
	secret = File{Path: path.Join(dir, secretName), Mode: 0o600, Content: secretValue, Service: s.Name}
	return cfg, secret, nil
}

// VLESSEncryption returns the server ("decryption") and client
// ("encryption") strings of Xray VLESS encryption with ML-KEM-768
// authentication, as "xray vlessenc" prints them.
func VLESSEncryption(seed []byte) (decryption, encryption string, err error) {
	key, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return "", "", err
	}
	enc := base64.RawURLEncoding
	return "mlkem768x25519plus.native.600s." + enc.EncodeToString(seed),
		"mlkem768x25519plus.native.0rtt." + enc.EncodeToString(key.EncapsulationKey().Bytes()), nil
}

// DNSTTPublicKey returns the hex public key clients need for a dnstt service.
func DNSTTPublicKey(s Service) (string, error) {
	priv, err := ecdh.X25519().NewPrivateKey(s.Secrets[provision.SecretNoisePrivate])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(priv.PublicKey().Bytes()), nil
}

// privateNets are never reachable through the inner stage.
var privateNets = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
}

// InnerTag is the inbound tag of the inner stage (Xray API target).
const InnerTag = "inner"

// InnerEmail is the Xray user identifier of a raycontrol user.
func InnerEmail(userID int64) string { return fmt.Sprintf("u%d", userID) }

func innerConfig(s Service, m Model, p Paths) (File, error) {
	decryption, _, err := VLESSEncryption(s.Secrets[provision.SecretMLKEMSeed])
	if err != nil {
		return File{}, fmt.Errorf("inner %s: %w", s.Name, err)
	}
	ids := make([]int64, 0, len(m.Inner))
	for id := range m.Inner {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	clients := make([]map[string]string, 0, len(ids))
	for _, id := range ids {
		clients = append(clients, map[string]string{"id": m.Inner[id], "email": InnerEmail(id)})
	}
	return xrayFile(s, p, map[string]any{
		"tag":      InnerTag,
		"listen":   p.InnerSocket(s.Name) + ",0660",
		"protocol": "vless",
		"settings": map[string]any{"clients": clients, "decryption": decryption},
		// Sniffing only for routing: the BitTorrent rule needs it.
		"sniffing": sniffing,
	})
}

var sniffing = map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}

// xrayFile is the config of an Xray exit: one inbound, the API on its own
// unix socket, DoH, and routing that keeps private networks and BitTorrent
// out.
func xrayFile(s Service, p Paths, inbound map[string]any) (File, error) {
	b, err := jsonFile(map[string]any{
		"log": map[string]string{"loglevel": "warning", "access": "none"},
		"api": map[string]any{"tag": "api", "listen": p.APISocket(s.Name), "services": []string{"HandlerService"}},
		"dns": map[string]any{
			// DoH to public resolvers: the host resolver may sit in a private
			// range that the routing below blocks.
			"servers":       []string{"https+local://1.1.1.1/dns-query", "https+local://9.9.9.9/dns-query"},
			"queryStrategy": "UseIP",
		},
		"inbounds": []map[string]any{inbound},
		"outbounds": []map[string]any{
			{"tag": "direct", "protocol": "freedom", "streamSettings": map[string]any{"sockopt": map[string]string{"domainStrategy": "UseIP"}}},
			{"tag": "block", "protocol": "blackhole"},
		},
		"routing": map[string]any{
			"domainStrategy": "IPOnDemand",
			"rules": []map[string]any{
				{"ip": privateNets, "outboundTag": "block"},
				{"protocol": []string{"bittorrent"}, "outboundTag": "block"},
			},
		},
	})
	if err != nil {
		return File{}, err
	}
	return File{Path: path.Join(p.Rendered, s.Name, "xray.json"), Mode: 0o640, Group: GroupName(s.Name), Content: b, Service: s.Name}, nil
}

// RealityTag is the inbound tag of a REALITY service (Xray API target).
const RealityTag = "reality"

// RealityFlow is the VLESS flow of REALITY clients.
const RealityFlow = "xtls-rprx-vision"

// RealitySettings are the settings of a REALITY service.
type RealitySettings struct {
	Target      string `json:"target"`      // host:port or unix socket: who answers non-clients
	SNI         string `json:"sni"`         // server name clients send
	Fingerprint string `json:"fingerprint"` // uTLS fingerprint of clients
}

// RealityMaxTimeDiff bounds the client clock in the REALITY session ID; SPA
// already needs the clock within seconds.
const RealityMaxTimeDiff = 120 * time.Second

// RealityKeys returns what clients need: the X25519 public key and the
// ML-DSA-65 public key ("pbk" and "pqv" of share links), base64url.
func RealityKeys(s Service) (pbk, pqv string, err error) {
	priv, err := ecdh.X25519().NewPrivateKey(s.Secrets[provision.SecretRealityKey])
	if err != nil {
		return "", "", err
	}
	seed := s.Secrets[provision.SecretRealityMLDSA]
	if len(seed) != mldsa65.SeedSize {
		return "", "", fmt.Errorf("reality %s: bad ML-DSA-65 seed", s.Name)
	}
	pub, _ := mldsa65.NewKeyFromSeed((*[mldsa65.SeedSize]byte)(seed))
	raw, err := pub.MarshalBinary()
	if err != nil {
		return "", "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(priv.PublicKey().Bytes()), enc.EncodeToString(raw), nil
}

// ShortIDs returns the shortIds of a REALITY service.
func ShortIDs(s Service) []string {
	return strings.Split(string(s.Secrets[provision.SecretShortIDs]), ",")
}

// ShortID is the shortId a user's clients send.
func ShortID(s Service, userID int64) string {
	ids := ShortIDs(s)
	return ids[int(userID)%len(ids)]
}

func realityConfig(s Service, m Model, p Paths) (File, error) {
	var rs RealitySettings
	if err := json.Unmarshal([]byte(s.Settings), &rs); err != nil || rs.Target == "" || rs.SNI == "" {
		return File{}, fmt.Errorf("reality %s: settings need target and sni", s.Name)
	}
	decryption, _, err := VLESSEncryption(s.Secrets[provision.SecretMLKEMSeed])
	if err != nil {
		return File{}, fmt.Errorf("reality %s: %w", s.Name, err)
	}
	enc := base64.RawURLEncoding
	creds := m.Creds[s.ID]
	ids := slices.Sorted(maps.Keys(creds))
	clients := make([]map[string]string, 0, len(ids))
	for _, id := range ids {
		clients = append(clients, map[string]string{"id": creds[id], "email": InnerEmail(id), "flow": RealityFlow})
	}
	stream := map[string]any{
		"network":  "raw",
		"security": "reality",
		"realitySettings": map[string]any{
			"target":      rs.Target,
			"xver":        0,
			"serverNames": []string{rs.SNI},
			"privateKey":  enc.EncodeToString(s.Secrets[provision.SecretRealityKey]),
			"mldsa65Seed": enc.EncodeToString(s.Secrets[provision.SecretRealityMLDSA]),
			"shortIds":    ShortIDs(s),
			"maxTimeDiff": RealityMaxTimeDiff.Milliseconds(),
		},
	}
	inbound := map[string]any{
		"tag":      RealityTag,
		"protocol": "vless",
		"settings": map[string]any{"clients": clients, "decryption": decryption},
		"sniffing": sniffing,
	}
	if m.FrontTCP {
		// The front passes the stream with a PROXY v2 header (CONFIG.md).
		inbound["listen"] = p.socket(s.Name, "reality") + ",0660"
		stream["sockopt"] = map[string]any{"acceptProxyProtocol": true}
	} else {
		port, err := tcpPort(s)
		if err != nil {
			return File{}, err
		}
		inbound["listen"], inbound["port"] = "0.0.0.0", port
		if m.IPv6 {
			inbound["listen"] = "::"
		}
	}
	inbound["streamSettings"] = stream
	return xrayFile(s, p, inbound)
}

// tcpPort is the TCP port of a service (443 unless its settings say else).
func tcpPort(s Service) (int, error) {
	ports, err := s.Ports()
	if err != nil {
		return 0, err
	}
	for _, pt := range ports {
		if pt.Proto == "tcp" {
			return int(pt.Num), nil
		}
	}
	return 0, fmt.Errorf("service %s has no TCP port", s.Name)
}
