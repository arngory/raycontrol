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
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"os"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/sys/unix"

	"github.com/arngory/raycontrol/internal/naive"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/probe"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/site"
	"github.com/arngory/raycontrol/internal/spa"
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
	// Supervised: the data plane runs as rayd's child processes, under
	// rayd's own user, without systemd (rayd serve -supervise). The peer
	// checks on the sockets then expect that user, not the fixed UIDs.
	Supervised bool
}

// PeerUID is the UID a process accepts on its socket: the fixed one, or
// rayd's own when the data plane runs supervised.
func (p Paths) PeerUID(fixed int) int {
	if p.Supervised {
		return os.Getuid()
	}
	return fixed
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
	// Creds maps service ID and user ID to the user's current UUID for
	// services whose users are Xray clients (REALITY).
	Creds map[int64]map[int64]string
	// Sets are the same credentials (inner included) with their rotation:
	// the next UUID and the previous one in its grace period (R4-1).
	Sets map[int64]map[int64]store.Credential
	// Now dates the generated site; zero is the time of rendering.
	Now time.Time
	// FrontTCP puts TCP 443 behind the niko-server front (tcpmux, v0.2,
	// docs/08-decisions.md R2-15): REALITY on a unix socket with PROXY v2,
	// DoH and naive as passed sockets. Collect sets it; without it REALITY
	// binds its TCP port itself (R2-7), and DoH and naive are not served.
	FrontTCP bool
	// FrontUDP puts UDP 443 behind the front (udpmux, v0.3, R3-4, R3-5):
	// Hysteria2 always; DoH3 and naive-quic only with it.
	FrontUDP bool
	// DNSAuth maps a DNS tunnel with dnsauth on to the keys of the
	// devices allowed on it (spec/dnsauth-v1.md): "<device id> <hex>".
	// Only CollectForRender fills it.
	DNSAuth map[int64][]string
	// DNSProbeKey is the node's dnsprobe-v1 key (docs/spec/dnsprobe-v1.md)
	// when it has a DNS tunnel: the front answers resolver checks with it.
	DNSProbeKey []byte
	// NSName is the name DNS tunnel zones are delegated to ("" before
	// one is chosen): the front answers the apex of dnstt zones with it.
	NSName string
	// Debug: the debug window is open (rayctl debug): niko-server logs at
	// debug level. Xray stays at warning: at info it logs the users'
	// destinations.
	Debug bool
}

// nikoLevel is niko-server's log level for the model.
func (m Model) nikoLevel() string {
	if m.Debug {
		return "debug"
	}
	return "warn"
}

// DNSSealMode is a DNS tunnel's seal mode (dnsseal-v1 for dnstt, mdseal-v1
// for masterdns): off, optional or required; off when unset.
func DNSSealMode(s store.Service) string { return provision.DNSSealMode(s) }

// DNSSealKeyFile is the dnsseal-v1 keys file among a dnstt service's.
const DNSSealKeyFile = "seal.keys"

// DNSAuthMode is a DNS tunnel's dnsauth-v1 mode: off, optional or
// required (spec/dnsauth-v1.md §5).
func DNSAuthMode(s store.Service) string { return provision.DNSAuthMode(s) }

// DNSAuthKeys is the file name of a DNS tunnel's device keys.
const DNSAuthKeys = "auth.keys"

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
	m := Model{IPv6: HostIPv6(), FrontTCP: true, FrontUDP: true}
	m.Debug = time.Now().Before(st.DebugUntil(ctx))
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
		// dnsseal-v1: a dnstt service from before it gets its key now.
		if s.Kind == "dnstt" {
			if secrets[provision.SecretSealKey], err = provision.EnsureSealKey(ctx, st, s, secrets); err != nil {
				return m, err
			}
		}
		m.Services = append(m.Services, Service{s, secrets})
	}
	for i := range m.Services {
		if m.Services[i].Kind == "inner" {
			inner = &m.Services[i]
		}
	}
	// The dnsprobe-v1 key, made once whatever the services: the front's
	// unit installs it from the first deploy, so a dnstt service added
	// later through the API finds it there (a front told to read a key
	// its unit never copied in would stay down, 443 and 53 with it).
	if m.DNSProbeKey, err = st.DNSProbeKey(ctx); err != nil {
		return m, err
	}
	if m.NSName, err = provision.NSName(ctx, st); err != nil {
		return m, err
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
	m.Sets = map[int64]map[int64]store.Credential{}
	for _, svc := range m.Services {
		if !UserCredentials(svc.Kind) {
			continue
		}
		var ids []int64
		for _, u := range m.Users {
			if slices.Contains(u.Services, svc.ID) {
				ids = append(ids, u.ID)
			}
		}
		all, err := st.CredentialSets(ctx, svc.ID, ids, NewUUID)
		if err != nil {
			return m, err
		}
		m.Creds[svc.ID] = map[int64]string{}
		m.Sets[svc.ID] = map[int64]store.Credential{}
		for _, id := range ids {
			m.Creds[svc.ID][id] = all[id].Current
			m.Sets[svc.ID][id] = all[id]
		}
	}
	if inner != nil {
		all, err := st.CredentialSets(ctx, inner.ID, needInner, NewUUID)
		if err != nil {
			return m, err
		}
		m.Inner = map[int64]string{}
		m.Sets[inner.ID] = map[int64]store.Credential{}
		for _, id := range needInner {
			m.Inner[id] = all[id].Current
			m.Sets[inner.ID][id] = all[id]
		}
	}
	return m, nil
}

// CollectForRender is Collect plus what only the rendered files need: the
// dnsauth-v1 keys of the devices allowed on each DNS tunnel that has it
// on, derived per service (spec/dnsauth-v1.md §2). Subscriptions and
// exports take Collect and skip the devices and the key derivation.
func CollectForRender(ctx context.Context, st *store.Store) (Model, error) {
	m, err := Collect(ctx, st)
	if err != nil {
		return m, err
	}
	var params spa.Params
	var devices []spa.Device
	var checkKey []byte
	for _, svc := range m.Services {
		if DNSAuthMode(svc.Service) == "off" {
			continue
		}
		if devices == nil {
			if params, err = node.LoadParams(ctx, st); err != nil {
				return m, err
			}
			if devices, err = st.SPADevices(ctx); err != nil {
				return m, err
			}
		}
		if m.DNSAuth == nil {
			m.DNSAuth = map[int64][]string{}
		}
		lines := []string{}
		for _, d := range devices {
			if slices.Contains(d.Allowed, uint16(svc.ID)) {
				k := spa.DNSAuthKey(d.Key, params.NodeID, uint16(svc.ID))
				lines = append(lines, d.ID+" "+hex.EncodeToString(k[:]))
			}
		}
		// The node's own line: its check tags its polls (dnscheck). Not
		// for masterdns, whose check asks a random name, untagged: a key
		// there would be one nobody uses.
		if svc.Kind == "dnstt" {
			if checkKey == nil {
				if checkKey, err = st.DNSCheckKey(ctx); err != nil {
					return m, err
				}
			}
			k, err := provision.DNSCheckAuthKey(checkKey, params.NodeID, svc.ID)
			if err != nil {
				return m, err
			}
			lines = append(lines, provision.DNSCheckDevice+" "+hex.EncodeToString(k[:]))
		}
		m.DNSAuth[svc.ID] = lines
	}
	return m, nil
}

// NewUUID makes a random (version 4) UUID, the VLESS credential.
func NewUUID() (string, error) {
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
	// Reload: the process reads the file again by itself when it changes
	// (users of naive), so a change needs no restart.
	Reload bool
	// Refresh: only replaces the file if it is there. The users of a
	// service that failed to render (Q-1) still go out, so a revocation
	// reaches its running process; nothing new is made for it.
	Refresh bool
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

// UserCredentials reports whether every user of a service kind has a
// secret of their own there, with rotation (R4-1): a UUID for REALITY, a
// password for Hysteria2 (a UUID too: 122 random bits).
func UserCredentials(kind string) bool {
	return kind == "reality" || kind == "doh" || kind == "naive" || IsHysteria(kind)
}

// IsHysteria reports whether the kind is Hysteria2.
func IsHysteria(kind string) bool { return kind == "hy2-masq" || kind == "hy2-obfs" }

// IsXray reports whether the service runs on Xray.
func IsXray(kind string) bool { return slices.Contains(XrayKinds, kind) }

// XrayUsers returns the inbound tag and the users (email -> UUID) of an Xray
// service, as rayd syncs them through the API.
func XrayUsers(m Model, s Service) (tag string, users map[string]string) {
	creds := m.Inner
	tag = InnerTag
	switch {
	case s.Kind == "reality":
		creds, tag = m.Creds[s.ID], RealityTag
	case IsHysteria(s.Kind):
		creds, tag = m.Creds[s.ID], "" // niko-server: the same users in a file
	case s.Kind == "naive":
		creds, tag = m.Creds[s.ID], "" // not Xray: the same users, hashed into a file
	}
	now := m.Now
	if now.IsZero() {
		now = time.Now()
	}
	users = make(map[string]string, len(creds))
	for id, uuid := range creds {
		users[InnerEmail(id)] = uuid
		// While a credential rotates, the next UUID (and for a grace period
		// the previous one) gets in too.
		if set, ok := m.Sets[s.ID][id]; ok {
			if set.Next != "" {
				users[InnerEmail(id)+"-n"] = set.Next
			}
			if set.Prev != "" && now.Before(set.PrevUntil) {
				users[InnerEmail(id)+"-p"] = set.Prev
			}
		}
	}
	return tag, users
}

// xrayClients are the inbound's clients, in a stable order.
func xrayClients(m Model, s Service, flow string) []map[string]string {
	_, users := XrayUsers(m, s)
	clients := make([]map[string]string, 0, len(users))
	for _, email := range slices.Sorted(maps.Keys(users)) {
		c := map[string]string{"id": users[email], "email": email}
		if flow != "" {
			c["flow"] = flow
		}
		clients = append(clients, c)
	}
	return clients
}

// InnerSocket is the VLESS socket of the inner stage.
func (p Paths) InnerSocket(inner string) string { return p.socket(inner, "vless") }

func jsonFile(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	return append(b, '\n'), err
}

// Render returns all files for the model. Kinds the renderer does not
// handle yet, and services waiting for a certificate, are skipped and named
// in the second result. A service that cannot be rendered comes back in a
// ServiceErrors, with the files of all the others.
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
		// Probe: the front answers dnsprobe-v1 in this zone. dnstt
		// only: the answers are built as dnstt's.
		Probe bool `json:"probe,omitempty"`
		// NS: the name the zone is delegated to; the front answers SOA
		// and NS at its apex (niko-server v0.9.0). dnstt only, as Probe.
		NS []string `json:"ns,omitempty"`
		// SealPad: probe answers padded as the zone's sealed ones
		// (niko-server v0.10.0).
		SealPad bool `json:"seal_pad,omitempty"`
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
	type udpRoute struct {
		SNI                    []string `json:"sni,omitempty"`
		SalamanderPasswordFile string   `json:"salamander_password_file,omitempty"`
		Backend                string   `json:"backend"`
	}
	var udpRoutes []udpRoute
	var zones []route
	taken := map[string]string{} // a zone in the front: its service
	var tcpRoutes []tcpRoute
	tcpDefault := "" // the first REALITY service: its target answers like the site
	backends := map[string]backendRef{}

	// one renders a service. On an error nothing of it is kept, and the
	// others go on (Q-1): one broken service must not hold back users,
	// revocations and key rotations everywhere else.
	one := func(s Service) error {
		switch s.Kind {
		case "dnstt", "masterdns":
			if inner == nil {
				return errors.New("needs the inner stage, which is missing or disabled")
			}
			all := provision.Zones(s.Service)
			if len(all) == 0 {
				return errors.New("no zone")
			}
			// Zones stored before they were checked (v0.13 took nested
			// ones): the later service is left out, as a broken one is,
			// not the front's whole config (niko-server v0.11.0 refuses
			// zones that nest, and TCP and UDP 443 would go with it).
			for _, z := range all {
				for other, svc := range taken {
					if provision.ZonesClash(z, other) {
						return fmt.Errorf("zone %s is, or nests with, zone %s of %s: a name under both would be either's; give it another zone", z, other, svc)
					}
				}
			}
			for _, z := range all {
				taken[z] = s.Name
			}
			r := route{Backend: s.Name, Probe: s.Kind == "dnstt" && len(m.DNSProbeKey) == 32}
			// A zone whose answers are all sealed: the front pads its
			// probe answers as they are (dnsseal-v1 §6).
			r.SealPad = r.Probe && DNSSealMode(s.Service) == "required"
			if s.Kind == "dnstt" && m.NSName != "" {
				r.NS = []string{m.NSName}
			}
			// Each zone, the spare ones as the main one: the same
			// backend, probe, apex and padding (spec/dnszones-v1.md §4;
			// the front does not tie a tunnel's entries together).
			for _, z := range all {
				r.Zone = z
				zones = append(zones, r)
			}
			backends[s.Name] = backendRef{Socket: p.FrontSocket(s.Name, "packet"), Mode: "packet", UID: p.PeerUID(s.UID)}
			keys, ok := m.DNSAuth[s.ID]
			if !ok && DNSAuthMode(s.Service) != "off" {
				// An empty keys file would lock every device out.
				return errors.New("dnsauth keys not collected (render.CollectForRender)")
			}
			f, secrets, auth, err := dnsBackend(s, all, inner.Name, p, keys, m.nikoLevel())
			if err != nil {
				return err
			}
			files = append(files, f)
			files = append(files, secrets...)
			if auth != nil {
				files = append(files, *auth)
			}
		case "inner":
			f, err := innerConfig(s, m, p)
			if err != nil {
				return err
			}
			files = append(files, f)
		case "reality":
			var rs RealitySettings
			_ = json.Unmarshal([]byte(s.Settings), &rs)
			if rs.Site != "" && !m.hasCert(rs.Site) {
				skipped = append(skipped, s.Name+" (waits for the certificate of "+rs.Site+")")
				return nil
			}
			f, err := realityConfig(s, m, p)
			if err != nil {
				return err
			}
			files = append(files, f)
			if m.FrontTCP {
				backends[s.Name] = backendRef{Socket: p.FrontSocket(s.Name, "reality"), Mode: "proxy-v2", UID: p.PeerUID(s.UID)}
				var rs RealitySettings
				_ = json.Unmarshal([]byte(s.Settings), &rs)
				tcpRoutes = append(tcpRoutes, tcpRoute{SNI: []string{rs.SNI}, Backend: s.Name})
				if tcpDefault == "" {
					tcpDefault = s.Name
				}
			}
		case "hy2-masq", "hy2-obfs":
			if site := provision.SiteOf(s.Service); s.Kind == "hy2-masq" && !m.hasCert(site) {
				skipped = append(skipped, s.Name+" (waits for the certificate of "+site+")")
				return nil
			}
			fs, err := hysteriaFiles(s, m, p)
			if err != nil {
				return err
			}
			files = append(files, fs...)
			backends[s.Name] = backendRef{Socket: p.FrontSocket(s.Name, "packet"), Mode: "packet", UID: p.PeerUID(s.UID)}
			if s.Kind == "hy2-obfs" {
				udpRoutes = append(udpRoutes, udpRoute{SalamanderPasswordFile: p.FrontSalamander(s.Name), Backend: s.Name})
			} else {
				var st struct {
					SNI string `json:"sni"`
				}
				_ = json.Unmarshal([]byte(s.Settings), &st)
				udpRoutes = append(udpRoutes, udpRoute{SNI: []string{strings.ToLower(st.SNI)}, Backend: s.Name})
			}
		case "site":
			fs, err := siteFiles(s, m, p)
			if err != nil {
				return err
			}
			if fs == nil {
				skipped = append(skipped, s.Name+" (waits for its certificate)")
			}
			files = append(files, fs...)
		case "doh", "naive":
			// Behind the front only (R2-15): rayd (DoH) and rayd naive take the
			// sockets it passes.
			if !m.FrontTCP {
				skipped = append(skipped, s.Name+" (needs the front on TCP 443)")
				return nil
			}
			var st struct {
				SNI string `json:"sni"`
			}
			_ = json.Unmarshal([]byte(s.Settings), &st)
			ref := backendRef{Socket: p.DoHSocket(s.Name), Mode: "fd", UID: p.PeerUID(RaydUID)}
			quic := backendRef{Socket: p.DoH3Socket(s.Name), Mode: "packet", UID: p.PeerUID(RaydUID)}
			if s.Kind == "naive" {
				fs, err := naiveFiles(s, m, p)
				if err != nil {
					return err
				}
				if fs == nil {
					skipped = append(skipped, s.Name+" (waits for its site's certificate)")
					return nil
				}
				files = append(files, fs...)
				ref = backendRef{Socket: p.NaiveSocket(s.Name), Mode: "fd", UID: p.PeerUID(s.UID)}
				quic = backendRef{Socket: p.NaiveQUICSocket(s.Name), Mode: "packet", UID: p.PeerUID(s.UID)}
			}
			backends[s.Name] = ref
			tcpRoutes = append(tcpRoutes, tcpRoute{SNI: []string{strings.ToLower(st.SNI)}, Backend: s.Name})
			// The same name over QUIC: DoH3 and naive-quic (R3-5).
			if m.FrontUDP {
				backends[quicBackend(s.Name)] = quic
				udpRoutes = append(udpRoutes, udpRoute{SNI: []string{strings.ToLower(st.SNI)}, Backend: quicBackend(s.Name)})
			}
		case "yggdrasil":
			// A TLS link behind tcpmux by name (R4-15), into inner.
			if !m.FrontTCP {
				skipped = append(skipped, s.Name+" (needs the front on TCP 443)")
				return nil
			}
			if inner == nil {
				return errors.New("needs the inner stage, which is missing or disabled")
			}
			if !m.hasCert(provision.SiteOf(s.Service)) {
				skipped = append(skipped, s.Name+" (waits for its site's certificate)")
				return nil
			}
			fs, err := yggdrasilFiles(s, m, *inner, p)
			if err != nil {
				return err
			}
			files = append(files, fs...)
			st, _, _ := YggdrasilNode(s)
			backends[s.Name] = backendRef{Socket: p.FrontSocket(s.Name, "fd"), Mode: "fd", UID: p.PeerUID(s.UID)}
			tcpRoutes = append(tcpRoutes, tcpRoute{SNI: []string{strings.ToLower(st.SNI)}, Backend: s.Name})
		case "ssh", "subscription", "api":
			// Not data-plane processes.
		default:
			skipped = append(skipped, s.Name+" ("+s.Kind+")")
		}
		return nil
	}
	var errs ServiceErrors
	for _, s := range m.Services {
		nf, nz, nt, nu, def := len(files), len(zones), len(tcpRoutes), len(udpRoutes), tcpDefault
		if err := one(s); err != nil {
			files, zones, tcpRoutes, udpRoutes, tcpDefault = files[:nf], zones[:nz], tcpRoutes[:nt], udpRoutes[:nu], def
			delete(backends, s.Name)
			delete(backends, quicBackend(s.Name))
			errs = append(errs, fmt.Errorf("service %s: %w", s.Name, err))
			files = append(files, accessFiles(s, m, p, inner)...)
		}
	}

	if len(backends) > 0 {
		sort.Slice(zones, func(i, j int) bool { return zones[i].Zone < zones[j].Zone })
		front := map[string]any{
			"schema":   Schema,
			"role":     "front",
			"log":      map[string]string{"level": m.nikoLevel()},
			"backends": backends,
		}
		if len(zones) > 0 {
			listen := []string{"0.0.0.0:53"}
			if m.IPv6 {
				listen = append(listen, "[::]:53")
			}
			dns := map[string]any{"listen": listen, "zones": zones}
			// dnsprobe-v1: the front answers resolver checks itself in
			// the dnstt zones (niko-server v0.8.3).
			if slices.ContainsFunc(zones, func(z route) bool { return z.Probe }) {
				dns["probe_key_file"] = p.FrontDNSProbe()
			}
			front["dns"] = dns
		}
		// The key root copies in, with every front: the unit is written by
		// rayctl apply, the config also by rayd as services change, and a
		// dnstt zone may come between the two.
		if len(m.DNSProbeKey) == 32 {
			files = append(files, File{Path: path.Join(p.Rendered, "front", DNSProbeKeyFile), Mode: 0o600,
				Content: []byte(hex.EncodeToString(m.DNSProbeKey) + "\n"), Service: "front"})
		}
		if len(tcpRoutes) > 0 {
			listen := []string{"0.0.0.0:443"}
			if m.IPv6 {
				listen = append(listen, "[::]:443")
			}
			// Unknown SNI goes to the first REALITY service: its target
			// answers like the site it stands for.
			tcp := map[string]any{"listen": listen, "sniff_timeout": "5s", "routes": tcpRoutes}
			if tcpDefault != "" {
				tcp["default"] = tcpDefault
			}
			front["tcp"] = tcp
		}
		if len(udpRoutes) > 0 {
			// udpmux (R3-4): QUIC by name, salamander by password.
			listen := []string{"0.0.0.0:443"}
			if m.IPv6 {
				listen = append(listen, "[::]:443")
			}
			front["udp"] = map[string]any{"listen": listen, "idle": "60s", "routes": udpRoutes}
		}
		b, err := jsonFile(front)
		if err != nil {
			return nil, nil, err
		}
		files = append(files, File{Path: path.Join(p.Rendered, "front", "front.json"), Mode: 0o640, Group: GroupName("front"), Content: b, Service: "front"})
	}
	if len(errs) > 0 {
		return files, skipped, errs
	}
	return files, skipped, nil
}

// ServiceErrors are the services Render could not render. The files it
// returns with them are complete for every other service and may be
// applied: the broken ones keep their files on disk, and the front leaves
// them out.
type ServiceErrors []error

func (e ServiceErrors) Error() string   { return errors.Join(e...).Error() }
func (e ServiceErrors) Unwrap() []error { return e }

// Partial reports whether err from Render leaves the other services' files
// usable.
func Partial(err error) bool {
	var se ServiceErrors
	return errors.As(err, &se)
}

// DNSSecret is the file of a DNS tunnel's key, by kind: systemd copies it
// for the backend (Paths.Credential), whether this render wrote it or an
// earlier one did.
func DNSSecret(kind string) string {
	if kind == "masterdns" {
		return "encryption.key"
	}
	return "noise.key"
}

// dnsAuthFile is a DNS tunnel's keys file (spec/dnsauth-v1.md), which the
// backend rereads.
func dnsAuthFile(s Service, p Paths, authKeys []string) File {
	content := "# dnsauth-v1 keys of the devices allowed on " + s.Name + ", written by rayd\n"
	for _, l := range authKeys {
		content += l + "\n"
	}
	return File{Path: path.Join(p.Rendered, s.Name, DNSAuthKeys), Mode: 0o640, Group: GroupName(s.Name), Content: []byte(content), Service: s.Name, Reload: true}
}

// accessFiles are the files that say who may connect to a service, built
// without the rest of it: a service that failed to render still gets them
// (Refresh), so a revoked user or device loses it there too (Q-1).
func accessFiles(s Service, m Model, p Paths, inner *Service) []File {
	dir := path.Join(p.Rendered, s.Name)
	var out []File
	add := func(name string, b []byte, err error) {
		if err == nil {
			out = append(out, File{Path: path.Join(dir, name), Mode: 0o640, Group: GroupName(s.Name), Content: b, Service: s.Name, Reload: true, Refresh: true})
		}
	}
	switch s.Kind {
	case "hy2-masq", "hy2-obfs":
		b, err := hysteriaUsers(m, s)
		add(HysteriaUsers, b, err)
	case "naive":
		b, err := naiveUsers(m, s)
		add(NaiveUsers, b, err)
	case "yggdrasil":
		if inner != nil {
			b, err := jsonFile(map[string]any{"users": yggdrasilUsers(m, s, *inner)})
			add(YggdrasilUsers, b, err)
		}
	case "dnstt", "masterdns":
		if keys, ok := m.DNSAuth[s.ID]; ok && DNSAuthMode(s.Service) != "off" {
			f := dnsAuthFile(s, p, keys)
			f.Refresh = true
			out = append(out, f)
		}
	}
	return out
}

// dnsBackend renders a DNS tunnel's backend for its zones, the main one
// first.
func dnsBackend(s Service, zones []string, inner string, p Paths, authKeys []string, level string) (cfg File, secrets []File, auth *File, err error) {
	opts := map[string]any{}
	// dnsauth-v1 (spec/dnsauth-v1.md): the devices' keys in a file of the
	// service group (the front is in none, R4-28), which the backend
	// rereads: a new or revoked device needs no restart.
	if mode := DNSAuthMode(s.Service); mode != "off" {
		if mode != "optional" && mode != "required" {
			// The backend would refuse to start, or worse, read it as off.
			return cfg, nil, nil, fmt.Errorf("service %s: auth %q: off, optional or required", s.Name, mode)
		}
		f := dnsAuthFile(s, p, authKeys)
		opts["auth"] = mode
		opts["auth_keys_file"] = f.Path
		auth = &f
	}
	seal := DNSSealMode(s.Service)
	if seal != "off" && seal != "optional" && seal != "required" {
		return cfg, nil, nil, fmt.Errorf("service %s: seal %q: off, optional or required", s.Name, seal)
	}
	var secretName string
	var secretValue []byte
	secretName = DNSSecret(s.Kind)
	switch s.Kind {
	case "dnstt":
		secretValue = []byte(hex.EncodeToString(s.Secrets[provision.SecretNoisePrivate]) + "\n")
		opts["zone"] = zones[0]
		if len(zones) > 1 {
			// Spare zones of the same tunnel (niko-server v0.11.0).
			opts["zones"] = zones[1:]
		}
		opts["private_key_file"] = p.Credential(s.Name, secretName)
		// dnsseal-v1 (spec/dnsseal-v1.md): the keys in a file of the
		// service group, as dnsauth's, which the backend rereads (niko-
		// server v0.10.0): a new key and the end of the previous one's
		// grace need no restart. The current key first, then the previous
		// one while it is accepted (§8, provision.RotateSealKey). Written
		// whatever the mode; the mode goes to the backend when it is on.
		if len(s.Secrets[provision.SecretSealKey]) != 32 {
			return cfg, nil, nil, fmt.Errorf("service %s has no seal key (render.Collect)", s.Name)
		}
		var keys strings.Builder
		keys.WriteString("# dnsseal-v1 keys of " + s.Name + ", the current first, written by rayd\n")
		for _, k := range provision.SealKeys(s.Service, s.Secrets) {
			keys.WriteString(hex.EncodeToString(k) + "\n")
		}
		sealFile := File{Path: path.Join(p.Rendered, s.Name, DNSSealKeyFile), Mode: 0o640, Group: GroupName(s.Name),
			Content: []byte(keys.String()), Service: s.Name, Reload: true}
		secrets = append(secrets, sealFile)
		if seal != "off" {
			opts["seal"] = seal
			opts["seal_key_file"] = sealFile.Path
		}
	case "masterdns":
		var settings struct {
			Method int `json:"encryption_method"`
		}
		_ = json.Unmarshal([]byte(s.Settings), &settings)
		secretValue = s.Secrets[provision.SecretMasterDNSKey]
		opts["zones"] = zones // masterdns takes a list as it is (DOMAIN)
		opts["encryption_method"] = settings.Method
		opts["encryption_key_file"] = p.Credential(s.Name, secretName)
		// mdseal-v1 (spec/mdseal-v1.md §6): sealed with the service's own
		// key, the one above; the mode alone.
		if seal != "off" {
			opts["seal"] = seal
		}
	}
	if len(s.Secrets) == 0 || len(secretValue) == 0 {
		return cfg, nil, nil, fmt.Errorf("service %s has no key", s.Name)
	}
	b, err := jsonFile(map[string]any{
		"schema":    Schema,
		"role":      "backend",
		"kind":      s.Kind,
		"log":       map[string]string{"level": level},
		"socket":    p.FrontSocket(s.Name, "packet"),
		"front_uid": p.PeerUID(FrontUID),
		"options":   opts,
		"inner":     p.InnerSocket(inner),
	})
	if err != nil {
		return cfg, nil, nil, err
	}
	dir := path.Join(p.Rendered, s.Name)
	cfg = File{Path: path.Join(dir, "backend.json"), Mode: 0o640, Group: GroupName(s.Name), Content: b, Service: s.Name}
	// Secrets are read by systemd (root), which gives the process its own
	// copy (Paths.Credential), so the file needs no group access.
	secret := File{Path: path.Join(dir, secretName), Mode: 0o600, Content: secretValue, Service: s.Name}
	return cfg, append([]File{secret}, secrets...), auth, nil
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

// ProbeName is where a client reaches the channel probes through a tunnel
// (spec/probe-v1.md): the exits send it to the subscription endpoint.
const ProbeName = probe.Name

// SubscriptionPort is the port of the enabled subscription endpoint, or 0.
func (m Model) SubscriptionPort() int {
	for _, s := range m.Services {
		if s.Kind == "subscription" {
			if ports, err := s.Ports(); err == nil && len(ports) > 0 {
				return int(ports[0].Num)
			}
		}
	}
	return 0
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
	clients := xrayClients(m, s, "")
	return xrayFile(s, m, p, map[string]any{
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
func xrayFile(s Service, m Model, p Paths, inbounds ...map[string]any) (File, error) {
	outbounds := []map[string]any{
		{"tag": "direct", "protocol": "freedom", "streamSettings": map[string]any{"sockopt": map[string]string{"domainStrategy": "UseIP"}}},
		{"tag": "block", "protocol": "blackhole"},
	}
	rules := []map[string]any{
		{"ip": privateNets, "outboundTag": "block"},
		{"protocol": []string{"bittorrent"}, "outboundTag": "block"},
	}
	// Channel probes through the tunnel (R4-16): the probe name goes to the
	// subscription endpoint on loopback, TCP and UDP alike, before the rule
	// that keeps loopback out.
	if port := m.SubscriptionPort(); port != 0 {
		// Xray's freedom refuses private targets unless a final rule lets
		// this one through.
		outbounds = append(outbounds, map[string]any{"tag": "probe", "protocol": "freedom",
			"settings": map[string]any{"redirect": fmt.Sprintf("127.0.0.1:%d", port),
				"finalRules": []map[string]any{{"action": "allow", "network": "tcp,udp", "ip": []string{"127.0.0.1/32"}, "port": strconv.Itoa(port)}}}})
		rules = append([]map[string]any{{"domain": []string{"full:" + ProbeName}, "outboundTag": "probe"}}, rules...)
	}
	b, err := jsonFile(map[string]any{
		// Warning even in the debug window: at info Xray logs where every
		// connection goes, the users' destinations.
		"log": map[string]string{"loglevel": "warning", "access": "none"},
		"api": map[string]any{"tag": "api", "listen": p.APISocket(s.Name), "services": []string{"HandlerService"}},
		"dns": map[string]any{
			// DoH to public resolvers: the host resolver may sit in a private
			// range that the routing below blocks.
			"servers":       []string{"https+local://1.1.1.1/dns-query", "https+local://9.9.9.9/dns-query"},
			"queryStrategy": "UseIP",
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   map[string]any{"domainStrategy": "IPOnDemand", "rules": rules},
	})
	if err != nil {
		return File{}, err
	}
	return File{Path: path.Join(p.Rendered, s.Name, "xray.json"), Mode: 0o640, Group: GroupName(s.Name), Content: b, Service: s.Name}, nil
}

// RealityTag is the inbound tag of a REALITY service (Xray API target);
// RealityPrevTag the inbound of its previous keys during the grace period
// after a switch (R4-19).
const (
	RealityTag     = "reality"
	RealityPrevTag = "reality-prev"
)

// RealityFlow is the VLESS flow of REALITY clients.
const RealityFlow = "xtls-rprx-vision"

// RealitySettings are the settings of a REALITY service.
type RealitySettings struct {
	Site        string `json:"site"`        // the node's decoy site (self-steal), or
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

// NextReality returns a REALITY service as it will be after its published
// switch (R4-7): the next keys, shortIds and server name. ok is false when
// no switch is published.
func NextReality(s Service) (next Service, from time.Time, ok bool) {
	state := provision.ParseRealityState(s.Service)
	if state.NextFrom == 0 {
		return s, time.Time{}, false
	}
	next = s
	next.Secrets = maps.Clone(s.Secrets)
	for _, name := range provision.RealitySecrets {
		v, ok := s.Secrets[provision.NextSecret(name)]
		if !ok {
			return s, time.Time{}, false
		}
		next.Secrets[name] = v
	}
	if state.SNINext != "" {
		var settings map[string]any
		if err := json.Unmarshal([]byte(s.Settings), &settings); err != nil {
			return s, time.Time{}, false
		}
		settings["sni"] = state.SNINext
		b, err := json.Marshal(settings)
		if err != nil {
			return s, time.Time{}, false
		}
		next.Settings = string(b)
	}
	return next, time.Unix(state.NextFrom, 0), true
}

// PrevReality returns a REALITY service as it was before its last switch,
// while the previous keys are accepted (R4-19); ok is false otherwise.
func PrevReality(s Service) (prev Service, ok bool) {
	state := provision.ParseRealityState(s.Service)
	if state.PrevUntil == 0 {
		return s, false
	}
	prev = s
	prev.Secrets = maps.Clone(s.Secrets)
	for _, name := range provision.RealitySecrets {
		v, ok := s.Secrets[provision.PrevSecret(name)]
		if !ok {
			return s, false
		}
		prev.Secrets[name] = v
	}
	if state.SNIPrev != "" {
		var settings map[string]any
		if err := json.Unmarshal([]byte(s.Settings), &settings); err != nil {
			return s, false
		}
		settings["sni"] = state.SNIPrev
		b, err := json.Marshal(settings)
		if err != nil {
			return s, false
		}
		prev.Settings = string(b)
	}
	return prev, true
}

// XrayTags are the inbounds of an Xray service whose users rayd syncs.
func XrayTags(s Service) []string {
	if s.Kind != "reality" {
		return []string{InnerTag}
	}
	if _, ok := PrevReality(s); ok {
		return []string{RealityTag, RealityPrevTag}
	}
	return []string{RealityTag}
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
	if err := json.Unmarshal([]byte(s.Settings), &rs); err != nil || (rs.Target == "" && rs.Site == "") || rs.SNI == "" {
		return File{}, fmt.Errorf("reality %s: settings need a target or site, and sni", s.Name)
	}
	if rs.Site != "" {
		rs.Target = p.SiteSocket(rs.Site)
	}
	clients := xrayClients(m, s, RealityFlow)
	// During the grace period after a switch (R4-19) the previous keys get an
	// inbound of their own on a socket of this process: the current inbound
	// hands it what it does not recognise, and it hands the site (or the
	// target) what it does not recognise in turn. Clients that have not moved
	// yet get in; a probe meets the same site as ever.
	var prevInbound map[string]any
	target := rs.Target
	if prev, ok := PrevReality(s); ok {
		var ps RealitySettings
		_ = json.Unmarshal([]byte(prev.Settings), &ps)
		in, err := realityInbound(prev, RealityPrevTag, ps.SNI, rs.Target, clients)
		if err != nil {
			return File{}, err
		}
		in["listen"] = p.socket(s.Name, RealityPrevTag) + ",0600"
		prevInbound, target = in, p.socket(s.Name, RealityPrevTag)
	}
	inbound, err := realityInbound(s, RealityTag, rs.SNI, target, clients)
	if err != nil {
		return File{}, err
	}
	stream := inbound["streamSettings"].(map[string]any)
	if m.FrontTCP {
		// The front passes the stream with a PROXY v2 header (CONFIG.md).
		inbound["listen"] = p.FrontSocket(s.Name, "reality") + ",0660"
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
	if prevInbound != nil {
		return xrayFile(s, m, p, inbound, prevInbound)
	}
	return xrayFile(s, m, p, inbound)
}

// realityInbound is a REALITY inbound with the keys of s under a server
// name; what it does not recognise goes to target.
func realityInbound(s Service, tag, sni, target string, clients []map[string]string) (map[string]any, error) {
	decryption, _, err := VLESSEncryption(s.Secrets[provision.SecretMLKEMSeed])
	if err != nil {
		return nil, fmt.Errorf("reality %s: %w", s.Name, err)
	}
	enc := base64.RawURLEncoding
	return map[string]any{
		"tag":      tag,
		"protocol": "vless",
		"settings": map[string]any{"clients": clients, "decryption": decryption},
		"sniffing": sniffing,
		"streamSettings": map[string]any{
			"network":  "raw",
			"security": "reality",
			"realitySettings": map[string]any{
				"target":      target,
				"xver":        0,
				"serverNames": []string{sni},
				"privateKey":  enc.EncodeToString(s.Secrets[provision.SecretRealityKey]),
				"mldsa65Seed": enc.EncodeToString(s.Secrets[provision.SecretRealityMLDSA]),
				"shortIds":    ShortIDs(s),
				"maxTimeDiff": RealityMaxTimeDiff.Milliseconds(),
			},
		},
	}, nil
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

// Hysteria2 files (R3-4): the backend's config, its users (read again by
// the backend when they change), the certificate chain, the key and for
// hy2-obfs the salamander password, which systemd copies for the backend;
// the front gets its own copy of that password to recognise the flows.
const (
	HysteriaChain = "chain.pem"
	HysteriaKey   = "key.pem"
	HysteriaUsers = "users.json"
	HysteriaObfs  = "salamander"
)

// DNSProbeKeyFile is the dnsprobe-v1 key's file among the front's.
const DNSProbeKeyFile = "dnsprobe.key"

// FrontStats is where the DNS front gives its counters (dns.stats_socket,
// niko-server v0.11.0): in the front's runtime directory, which the front
// group (rayd) may pass through.
func (p Paths) FrontStats() string { return p.socket("front", "stats") }

// FrontDNSProbe is where the front reads the dnsprobe-v1 key.
func (p Paths) FrontDNSProbe() string {
	return p.Credential("front", DNSProbeKeyFile)
}

// FrontSalamander is where the front reads a hy2-obfs password.
func (p Paths) FrontSalamander(service string) string {
	return p.Credential("front", service+".salamander")
}

// hysteriaFiles renders a Hysteria2 service as a niko-server backend behind
// udpmux (R3-4): TLS 1.3 with X25519MLKEM768 only; hy2-masq under its own
// name with the site's certificate and an empty 404 without a password,
// like the site; hy2-obfs with a self-signed certificate clients pin,
// inside salamander.
// hysteriaUsers is a Hysteria2 backend's users file: the current credential
// of each, and the next and previous while they rotate (R4-1), under
// distinct names.
func hysteriaUsers(m Model, s Service) ([]byte, error) {
	_, creds := XrayUsers(m, s)
	type user struct {
		Name    string            `json:"name"`
		Enabled bool              `json:"enabled"`
		Hy2     map[string]string `json:"hy2"`
	}
	users := []user{}
	for _, name := range slices.Sorted(maps.Keys(creds)) {
		users = append(users, user{Name: name, Enabled: true, Hy2: map[string]string{"password": creds[name]}})
	}
	return jsonFile(map[string]any{"users": users})
}

func hysteriaFiles(s Service, m Model, p Paths) ([]File, error) {
	// hy2-masq: the site's certificate; hy2-obfs: its own, self-signed.
	chain, keyDER := s.Secrets[provision.SecretTLSChain], s.Secrets[provision.SecretTLSKey]
	if s.Kind == "hy2-obfs" {
		chain = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Secrets[provision.SecretTLSCert]})
	} else {
		for _, x := range m.Services {
			if x.Kind == "site" && x.Name == provision.SiteOf(s.Service) {
				chain, keyDER = x.Secrets[provision.SecretTLSChain], x.Secrets[provision.SecretTLSKey]
			}
		}
	}
	dir := path.Join(p.Rendered, s.Name)
	options := map[string]any{}
	// The ceilings of the server's Brutal (R4-16): it sends at min(up_mbps,
	// the client's rate), BBR without the client's; down_mbps caps clients.
	var ceil struct {
		Up   int `json:"up_mbps"`
		Down int `json:"down_mbps"`
	}
	_ = json.Unmarshal([]byte(s.Settings), &ceil)
	if ceil.Up > 0 {
		options["up_mbps"] = ceil.Up
	}
	if ceil.Down > 0 {
		options["down_mbps"] = ceil.Down
	}
	// Channel probes through the tunnel (R4-16): the probe name leads to the
	// subscription endpoint on loopback (niko-server v0.5).
	if port := m.SubscriptionPort(); port != 0 {
		options["probe"] = map[string]any{"name": ProbeName, "address": fmt.Sprintf("127.0.0.1:%d", port)}
	}
	cfg := map[string]any{
		"schema": Schema, "role": "backend", "kind": s.Kind, "log": map[string]string{"level": m.nikoLevel()},
		"socket": p.FrontSocket(s.Name, "packet"), "front_uid": p.PeerUID(FrontUID),
		// Session stats for the channel probes' link (R4-16, niko-server v0.6).
		"stats_socket": p.StatsSocket(s.Name),
		"users_file":   path.Join(dir, HysteriaUsers),
		"tls": map[string]any{
			"certificate_file": path.Join(dir, HysteriaChain),
			"key_file":         p.Credential(s.Name, HysteriaKey),
			"curves":           []string{"X25519MLKEM768"},
		},
		"options": options,
	}
	var files []File
	if s.Kind == "hy2-obfs" {
		options["obfs_password_file"] = p.Credential(s.Name, HysteriaObfs)
		pw := s.Secrets[provision.SecretObfsPassword]
		files = append(files,
			File{Path: path.Join(dir, HysteriaObfs), Mode: 0o600, Content: pw, Service: s.Name},
			File{Path: path.Join(p.Rendered, "front", s.Name+".salamander"), Mode: 0o600, Content: pw, Service: "front"})
	}
	b, err := jsonFile(cfg)
	if err != nil {
		return nil, err
	}
	u, err := hysteriaUsers(m, s)
	if err != nil {
		return nil, err
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return append(files,
		File{Path: path.Join(dir, "backend.json"), Mode: 0o640, Group: GroupName(s.Name), Content: b, Service: s.Name},
		File{Path: path.Join(dir, HysteriaUsers), Mode: 0o640, Group: GroupName(s.Name), Content: u, Service: s.Name, Reload: true},
		File{Path: path.Join(dir, HysteriaChain), Mode: 0o640, Group: GroupName(s.Name), Content: chain, Service: s.Name},
		File{Path: path.Join(dir, HysteriaKey), Mode: 0o600, Content: key, Service: s.Name},
	), nil
}

// SiteSocket is the TLS socket of the decoy site, the self-steal target.
func (p Paths) SiteSocket(site string) string { return p.socket(site, "tls") }

// Site files: content under www/, the certificate chain and the key, which
// systemd copies for the site process (Paths.Credential).
const (
	SiteChain = "chain.pem"
	SiteKey   = "key.pem"
	SiteRoot  = "www"
)

// StatsSocket is where a Hysteria2 backend answers for the sessions of a
// client address; the directory lets the service's group (rayd) in.
func (p Paths) StatsSocket(service string) string { return p.socket(service, "stats") }

// DoHSocket is where rayd serves a DoH service for the site to pass it on.
func (p Paths) DoHSocket(service string) string { return p.socket(service, "doh") }

// FrontSocket is where a backend takes what the front passes it. The
// directory belongs to the service user and the front's group (setgid, so
// the socket gets that group): the front reaches the socket and nothing
// else of the service, its rendered keys least of all (S-1).
func (p Paths) FrontSocket(service, kind string) string {
	return path.Join(p.FrontDir(service), kind+".sock")
}

// FrontDir is the directory of a service's FrontSockets.
func (p Paths) FrontDir(service string) string { return path.Join(p.Run, service+"-in") }

// NaiveSocket is where a naive process takes the connections the front
// passes.
func (p Paths) NaiveSocket(service string) string { return p.FrontSocket(service, "naive") }

// NaiveQUICSocket is where a naive process takes its QUIC datagrams from
// the front (naive-quic, R3-5).
func (p Paths) NaiveQUICSocket(service string) string { return p.FrontSocket(service, "quic") }

// DoH3Socket is where rayd takes the DoH service's QUIC datagrams (DoH3).
func (p Paths) DoH3Socket(service string) string { return p.socket(service, "doh3") }

// quicBackend names the front's backend for a service's QUIC side; "/" is
// not allowed in service names.
func quicBackend(service string) string { return service + "/quic" }

// Files of a naive service (R2-14).
const (
	NaiveUsers = "users.json"
	NaiveChain = "chain.pem"
	NaiveKey   = "key.pem"
)

// naiveFiles are the site's certificate (naive answers for a name under
// it) and the hashes of the users' passwords, which the process reads again
// when they rotate.
// naiveUsers is a naive process's users file: the hashes of the
// credentials, sorted.
func naiveUsers(m Model, s Service) ([]byte, error) {
	_, users := XrayUsers(m, s)
	hashes := make([]string, 0, len(users))
	for _, email := range slices.Sorted(maps.Keys(users)) {
		hashes = append(hashes, naive.HashPassword(users[email]))
	}
	slices.Sort(hashes)
	return jsonFile(hashes)
}

func naiveFiles(s Service, m Model, p Paths) ([]File, error) {
	site := provision.SiteOf(s.Service)
	if !m.hasCert(site) {
		return nil, nil
	}
	var chain, keyDER []byte
	for _, x := range m.Services {
		if x.Kind == "site" && x.Name == site {
			chain, keyDER = x.Secrets[provision.SecretTLSChain], x.Secrets[provision.SecretTLSKey]
		}
	}
	u, err := naiveUsers(m, s)
	if err != nil {
		return nil, err
	}
	dir := path.Join(p.Rendered, s.Name)
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return []File{
		{Path: path.Join(dir, NaiveUsers), Mode: 0o640, Group: GroupName(s.Name), Content: u, Service: s.Name, Reload: true},
		{Path: path.Join(dir, NaiveChain), Mode: 0o640, Group: GroupName(s.Name), Content: chain, Service: s.Name},
		{Path: path.Join(dir, NaiveKey), Mode: 0o600, Content: key, Service: s.Name},
	}, nil
}

// hasCert reports whether the site service has its certificate yet.
func (m Model) hasCert(site string) bool {
	for _, s := range m.Services {
		if s.Name == site && s.Kind == "site" {
			return len(s.Secrets[provision.SecretTLSChain]) > 0 && len(s.Secrets[provision.SecretTLSKey]) > 0
		}
	}
	return false
}

// siteFiles renders the decoy site; nil until it has a certificate.
func siteFiles(s Service, m Model, p Paths) ([]File, error) {
	if !m.hasCert(s.Name) {
		return nil, nil
	}
	dir := path.Join(p.Rendered, s.Name)
	var files []File
	// Content only for a site that serves pages; by default it answers
	// every request with 404 and has none (R4-8).
	if provision.SiteAnswer(s.Service) == site.AnswerPages {
		now := m.Now
		if now.IsZero() {
			now = time.Now()
		}
		content, err := site.Generate(s.Secrets[provision.SecretSiteSeed], provision.SiteName(s.Service), now)
		if err != nil {
			return nil, err
		}
		for _, name := range slices.Sorted(maps.Keys(content)) {
			files = append(files, File{Path: path.Join(dir, SiteRoot, name), Mode: 0o640, Group: GroupName(s.Name), Content: content[name], Service: s.Name})
		}
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: s.Secrets[provision.SecretTLSKey]})
	files = append(files,
		File{Path: path.Join(dir, SiteChain), Mode: 0o640, Group: GroupName(s.Name), Content: s.Secrets[provision.SecretTLSChain], Service: s.Name},
		File{Path: path.Join(dir, SiteKey), Mode: 0o600, Content: key, Service: s.Name},
	)
	return files, nil
}
