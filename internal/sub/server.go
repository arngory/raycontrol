package sub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/arngory/raycontrol/internal/httpx"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/probe"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/summary"
)

// Path is the endpoint path; DeviceHeader names the device.
const (
	Path         = "/sub/v1"
	DeviceHeader = "X-Raycontrol-Device"
	settingSeq   = "sub_seq"
)

// Server serves subscriptions over TLS 1.3 with X25519MLKEM768 only. Any
// request that does not authenticate gets a plain 404.
type Server struct {
	Store *store.Store
	Keys  provision.NodeKeys
	Log   *slog.Logger
	// ClockSeqAfter: seq keeps to the clock in milliseconds only from then
	// on (rayd: 10 minutes after it starts). An update that fails in its
	// first minutes puts the database back under the old version, which
	// counts on from the old seq: a client that took the clock's from the
	// new rayd meanwhile would refuse every answer of the old one (review).
	ClockSeqAfter time.Time
	// Probe, when set, serves the channel probes (spec/probe-v1.md) on the
	// same endpoint, and the subscription says so.
	Probe *probe.Server
	// Hints, when set, gives the hint for the network of an address and the
	// services of the profiles (R4-21).
	Hints func(ctx context.Context, addr netip.Addr, svcs []uint16) *summary.Hints
	// TCPCarrier: the node takes SPA over TCP, bare and as a ClientHello
	// (rayd -spa-tcp); the subscription lists the carriers.
	TCPCarrier bool
	// RelayProbe, when set, says whether a relay's rayd relay is there:
	// the subscription lists its probe endpoint only then (relay-v1 §9.2).
	RelayProbe func(name string) bool
	now        func() time.Time

	mu sync.Mutex // serialises seq
}

func (s *Server) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// TLSConfig returns the server TLS settings for the subscription service.
func TLSConfig(certDER, keyDER []byte) (*tls.Config, error) {
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		Certificates:     []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}},
		NextProtos:       []string{"h2", "http/1.1"},
	}, nil
}

// Serve listens on addr until ctx ends.
func (s *Server) Serve(ctx context.Context, addr string, tlsCfg *tls.Config) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle(Path, s)
	if s.Probe != nil {
		mux.Handle("/probe/v1/", s.Probe)
	}
	srv := &http.Server{
		// No redirects, not even ServeMux's: Niko takes a 3xx from the
		// subscription or the probes for an error (RAYCONTROL.md §22).
		Handler:           httpx.NoRedirect(mux),
		ConnContext:       probe.ConnContext,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      20 * time.Second,
		ErrorLog:          slog.NewLogLogger(s.Log.Handler(), slog.LevelDebug),
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ServeTLS(ln, "", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	env, err := s.handle(r)
	if err != nil {
		s.Log.Debug("subscription refused", "remote", r.RemoteAddr, "err", err)
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(env)
}

// Device checks a request as the subscription does (spec/subscription-v1.md
// §2) and returns the device's ID.
func (s *Server) Device(r *http.Request) (string, error) {
	id := r.Header.Get(DeviceHeader)
	_, key, err := s.Store.ActiveDevice(r.Context(), id)
	if err != nil {
		return "", err
	}
	if !CheckAuth(r.Header.Get("Authorization"), key, s.clock()) {
		return "", errors.New("auth")
	}
	return id, nil
}

func (s *Server) handle(r *http.Request) (Envelope, error) {
	if r.Method != http.MethodGet {
		return Envelope{}, errors.New("method")
	}
	ctx := r.Context()
	dev, key, err := s.Store.ActiveDevice(ctx, r.Header.Get(DeviceHeader))
	if err != nil {
		return Envelope{}, err
	}
	now := s.clock()
	if !CheckAuth(r.Header.Get("Authorization"), key, now) {
		return Envelope{}, errors.New("auth")
	}
	addr := netip.Addr{}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		addr = ap.Addr().Unmap()
	}
	return s.BuildFor(ctx, dev.UserName, addr, now)
}

// Build returns the signed subscription of a user.
func (s *Server) Build(ctx context.Context, userName string, now time.Time) (Envelope, error) {
	return s.BuildFor(ctx, userName, netip.Addr{}, now)
}

// BuildFor returns the signed subscription of a user asking from addr: with
// the hint for that network, when there is one.
func (s *Server) BuildFor(ctx context.Context, userName string, addr netip.Addr, now time.Time) (Envelope, error) {
	m, err := render.Collect(ctx, s.Store)
	if err != nil {
		return Envelope{}, err
	}
	var user *render.User
	for i := range m.Users {
		if m.Users[i].Name == userName {
			user = &m.Users[i]
		}
	}
	if user == nil {
		return Envelope{}, errors.New("user not active")
	}
	profiles, err := Profiles(m, *user)
	// Not the links of a DNS tunnel the front leaves out for its zones
	// (rayd logs why; zones v0.13 took that nest): they would fail every
	// client that tries them.
	if out := render.UnservedZones(m); len(out) > 0 {
		profiles = slices.DeleteFunc(profiles, func(pr Profile) bool { return out[int64(pr.Svc)] != nil })
	}
	if err != nil {
		// The others go out: a 404 for all of them kept the client on its
		// last subscription, without the next keys of the rest (review).
		s.Log.Warn("subscription: profiles left out", "user", userName, "err", err)
		if len(profiles) == 0 {
			return Envelope{}, err
		}
	}
	name, err := node.Name(ctx, s.Store)
	if err != nil {
		return Envelope{}, err
	}
	seq, err := s.nextSeq(ctx, now)
	if err != nil {
		return Envelope{}, err
	}
	p := Payload{
		V: 1, NodeID: m.NodeID, Name: name, Seq: seq, Time: now.Unix(), Issued: now.Unix(),
		Expires: now.Add(Lifetime).Unix(), Profiles: profiles,
		SPA: &SPAHint{Carriers: []string{"udp"}},
	}
	if s.TCPCarrier {
		// In the order to try: the ClientHello before bare TCP, which a
		// DPI box sees as odd.
		p.SPA.Carriers = append(p.SPA.Carriers, "tls", "tcp")
	}
	if s.Probe != nil {
		p.Probe = &ProbeHint{V: 1, UDP: s.Probe.UDPPort != 0, Tunnel: probe.Name}
		if s.Probe.Report != nil {
			p.Probe.Report = summary.Optional
		}
		for _, pr := range profiles {
			for _, svc := range m.Services {
				if uint16(svc.ID) == pr.Svc && slices.Contains(ProbeTunnels, svc.Kind) && !slices.Contains(p.Probe.TunnelSvc, pr.Svc) {
					p.Probe.TunnelSvc = append(p.Probe.TunnelSvc, pr.Svc)
				}
			}
		}
	}
	if err := s.addRelays(ctx, &p, m); err != nil {
		return Envelope{}, err
	}
	// dnsprobe-v1: for a user with a dnstt or slipstream profile, the
	// zones the front answers probes in (masterdns answers look
	// otherwise).
	if len(m.DNSProbeKey) == 32 && slices.ContainsFunc(profiles, func(pr Profile) bool {
		return slices.ContainsFunc(m.Services, func(svc render.Service) bool {
			return uint16(svc.ID) == pr.Svc && (svc.Kind == "dnstt" || svc.Kind == "slipstream")
		})
	}) {
		p.DNSProbe = &DNSProbeHint{V: 1, Key: base64.RawURLEncoding.EncodeToString(m.DNSProbeKey)}
	}
	p.DNSAuth = dnsAuthVersions(m, profiles)
	// Through a relay the address is the relay's: its network's hints are
	// not the client's (relay-v1 §9.3).
	if s.Hints != nil && addr.IsValid() && !addr.IsLoopback() && !s.FromRelay(ctx, addr) {
		svcs := make([]uint16, 0, len(profiles))
		for _, pr := range profiles {
			svcs = append(svcs, pr.Svc)
		}
		p.Hints = s.Hints(ctx, addr, svcs)
	}
	return Sign(p, s.Keys)
}

// FromRelay reports whether addr is a relay's (relay-v1 §3): what comes
// from there is a client's behind the relay, whose own address the node
// does not see.
func (s *Server) FromRelay(ctx context.Context, addr netip.Addr) bool {
	relays, err := s.Store.ListRelays(ctx)
	if err != nil {
		return true // unknown: no hints, no report, rather than a wrong AS
	}
	addr = addr.Unmap()
	return slices.ContainsFunc(relays, func(r store.Relay) bool { return r.Address == addr })
}

// addRelays lists the relays in front of the node and marks the profiles
// they forward (relay-v1 §4). A relay is listed once its bundle is issued:
// before that its host forwards nothing.
func (s *Server) addRelays(ctx context.Context, p *Payload, m render.Model) error {
	relays, err := s.Store.ListRelays(ctx)
	if err != nil {
		return err
	}
	var listed []store.Relay
	for _, r := range relays {
		if r.CertPin == "" {
			continue
		}
		params, err := provision.RelayParams(ctx, s.Store, r.Name)
		if err != nil {
			return err
		}
		h := RelayHint{ID: r.Name, Host: r.Address.String(), SPA: node.FromParams(params)}
		if r.ProbePort != 0 && r.ProbePin != "" && s.RelayProbe != nil && s.RelayProbe(r.Name) {
			// The relay passes reports on to this node: it takes them when
			// this node does.
			h.Probe = &RelayProbeHint{V: 1, Port: r.ProbePort, Pin: r.ProbePin, Svc: provision.RelayProbeSvc, UDP: true,
				Report: s.Probe != nil && s.Probe.Report != nil}
		}
		p.Relays = append(p.Relays, h)
		listed = append(listed, r)
	}
	if len(listed) == 0 {
		return nil
	}
	services, err := s.Store.ListServices(ctx)
	if err != nil {
		return err
	}
	byID := map[uint16]store.Service{}
	for _, svc := range services {
		byID[uint16(svc.ID)] = svc
	}
	ssh := provision.SSHPorts(services)
	// A relay forwards what its snapshot says (provision.RelayPorts).
	forwards := func(r store.Relay, svc uint16) bool {
		ports, err := provision.RelayPorts(r, byID[svc], ssh)
		return err == nil && len(ports) > 0
	}
	for i := range p.Profiles {
		for _, svc := range m.Services {
			if uint16(svc.ID) != p.Profiles[i].Svc || !RelayKinds(svc.Kind) || svc.Public() {
				continue
			}
			var via []string
			for _, r := range listed {
				if forwards(r, p.Profiles[i].Svc) {
					via = append(via, r.Name)
				}
			}
			p.Profiles[i].Via = via
		}
	}
	return nil
}

// nextSeq returns a counter that grows with every response, across restarts.
func (s *Server) nextSeq(ctx context.Context, now time.Time) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var seq uint64
	if b, err := s.Store.GetSetting(ctx, settingSeq); err == nil {
		seq, _ = strconv.ParseUint(string(b), 10, 64)
	} else if !errors.Is(err, store.ErrNotFound) {
		return 0, err
	}
	// Never below the clock in milliseconds: a database put back (update
	// rollback, restore) holds an older count, and clients drop answers
	// with a seq below one they have seen (subscription-v1 §3).
	seq++
	if !now.Before(s.ClockSeqAfter) {
		seq = max(seq, uint64(max(now.UnixMilli(), 0)))
	}
	return seq, s.Store.SetSetting(ctx, settingSeq, []byte(strconv.FormatUint(seq, 10)))
}

// dnsAuthVersions is what the user's DNS tunnels that check tags take
// (spec/dnsauth-v2.md §4): 1 unless one of them takes v2 only
// (auth_hint=required), 2 unless one of them takes no v2 (auth_hint=off).
// The field is one for all of them: when they disagree both ways, 2,
// where the tunnels go.
func dnsAuthVersions(m render.Model, profiles []Profile) *DNSAuthVersions {
	v1, v2, any := true, true, false
	for _, svc := range m.Services {
		if !provision.DNSTunnel(svc.Kind) || render.DNSAuthMode(svc.Service) == "off" ||
			!slices.ContainsFunc(profiles, func(pr Profile) bool { return pr.Svc == uint16(svc.ID) }) {
			continue
		}
		any = true
		switch render.DNSAuthHint(svc.Service) {
		case "required":
			v1 = false
		case "off":
			v2 = false
		}
	}
	if !any {
		return nil
	}
	d := &DNSAuthVersions{}
	if v1 {
		d.V = append(d.V, 1)
	}
	if v2 || !v1 {
		d.V = append(d.V, 2)
	}
	return d
}
