package sub

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arngory/raycontrol/internal/appmirror"
	"github.com/arngory/raycontrol/internal/clientver"
	"github.com/arngory/raycontrol/internal/httpx"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/probe"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/summary"
)

// AppFiles is the mirror of the client's releases (appmirror.Mirror).
type AppFiles interface {
	// Hint is the subscription's field; nil leaves it out.
	Hint(ctx context.Context) *appmirror.Hint
	// Handler serves appmirror.Path to the devices auth takes.
	Handler(auth func(*http.Request) (string, error)) http.Handler
}

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
	// PinsSince: pins made from then on (a site's next key or a switch,
	// tls_next_at) reach no line before ClockSeqAfter, for the same
	// rollback (spec/cert-pin-v1.md §8). rayd: its start. Zero: none held.
	PinsSince time.Time
	// PinsAfter, when set, is when those pins reach the lines instead of
	// ClockSeqAfter: rayd's test stand (RAYCONTROL_UNSAFE_SITE_KEY_SETTLE_NOW)
	// lets them through seconds after its start, its seq still keeping to
	// the stored count for ClockSeqAfter.
	PinsAfter time.Time
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
	// SPAVersions, when set, gives the SPA versions the node offers
	// (spa-v3 §5, api.Server.SPAVersions); unset: all this build takes.
	SPAVersions func(ctx context.Context) []int
	// RelaySPA, when set, gives the SPA versions a relay's rayspa takes
	// (spa-v3 §5), nil when it has not said: relays[].spa.versions.
	RelaySPA func(name string) []int
	// App, when set, serves the client's releases on the same endpoint
	// (spec/app-update-v1.md) and lists them in the subscription while
	// the administrator has the mirror on (appmirror.Mirror).
	App AppFiles
	// Stall: appmirror.Stall when zero (a test seam).
	Stall time.Duration
	// Changed, when set, is told that a request changed what the node
	// renders: a device's LAN consent (lan-v1 §1.1), which the Yggdrasil
	// users files carry. rayd wakes apply with it.
	Changed func()
	// Requests, when set, counts the answers by outcome (rayctl metrics
	// and stats).
	Requests *Requests
	now      func() time.Time

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
	if s.App != nil {
		mux.Handle(appmirror.Path, s.App.Handler(s.Device))
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
		// A connection that takes no byte for so long goes. Over HTTP/2 a
		// stream's write deadline only queues a reset behind the frame a
		// stalled socket holds: a client that stopped reading kept its
		// download's place until rayd restarted (review).
		HTTP2: &http.HTTP2Config{WriteByteTimeout: cmp.Or(s.Stall, appmirror.Stall)},
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

// Requests counts the subscription's answers since rayd started, by
// outcome: counts only, never who.
type Requests struct {
	// OK: profiles went out. ClientRefused: the device's client is below
	// the node's minimum (client-min-v1 §4). TrafficExhausted: the user is
	// over the traffic limit (traffic-limit-v1 §4). Denied: 404, no
	// subscription (unknown or revoked device, a wrong Authorization, a
	// user disabled or expired).
	OK, ClientRefused, TrafficExhausted, Denied atomic.Uint64
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	env, out, err := s.handle(r)
	if err != nil {
		if s.Requests != nil {
			s.Requests.Denied.Add(1)
		}
		s.Log.Debug("subscription refused", "remote", r.RemoteAddr, "err", err)
		http.NotFound(w, r)
		return
	}
	if q := s.Requests; q != nil {
		switch {
		case out.exhausted:
			q.TrafficExhausted.Add(1)
		case out.refused:
			q.ClientRefused.Add(1)
		default:
			q.OK.Add(1)
		}
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

// handle answers a request: the envelope, and the client it named with
// what the answer did to it (refused, exhausted).
func (s *Server) handle(r *http.Request) (Envelope, *requestClient, error) {
	if r.Method != http.MethodGet {
		return Envelope{}, nil, errors.New("method")
	}
	ctx := r.Context()
	dev, key, err := s.Store.ActiveDevice(ctx, r.Header.Get(DeviceHeader))
	if err != nil {
		return Envelope{}, nil, err
	}
	now := s.clock()
	if !CheckAuth(r.Header.Get("Authorization"), key, now) {
		return Envelope{}, nil, errors.New("auth")
	}
	addr := netip.Addr{}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		addr = ap.Addr().Unmap()
	}
	// The device's LAN consent (lan-v1 §1.1, §4.4): written when it
	// changes, before the answer, which follows it. Not logged: it is the
	// device's activity (observability §1); rayctl device list shows
	// the state.
	if on, said := lanConsent(r.Header); said {
		changed, err := s.Store.SetDeviceLAN(ctx, dev.ID, on, store.LANShowEvery)
		if err != nil {
			return Envelope{}, nil, err
		}
		if changed && s.Changed != nil {
			s.Changed()
		}
	}
	// The client the request names (client-min-v1 §1, §5): kept on the
	// device once its Authorization holds, product and version only.
	cl := &requestClient{}
	cl.Client, cl.known = clientver.Parse(r.Header.Get(clientver.Header))
	cl.names = clientver.HasFeature(r.Header.Get(clientver.FeaturesHeader), clientver.FeatureNames)
	if cl.known {
		// Bookkeeping only: the subscription goes out without it.
		if err := s.Store.SetDeviceClient(ctx, dev.ID, cl.Product+"/"+cl.Version.String(), ClientSeenEvery); err != nil {
			s.Log.Warn("subscription: the device's client not kept", "err", err)
		}
	}
	env, err := s.build(ctx, dev.UserName, dev.ID, key[:], addr, now, cl)
	if err != nil {
		return Envelope{}, nil, err
	}
	// The device once more, after the last read of what the subscription
	// carries: a revocation that commits after the check above gives the
	// user new credentials and a new LAN key in the same transaction
	// (store.RevokeDevice), and build reads them in statements of their
	// own. Whatever of that build saw, this read sees the revocation too
	// (the store's one connection: each statement after the commits
	// before it), and the device gets what a revoked one gets.
	if _, _, err := s.Store.ActiveDevice(ctx, dev.ID); err != nil {
		return Envelope{}, nil, err
	}
	return env, cl, nil
}

// Build returns the signed subscription of a user.
func (s *Server) Build(ctx context.Context, userName string, now time.Time) (Envelope, error) {
	return s.BuildFor(ctx, userName, netip.Addr{}, now)
}

// BuildFor returns the signed subscription of a user asking from addr: with
// the hint for that network, when there is one.
func (s *Server) BuildFor(ctx context.Context, userName string, addr netip.Addr, now time.Time) (Envelope, error) {
	return s.BuildForDevice(ctx, userName, nil, addr, now)
}

// BuildForDevice is BuildFor for one of the user's devices, given by its
// SPA key: its own links where they differ by device (Yggdrasil's key).
// Its lan field is that of a device that does not show itself.
func (s *Server) BuildForDevice(ctx context.Context, userName string, device []byte, addr netip.Addr, now time.Time) (Envelope, error) {
	return s.build(ctx, userName, "", device, addr, now, nil)
}

// ClientSeenEvery is how often a device's client is written again when it
// has not changed (store.SetDeviceClient).
const ClientSeenEvery = time.Hour

// RefusedExpiry is the longest a refused client's answer lives
// (client-min-v1 §4): it asks again soon after its update.
const RefusedExpiry = time.Hour

// requestClient is the client a device's request named: known is false
// for no header or one that does not parse.
type requestClient struct {
	clientver.Client
	known bool
	// names: the client resolves names (spec/names-v1.md §4), so its
	// links carry them.
	names bool
	// What build answered: below the node's minimum, or over the
	// traffic limit.
	refused, exhausted bool
}

// build is the subscription of a user's device, given by its ID (for its
// lan field), its SPA key and the client its request named; none of them
// for the user's own (rayctl user export), which no policy refuses.
func (s *Server) build(ctx context.Context, userName, deviceID string, device []byte, addr netip.Addr, now time.Time, cl *requestClient) (Envelope, error) {
	m, err := render.Collect(ctx, s.Store)
	if err != nil {
		return Envelope{}, err
	}
	m.Now = now // what depends on the time (a pin of an hour) follows the subscription's
	m.ByName = cl != nil && cl.names
	m.PinsSince, m.PinsAfter = s.PinsSince, s.PinsAfter
	if m.PinsAfter.IsZero() {
		m.PinsAfter = s.ClockSeqAfter
	}
	u, err := s.Store.UserByName(ctx, userName)
	if err != nil {
		return Envelope{}, err
	}
	var user *render.User
	for i := range m.Users {
		if m.Users[i].Name == userName {
			user = &m.Users[i]
		}
	}
	// Over the traffic limit (traffic-limit-v1 §4): the subscription goes
	// on, with no profiles and the marker, so that the client keeps the
	// node's rows and says why. Disabled and expired: none (404).
	exhausted := user == nil && u.Live(now) && u.OverLimit(now)
	if user == nil && !exhausted {
		return Envelope{}, errors.New("user not active")
	}
	// Below the node's minimum (client-min-v1 §4): no profiles, no LAN, and
	// what the client needs to update through the node (app, relays, spa).
	policy, err := node.ClientPolicy(ctx, s.Store)
	if err != nil {
		// Unreadable: none, rather than no subscription (and no next keys)
		// for every device.
		s.Log.Warn("subscription: client policy unreadable, taken as none", "err", err)
		policy, err = clientver.Policy{}, nil
	}
	refused := cl != nil && policy.Refuses(cl.Client, cl.known, now)
	if cl != nil {
		cl.refused, cl.exhausted = refused, exhausted
	}
	profiles := []Profile{}
	if !exhausted && !refused {
		profiles, err = DeviceProfiles(m, *user, device)
	}
	// Not the links of a DNS tunnel the front leaves out for its zones
	// (rayd logs why; zones v0.13 took that nest): they would fail every
	// client that tries them.
	if out := render.UnservedZones(m); len(out) > 0 {
		profiles = slices.DeleteFunc(profiles, func(pr Profile) bool { return out[int64(pr.Svc)] != nil })
	}
	if err != nil {
		// The others go out: a 404 for all of them kept the client on its
		// last subscription, without the next keys of the rest (review).
		// By the user's ID, not the name: logs carry no names (docs/design/observability.md §7).
		s.Log.Warn("subscription: profiles left out", "user", u.ID, "err", err)
		if len(profiles) == 0 {
			return Envelope{}, err
		}
	}
	name, err := node.Name(ctx, s.Store)
	if err != nil {
		return Envelope{}, err
	}
	note, err := node.Note(ctx, s.Store)
	if err != nil {
		return Envelope{}, err
	}
	seq, err := s.nextSeq(ctx, now)
	if err != nil {
		return Envelope{}, err
	}
	p := Payload{
		V: 1, NodeID: m.NodeID, Name: name, Note: note, Seq: seq, Time: now.Unix(), Issued: now.Unix(),
		Expires: now.Add(Lifetime).Unix(), Profiles: profiles,
		SPA:     &SPAHint{Carriers: []string{"udp"}, Versions: s.spaVersions(ctx)},
		DNSName: m.DNSName, Addrs: node.Addrs(m.Host),
	}
	if u.Limited() {
		p.Traffic = &TrafficHint{V: 1, Used: u.Used(now), Limit: *u.TrafficLimit, Since: u.PeriodStart(now).Unix(),
			Reset: unixOrZero(u.NextResetAt(now)), Exhausted: exhausted}
		if exhausted {
			p.Expires = ExhaustedExpiry(now, u.NextResetAt(now), mrand.N(ExhaustedJitter)).Unix() //nolint:gosec // G404: when to ask, no secret
		}
	}
	p.Client = policy.Field(refused, now)
	if refused {
		p.Expires = min(p.Expires, now.Add(RefusedExpiry).Unix())
	} else if cl != nil && policy.From > now.Unix() && policy.Refuses(cl.Client, cl.known, time.Unix(policy.From, 0)) {
		// Refused from a date ahead: the answer lives no longer than to
		// it (and a little, so that such devices do not all ask at once).
		p.Expires = min(p.Expires, policy.From+int64(mrand.N(ExhaustedJitter)/time.Second)) //nolint:gosec // G404: when to ask, no secret
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
	if s.App != nil {
		p.App = s.App.Hint(ctx)
	}
	// dnsprobe-v1: for a user with a dnstt profile, the zones the front
	// answers probes in (masterdns answers look otherwise). Not for
	// slipstream, though the front answers them in its zone too: clients
	// probe resolvers for dnstt only (Niko 1.37).
	if len(m.DNSProbeKey) == 32 && slices.ContainsFunc(profiles, func(pr Profile) bool {
		return slices.ContainsFunc(m.Services, func(svc render.Service) bool {
			return uint16(svc.ID) == pr.Svc && svc.Kind == "dnstt"
		})
	}) {
		p.DNSProbe = &DNSProbeHint{V: 1, Key: base64.RawURLEncoding.EncodeToString(m.DNSProbeKey)}
	}
	p.DNSAuth = dnsAuthVersions(m, profiles)
	if !refused {
		if p.LAN, err = s.lanHint(ctx, m, u, profiles, deviceID, name); err != nil {
			return Envelope{}, err
		}
	}
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
		if s.RelaySPA != nil {
			// What the relay's rayspa said it takes (spa-v3 §5): relays
			// update apart from the exit.
			h.SPA.Versions = s.RelaySPA(r.Name)
		}
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

// SeqToClock moves the stored seq up to the clock in milliseconds, so that
// the next answer is above every one a client has seen. For a database put
// back by rayctl restore: it holds the count of the day of the backup, and
// rayd keeps to the stored count for its first minutes (ClockSeqAfter),
// where clients would drop its answers (subscription-v1 §3). Not for an
// update's rollback: there the old count is the right one.
func SeqToClock(ctx context.Context, st *store.Store, now time.Time) error {
	var seq uint64
	if b, err := st.GetSetting(ctx, settingSeq); err == nil {
		seq, _ = strconv.ParseUint(string(b), 10, 64)
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if clock := uint64(max(now.UnixMilli(), 0)); clock > seq {
		return st.SetSetting(ctx, settingSeq, []byte(strconv.FormatUint(clock, 10)))
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

// dnsAuthVersions is what the user's dnstt and masterdns tunnels that check
// tags take (spec/dnsauth-v2.md §4): 1 unless one of them takes v2 only
// (auth_hint=required), 2 unless one of them takes no v2 (auth_hint=off).
// The field is one for all of them: when they disagree both ways, 2,
// where the tunnels go.
func dnsAuthVersions(m render.Model, profiles []Profile) *DNSAuthVersions {
	v1, v2, any := true, true, false
	for _, svc := range m.Services {
		// slipstream signs v2 always, whatever this says (Niko 1.37): a [2]
		// for it would turn a dnstt with auth_hint=off to v2 as well.
		if (svc.Kind != "dnstt" && svc.Kind != "masterdns") || render.DNSAuthMode(svc.Service) == "off" ||
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

// spaVersions are the SPA versions the subscription offers.
func (s *Server) spaVersions(ctx context.Context) []int {
	if s.SPAVersions != nil {
		return s.SPAVersions(ctx)
	}
	return slices.Clone(node.SPAVersions)
}
