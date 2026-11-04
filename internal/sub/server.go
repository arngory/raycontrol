package sub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	// Probe, when set, serves the channel probes (spec/probe-v1.md) on the
	// same endpoint, and the subscription says so.
	Probe *probe.Server
	// Hints, when set, gives the hint for the network of an address and the
	// services of the profiles (R4-21).
	Hints func(ctx context.Context, addr netip.Addr, svcs []uint16) *summary.Hints
	now   func() time.Time

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
		Handler:           mux,
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
	if err != nil {
		return Envelope{}, err
	}
	seq, err := s.nextSeq(ctx)
	if err != nil {
		return Envelope{}, err
	}
	p := Payload{
		V: 1, NodeID: m.NodeID, Seq: seq, Time: now.Unix(), Issued: now.Unix(),
		Expires: now.Add(Lifetime).Unix(), Profiles: profiles,
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
	if s.Hints != nil && addr.IsValid() && !addr.IsLoopback() {
		svcs := make([]uint16, 0, len(profiles))
		for _, pr := range profiles {
			svcs = append(svcs, pr.Svc)
		}
		p.Hints = s.Hints(ctx, addr, svcs)
	}
	return Sign(p, s.Keys)
}

// nextSeq returns a counter that grows with every response, across restarts.
func (s *Server) nextSeq(ctx context.Context) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var seq uint64
	if b, err := s.Store.GetSetting(ctx, settingSeq); err == nil {
		seq, _ = strconv.ParseUint(string(b), 10, 64)
	} else if !errors.Is(err, store.ErrNotFound) {
		return 0, err
	}
	seq++
	return seq, s.Store.SetSetting(ctx, settingSeq, []byte(strconv.FormatUint(seq, 10)))
}
