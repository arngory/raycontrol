// Package relayprobe is rayd relay: the probe-v1 endpoint of a relay host
// (relay-v1 §9.1). It takes the devices and their keys for this relay
// (K_relay) from the exit's RelayService, as the relay's rayspa does, and
// serves down, up and the UDP echo; reports go on to the exit with the
// client's network, never its address (§9.3).
package relayprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/api"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1/perimeterv1connect"
	"github.com/arngory/raycontrol/internal/httpx"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/probe"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/sub"
	"github.com/arngory/raycontrol/internal/summary"
)

// ReportTimeout bounds passing a report on to the exit.
const ReportTimeout = 10 * time.Second

// Server is a relay's probe endpoint.
type Server struct {
	Name  string // the relay's, for the log
	Exit  perimeterv1connect.RelayServiceClient
	Probe *probe.Server
	Log   *slog.Logger

	mu      sync.Mutex
	devices map[string][spa.KeySize]byte // K_relay of the devices the relay knows
	up      bool                         // the exit's feed is open
	now     func() time.Time
}

// New makes the endpoint of the relay in b, with its daily probe volume per
// device (0: probe.DefaultDaily).
func New(b node.RelayBundle, daily int64, log *slog.Logger) (*Server, *tls.Config, error) {
	if b.Probe == nil {
		return nil, nil, errors.New("the relay bundle has no probe endpoint: a new one from the exit (rayctl relay bundle) has")
	}
	cert, err := api.DecodeClientCertificate([]byte(b.Cert))
	if err != nil {
		return nil, nil, fmt.Errorf("relay bundle certificate: %w", err)
	}
	certDER, keyDER, err := splitPEM([]byte(b.Probe.Cert))
	if err != nil {
		return nil, nil, fmt.Errorf("relay bundle probe certificate: %w", err)
	}
	tlsCfg, err := sub.TLSConfig(certDER, keyDER)
	if err != nil {
		return nil, nil, fmt.Errorf("relay bundle probe certificate: %w", err)
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: api.PinnedTLS(b.API.Pin, &cert), ForceAttemptHTTP2: true}}
	s := &Server{
		Name: b.Name,
		Exit: perimeterv1connect.NewRelayServiceClient(hc, "https://"+netip.AddrPortFrom(b.Exit, b.API.Port).String()),
		Log:  log,
	}
	s.Probe = &probe.Server{Auth: s.auth, Daily: daily, UDPPort: int(b.Probe.Port), Report: s.report, Log: log}
	return s, tlsCfg, nil
}

func (s *Server) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// splitPEM reads a certificate and its PKCS#8 key.
func splitPEM(b []byte) (certDER, keyDER []byte, err error) {
	for {
		var blk *pem.Block
		if blk, b = pem.Decode(b); blk == nil {
			break
		}
		switch blk.Type {
		case "CERTIFICATE":
			certDER = blk.Bytes
		case "PRIVATE KEY":
			keyDER = blk.Bytes
		}
	}
	if certDER == nil || keyDER == nil {
		return nil, nil, errors.New("no certificate or key")
	}
	if _, err := x509.ParseCertificate(certDER); err != nil {
		return nil, nil, err
	}
	return certDER, keyDER, nil
}

// auth checks RC1 (probe-v1 §2) with the device's key for this relay.
func (s *Server) auth(r *http.Request) (string, error) {
	id := r.Header.Get(sub.DeviceHeader)
	s.mu.Lock()
	key, ok := s.devices[id]
	s.mu.Unlock()
	if !ok || !sub.CheckAuth(r.Header.Get("Authorization"), key, s.clock()) {
		return "", errors.New("auth")
	}
	return id, nil
}

// Network is what the exit learns of a client's address: its /24 or /48.
func Network(addr netip.Addr) netip.Prefix {
	addr = addr.Unmap()
	bits := 48
	if addr.Is4() {
		bits = 24
	}
	p, _ := addr.Prefix(bits)
	return p
}

// report passes a report on to the exit (relay-v1 §9.3), answering as the
// exit's own endpoint would; while the exit is away, later (503).
func (s *Server) report(ctx context.Context, device string, addr netip.Addr, body io.Reader) error {
	s.mu.Lock()
	up := s.up
	s.mu.Unlock()
	if !up {
		return summary.ErrUnavailable
	}
	b, err := io.ReadAll(io.LimitReader(body, summary.MaxBody+1))
	if err != nil {
		return fmt.Errorf("%w: %w", summary.ErrInvalid, err)
	}
	if len(b) > summary.MaxBody {
		return fmt.Errorf("%w: over %d bytes", summary.ErrInvalid, summary.MaxBody)
	}
	ctx, cancel := context.WithTimeout(ctx, ReportTimeout)
	defer cancel()
	_, err = s.Exit.Report(ctx, connect.NewRequest(&perimeterv1.ReportRequest{Device: device, Network: Network(addr).String(), Body: b}))
	if err == nil {
		return nil
	}
	var ce *connect.Error
	switch {
	case !errors.As(err, &ce):
	case ce.Code() == connect.CodeFailedPrecondition || ce.Code() == connect.CodePermissionDenied:
		// Summaries off, or a device the exit no longer gives this relay:
		// nothing here, as for a device the relay does not know.
		return summary.ErrDisabled
	case ce.Code() == connect.CodeResourceExhausted:
		return summary.ErrRepeated
	case ce.Code() == connect.CodeInvalidArgument:
		return fmt.Errorf("%w: %s", summary.ErrInvalid, ce.Message())
	}
	s.Log.Debug("relay probe: report not passed on", "err", err)
	return summary.ErrUnavailable
}

// Handler is the endpoint: probe-v1 without link, which has no sessions
// here to give.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/probe/v1/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == probe.PathLink {
			http.NotFound(w, r)
			return
		}
		s.Probe.ServeHTTP(w, r)
	}))
	return httpx.NoRedirect(mux)
}

// take adopts a snapshot of the exit's: the devices allowed this endpoint.
func (s *Server) take(snap *perimeterv1.Snapshot) {
	devices := map[string][spa.KeySize]byte{}
	for _, d := range snap.GetDevices() {
		if len(d.Key) != spa.KeySize || !slices.Contains(d.Allowed, uint32(provision.RelayProbeSvc)) {
			continue
		}
		var k [spa.KeySize]byte
		copy(k[:], d.Key)
		devices[d.Id] = k
	}
	s.mu.Lock()
	s.devices = devices
	s.mu.Unlock()
}

func (s *Server) setUp(up bool) {
	s.mu.Lock()
	s.up = up
	s.mu.Unlock()
}

// Watch follows the exit's feed for this relay's rayd relay, reconnecting
// with backoff; the devices it last gave stay until the next snapshot.
func (s *Server) Watch(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		stream, err := s.Exit.WatchRelay(ctx, connect.NewRequest(&perimeterv1.WatchRelayRequest{Probe: true}))
		if err == nil {
			for stream.Receive() {
				backoff = time.Second
				s.take(stream.Msg().Snapshot)
				s.setUp(true)
			}
			err = stream.Err()
			_ = stream.Close()
		}
		s.setUp(false)
		if ctx.Err() != nil {
			return
		}
		s.Log.Warn("relay probe: the exit's feed", "err", err, "retry", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}
}

// Serve serves the endpoint on ln (TCP, TLS) and pc (the UDP echo, same
// port) until ctx ends, following the exit's feed meanwhile.
func (s *Server) Serve(ctx context.Context, ln net.Listener, pc net.PacketConn, tlsCfg *tls.Config) error {
	go s.Watch(ctx)
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()
	go func() { _ = s.Probe.ServeUDP(pc) }()
	srv := &http.Server{
		Handler:           s.Handler(),
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
