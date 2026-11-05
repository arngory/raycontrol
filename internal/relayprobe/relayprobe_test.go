package relayprobe

import (
	"context"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/api"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1/perimeterv1connect"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/probe"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/sub"
	"github.com/arngory/raycontrol/internal/summary"
)

// exit is the part of the exit's RelayService a relay's probe endpoint
// uses: one snapshot, then the feed stays open; reports recorded.
type exit struct {
	perimeterv1connect.UnimplementedRelayServiceHandler
	snap *perimeterv1.Snapshot

	mu      sync.Mutex
	probe   bool
	reports []*perimeterv1.ReportRequest
	answer  error
	drop    chan struct{} // closed: the feed ends
}

func (e *exit) WatchRelay(ctx context.Context, req *connect.Request[perimeterv1.WatchRelayRequest], s *connect.ServerStream[perimeterv1.WatchRelayResponse]) error {
	e.mu.Lock()
	e.probe = req.Msg.Probe
	drop := e.drop
	e.mu.Unlock()
	if err := s.Send(&perimeterv1.WatchRelayResponse{Snapshot: e.snap}); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
	case <-drop:
	}
	return connect.NewError(connect.CodeUnavailable, errors.New("going away"))
}

func (e *exit) Report(_ context.Context, req *connect.Request[perimeterv1.ReportRequest]) (*connect.Response[perimeterv1.ReportResponse], error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.reports = append(e.reports, req.Msg)
	if e.answer != nil {
		return nil, e.answer
	}
	return connect.NewResponse(&perimeterv1.ReportResponse{}), nil
}

// The endpoint takes the devices the exit allows it, checks RC1 with their
// K_relay, gives down and up and no link, and passes reports on with the
// client's network, answering as the exit's own endpoint does.
func TestRelayProbe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var key, other [spa.KeySize]byte
	key[0], other[0] = 1, 2
	probeSvc := uint32(provision.RelayProbeSvc)
	e := &exit{drop: make(chan struct{}), snap: &perimeterv1.Snapshot{Devices: []*perimeterv1.Device{
		{Id: "dev1", Key: key[:], Allowed: []uint32{1, probeSvc}},
		{Id: "dev2", Key: other[:], Allowed: []uint32{1}}, // not this endpoint's
	}}}
	_, h := perimeterv1connect.NewRelayServiceHandler(e)
	hs := httptest.NewUnstartedServer(h)
	hs.EnableHTTP2 = true
	hs.StartTLS()
	defer hs.Close()

	s := &Server{Name: "r1", Exit: perimeterv1connect.NewRelayServiceClient(hs.Client(), hs.URL), Log: slog.New(slog.DiscardHandler)}
	s.Probe = &probe.Server{Auth: s.auth, Report: s.report, Log: s.Log}
	go s.Watch(ctx)
	waitUp := func(want bool) {
		t.Helper()
		for range 200 {
			s.mu.Lock()
			up := s.up
			s.mu.Unlock()
			if up == want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("feed up: want %v", want)
	}
	waitUp(true)
	e.mu.Lock()
	if !e.probe {
		t.Error("the feed did not say it is rayd relay's")
	}
	e.mu.Unlock()

	front := httptest.NewServer(s.Handler())
	defer front.Close()
	do := func(method, path, device string, k [spa.KeySize]byte, body string) *http.Response {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, method, front.URL+path, strings.NewReader(body))
		req.Header.Set(sub.DeviceHeader, device)
		req.Header.Set("Authorization", sub.AuthToken(k, time.Now().Unix()/60))
		resp, err := front.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp
	}
	if r := do(http.MethodGet, probe.PathDown+"?bytes=1000", "dev1", key, ""); r.StatusCode != http.StatusOK {
		t.Fatalf("down: %d", r.StatusCode)
	}
	for name, c := range map[string]struct {
		device string
		key    [spa.KeySize]byte
		path   string
	}{
		"the exit's own key":             {"dev1", other, probe.PathDown + "?bytes=1000"},
		"a device not allowed the probe": {"dev2", other, probe.PathDown + "?bytes=1000"},
		"an unknown device":              {"dev9", key, probe.PathDown + "?bytes=1000"},
		"link":                           {"dev1", key, probe.PathLink},
	} {
		method := http.MethodGet
		if r := do(method, c.path, c.device, c.key, ""); r.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d", name, r.StatusCode)
		}
	}

	// Reports: the client's /24, not its address (httptest's is loopback,
	// which the probe server refuses as a tunnel's, so report directly).
	if err := s.report(ctx, "dev1", netip.MustParseAddr("203.0.113.77"), strings.NewReader(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.report(ctx, "dev1", netip.MustParseAddr("2001:db8:5:6::7"), strings.NewReader(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	if len(e.reports) != 2 || e.reports[0].Network != "203.0.113.0/24" || e.reports[1].Network != "2001:db8:5::/48" ||
		e.reports[0].Device != "dev1" || string(e.reports[0].Body) != `{"v":1}` {
		t.Errorf("passed on %v", e.reports)
	}
	e.mu.Unlock()
	for code, want := range map[connect.Code]error{
		connect.CodeFailedPrecondition: summary.ErrDisabled,
		connect.CodePermissionDenied:   summary.ErrDisabled,
		connect.CodeResourceExhausted:  summary.ErrRepeated,
		connect.CodeInvalidArgument:    summary.ErrInvalid,
		connect.CodeUnavailable:        summary.ErrUnavailable,
		connect.CodeInternal:           summary.ErrUnavailable,
	} {
		e.mu.Lock()
		e.answer = connect.NewError(code, errors.New("no"))
		e.mu.Unlock()
		if err := s.report(ctx, "dev1", netip.MustParseAddr("203.0.113.77"), strings.NewReader("{}")); !errors.Is(err, want) {
			t.Errorf("%v: %v, want %v", code, err, want)
		}
	}
	e.mu.Lock()
	e.answer = nil
	sent := len(e.reports)
	e.mu.Unlock()
	if err := s.report(ctx, "dev1", netip.MustParseAddr("203.0.113.77"), strings.NewReader(strings.Repeat(" ", summary.MaxBody+1))); !errors.Is(err, summary.ErrInvalid) {
		t.Errorf("a report over the limit: %v", err)
	}
	e.mu.Lock()
	if len(e.reports) != sent {
		t.Error("a report over the limit passed on")
	}
	e.mu.Unlock()

	// The exit away: reports later; the devices stay for down and up.
	close(e.drop)
	waitUp(false)
	e.mu.Lock()
	n := len(e.reports)
	e.drop = make(chan struct{})
	e.mu.Unlock()
	if err := s.report(ctx, "dev1", netip.MustParseAddr("203.0.113.77"), strings.NewReader("{}")); !errors.Is(err, summary.ErrUnavailable) {
		t.Errorf("exit away: %v", err)
	}
	e.mu.Lock()
	if len(e.reports) != n {
		t.Error("a report tried while the exit's feed is down")
	}
	e.mu.Unlock()
	if r := do(http.MethodGet, probe.PathDown+"?bytes=1000", "dev1", key, ""); r.StatusCode != http.StatusOK {
		t.Errorf("down with the exit away: %d", r.StatusCode)
	}
}

func TestNetwork(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.77":          "203.0.113.0/24",
		"::ffff:203.0.113.77":   "203.0.113.0/24",
		"2001:db8:5:6::7":       "2001:db8:5::/48",
		"2001:db8:ffff:ffff::1": "2001:db8:ffff::/48",
	} {
		if got := Network(netip.MustParseAddr(in)).String(); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

// A bundle's probe endpoint: TLS with its certificate, which a client
// checks by the pin the exit put in the subscription; a bundle from before
// R6-c has none.
func TestNew(t *testing.T) {
	cert, err := api.NewClientCertificate()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _ := api.EncodeClientCertificate(cert)
	keyDER, certDER, err := provision.SelfSigned("r1")
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := provision.SPKIPin(certDER)
	probePEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	b := node.RelayBundle{Version: 1, Name: "r1", Exit: netip.MustParseAddr("127.0.0.1"), API: node.BundleSub{Port: 1, Pin: "x"}, Cert: string(certPEM)}
	if _, _, err := New(b, 0, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("a bundle without a probe endpoint taken")
	}
	b.Probe = &node.RelayProbe{Port: 31000, Cert: "junk"}
	if _, _, err := New(b, 0, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("a probe endpoint without a certificate taken")
	}
	b.Probe.Cert = string(probePEM)
	s, tlsCfg, err := New(b, 0, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if s.Probe.UDPPort != 31000 {
		t.Errorf("UDP port %d", s.Probe.UDPPort)
	}
	srv := httptest.NewUnstartedServer(s.Handler())
	srv.TLS = tlsCfg
	srv.StartTLS()
	defer srv.Close()
	for want, p := range map[bool]string{true: pin, false: "another"} {
		hc := &http.Client{Transport: &http.Transport{TLSClientConfig: api.PinnedTLS(p, nil), ForceAttemptHTTP2: true}}
		resp, err := hc.Get(srv.URL + probe.PathDown + "?bytes=1")
		if (err == nil) != want {
			t.Fatalf("pin %s: %v", p, err)
		}
		if err == nil {
			// Nobody known yet: as for a wrong key.
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("before the exit's feed: %d", resp.StatusCode)
			}
			_ = resp.Body.Close()
		}
	}
}
