package naive

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/site"
)

// serveNaive serves h over HTTP/2 as the service does (Server.HTTPServer)
// and gives its URL.
func serveNaive(t *testing.T, h *Server) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.Config = h.HTTPServer() // the limits of a connection as the service has them
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL
}

// One connection carries all a user may hold: with every TCP, UoT and ICMP
// place of the user taken on a single HTTP/2 connection, the next request
// is still answered (429). It must not wait for a stream of the
// connection's: the client would see a tunnel that hangs, not a limit.
func TestConnectionCarriesUserLimits(t *testing.T) {
	users := filepath.Join(t.TempDir(), "users.json")
	writeUsersNamed(t, users, map[string]string{"pw": "u5-ab12"})
	answer, _ := site.Responder(site.Answer404, "")
	h := &Server{Users: &Users{Path: users}, Answer: answer, ICMP: true, icmpOpen: newFakeNet().open, Log: slog.New(slog.DiscardHandler),
		Dial: func(context.Context, string, string) (net.Conn, error) {
			c, s := net.Pipe()
			go func() { _, _ = io.Copy(io.Discard, s) }()
			return c, nil
		}}
	// A clock that runs ahead: the attempts' bucket (30 a second) is no
	// part of this.
	var ticks atomic.Int64
	start := time.Now()
	h.lim.now = func() time.Time { return start.Add(time.Duration(ticks.Add(1)) * time.Second) }
	url := serveNaive(t, h)

	// A client that keeps to one connection whatever the server's limit of
	// streams: past it a request waits.
	var dials atomic.Int32
	tlsConf := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402: the test's own server
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{"h2"},
	}
	tr := &http.Transport{ForceAttemptHTTP2: true, HTTP2: &http.HTTP2Config{StrictMaxConcurrentRequests: true},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.Add(1)
			d := tls.Dialer{Config: tlsConf}
			return d.DialContext(ctx, network, addr)
		}}
	t.Cleanup(tr.CloseIdleConnections)
	// Every request ends with the test, answered or not: a tunnel left open
	// would hold the server's Close.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	opened := 0
	open := func(target string) *http.Response {
		t.Helper()
		pr, pw := io.Pipe()
		t.Cleanup(func() { pw.Close() })
		req, err := http.NewRequestWithContext(ctx, http.MethodConnect, url, pr)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = target
		req.Header.Set("Padding", paddingHeader())
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("niko:pw")))
		type result struct {
			resp *http.Response
			err  error
		}
		done := make(chan result, 1)
		go func() {
			resp, err := tr.RoundTrip(req)
			done <- result{resp, err}
		}()
		select {
		case r := <-done:
			if r.err != nil {
				t.Fatalf("request %d to %s: %v", opened+1, target, r.err)
			}
			t.Cleanup(func() { r.resp.Body.Close() })
			opened++
			return r.resp
		case <-time.After(20 * time.Second):
			t.Fatalf("request %d to %s got no answer: it waits for a stream of the connection's", opened+1, target)
			return nil
		}
	}
	for _, of := range []struct {
		target string
		n      int
	}{{"192.0.2.1:443", tcpPerUser}, {UoTName + ":0", uotPerUser}, {ICMPName + ":0", icmpPerUser}} {
		for range of.n {
			if resp := open(of.target); resp.StatusCode != http.StatusOK {
				t.Fatalf("request %d to %s: %s", opened, of.target, resp.Status)
			}
		}
	}
	if resp := open("192.0.2.1:443"); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("past the user's limit: %s, not 429", resp.Status)
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("the client made %d connections, not one", n)
	}
	if MaxStreams <= tcpPerUser+uotPerUser+icmpPerUser {
		t.Fatalf("a connection's %d streams leave no room past the user's %d", MaxStreams, tcpPerUser+uotPerUser+icmpPerUser)
	}
}
