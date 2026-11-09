package naive

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/site"
)

// limitServer is a naive server over HTTP/2 whose dials go to dial, and a
// CONNECT to it with a password ("" none).
func limitServer(t *testing.T, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (*Server, func(password, target string) (*http.Response, error)) {
	t.Helper()
	users := filepath.Join(t.TempDir(), "users.json")
	writeUsersNamed(t, users, map[string]string{"pw": "u5-ab12", "other": "u6"})
	answer, _ := site.Responder(site.Answer404, "")
	h := &Server{Users: &Users{Path: users}, Answer: answer, Dial: dial, Log: slog.New(slog.DiscardHandler)}
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402: the test's own server
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{"h2"},
	}}
	t.Cleanup(tr.CloseIdleConnections)
	return h, func(password, target string) (*http.Response, error) {
		pr, pw := io.Pipe()
		t.Cleanup(func() { pw.Close() })
		req, err := http.NewRequest(http.MethodConnect, srv.URL, pr)
		if err != nil {
			return nil, err
		}
		req.Host = target
		req.Header.Set("Padding", paddingHeader())
		if password != "" {
			req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("niko:"+password)))
		}
		resp, err := tr.RoundTrip(req)
		if err == nil {
			t.Cleanup(func() { resp.Body.Close() })
		}
		return resp, err
	}
}

func writeUsersNamed(t *testing.T, path string, byPassword map[string]string) {
	t.Helper()
	m := map[string]string{}
	for pw, name := range byPassword {
		m[HashPassword(pw)] = name
	}
	if err := writeJSON(path, m); err != nil {
		t.Fatal(err)
	}
}

// The 1025th CONNECT of a user gets 429 before any 200; another user and
// an unauthorised request do not: the latter still gets the site's answer.
func TestNaive429(t *testing.T) {
	dials := atomic.Int32{}
	h, connect := limitServer(t, func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		c, s := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, s) }()
		return c, nil
	})
	// The user's 1024 places taken (as 1024 tunnels would).
	for range tcpPerUser {
		h.lim.mu.Lock()
		h.lim.userLocked("u5", time.Now()).tcp++
		h.lim.mu.Unlock()
	}
	resp, err := connect("pw", "192.0.2.1:443")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusTooManyRequests || dials.Load() != 0 {
		t.Fatalf("over the limit: %s, %d dials", resp.Status, dials.Load())
	}
	if resp, err := connect("other", "192.0.2.1:443"); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("another user: %v %v", resp, err)
	}
	if resp, err := connect("wrong", "192.0.2.1:443"); err != nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthorised: %v %v", resp, err)
	}
	if got := h.Refused()["u5"][refusedTCP]; got != 1 {
		t.Fatalf("counted %d", got)
	}
	// Off: no limit.
	h.SetConnLimit(false)
	if resp, err := connect("pw", "192.0.2.1:443"); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("off: %v %v", resp, err)
	}
}

// A dial to a silent address times out and charges the failed dials; in
// debt the next CONNECT gets 429 without a dial. One that cannot route
// (ENETUNREACH) is not charged.
func TestNaiveFailedDebt(t *testing.T) {
	var silent atomic.Bool // a silent address: the dial times out
	dials := atomic.Int32{}
	h, connect := limitServer(t, func(ctx context.Context, _, _ string) (net.Conn, error) {
		dials.Add(1)
		if !silent.Load() {
			return nil, &net.OpError{Op: "dial", Err: syscall.ENETUNREACH}
		}
		// naive's own deadline, shorter here than its 10 s.
		ctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
		defer cancel()
		<-ctx.Done()
		return nil, &net.OpError{Op: "dial", Err: ctx.Err()}
	})
	for range failBurst + 5 {
		if _, err := connect("pw", "192.0.2.1:443"); err != nil {
			t.Fatal(err)
		}
	}
	level := func() float64 {
		h.lim.mu.Lock()
		defer h.lim.mu.Unlock()
		return h.lim.users["u5"].failed.level(time.Now(), failRate, failBurst)
	}
	if v := level(); v < failBurst-1 {
		t.Fatalf("ENETUNREACH charged: %v left", v)
	}
	silent.Store(true)
	h.lim.mu.Lock()
	h.lim.users["u5"].failed = bucket{0, time.Now()}
	h.lim.mu.Unlock()
	if _, err := connect("pw", "192.0.2.1:443"); err != nil {
		t.Fatal(err)
	}
	// The 200 comes before the dial: the charge follows it.
	eventually(t, "a timeout not charged", func() bool { return level() < 0 })
	before := dials.Load()
	resp, err := connect("pw", "192.0.2.1:443")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusTooManyRequests || dials.Load() != before {
		t.Fatalf("in debt: %s, %d dials", resp.Status, dials.Load()-before)
	}
	if got := h.Refused()["u5"][refusedFailed]; got != 1 {
		t.Fatalf("refused failed: %d", got)
	}
}

// A name's lookup takes a token before the 200 when the limits are on (none
// left: 429), and none when they are off.
func TestNaiveLookupToken(t *testing.T) {
	var looked atomic.Int32
	h, connect := limitServer(t, nil)
	h.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		looked.Add(1)
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}
	h.Allow = func(netip.Addr) bool { return false } // no dial: the lookup is what counts
	h.lim.mu.Lock()
	h.lim.userLocked("u5", time.Now()).lookups = bucket{0, time.Now()}
	h.lim.mu.Unlock()
	resp, err := connect("pw", "example.test:443")
	if err != nil || resp.StatusCode != http.StatusTooManyRequests || looked.Load() != 0 {
		t.Fatalf("on, no token: %v %v, %d lookups", resp, err, looked.Load())
	}
	h.SetConnLimit(false)
	resp, err = connect("pw", "example.test:443")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("off: %v %v", resp, err)
	}
	eventually(t, "off: not looked up", func() bool { return looked.Load() == 1 })
	if got := h.Refused()["u5"][refusedLookup]; got != 1 {
		t.Fatalf("lookups refused %d, want the one while on", got)
	}
}

func writeJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// A client that leaves while its CONNECT waits for a token gives its place
// back.
func TestNaiveClientLeavesWaiting(t *testing.T) {
	h, _ := limitServer(t, nil)
	h.lim.mu.Lock()
	u := h.lim.userLocked("u5", time.Now())
	u.attempts = bucket{0.99, time.Now()} // the next token in under a millisecond: it waits
	h.lim.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	h.lim.sleep = func(ctx context.Context, _ time.Duration) error {
		cancel() // the client goes while it waits
		<-ctx.Done()
		return ctx.Err()
	}
	if _, kind := h.lim.tcpStart(ctx, "u5"); kind != refusedRate {
		t.Fatalf("a client gone: %q", kind)
	}
	h.lim.mu.Lock()
	defer h.lim.mu.Unlock()
	if u.tcp != 0 {
		t.Fatalf("places held: %d", u.tcp)
	}
}
