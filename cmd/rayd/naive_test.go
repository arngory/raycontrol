package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/arngory/raycontrol/internal/naive"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/site"
)

const naiveTestPassword = "secret-one"

// naiveTest is a naive server for the user of naiveTestPassword whose
// destinations are dial's, and a certificate for it.
func naiveTest(t *testing.T, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (*naive.Server, tls.Certificate) {
	t.Helper()
	users := filepath.Join(t.TempDir(), "users.json")
	b, _ := json.Marshal(map[string]string{naive.HashPassword(naiveTestPassword): "u1-ab12"})
	if err := os.WriteFile(users, b, 0o600); err != nil {
		t.Fatal(err)
	}
	answer, err := site.Responder(site.Answer404, "")
	if err != nil {
		t.Fatal(err)
	}
	keyDER, certDER, err := provision.SelfSigned("naive.test")
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		t.Fatal(err)
	}
	ns := &naive.Server{Users: &naive.Users{Path: users}, Answer: answer, Dial: dial, Log: slog.New(slog.DiscardHandler)}
	return ns, tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}
}

// sink is a destination that takes what it is sent and says nothing.
func sink(context.Context, string, string) (net.Conn, error) {
	c, s := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, s) }()
	return c, nil
}

func naiveClientTLS(protos ...string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402: the test's own server
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768}, NextProtos: protos,
	}
}

// naiveConnect is a CONNECT to target as the test's user; cancel ends it.
func naiveConnect(ctx context.Context, t *testing.T, url, target string) (*http.Request, *io.PipeWriter) {
	t.Helper()
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.Close() })
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, url, pr)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = target
	req.Header.Set("Padding", naive.PaddingHeader())
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("niko:"+naiveTestPassword)))
	return req, pw
}

// serveNaiveH2 serves ns over HTTP/2 as cmdNaive does, on loopback.
func serveNaiveH2(t *testing.T, ns *naive.Server, cert tls.Certificate) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := naiveHTTPServer(ns, fixedCert(cert), slog.New(slog.DiscardHandler))
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// serveNaiveH3 serves ns over HTTP/3 as cmdNaive does, on a UDP socket of
// loopback in place of the front's datagrams; the transport reaches it.
func serveNaiveH3(t *testing.T, ns *naive.Server, cert tls.Certificate, o quicOptions) *http3.Transport {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveHTTP3(ctx, pc, fixedCert(cert), ns, o) }()
	addr := pc.LocalAddr().String()
	tr := &http3.Transport{TLSClientConfig: naiveClientTLS(), QUICConfig: &quic.Config{MaxIdleTimeout: 30 * time.Second},
		Dial: func(ctx context.Context, _ string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
			return quic.DialAddrEarly(ctx, addr, tlsConf, conf)
		}}
	t.Cleanup(func() {
		_ = tr.Close()
		stop()
		if err := <-done; err != nil {
			t.Errorf("serveHTTP3: %v", err)
		}
	})
	return tr
}

// Over HTTP/3 a header past naive.MaxHeaderBytes is not the handler's to
// read: nothing of it is kept, and nothing is dialled. Over HTTP/2 the
// limit is Go's own, as the site's is (TestNamesLookAlike), and the same
// request is served.
func TestNaiveHeaderLimit(t *testing.T) {
	var dials atomic.Int32
	ns, cert := naiveTest(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return sink(ctx, network, addr)
	})
	h2 := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: naiveClientTLS("h2")}
	t.Cleanup(h2.CloseIdleConnections)
	h3 := serveNaiveH3(t, ns, cert, quicOptions{})
	for _, c := range []struct {
		name   string
		rt     http.RoundTripper
		url    string
		served bool
	}{{"h2", h2, "https://" + serveNaiveH2(t, ns, cert), true}, {"h3", h3, "https://naive.test", false}} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		req, _ := naiveConnect(ctx, t, c.url, "192.0.2.1:443")
		resp, err := c.rt.RoundTrip(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: a CONNECT: %v %v", c.name, resp, err)
		}
		resp.Body.Close()
		req, _ = naiveConnect(ctx, t, c.url, "192.0.2.1:443")
		req.Header.Set("X-Filler", strings.Repeat("x", 2*naive.MaxHeaderBytes))
		resp, err = c.rt.RoundTrip(req)
		served := err == nil && resp.StatusCode == http.StatusOK
		if err == nil {
			resp.Body.Close()
		}
		if served != c.served {
			t.Fatalf("%s: a CONNECT with a header of %d bytes: served %v (%v)", c.name, 2*naive.MaxHeaderBytes, served, err)
		}
		cancel()
	}
	if n := dials.Load(); n != 3 {
		t.Fatalf("%d dials, want two over HTTP/2 and one over HTTP/3", n)
	}
}

// A QUIC connection carries all a user may hold: more tunnels at once than
// quic-go's default of 100 streams, and more than may be without a header
// at once (naive.PendingStreams), none of them waiting for a stream.
func TestNaiveHTTP3Streams(t *testing.T) {
	if got := quicConfig().MaxIncomingStreams; got != naive.MaxStreams {
		t.Fatalf("MaxIncomingStreams %d, want %d", got, naive.MaxStreams)
	}
	ns, cert := naiveTest(t, sink)
	tr := serveNaiveH3(t, ns, cert, quicOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// Under the burst of TCP attempts (600): the limits refuse none.
	const tunnels = 300
	type result struct {
		resp *http.Response
		err  error
	}
	for i := range tunnels {
		req, _ := naiveConnect(ctx, t, "https://naive.test", "192.0.2.1:443")
		done := make(chan result, 1)
		go func() {
			resp, err := tr.RoundTrip(req)
			done <- result{resp, err}
		}()
		select {
		case r := <-done:
			if r.err != nil || r.resp.StatusCode != http.StatusOK {
				t.Fatalf("tunnel %d: %v %v", i+1, r.resp, r.err)
			}
			t.Cleanup(func() { r.resp.Body.Close() })
		case <-time.After(20 * time.Second):
			t.Fatalf("tunnel %d got no answer: it waits for a stream of the connection's", i+1)
		}
	}
}

// rayd's QUIC servers give a silent connection up before the front forgets
// its flow (render.FrontUDPIdle, which render's own test holds above
// render.QUICIdle), and keep none alive themselves.
func TestQUICIdleUnderFront(t *testing.T) {
	c := quicConfig() // naive-quic's and DoH3's
	if c.MaxIdleTimeout != render.QUICIdle || c.MaxIdleTimeout >= render.FrontUDPIdle {
		t.Errorf("QUIC idle %v, the front's flow idle %v", c.MaxIdleTimeout, render.FrontUDPIdle)
	}
	if c.KeepAlivePeriod != 0 {
		t.Errorf("the server keeps connections alive every %v", c.KeepAlivePeriod)
	}
}

// Over HTTP/3 as over HTTP/2 (naive's TestDestinationEnd): a destination
// that breaks off resets the client's stream, one that ends its side ends
// it.
func TestNaiveHTTP3DestinationEnd(t *testing.T) {
	var d net.Dialer
	ns, cert := naiveTest(t, d.DialContext)
	tr := serveNaiveH3(t, ns, cert, quicOptions{})
	for name, reset := range map[string]bool{"reset": true, "end": false} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		told := make(chan struct{})
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("hello"))
			<-told
			if reset {
				_ = c.(*net.TCPConn).SetLinger(0) // close sends a RST
			}
			c.Close()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		req, pw := naiveConnect(ctx, t, "https://naive.test", ln.Addr().String())
		resp, err := tr.RoundTrip(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: CONNECT: %v %v", name, resp, err)
		}
		s := naive.ClientStream(resp.Body, pw)
		got := make([]byte, 5)
		if _, err := io.ReadFull(s, got); err != nil || string(got) != "hello" {
			t.Fatalf("%s: read %q %v", name, got, err)
		}
		close(told)
		rest, err := io.ReadAll(s)
		switch {
		case len(rest) != 0:
			t.Errorf("%s: %q after the destination was done", name, rest)
		case reset && err == nil:
			t.Errorf("%s: the stream ended cleanly: the client cannot tell a reset from the destination's end", name)
		case !reset && err != nil:
			t.Errorf("%s: the stream failed with %v after a clean end", name, err)
		}
		resp.Body.Close()
		cancel()
	}
}

// The honest connect over HTTP/3 as over HTTP/2 (naive's TestAckConnect):
// with niko-ack: 1 the answer comes after the dial, 200 with the early
// bytes passed on first, or 502 and the reason.
func TestNaiveHTTP3AckConnect(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	gone, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := gone.Addr().String()
	gone.Close()
	var dialed atomic.Int32
	var d net.Dialer
	ns, cert := naiveTest(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		defer dialed.Add(1)
		select {
		case <-time.After(200 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return d.DialContext(ctx, network, addr)
	})
	tr := serveNaiveH3(t, ns, cert, quicOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, pw := naiveConnect(ctx, t, "https://naive.test", echo.Addr().String())
	req.Header.Set(naive.AckHeader, "1")
	early := []byte(strings.Repeat("early bytes ", 3000))
	s := naive.ClientStream(nil, pw)
	go func() { _, _ = s.Write(early) }()
	resp, err := tr.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK || resp.Header.Get("Padding") == "" {
		t.Fatalf("a live destination: %v %v", resp, err)
	}
	defer resp.Body.Close()
	if dialed.Load() != 1 {
		t.Fatal("the 200 came before the dial was done")
	}
	got := make([]byte, len(early))
	if _, err := io.ReadFull(naive.ClientStream(resp.Body, nil), got); err != nil || string(got) != string(early) {
		t.Fatalf("the early bytes came back changed (%v)", err)
	}

	req, _ = naiveConnect(ctx, t, "https://naive.test", dead)
	req.Header.Set(naive.AckHeader, "1")
	resp, err = tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || resp.Header.Get(naive.AckHeader) != "refused" || len(body) != 0 || err != nil {
		t.Fatalf("a closed port: %s, niko-ack %q, %d bytes after it (%v)", resp.Status, resp.Header.Get(naive.AckHeader), len(body), err)
	}
}
