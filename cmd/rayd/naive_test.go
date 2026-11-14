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
	"golang.org/x/net/http2"

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

// The HTTP/2 server tells its clients naive's limits of a connection, not
// Go's defaults (250 streams, 1 MiB of header).
func TestNaiveHTTP2Settings(t *testing.T) {
	ns, cert := naiveTest(t, sink)
	c, err := tls.Dial("tcp", serveNaiveH2(t, ns, cert), naiveClientTLS("h2"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(c, c)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	settings := map[http2.SettingID]uint32{}
	for len(settings) == 0 {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if s, ok := f.(*http2.SettingsFrame); ok && !s.IsAck() {
			_ = s.ForeachSetting(func(x http2.Setting) error { settings[x.ID] = x.Val; return nil })
		}
	}
	if got := settings[http2.SettingMaxConcurrentStreams]; got != naive.MaxStreams {
		t.Errorf("MAX_CONCURRENT_STREAMS %d, want %d", got, naive.MaxStreams)
	}
	// Go adds 320 bytes to MaxHeaderBytes for the fields' overhead.
	if got := settings[http2.SettingMaxHeaderListSize]; got < naive.MaxHeaderBytes || got > naive.MaxHeaderBytes+1024 {
		t.Errorf("MAX_HEADER_LIST_SIZE %d, want about %d", got, naive.MaxHeaderBytes)
	}
}

// A header past the limit is not the handler's to read, over either
// transport: nothing of it is kept past MaxHeaderBytes.
func TestNaiveHeaderLimit(t *testing.T) {
	var dials atomic.Int32
	ns, cert := naiveTest(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return sink(ctx, network, addr)
	})
	h2 := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: naiveClientTLS("h2")}
	t.Cleanup(h2.CloseIdleConnections)
	h3 := serveNaiveH3(t, ns, cert, naiveQUIC())
	for _, c := range []struct {
		name string
		rt   http.RoundTripper
		url  string
	}{{"h2", h2, "https://" + serveNaiveH2(t, ns, cert)}, {"h3", h3, "https://naive.test"}} {
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
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Fatalf("%s: a CONNECT with a header of %d bytes was served", c.name, 2*naive.MaxHeaderBytes)
			}
		}
		cancel()
	}
	if n := dials.Load(); n != 2 {
		t.Fatalf("%d dials, want one for each transport", n)
	}
}

// A QUIC connection carries all a user may hold, as an HTTP/2 one does
// (naive's TestConnectionCarriesUserLimits): more tunnels at once than
// quic-go's default of 100 streams, none of them waiting for a stream.
func TestNaiveHTTP3Streams(t *testing.T) {
	if got := naiveQUIC().config().MaxIncomingStreams; got != naive.MaxStreams {
		t.Fatalf("MaxIncomingStreams %d, want %d", got, naive.MaxStreams)
	}
	ns, cert := naiveTest(t, sink)
	tr := serveNaiveH3(t, ns, cert, naiveQUIC())
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
	for name, o := range map[string]quicOptions{"naive": naiveQUIC(), "doh3": {}} {
		c := o.config()
		if c.MaxIdleTimeout != render.QUICIdle || c.MaxIdleTimeout >= render.FrontUDPIdle {
			t.Errorf("%s: QUIC idle %v, the front's flow idle %v", name, c.MaxIdleTimeout, render.FrontUDPIdle)
		}
		if c.KeepAlivePeriod != 0 {
			t.Errorf("%s: the server keeps connections alive every %v", name, c.KeepAlivePeriod)
		}
	}
}

// Over HTTP/3 as over HTTP/2 (naive's TestDestinationEnd): a destination
// that breaks off resets the client's stream, one that ends its side ends
// it.
func TestNaiveHTTP3DestinationEnd(t *testing.T) {
	var d net.Dialer
	ns, cert := naiveTest(t, d.DialContext)
	tr := serveNaiveH3(t, ns, cert, naiveQUIC())
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
