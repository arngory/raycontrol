package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/arngory/raycontrol/internal/doh"
)

// classicalTLS are the handshakes of a client without ML-KEM: TLS 1.2,
// and TLS 1.3 with a classical group only. The site takes them, and since
// v0.36.1 naive and DoH take them as well (site.TLSConfigFor); only TLS
// 1.3 ones go over QUIC.
func classicalTLS(protos ...string) map[string]*tls.Config {
	return map[string]*tls.Config{
		"TLS 1.2": {InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12, NextProtos: protos}, //nolint:gosec // G402: a probe
		"TLS 1.3, X25519 only": {InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, //nolint:gosec // G402: a probe
			CurvePreferences: []tls.CurveID{tls.X25519}, NextProtos: protos},
		"TLS 1.3, P-256 only": {InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, //nolint:gosec // G402: a probe
			CurvePreferences: []tls.CurveID{tls.CurveP256}, NextProtos: protos},
	}
}

// A naive tunnel and a DoH answer go over X25519MLKEM768 only, over HTTP/2
// and HTTP/3: a client without ML-KEM completes the handshake, as the
// site's would, and gets the site's answer for a CONNECT with the right
// password and padding and for a query with a good token; nothing is
// dialled and no query goes upstream. Over X25519MLKEM768 the same
// requests are served. Before v0.36.1 the handshakes failed.
func TestPostQuantumOnly(t *testing.T) {
	var dials atomic.Int64
	ns, cert := naiveTest(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return sink(ctx, network, addr)
	})
	const token = "0000000a-0000-4000-8000-000000000000"
	var asked atomic.Int64
	dh := &doh.Handler{Upstreams: []string{"http://upstream.invalid/dns-query"},
		Tokens: func(context.Context) (map[string]bool, error) { return map[string]bool{token: true}, nil },
		HTTP: &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
			asked.Add(1)
			return nil, fmt.Errorf("no upstream here")
		})}}
	answer := ns.Answer
	dh.Answer = answer
	h2addr := map[string]string{"naive": serveNaiveH2(t, ns, cert)}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dsrv := dohHTTPServer(dh, fixedCert(cert), slog.New(slog.DiscardHandler))
	go func() { _ = dsrv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = dsrv.Close() })
	h2addr["DoH"] = ln.Addr().String()
	h3addr := map[string]string{"naive": serveQUIC(t, ns, cert, quicOptions{}), "DoH": serveQUIC(t, dh, cert, quicOptions{})}

	// What each name answers its own request with: a tunnel's 200 for
	// naive, a 502 for DoH (its upstream fails: the query went there).
	request := func(name, host string) *http.Request {
		if name == "naive" {
			req, _ := naiveConnect(context.Background(), t, "https://"+host, "192.0.2.1:443")
			return req
		}
		query := []byte{0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
		req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/dns-query/"+token+"?dns="+base64.RawURLEncoding.EncodeToString(query), nil)
		return req
	}
	served := map[string]int{"naive": http.StatusOK, "DoH": http.StatusBadGateway}
	status := func(rt http.RoundTripper, req *http.Request) (int, tls.CurveID, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		resp, err := rt.RoundTrip(req.WithContext(ctx))
		if err != nil {
			return 0, 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
		}
		var curve tls.CurveID
		if resp.TLS != nil {
			curve = resp.TLS.CurveID
		}
		return resp.StatusCode, curve, nil
	}
	h3 := func(addr string, conf *tls.Config) *http3.Transport {
		return &http3.Transport{TLSClientConfig: conf, QUICConfig: &quic.Config{MaxIdleTimeout: 30 * time.Second},
			Dial: func(ctx context.Context, _ string, tlsConf *tls.Config, qc *quic.Config) (*quic.Conn, error) {
				return quic.DialAddrEarly(ctx, addr, tlsConf, qc)
			}}
	}
	for _, name := range []string{"naive", "DoH"} {
		for probe, conf := range classicalTLS("h2") {
			tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: conf}
			got, curve, err := status(tr, request(name, h2addr[name]))
			tr.CloseIdleConnections()
			if err != nil || got != http.StatusNotFound || curve == tls.X25519MLKEM768 {
				t.Errorf("%s over h2, %s: %d %v (%v), want the handshake and the site's 404", name, probe, got, curve, err)
			}
			if conf.MaxVersion == tls.VersionTLS12 {
				continue // not over QUIC
			}
			q := conf.Clone()
			q.NextProtos = nil
			tq := h3(h3addr[name], q)
			got, curve, err = status(tq, request(name, "naive.test"))
			_ = tq.Close()
			if err != nil || got != http.StatusNotFound || curve == tls.X25519MLKEM768 {
				t.Errorf("%s over h3, %s: %d %v (%v), want the handshake and the site's 404", name, probe, got, curve, err)
			}
		}
	}
	if n, m := dials.Load(), asked.Load(); n != 0 || m != 0 {
		t.Fatalf("without ML-KEM: %d dials, %d queries upstream", n, m)
	}
	for _, name := range []string{"naive", "DoH"} {
		tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: naiveClientTLS("h2")}
		got, curve, err := status(tr, request(name, h2addr[name]))
		tr.CloseIdleConnections()
		if err != nil || got != served[name] || curve != tls.X25519MLKEM768 {
			t.Errorf("%s over h2, X25519MLKEM768: %d %v (%v), want %d", name, got, curve, err, served[name])
		}
		tq := h3(h3addr[name], naiveClientTLS())
		got, curve, err = status(tq, request(name, "naive.test"))
		_ = tq.Close()
		if err != nil || got != served[name] || curve != tls.X25519MLKEM768 {
			t.Errorf("%s over h3, X25519MLKEM768: %d %v (%v), want %d", name, got, curve, err, served[name])
		}
	}
	if dials.Load() == 0 || asked.Load() == 0 {
		t.Errorf("over X25519MLKEM768: %d dials, %d queries upstream", dials.Load(), asked.Load())
	}
}

// roundTrip is an http.RoundTripper of a func.
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
