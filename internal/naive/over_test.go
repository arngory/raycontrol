package naive

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/arngory/raycontrol/internal/h3serve"
)

// The transports a behaviour of naive is tested over: HTTP/2 as the
// service serves it (Server.HTTPServer, behind the front's TCP), and
// HTTP/3 as rayd naive serves it (h3serve.Serve with rayd's numbers,
// cmd/rayd's serveHTTP3), on a UDP socket of loopback in place of the
// front's datagrams.
var protos = []string{"h2", "h3"}

// overProtos runs f once over each transport, as a subtest of its name:
// the servers f starts (serveOver, and tunnelServer, uotServer,
// icmpServer, limitServer, ackServer over it) serve over that one.
func overProtos(t *testing.T, f func(t *testing.T)) {
	t.Helper()
	for _, proto := range protos {
		t.Run(proto, f)
	}
}

// protoOf is the transport of t: the one overProtos named it after, or
// HTTP/2 for a test that runs over HTTP/2 only.
func protoOf(t *testing.T) string {
	t.Helper()
	for name := t.Name(); name != ""; {
		i := strings.LastIndexByte(name, '/')
		if i < 0 {
			break
		}
		if p := name[i+1:]; slices.Contains(protos, p) {
			return p
		}
		name = name[:i]
	}
	return "h2"
}

// h3Options are rayd's (cmd/rayd h3Options) but the idle time, whose
// number is render's, which naive's tests cannot import.
func h3Options() h3serve.Options {
	return h3serve.Options{Idle: 2 * time.Minute, MaxStreams: MaxStreams, PendingStreams: PendingStreams, MaxHeaderBytes: MaxHeaderBytes}
}

// window, when not 0, is a client's receive window for a stream and for a
// connection: a client that does not read stops the server's writes at
// it.
type clientOpts struct{ window int }

// serveOver serves h over the test's transport (protoOf) and gives the URL
// of the service and a client of it.
func serveOver(t *testing.T, h *Server, opts ...clientOpts) (string, http.RoundTripper) {
	t.Helper()
	var o clientOpts
	if len(opts) > 0 {
		o = opts[0]
	}
	switch proto := protoOf(t); proto {
	case "h2":
		tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: testClientTLS("h2")}
		if o.window > 0 {
			tr.HTTP2 = &http.HTTP2Config{MaxReceiveBufferPerStream: o.window, MaxReceiveBufferPerConnection: o.window}
		}
		t.Cleanup(tr.CloseIdleConnections)
		return serveNaive(t, h), tr
	case "h3":
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		cert := testCert(t)
		ctx, stop := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- h3serve.Serve(ctx, pc, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }, h, h3Options())
		}()
		addr := pc.LocalAddr().String()
		qc := &quic.Config{MaxIdleTimeout: 30 * time.Second}
		if o.window > 0 {
			w := uint64(o.window) //nolint:gosec // G115: a test's window
			qc.InitialStreamReceiveWindow, qc.MaxStreamReceiveWindow = w, w
			qc.InitialConnectionReceiveWindow, qc.MaxConnectionReceiveWindow = w, w
		}
		tr := &http3.Transport{TLSClientConfig: testClientTLS(), QUICConfig: qc,
			Dial: func(ctx context.Context, _ string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
				return quic.DialAddrEarly(ctx, addr, tlsConf, conf)
			}}
		t.Cleanup(func() {
			_ = tr.Close()
			stop()
			if err := <-done; err != nil {
				t.Errorf("h3serve.Serve: %v", err)
			}
		})
		return "https://naive.test", tr
	default:
		t.Fatalf("no transport %q", proto)
	}
	return "", nil
}

// resetBeforeAnswer is the 200 of a stream that the server reset right
// after it: over HTTP/3 the reset may overtake the answer (RESET_STREAM
// drops what the stream has not delivered, spec/naive-uot-v1.md §4), and
// the client sees the request fail, not a 200 and a read that fails. The
// body gives the error. Only the server's own reset is that (serverReset);
// any other error fails the test, and so does any error over HTTP/2,
// where the answer always comes first. Only tests that expect the stream
// reset take it (mayReset).
func resetBeforeAnswer(t *testing.T, err error) *http.Response {
	t.Helper()
	if protoOf(t) != "h3" || !serverReset(t, err) {
		t.Fatal(err)
	}
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK (reset before it)", Body: io.NopCloser(iotest.ErrReader(err))}
}

// serverReset reports whether err is a stream that the server reset as
// naive resets one (http.ErrAbortHandler): H3_INTERNAL_ERROR from the
// peer over HTTP/3, what http3 sends for a handler that aborts, and
// INTERNAL_ERROR over HTTP/2 (net/http's handlerPanicRST), which Go's
// client says only in the error's text.
func serverReset(t *testing.T, err error) bool {
	t.Helper()
	if err == nil {
		return false
	}
	if protoOf(t) != "h3" {
		return strings.Contains(err.Error(), "INTERNAL_ERROR; received from peer")
	}
	var h3err *http3.Error
	return errors.As(err, &h3err) && h3err.Remote && h3err.ErrorCode == http3.ErrCodeInternalError
}

// roundTrip is tr.RoundTrip(req). Given mayReset(true), for a request that
// the server may reset right after its answer, an HTTP/3 stream that the
// server reset before its answer came is the 200 of resetBeforeAnswer.
func roundTrip(t *testing.T, tr http.RoundTripper, req *http.Request, r ...mayReset) (*http.Response, error) {
	t.Helper()
	resp, err := tr.RoundTrip(req)
	var h3err *http3.Error
	if err != nil && len(r) > 0 && bool(r[0]) && protoOf(t) == "h3" && errors.As(err, &h3err) {
		return resetBeforeAnswer(t, err), nil
	}
	return resp, err
}

func testClientTLS(alpn ...string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402: the test's own server
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768}, NextProtos: alpn,
	}
}

var testCertOnce = sync.OnceValues(func() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "naive.test"}, DNSNames: []string{"naive.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
})

// testCert is a self-signed certificate for the HTTP/3 server (httptest
// makes HTTP/2's).
func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	c, err := testCertOnce()
	if err != nil {
		t.Fatal(err)
	}
	return c
}
