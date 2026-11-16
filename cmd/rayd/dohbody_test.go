package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/arngory/raycontrol/internal/doh"
)

// A DoH POST whose body is shorter than its Content-Length, over HTTP/2
// and HTTP/3, gets 400, as a message too short does, and no empty 200:
// HTTP/2 tells the handler at the stream's end, HTTP/3 (quic-go) ends the
// body with what came. A whole one is answered.
func TestDoHShortBody(t *testing.T) {
	query, answer := bytes.Repeat([]byte{1}, 20), bytes.Repeat([]byte{2}, 30)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, _ := io.ReadAll(r.Body); !bytes.Equal(b, query) {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		w.Write(answer)
	}))
	defer upstream.Close()
	const tok = "0000000a-0000-4000-8000-000000000000"
	h := &doh.Handler{Upstreams: []string{upstream.URL},
		Tokens: func(context.Context) (map[string]bool, error) { return map[string]bool{tok: true}, nil }}
	_, cert := naiveTest(t, sink)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := dohHTTPServer(h, fixedCert(cert), slog.New(slog.DiscardHandler))
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer srv.Close()
	h2 := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: naiveClientTLS("h2")}
	defer h2.CloseIdleConnections()
	h3addr := serveQUIC(t, h, cert, quicOptions{})
	h3 := &http3.Transport{TLSClientConfig: naiveClientTLS(), QUICConfig: &quic.Config{MaxIdleTimeout: 30 * time.Second},
		Dial: func(ctx context.Context, _ string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
			return quic.DialAddrEarly(ctx, h3addr, tlsConf, conf)
		}}
	defer h3.Close()

	for proto, c := range map[string]struct {
		rt   http.RoundTripper
		host string
	}{"h2": {h2, ln.Addr().String()}, "h3": {h3, "doh.test"}} {
		for _, p := range []struct {
			name   string
			body   []byte
			length int64
			status int
		}{
			{"whole", query, int64(len(query)), http.StatusOK},
			{"a message, its length more", query, int64(len(query)) + 10, http.StatusBadRequest},
			{"less than a message", query[:5], int64(len(query)), http.StatusBadRequest},
		} {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+c.host+"/dns-query/"+tok, bytes.NewReader(p.body))
			req.Header.Set("Content-Type", "application/dns-message")
			req.ContentLength = p.length
			resp, err := c.rt.RoundTrip(req)
			if err != nil {
				cancel()
				t.Errorf("%s, %s: %v", proto, p.name, err)
				continue
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			cancel()
			if resp.StatusCode != p.status || p.status == http.StatusOK && !bytes.Equal(b, answer) {
				t.Errorf("%s, %s: %s %q, want %d", proto, p.name, resp.Status, b, p.status)
			}
		}
	}
}
