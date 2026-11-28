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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/arngory/raycontrol/internal/h3serve"
	"github.com/arngory/raycontrol/internal/site"
)

// A TCP tunnel's throughput over loopback, both ways, over each transport:
// the destination a TCP socket that sends zeros without an end (down) or
// takes all it gets (up), 1 MiB an iteration.
func BenchmarkTunnel(b *testing.B) {
	for _, proto := range protos {
		for _, dir := range []string{"down", "up"} {
			b.Run(proto+"/"+dir, func(b *testing.B) { benchTunnel(b, proto, dir == "up") })
		}
	}
}

func benchTunnel(b *testing.B, proto string, up bool) {
	dest, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer dest.Close()
	go func() {
		for {
			c, err := dest.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if up {
					_, _ = io.Copy(io.Discard, c)
					return
				}
				buf := make([]byte, 64<<10)
				for {
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}()
		}
	}()
	users := filepath.Join(b.TempDir(), "users.json")
	raw, _ := json.Marshal(map[string]string{HashPassword("pw"): "u5"})
	if err := os.WriteFile(users, raw, 0o600); err != nil {
		b.Fatal(err)
	}
	answer, _ := site.Responder(site.Answer404, "")
	var d net.Dialer
	h := &Server{Users: &Users{Path: users}, Answer: answer, Dial: d.DialContext, Log: slog.New(slog.DiscardHandler)}
	url, tr := benchServe(b, h, proto)
	pr, pw := io.Pipe()
	defer pw.Close()
	req, _ := http.NewRequest(http.MethodConnect, url, pr)
	req.Host = dest.Addr().String()
	req.Header.Set("Padding", paddingHeader())
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("niko:pw")))
	resp, err := tr.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		b.Fatal(resp, err)
	}
	defer resp.Body.Close()
	s := ClientStream(resp.Body, pw)
	buf := make([]byte, 1<<20)
	// Past the padded first frames.
	if up {
		_, _ = s.Write(buf[:64<<10])
	} else {
		_, _ = io.ReadFull(s, buf[:64<<10])
	}
	b.SetBytes(int64(len(buf)))
	for b.Loop() {
		if up {
			_, err = s.Write(buf)
		} else {
			_, err = io.ReadFull(s, buf)
		}
		if err != nil {
			b.Fatal(err)
		}
	}
}

// benchServe serves h over proto as serveOver does, for a benchmark.
func benchServe(b *testing.B, h *Server, proto string) (string, http.RoundTripper) {
	cert, err := testCertOnce()
	if err != nil {
		b.Fatal(err)
	}
	if proto == "h2" {
		srv := httptest.NewUnstartedServer(h)
		srv.Config = h.HTTPServer()
		srv.EnableHTTP2 = true
		srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
		srv.StartTLS()
		b.Cleanup(srv.Close)
		tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: testClientTLS("h2")}
		b.Cleanup(tr.CloseIdleConnections)
		return srv.URL, tr
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- h3serve.Serve(ctx, pc, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }, h, h3Options())
	}()
	addr := pc.LocalAddr().String()
	tr := &http3.Transport{TLSClientConfig: testClientTLS(), QUICConfig: &quic.Config{MaxIdleTimeout: 30 * time.Second},
		Dial: func(ctx context.Context, _ string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
			return quic.DialAddrEarly(ctx, addr, tlsConf, conf)
		}}
	b.Cleanup(func() {
		_ = tr.Close()
		stop()
		<-done
	})
	return "https://naive.test", tr
}
