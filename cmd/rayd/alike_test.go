package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/arngory/raycontrol/internal/naive"
	"github.com/arngory/raycontrol/internal/site"
)

// threeNames serves the three names of the node's address in process, as
// rayd serves them: naive (rayd naive with the site's answer), the site
// (rayd site) and DoH (rayd, its strangers given the site's answer too),
// for a site answering mode; it gives each one's address.
func threeNames(t *testing.T, mode string) map[string]string {
	t.Helper()
	ns, cert := naiveTest(t, sink)
	answer, err := site.Responder(mode, "")
	if err != nil {
		t.Fatal(err)
	}
	ns.Answer = answer
	log := slog.New(slog.DiscardHandler)
	listen := func() net.Listener {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return ln
	}
	names := map[string]string{"naive": serveNaiveH2(t, ns, cert)}
	ctx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	sln := listen()
	go func() { _ = site.ServeCertificates(ctx, sln, answer, fixedCert(cert), log) }()
	names["site"] = sln.Addr().String()
	dln := listen()
	h := noTokens()
	_, h.Answer = dohAnswer(`{"answer":"` + mode + `"}`)
	dsrv := dohHTTPServer(h, fixedCert(cert), log)
	go func() { _ = dsrv.ServeTLS(dln, "", "") }()
	t.Cleanup(func() { _ = dsrv.Close() })
	names["DoH"] = dln.Addr().String()
	return names
}

// dateLine is the Date of an answer, the one thing in it that is the
// moment's.
var dateLine = regexp.MustCompile(`(?m)^Date: .*\r\n`)

// h1 is what a server answers raw over TLS with ALPN http/1.1: its bytes,
// without the Date.
func h1(t *testing.T, addr, request string) string {
	t.Helper()
	return h1With(t, addr, naiveClientTLS("http/1.1"), request)
}

// h1With is h1 over a handshake of conf.
func h1With(t *testing.T, addr string, conf *tls.Config, request string) string {
	t.Helper()
	c, err := tls.Dial("tcp", addr, conf)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, request); err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(bufio.NewReader(c))
	return dateLine.ReplaceAllString(string(b), "")
}

// h2Answer is a request's answer over HTTP/2: the status, the header
// without Date, the body.
func h2Answer(t *testing.T, tr http.RoundTripper, req *http.Request) string {
	t.Helper()
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return "error " + err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	resp.Header.Del("Date")
	var h []string
	for k, v := range resp.Header {
		h = append(h, k+": "+strings.Join(v, ", "))
	}
	slices.Sort(h)
	return fmt.Sprintf("%s %s %q", resp.Status, h, body)
}

// handshake is how a TLS handshake with conf ends: the version, the
// protocol and the group taken, or the server's alert ("refused remote
// error: tls: ...").
func handshake(addr string, conf *tls.Config) string {
	c, err := tls.Dial("tcp", addr, conf)
	if err != nil {
		return "refused " + err.Error()
	}
	defer c.Close()
	s := c.ConnectionState()
	return fmt.Sprintf("%s %q %s", tls.VersionName(s.Version), s.NegotiatedProtocol, s.CurveID)
}

// The three names past their first frames (TestNamesLookAlike has those):
// whatever one without a password or a token can provoke of them, over
// TLS, HTTP/2 and HTTP/1.1, for each answer of the site's but its pages.
// The handshakes too: since v0.36.1 naive and DoH take what the site
// takes, TLS 1.2 and classical groups as well, and answer a request over
// them as the site does, a CONNECT with the right password too
// (TestPostQuantumOnly; docs/design/traffic.md, "Одно лицо"). Before, they
// refused them and the site did not.
func TestNamesAlikeBeyondFirstFrames(t *testing.T) {
	if (&naive.Server{}).HTTPServer().IdleTimeout != site.IdleTimeout ||
		dohHTTPServer(noTokens(), nil, slog.New(slog.DiscardHandler)).IdleTimeout != site.IdleTimeout {
		t.Fatal("an idle time of its own: the name that closes its idle connections later is told from the others")
	}
	for _, mode := range []string{site.Answer404, site.Answer403} {
		names := threeNames(t, mode)
		tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: naiveClientTLS("h2")}
		t.Cleanup(tr.CloseIdleConnections)
		probes := map[string]func(addr string) string{
			"h2 GET /": func(addr string) string {
				req, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/", nil)
				return h2Answer(t, tr, req)
			},
			"h2 HEAD /index.html": func(addr string) string {
				req, _ := http.NewRequest(http.MethodHead, "https://"+addr+"/index.html", nil)
				return h2Answer(t, tr, req)
			},
			"h2 POST /dns-query/x": func(addr string) string {
				req, _ := http.NewRequest(http.MethodPost, "https://"+addr+"/dns-query/x", strings.NewReader("abc"))
				req.Header.Set("Content-Type", "application/dns-message")
				return h2Answer(t, tr, req)
			},
			"h2 CONNECT with Padding, no password": func(addr string) string {
				req, _ := http.NewRequest(http.MethodConnect, "https://"+addr, http.NoBody)
				req.Host = "192.0.2.1:443"
				req.Header.Set("Padding", naive.PaddingHeader())
				return h2Answer(t, tr, req)
			},
			"h1 GET /": func(addr string) string { return h1(t, addr, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n") },
			"h1 CONNECT": func(addr string) string {
				return h1(t, addr, "CONNECT 192.0.2.1:443 HTTP/1.1\r\nHost: 192.0.2.1:443\r\n\r\n")
			},
			"h1 malformed":        func(addr string) string { return h1(t, addr, "GARBAGE\r\n\r\n") },
			"h1 HTTP/1.0 no Host": func(addr string) string { return h1(t, addr, "GET / HTTP/1.0\r\n\r\n") },
			"TLS 1.3 no ALPN":     func(addr string) string { return handshake(addr, naiveClientTLS()) },
			"TLS 1.3 ALPN h3":     func(addr string) string { return handshake(addr, naiveClientTLS("h3")) },
			"TLS 1.3 ALPN http/1.1, h2": func(addr string) string {
				return handshake(addr, naiveClientTLS("http/1.1", "h2"))
			},
		}
		for probe, conf := range classicalTLS("h2") {
			probes[probe+", handshake"] = func(addr string) string { return handshake(addr, conf) }
			probes[probe+", h2 CONNECT with the password"] = func(addr string) string {
				ctr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: conf}
				defer ctr.CloseIdleConnections()
				req, _ := naiveConnect(context.Background(), t, "https://"+addr, "192.0.2.1:443")
				return h2Answer(t, ctr, req)
			}
			probes[probe+", h1 GET /"] = func(addr string) string {
				c := conf.Clone()
				c.NextProtos = []string{"http/1.1"}
				return h1With(t, addr, c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
			}
		}
		probes["TLS 1.2, ECDHE-ECDSA-AES128-GCM only, handshake"] = func(addr string) string {
			return handshake(addr, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12, //nolint:gosec // G402: a probe
				CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, NextProtos: []string{"h2"}})
		}
		for probe, f := range probes {
			want := f(names["site"])
			if strings.HasSuffix(probe, ", handshake") && strings.HasPrefix(want, "refused") {
				t.Errorf("%s, %s: the site refuses it: %s", mode, probe, want)
			}
			for _, name := range []string{"naive", "DoH"} {
				if got := f(names[name]); got != want {
					t.Errorf("%s, %s: %s is told from the site:\n %s\n %s (the site)", mode, probe, name, got, want)
				}
			}
		}
	}
}

// The QUIC twin (TestQUICNamesLookAlike has the transport parameters and
// SETTINGS): naive-quic and DoH3 answer a stranger alike for each answer
// of the site's, as naive and DoH do over HTTP/2.
func TestQUICNamesAnswerAlike(t *testing.T) {
	for _, mode := range []string{site.Answer404, site.Answer403} {
		ns, cert := naiveTest(t, sink)
		answer, err := site.Responder(mode, "")
		if err != nil {
			t.Fatal(err)
		}
		ns.Answer = answer
		// naive with udp=on (naive-udp-v1): a connect-udp without a
		// password is answered as DoH3 answers it.
		withUDP := naiveUDP(ns, true)
		h := noTokens()
		_, h.Answer = dohAnswer(`{"answer":"` + mode + `"}`)
		got := map[string][]string{}
		for name, srv := range map[string]http.Handler{"naive-quic": ns, "DoH3": h} {
			o := quicOptions{}
			if name == "naive-quic" {
				o = withUDP
			}
			addr := serveQUIC(t, srv, cert, o)
			tr := &http3.Transport{TLSClientConfig: naiveClientTLS(), QUICConfig: &quic.Config{MaxIdleTimeout: 30 * time.Second, EnableDatagrams: true},
				EnableDatagrams: true,
				Dial: func(ctx context.Context, _ string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
					return quic.DialAddrEarly(ctx, addr, tlsConf, conf)
				}}
			get, _ := http.NewRequest(http.MethodGet, "https://naive.test/dns-query/x?dns=AAAB", nil)
			connect, _ := http.NewRequest(http.MethodConnect, "https://naive.test", http.NoBody)
			connect.Host = "192.0.2.1:443"
			connect.Header.Set("Padding", naive.PaddingHeader())
			reqs := []*http.Request{get, connect}
			for _, pw := range []string{"", "wrong"} {
				udp, _ := http.NewRequest(http.MethodConnect, "https://naive.test/.well-known/masque/udp/%2A/%2A/", http.NoBody)
				udp.Proto = naive.ConnectUDP
				udp.Header.Set("Padding", naive.PaddingHeader())
				udp.Header.Set(naive.UDPHeader, "1")
				udp.Header.Set("Capsule-Protocol", "?1")
				if pw != "" {
					udp.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("niko:"+pw)))
				}
				reqs = append(reqs, udp)
			}
			for _, req := range reqs {
				got[name] = append(got[name], h2Answer(t, tr, req))
			}
			_ = tr.Close()
		}
		if !slices.Equal(got["naive-quic"], got["DoH3"]) {
			t.Errorf("%s: naive-quic is told from DoH3:\n %q\n %q", mode, got["naive-quic"], got["DoH3"])
		}
	}
}

// DoH answers strangers as its site does, but with an empty 404 for a site
// of pages, as naive does (internal/deploy).
func TestDoHAnswer(t *testing.T) {
	for settings, want := range map[string]string{`{"answer":"403"}`: "403", `{"answer":"silent"}`: "silent", `{"answer":"pages"}`: "404",
		`{}`: "404", `{"answer":"nonsense"}`: "404", `not json`: "404"} {
		if mode, h := dohAnswer(settings); mode != want || h == nil {
			t.Errorf("%s: %q, want %q", settings, mode, want)
		}
	}
}
