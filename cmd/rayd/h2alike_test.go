package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/arngory/raycontrol/internal/doh"
	"github.com/arngory/raycontrol/internal/site"
)

// noTokens is a DoH handler that knows no token: every request is a
// stranger's.
func noTokens() *doh.Handler {
	return &doh.Handler{Tokens: func(context.Context) (map[string]bool, error) { return map[string]bool{}, nil }}
}

// firstFrames are the bytes of the frames an HTTP/2 server sends a client
// that only completed the handshake and sent its preface, before any
// request: SETTINGS and the connection's WINDOW_UPDATE. What any prober
// sees.
func firstFrames(t *testing.T, addr string) []byte {
	t.Helper()
	c, err := tls.Dial("tcp", addr, naiveClientTLS("h2"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	var raw bytes.Buffer
	fr := http2.NewFramer(c, io.TeeReader(c, &raw))
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	var out []byte
	for kept := 0; kept < 2; {
		from := raw.Len()
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if s, ok := f.(*http2.SettingsFrame); ok && s.IsAck() {
			continue
		}
		out = append(out, raw.Bytes()[from:]...)
		kept++
	}
	return out
}

// The names of the node's address are not told from each other over
// HTTP/2 by one who has no password and no token: naive, the site and DoH
// send the same first frames, byte for byte, and give a request they do
// not know as their own (here with 20 KiB of header) the same answer.
// Nothing in the frames is a number of the node's own but the upload
// windows, which all three have (site.HTTPServer).
func TestNamesLookAlike(t *testing.T) {
	ns, cert := naiveTest(t, sink)
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

	answer, err := site.Responder(site.Answer404, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	sln := listen()
	go func() { _ = site.ServeCertificates(ctx, sln, answer, fixedCert(cert), log) }()
	names["the site"] = sln.Addr().String()

	dln := listen()
	dsrv := dohHTTPServer(noTokens(), fixedCert(cert), log)
	go func() { _ = dsrv.ServeTLS(dln, "", "") }()
	t.Cleanup(func() { _ = dsrv.Close() })
	names["DoH"] = dln.Addr().String()

	want := firstFrames(t, names["the site"])
	fr := http2.NewFramer(nil, bytes.NewReader(want))
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	settings := map[http2.SettingID]uint32{}
	_ = f.(*http2.SettingsFrame).ForeachSetting(func(x http2.Setting) error { settings[x.ID] = x.Val; return nil })
	if settings[http2.SettingMaxConcurrentStreams] != 250 || settings[http2.SettingMaxHeaderListSize] != http.DefaultMaxHeaderBytes+320 ||
		settings[http2.SettingInitialWindowSize] != site.StreamWindow {
		t.Errorf("the site's SETTINGS are %v: want Go's own streams and header, and the node's window", settings)
	}
	tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: naiveClientTLS("h2")}
	t.Cleanup(tr.CloseIdleConnections)
	for name, addr := range names {
		if got := firstFrames(t, addr); !bytes.Equal(got, want) {
			t.Errorf("%s is told from the site by its first frames:\n %x\n %x (the site)", name, got, want)
		}
		req, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/", nil)
		req.Header.Set("Cookie", strings.Repeat("x", 20<<10))
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Errorf("%s: a GET with a 20 KiB cookie: %v", name, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound || len(body) != 0 {
			t.Errorf("%s: a GET with a 20 KiB cookie: %s and %d bytes, want the site's empty 404", name, resp.Status, len(body))
		}
	}
}
