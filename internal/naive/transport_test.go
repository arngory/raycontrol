package naive

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

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

// headers sends a request's HEADERS on stream, in as many frames as it
// takes.
func (p *h2Peer) headers(t *testing.T, stream uint32, end bool, fields ...[2]string) {
	t.Helper()
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, f := range fields {
		_ = enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	p.wr.Lock()
	defer p.wr.Unlock()
	b := block.Bytes()
	first := true
	for first || len(b) > 0 {
		chunk := b[:min(len(b), 16<<10)]
		b = b[len(chunk):]
		var err error
		if first {
			err = p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: chunk, EndHeaders: len(b) == 0, EndStream: end})
		} else {
			err = p.fr.WriteContinuation(stream, len(b) == 0, chunk)
		}
		if err != nil {
			t.Fatal(err)
		}
		first = false
	}
}

// firstFrames are the frames a server sends a client that only completed
// the handshake and sent its preface: what any prober sees.
func firstFrames(t *testing.T, url string) string {
	t.Helper()
	c, err := tls.Dial("tcp", strings.TrimPrefix(url, "https://"), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402: the test's own server
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, http2.ClientPreface)
	fr := http2.NewFramer(c, c)
	_ = fr.WriteSettings()
	var out []string
	for len(out) < 2 {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				continue
			}
			var s []string
			_ = f.ForeachSetting(func(x http2.Setting) error { s = append(s, fmt.Sprintf("%v=%d", x.ID, x.Val)); return nil })
			out = append(out, "SETTINGS["+strings.Join(s, " ")+"]")
		case *http2.WindowUpdateFrame:
			out = append(out, fmt.Sprintf("WINDOW_UPDATE(stream %d, +%d)", f.StreamID, f.Increment))
		}
	}
	return strings.Join(out, " ")
}

// Without a password the naive name is not told from the site's name on
// the same address: both are the server site.HTTPServer makes, so the
// frames a client gets first are the same, and a request naive does not
// know as its own (here with 20 KiB of header, which a limit of naive's own
// once refused) gets the site's answer from both. The number of streams
// and the header's limit are Go's, not the node's.
func TestNaiveNameLooksLikeTheSite(t *testing.T) {
	users := filepath.Join(t.TempDir(), "users.json")
	writeUsersNamed(t, users, map[string]string{"pw": "u5-ab12"})
	answer, _ := site.Responder(site.Answer404, "")
	h := &Server{Users: &Users{Path: users}, Answer: answer, Log: slog.New(slog.DiscardHandler)}
	naiveURL := serveNaive(t, h)
	// The site's server, as site.ServeCertificates makes it.
	theSite := httptest.NewUnstartedServer(answer)
	theSite.Config = site.HTTPServer(answer, site.IdleTimeout)
	theSite.EnableHTTP2 = true
	theSite.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
	theSite.StartTLS()
	t.Cleanup(theSite.Close)

	n, s := firstFrames(t, naiveURL), firstFrames(t, theSite.URL)
	if n != s {
		t.Errorf("the first frames tell the naive name from the site's:\n naive %s\n site  %s", n, s)
	}
	stock := fmt.Sprintf("MAX_CONCURRENT_STREAMS=250 MAX_HEADER_LIST_SIZE=%d", http.DefaultMaxHeaderBytes+320)
	if !strings.Contains(n, stock) || !strings.Contains(n, fmt.Sprintf("INITIAL_WINDOW_SIZE=%d", site.StreamWindow)) {
		t.Errorf("naive's SETTINGS are %s; want Go's own (%s) and the node's window", n, stock)
	}
	get := func(url string) string {
		p := newH2Peer(t, url)
		p.headers(t, 1, true, [2]string{":method", "GET"}, [2]string{":scheme", "https"}, [2]string{":path", "/"},
			[2]string{":authority", "example.com"}, [2]string{"cookie", strings.Repeat("x", 20<<10)})
		eventually(t, "no answer", func() bool {
			p.mu.Lock()
			defer p.mu.Unlock()
			return p.status[1] != "" || p.ended != ""
		})
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.status[1] + " " + p.ended
	}
	if gn, gs := get(naiveURL), get(theSite.URL); gn != gs || gn != "404 " {
		t.Errorf("a GET with a 20 KiB cookie and no password: the naive name answers %q, the site's %q", gn, gs)
	}
}

// A QUIC connection has room for all a user may hold and for the requests
// on their way to a refusal; fewer of them may be without a header.
func TestMaxStreams(t *testing.T) {
	if MaxStreams <= tcpPerUser+uotPerUser+icmpPerUser || PendingStreams >= MaxStreams || PendingStreams < 16 {
		t.Fatalf("a connection's %d streams (%d without a header) for the user's %d", MaxStreams, PendingStreams, tcpPerUser+uotPerUser+icmpPerUser)
	}
}
