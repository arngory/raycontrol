package naive

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/arngory/raycontrol/internal/site"
)

// h2Peer is a bare HTTP/2 client: what the server sends it, counted.
type h2Peer struct {
	fr *http2.Framer
	wr sync.Mutex // the Framer's writes

	mu       sync.Mutex
	settings map[http2.SettingID]uint32
	windows  map[uint32]int64 // WINDOW_UPDATE increments by stream; 0 is the connection
	status   map[uint32]string
	ended    string // RST_STREAM or GOAWAY, if any came
}

func newH2Peer(t *testing.T, url string) *h2Peer {
	t.Helper()
	c, err := tls.Dial("tcp", strings.TrimPrefix(url, "https://"), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402: the test's own server
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(time.Minute))
	if _, err := io.WriteString(c, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	p := &h2Peer{fr: http2.NewFramer(c, c), windows: map[uint32]int64{}, status: map[uint32]string{}}
	if err := p.fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	go p.read()
	return p
}

func (p *h2Peer) read() {
	var stream uint32
	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		if f.Name == ":status" {
			p.status[stream] = f.Value // under p.mu
		}
	})
	for {
		f, err := p.fr.ReadFrame()
		if err != nil {
			return
		}
		p.mu.Lock()
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				p.settings = map[http2.SettingID]uint32{}
				_ = f.ForeachSetting(func(s http2.Setting) error { p.settings[s.ID] = s.Val; return nil })
				p.wr.Lock()
				_ = p.fr.WriteSettingsAck()
				p.wr.Unlock()
			}
		case *http2.WindowUpdateFrame:
			p.windows[f.StreamID] += int64(f.Increment)
		case *http2.HeadersFrame:
			stream = f.StreamID
			_, _ = dec.Write(f.HeaderBlockFragment())
		case *http2.RSTStreamFrame:
			p.ended = "RST_STREAM " + f.ErrCode.String()
		case *http2.GoAwayFrame:
			p.ended = "GOAWAY " + f.ErrCode.String()
		}
		p.mu.Unlock()
	}
}

func (p *h2Peer) setting(id http2.SettingID) (uint32, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.settings[id]
	return v, ok
}

func (p *h2Peer) window(stream uint32) int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.windows[stream]
}

func (p *h2Peer) statusOf(stream uint32) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status[stream]
}

// connect sends a naive CONNECT on stream as the user of password.
func (p *h2Peer) connect(t *testing.T, stream uint32, target, password string) {
	t.Helper()
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, f := range [][2]string{{":method", "CONNECT"}, {":authority", target}, {"padding", paddingHeader()},
		{"proxy-authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte("niko:"+password))}} {
		_ = enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	p.wr.Lock()
	defer p.wr.Unlock()
	if err := p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: block.Bytes(), EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
}

// h2Data writes a stream's DATA, room bytes of it at most: what a window
// lets a client send.
type h2Data struct {
	p      *h2Peer
	stream uint32
	room   int
}

func (d *h2Data) Write(b []byte) (int, error) {
	n := 0
	for len(b) > 0 {
		if d.room == 0 {
			return n, io.ErrShortWrite
		}
		chunk := b[:min(len(b), 16<<10, d.room)]
		d.p.wr.Lock()
		err := d.p.fr.WriteData(d.stream, false, chunk)
		d.p.wr.Unlock()
		if err != nil {
			return n, err
		}
		n, d.room, b = n+len(chunk), d.room-len(chunk), b[len(chunk):]
	}
	return n, nil
}

// The upload windows are the ones set, and they bound what the process
// holds of a stalled destination: the server takes a whole window of a
// tunnel and gives back only what the handler has read, the rest when the
// destination reads again.
func TestUploadWindows(t *testing.T) {
	users := filepath.Join(t.TempDir(), "users.json")
	writeUsersNamed(t, users, map[string]string{"pw": "u5-ab12"})
	answer, _ := site.Responder(site.Answer404, "")
	reads := make(chan struct{}) // closed: the destination reads
	h := &Server{Users: &Users{Path: users}, Answer: answer, Log: slog.New(slog.DiscardHandler),
		Dial: func(context.Context, string, string) (net.Conn, error) {
			c, s := net.Pipe()
			go func() {
				<-reads
				_, _ = io.Copy(io.Discard, s)
			}()
			return c, nil
		}}
	p := newH2Peer(t, serveNaive(t, h))

	eventually(t, "no SETTINGS", func() bool { _, ok := p.setting(http2.SettingInitialWindowSize); return ok })
	if got, _ := p.setting(http2.SettingInitialWindowSize); got != h2StreamWindow {
		t.Fatalf("a stream's window is %d, want %d", got, h2StreamWindow)
	}
	// A connection's window starts at 65535 whatever the settings say; the
	// server raises it at once.
	const initial = 65535
	eventually(t, "the connection's window was not raised", func() bool { return p.window(0) > 0 })
	if got := p.window(0) + initial; got != h2ConnWindow {
		t.Fatalf("a connection's window is %d, want %d", got, h2ConnWindow)
	}

	p.connect(t, 1, "192.0.2.1:443", "pw")
	eventually(t, "no answer to the CONNECT", func() bool { return p.statusOf(1) != "" })
	if s := p.statusOf(1); s != "200" {
		t.Fatalf("CONNECT: %s", s)
	}
	// All a stream's window lets through, to a destination that reads
	// nothing.
	up := &paddedStream{w: &h2Data{p: p, stream: 1, room: h2StreamWindow}}
	chunk := make([]byte, 60<<10)
	for {
		if _, err := up.Write(chunk); err != nil {
			if err != io.ErrShortWrite {
				t.Fatal(err)
			}
			break
		}
	}
	// The handler read one copy buffer and waits in the destination's
	// write: that much of the window comes back and no more.
	const copyBuffer = 32 << 10
	time.Sleep(300 * time.Millisecond)
	if got := p.window(1); got > 2*copyBuffer {
		t.Fatalf("%d bytes of the stream's window came back with the destination stalled: the server read ahead of it", got)
	}
	if got := p.window(0) + initial - h2ConnWindow; got > 2*copyBuffer {
		t.Fatalf("%d bytes of the connection's window came back with the destination stalled", got)
	}
	p.mu.Lock()
	ended := p.ended
	p.mu.Unlock()
	if ended != "" {
		t.Fatalf("the server ended the stream: %s", ended)
	}
	// The destination reads: the rest comes back (Go keeps updates under
	// 4 KiB for later).
	close(reads)
	eventually(t, "the stream's window did not come back", func() bool { return p.window(1) >= h2StreamWindow-4<<10 })
}
