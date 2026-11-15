package naive

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/arngory/raycontrol/internal/site"
)

// Upstream's constants (klzgrad/naiveproxy, src/net/tools/naive): the
// frames each way that are padded (naive_padding_socket.cc,
// kFirstPaddings), the frame's header (naive_padding_framer.h), the buffer
// a frame is built in (kMaxBufferSize) and the largest padding
// (max_padding_size).
const (
	upstreamFirstPaddings = 8
	upstreamFrameHeader   = 3
	upstreamMaxBuffer     = 64 * 1024
	upstreamMaxPadding    = 255
)

func TestPaddingConstantsAreUpstreams(t *testing.T) {
	if paddingFrames != upstreamFirstPaddings || paddedHeader != upstreamFrameHeader || paddedFrameMax != upstreamMaxBuffer {
		t.Fatalf("%d frames, a header of %d, frames up to %d: upstream's are %d, %d, %d", paddingFrames, paddedHeader, paddedFrameMax,
			upstreamFirstPaddings, upstreamFrameHeader, upstreamMaxBuffer)
	}
}

// pads gives the padding lengths of a stream's frames in turn.
func pads(n ...byte) func() byte {
	return func() byte {
		b := n[0]
		n = n[1:]
		return b
	}
}

// The first frames each way, byte for byte as NaivePaddingFramer::Write
// builds them (naive_padding_framer.cc: [size / 256][size % 256][padding
// size][payload][zeros]); the ninth write and on are the bare stream.
func TestPaddedFramesGolden(t *testing.T) {
	var out bytes.Buffer
	s := &paddedStream{w: &out, pad: pads(0, 3, 255, 1, 0, 0, 0, 7)}
	writes := []string{"a", "hello", "", "xy", strings.Repeat("z", 300), "1", "2", "seven", "end8", "bare", "!"}
	for _, w := range writes {
		if _, err := s.Write([]byte(w)); err != nil {
			t.Fatal(err)
		}
	}
	want := "000100" + "61" +
		"000503" + hex.EncodeToString([]byte("hello")) + "000000" +
		// An empty write is no frame: io.Copy never makes one, and
		// upstream's socket is never asked to write nothing.
		"0002ff" + hex.EncodeToString([]byte("xy")) + strings.Repeat("00", 255) +
		"012c01" + strings.Repeat("7a", 300) + "00" +
		"000100" + "31" +
		"000100" + "32" +
		"000500" + hex.EncodeToString([]byte("seven")) +
		"000407" + hex.EncodeToString([]byte("end8")) + strings.Repeat("00", 7) +
		hex.EncodeToString([]byte("bare!"))
	if got := hex.EncodeToString(out.Bytes()); got != want {
		t.Fatalf("the frames:\n got %s\nwant %s", got, want)
	}

	// Read back: the same frames, one byte at a time (upstream's framer
	// keeps its state across reads of any size), give the writes.
	r := &paddedStream{r: iotest.OneByteReader(bytes.NewReader(out.Bytes()))}
	got, err := io.ReadAll(r)
	if err != nil || string(got) != strings.Join(writes, "") {
		t.Fatalf("read back %q (%v)", got, err)
	}
}

// A padded frame is no longer than upstream's buffer, 64 KiB with its
// header and padding: a write's payload past that goes in the next frame,
// as NaivePaddingFramer::Write truncates it (payload_consumed_len).
func TestPaddedFrameMax(t *testing.T) {
	var out bytes.Buffer
	s := &paddedStream{w: &out, pad: pads(255, 0)}
	payload := bytes.Repeat([]byte{1}, 70000)
	if n, err := s.Write(payload); n != len(payload) || err != nil {
		t.Fatalf("wrote %d (%v)", n, err)
	}
	b := out.Bytes()
	first := int(b[0])<<8 | int(b[1])
	if first != upstreamMaxBuffer-upstreamFrameHeader-upstreamMaxPadding || b[2] != 255 {
		t.Fatalf("a first frame of %d bytes with %d of padding, want %d with 255", first, b[2], upstreamMaxBuffer-upstreamFrameHeader-upstreamMaxPadding)
	}
	rest := b[upstreamFrameHeader+first+255:]
	if second := int(rest[0])<<8 | int(rest[1]); second != len(payload)-first || rest[2] != 0 {
		t.Fatalf("a second frame of %d bytes, want %d", second, len(payload)-first)
	}
	got, err := io.ReadAll(&paddedStream{r: bytes.NewReader(b)})
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("read back %d bytes (%v)", len(got), err)
	}
}

// A truncated frame is an error, not an end: the stream broke.
func TestPaddedTruncated(t *testing.T) {
	for _, in := range []string{"00", "000500" + "6865", "000102" + "61" + "00"} {
		b, _ := hex.DecodeString(in)
		_, err := io.ReadAll(&paddedStream{r: bytes.NewReader(b)})
		if err == nil {
			t.Errorf("%s: read to its end without an error", in)
		}
	}
}

// rawFrame is a padded frame as a client builds it, whatever its length.
func rawFrame(payload []byte, pad int) []byte {
	f := make([]byte, paddedHeader+len(payload)+pad)
	binary.BigEndian.PutUint16(f, uint16(len(payload))) //nolint:gosec // G115: the cases' payloads fit
	f[2] = byte(pad)
	copy(f[paddedHeader:], payload)
	return f
}

// The largest frames each real client sends pass through the real
// listeners, both ways: cronet-go's (naive_conn.go, maxPaddingChunkSize
// 65535 and padding of up to 255, so 65793 bytes, past upstream's 64 KiB
// buffer) and Chromium's (NaivePaddingFramer::Write: payload and padding
// within kMaxBufferSize, with padding or none). The echo comes back whole,
// in frames of the server's of 64 KiB at most.
func TestLargestClientFrames(t *testing.T) {
	for _, c := range []struct {
		name         string
		payload, pad int
	}{
		{"cronet-go", 65535, 255},
		{"chromium", upstreamMaxBuffer - upstreamFrameHeader - upstreamMaxPadding, upstreamMaxPadding},
		{"chromium unpadded", upstreamMaxBuffer - upstreamFrameHeader, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			overProtos(t, func(t *testing.T) {
				echo := echoServer(t)
				_, connect := tunnelServer(t, func(*Server) {})
				resp, s, done := connect(echo)
				defer done()
				var want []byte
				for i := range paddingFrames {
					want = append(want, bytes.Repeat([]byte{byte('a' + i)}, c.payload)...)
				}
				want = append(want, "tail"...)
				go func() {
					for i := range paddingFrames {
						if _, err := s.w.Write(rawFrame(bytes.Repeat([]byte{byte('a' + i)}, c.payload), c.pad)); err != nil {
							return
						}
					}
					_, _ = s.w.Write([]byte("tail")) // bare past the padded frames
				}()
				// The server's frames, read raw to see their size.
				var got []byte
				for frame := 0; frame < paddingFrames && len(got) < len(want); frame++ {
					var h [paddedHeader]byte
					if _, err := io.ReadFull(resp.Body, h[:]); err != nil {
						t.Fatalf("frame %d: %v", frame, err)
					}
					n, pad := int(binary.BigEndian.Uint16(h[:2])), int(h[2])
					if paddedHeader+n+pad > paddedFrameMax {
						t.Fatalf("a frame of the server's of %d bytes", paddedHeader+n+pad)
					}
					b := make([]byte, n+pad)
					if _, err := io.ReadFull(resp.Body, b); err != nil {
						t.Fatalf("frame %d: %v", frame, err)
					}
					got = append(got, b[:n]...)
				}
				rest := make([]byte, len(want)-len(got))
				if _, err := io.ReadFull(resp.Body, rest); err != nil {
					t.Fatalf("%d bytes past the frames: %v", len(rest), err)
				}
				if got = append(got, rest...); !bytes.Equal(got, want) {
					t.Fatalf("the echo differs: %d bytes, want %d", len(got), len(want))
				}
			})
		})
	}
}

// The client's end of its upload inside the padded frames, between two
// frames or inside one, is a clean end: the destination's side is closed
// for writing, what it echoes still comes back, and the stream ends
// without a reset.
func TestFinInsidePaddedFrames(t *testing.T) {
	for name, cut := range map[string]bool{"between frames": false, "inside a frame": true} {
		t.Run(name, func(t *testing.T) {
			overProtos(t, func(t *testing.T) {
				echo := echoServer(t)
				_, connect := tunnelServer(t, func(*Server) {})
				_, s, done := connect(echo)
				defer done()
				want := ""
				for i := range 3 {
					w := []byte{byte('a' + i), 'x'}
					if _, err := s.Write(w); err != nil {
						t.Fatal(err)
					}
					want += string(w)
				}
				if cut {
					// A frame of 10 bytes, 2 of them sent.
					_, _ = s.w.Write([]byte{0, 10, 0, 'z', 'z'})
					want += "zz"
				}
				_ = s.w.(io.Closer).Close()
				end := make(chan error, 1)
				var got []byte
				go func() {
					var err error
					got, err = io.ReadAll(s)
					end <- err
				}()
				select {
				case err := <-end:
					if err != nil || string(got) != want {
						t.Fatalf("read %q (%v), want %q and a clean end", got, err, want)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("the stream did not end")
				}
			})
		})
	}
}

// The Padding header of an answer: 30 to 61 characters, the first 16
// random from the alphabet, the rest '~' (forwardproxy.go), every one of
// them with an HPACK Huffman code of 8 bits or more, so that Go's encoder,
// which takes Huffman only where it is shorter, sends the value as it is.
func TestPaddingHeader(t *testing.T) {
	for _, c := range paddingAlphabet + string(paddingFill) {
		// Eight of a code under 8 bits fit in under 8 bytes.
		if n := hpack.HuffmanEncodeLength(strings.Repeat(string(c), 8)); n < 8 {
			t.Errorf("%q has a Huffman code under 8 bits", c)
		}
	}
	lengths := map[int]bool{}
	for range 5000 {
		h := paddingHeader()
		lengths[len(h)] = true
		if len(h) < 30 || len(h) > 61 {
			t.Fatalf("a header of %d characters", len(h))
		}
		for i, c := range []byte(h) {
			if i < 16 && !strings.ContainsRune(paddingAlphabet, rune(c)) || i >= 16 && c != '~' {
				t.Fatalf("%q: %q at %d", h, c, i)
			}
		}
		if hpack.HuffmanEncodeLength(h) < uint64(len(h)) {
			t.Fatalf("%q is shorter Huffman coded", h)
		}
	}
	if len(lengths) != 32 {
		t.Errorf("%d lengths drawn of 32", len(lengths))
	}
}

func TestPaddingType(t *testing.T) {
	for _, c := range []struct {
		request []string
		reply   string
		padded  bool
	}{
		{nil, "", true},               // as before: no reply, type 1
		{[]string{"1, 0"}, "1", true}, // NaiveProxy's own (naive_proxy_bin.cc)
		{[]string{"0, 1"}, "0", false},
		{[]string{"0"}, "0", false},
		{[]string{" 1 "}, "1", true},
		{[]string{"2, 0, 1"}, "0", false}, // a type of a later version is passed over
		{[]string{"2"}, "", true},
		{[]string{"", "x", "1"}, "1", true},
		{[]string{",,"}, "", true},
		{[]string{"10"}, "", true},
	} {
		h := http.Header{}
		for _, v := range c.request {
			h.Add(PaddingTypeRequest, v)
		}
		if reply, padded := paddingType(h); reply != c.reply || padded != c.padded {
			t.Errorf("%q: reply %q padded %v, want %q %v", c.request, reply, padded, c.reply, c.padded)
		}
	}
}

// The reply over the wire, on every answer of an authenticated CONNECT:
// the 200 of a tunnel (TCP, UoT, ICMP), the honest connect's 502 and the
// limits' 429, and the framing the tunnel then takes. A request without
// Padding-Type-Request gets what it always got. A stranger gets the
// site's answer, with neither header.
func TestPaddingReply(t *testing.T) {
	overProtos(t, func(t *testing.T) {
		echo := echoServer(t)
		users := filepath.Join(t.TempDir(), "users.json")
		writeUsersNamed(t, users, map[string]string{"pw": "u5-ab12"})
		answer, _ := site.Responder(site.Answer404, "")
		var d net.Dialer
		h := &Server{Users: &Users{Path: users}, Answer: answer, Dial: d.DialContext, ICMP: true, icmpOpen: newFakeNet().open,
			Log: slog.New(slog.DiscardHandler)}
		url, tr := serveOver(t, h)
		connect := func(target, password, request string, header ...string) (*http.Response, *paddedStream) {
			t.Helper()
			pr, pw := io.Pipe()
			t.Cleanup(func() { pw.Close() })
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodConnect, url, pr)
			req.Host = target
			req.Header.Set("Padding", paddingHeader())
			req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("niko:"+password)))
			if request != "" {
				req.Header.Set(PaddingTypeRequest, request)
			}
			for i := 0; i+1 < len(header); i += 2 {
				req.Header.Set(header[i], header[i+1])
			}
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatalf("CONNECT %s: %v", target, err)
			}
			t.Cleanup(func() { resp.Body.Close() })
			return resp, &paddedStream{r: resp.Body, w: pw}
		}
		for _, c := range []struct {
			request, reply string
			padded         bool
		}{{"", "", true}, {"1, 0", "1", true}, {"0, 1", "0", false}, {"3", "", true}} {
			resp, s := connect(echo, "pw", c.request)
			if resp.StatusCode != http.StatusOK || resp.Header.Get("Padding") == "" || resp.Header.Get(PaddingTypeReply) != c.reply {
				t.Fatalf("%q: %s, padding %q, reply %q, want 200 with %q", c.request, resp.Status, resp.Header.Get("Padding"),
					resp.Header.Get(PaddingTypeReply), c.reply)
			}
			if !c.padded {
				s.unpadded()
			}
			// More writes than padded frames, each echoed whole before the
			// next: a framing the server does not share would garble them.
			for i := range 10 {
				msg := bytes.Repeat([]byte{byte('a' + i)}, 1+i*500)
				if _, err := s.Write(msg); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(msg))
				if _, err := io.ReadFull(s, got); err != nil || !bytes.Equal(got, msg) {
					t.Fatalf("%q: echo %d: %q (%v)", c.request, i, got, err)
				}
			}
		}
		// Streams without a dial take the same reply.
		for _, host := range []string{UoTName + ":0", ICMPName + ":0"} {
			if resp, _ := connect(host, "pw", "0, 1"); resp.StatusCode != http.StatusOK || resp.Header.Get(PaddingTypeReply) != "0" {
				t.Errorf("%s: %s, reply %q", host, resp.Status, resp.Header.Get(PaddingTypeReply))
			}
		}
		// The refusals.
		gone, _ := net.Listen("tcp", "127.0.0.1:0")
		dead := gone.Addr().String()
		gone.Close()
		resp, _ := connect(dead, "pw", "1, 0", AckHeader, "1")
		if resp.StatusCode != http.StatusBadGateway || resp.Header.Get("Padding") == "" || resp.Header.Get(PaddingTypeReply) != "1" {
			t.Errorf("a refused destination: %s, reply %q", resp.Status, resp.Header.Get(PaddingTypeReply))
		}
		resp, _ = connect("no-port.test", "pw", "0", AckHeader, "1")
		if resp.StatusCode != http.StatusBadGateway || resp.Header.Get(PaddingTypeReply) != "0" {
			t.Errorf("a bad target with niko-ack: %s, reply %q", resp.Status, resp.Header.Get(PaddingTypeReply))
		}
		// The user's 1024 places taken (as 1024 tunnels would).
		for range tcpPerUser {
			h.lim.mu.Lock()
			h.lim.userLocked("u5", time.Now()).tcp++
			h.lim.mu.Unlock()
		}
		resp, _ = connect(echo, "pw", "1, 0")
		if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Padding") == "" || resp.Header.Get(PaddingTypeReply) != "1" {
			t.Errorf("over the limit: %s, reply %q", resp.Status, resp.Header.Get(PaddingTypeReply))
		}
		resp, _ = connect(echo, "wrong", "1, 0")
		if resp.StatusCode != http.StatusNotFound || resp.Header.Get("Padding") != "" || resp.Header.Get(PaddingTypeReply) != "" {
			t.Errorf("a stranger: %s, padding %q, reply %q", resp.Status, resp.Header.Get("Padding"), resp.Header.Get(PaddingTypeReply))
		}
	})
}

// echoServer is a TCP destination that sends back what it gets.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}
