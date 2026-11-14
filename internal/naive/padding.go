package naive

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
)

// naive's padding (spec/naive-padding.md), as klzgrad's NaiveProxy has it
// (src/net/tools/naive/naive_protocol.h, naive_padding_framer.cc,
// naive_padding_socket.cc) and the server people run with it, Caddy's
// forwardproxy (klzgrad/forwardproxy, forwardproxy.go), does it:
//
//   - the request and the answer carry a header Padding of random length,
//     which hides the length of the rest of the header block;
//   - the first paddingFrames writes each way are frames
//     [payload length u16 BE][padding length u8][payload][zeros], the
//     padding uniform in 0..255; what follows is the bare stream.
//
// The padding type is negotiated: a client that knows more than one says
// so in Padding-Type-Request ("1, 0", the one it prefers first), and the
// server answers the one it takes in Padding-Type-Reply. A client that asks
// nothing, as Niko's (cronet-go's NaiveClient) and sing-box's, gets no
// reply and the padding of type 1: an answer with Padding and no reply is
// type 1 to every naive client (naive_proxy_delegate.cc, ParsePaddingHeaders).
const (
	// paddingFrames is how many writes each way are padded
	// (kFirstPaddings, naive_padding_socket.cc; NumFirstPaddings in
	// forwardproxy.go).
	paddingFrames = 8

	// paddedFrameMax bounds a padded frame, its header and padding
	// included: NaivePaddingSocket frames a write into a buffer of
	// kMaxBufferSize (64 KiB), so a write's payload past what fits with
	// its padding goes in the next frame.
	paddedFrameMax = 64 << 10
	paddedHeader   = 3

	PaddingTypeRequest = "Padding-Type-Request"
	PaddingTypeReply   = "Padding-Type-Reply"

	// The padding types (PaddingType, naive_protocol.h), as they go in the
	// headers.
	paddingNone     = "0"
	paddingVariant1 = "1"
)

// paddingType is the padding a CONNECT's tunnel takes, from its header:
// the reply ("" when the client asked nothing, or nothing the server
// knows), and whether the first frames are padded. The first type of the
// request that the server knows wins: the client's order is its
// preference. A type the server does not know is passed over, where
// NaiveProxy's own server fails the request (http_proxy_server_socket.cc,
// ParsePaddingHeaders): a client of a later version, which may list a type
// of its own first, still gets one it knows. With nothing known the
// answer is what it was before the request header was there: Padding, no
// reply, type 1.
func paddingType(h http.Header) (reply string, padded bool) {
	for _, v := range h.Values(PaddingTypeRequest) {
		for v != "" {
			var t string
			t, v, _ = strings.Cut(v, ",")
			switch strings.TrimSpace(t) {
			case paddingVariant1:
				return paddingVariant1, true
			case paddingNone:
				return paddingNone, false
			}
		}
	}
	return "", true
}

// answerPadding sets the padding headers of an answer to an authenticated
// CONNECT, a 200 or a refusal alike: Padding always, and the reply when
// there is one. A naive client takes the padding type of a proxy anew from
// every answer it gets, whatever the status (OnTunnelHeadersReceived runs
// before the status is looked at, spdy_proxy_client_socket.cc,
// quic_proxy_client_socket.cc), and keeps one for the proxy.
func answerPadding(w http.ResponseWriter, reply string) {
	w.Header().Set("Padding", paddingHeader())
	if reply != "" {
		w.Header().Set(PaddingTypeReply, reply)
	}
}

// randByte draws padding sizes: an observer must not predict them.
func randByte() byte {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return b[0]
}

// paddingAlphabet are the characters of a Padding header, as Caddy's
// forwardproxy and sing-box draw them: each has an HPACK Huffman code of 8
// bits or more (RFC 7541, Appendix B), so an encoder that takes Huffman
// only where it is shorter, as Go's and Chromium's do, sends the value as
// it is, and the header's length on the wire is the length drawn. The
// first 16 characters are random, 4 bits each; the rest are paddingFill.
// NaiveProxy's client draws from 17 codes of its own HPACK table instead
// (padding_utils.cc: !"#$&'()*+,;<>?@ and X) with the same property.
const (
	paddingAlphabet = "!#$()+<>?@[]^`{}"
	paddingFill     = '~'
	// A Padding header of the answer is 30 to 61 characters
	// (forwardproxy.go: rand.Intn(32) + 30).
	paddingHeaderMin  = 30
	paddingHeaderSpan = 32
)

func paddingHeader() string {
	b := make([]byte, paddingHeaderMin+int(randByte()%paddingHeaderSpan))
	for i := range b {
		if i < len(paddingAlphabet) {
			b[i] = paddingAlphabet[randByte()%16]
		} else {
			b[i] = paddingFill
		}
	}
	return string(b)
}

// ClientStream is the client's side of the tunnel: what it writes into the
// CONNECT request body and reads from the response, padded the same way.
func ClientStream(response io.Reader, request io.Writer) io.ReadWriter {
	return &paddedStream{r: response, w: request}
}

// PaddingHeader is a value for the Padding header of a CONNECT.
func PaddingHeader() string { return paddingHeader() }

// paddedStream is the tunnel inside the CONNECT stream.
type paddedStream struct {
	r io.Reader
	w io.Writer
	f http.Flusher
	// pad draws a frame's padding length; randByte when nil (tests pin
	// it).
	pad func() byte

	readFrames, writeFrames int
	remaining, skip         int
	mu                      sync.Mutex // writes
}

// unpadded makes p a stream without padding (type 0): its first frames
// are as bare as the rest.
func (p *paddedStream) unpadded() *paddedStream {
	p.readFrames, p.writeFrames = paddingFrames, paddingFrames
	return p
}

func (p *paddedStream) Read(b []byte) (int, error) {
	for {
		if p.remaining > 0 {
			if len(b) > p.remaining {
				b = b[:p.remaining]
			}
			n, err := p.r.Read(b)
			p.remaining -= n
			if err == io.EOF && p.remaining > 0 {
				// The stream ended inside a frame: it broke, it did not
				// end.
				err = io.ErrUnexpectedEOF
			}
			return n, err
		}
		if p.skip > 0 {
			if _, err := io.CopyN(io.Discard, p.r, int64(p.skip)); err != nil {
				if errors.Is(err, io.EOF) {
					err = io.ErrUnexpectedEOF
				}
				return 0, err
			}
			p.skip = 0
		}
		if p.readFrames >= paddingFrames {
			return p.r.Read(b)
		}
		var h [paddedHeader]byte
		if _, err := io.ReadFull(p.r, h[:]); err != nil {
			return 0, err
		}
		p.readFrames++
		p.remaining, p.skip = int(binary.BigEndian.Uint16(h[:2])), int(h[2])
	}
}

func (p *paddedStream) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	written := 0
	for len(b) > 0 {
		chunk := b
		var err error
		if p.writeFrames < paddingFrames {
			draw := p.pad
			if draw == nil {
				draw = randByte
			}
			pad := int(draw())
			if room := paddedFrameMax - paddedHeader - pad; len(chunk) > room {
				chunk = chunk[:room]
			}
			frame := make([]byte, paddedHeader+len(chunk)+pad)
			binary.BigEndian.PutUint16(frame, uint16(len(chunk))) //nolint:gosec // G115: under 64 KiB
			frame[2] = byte(pad)
			copy(frame[paddedHeader:], chunk)
			_, err = p.w.Write(frame)
			p.writeFrames++
		} else {
			_, err = p.w.Write(chunk)
		}
		if err != nil {
			return written, err
		}
		if p.f != nil {
			p.f.Flush()
		}
		written += len(chunk)
		b = b[len(chunk):]
	}
	return written, nil
}
