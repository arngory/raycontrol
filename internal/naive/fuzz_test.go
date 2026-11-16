package naive

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

// The three parsers of what a client sends naive, before any of it goes
// anywhere (docs/17-naive-default.md §3): the padded first frames of every
// tunnel (paddedStream.Read), the request and packets of a UoT v2 stream
// (readRequest, readPacketHead), and the echo frames of an ICMP stream
// (readEcho). Each target checks more than "no panic": what a length field
// may make the parser allocate, that it reads no byte past the frame it
// parses, that it ends on a truncated input, and the round trip where
// there is an encoder.

// allocated is what f allocated on the heap, to the byte.
// runtime.ReadMemStats stops the world, but it counts what the per-P
// caches gave out; /gc/heap/allocs:bytes counts a span's allocations when
// the span leaves its cache, so an allocation of up to 32 KiB from a span
// already cached went unseen, and others were counted a span at a time
// (the 64 KiB of slack this needed let a 64 KiB allocation through).
func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// allocBound fails t when f allocated more than limit bytes: no length
// field of an input may make a parser allocate past the bounds of the
// spec, so limit is a few bytes per item the input has (a frame, a
// packet), never the size of one. What the harness allocates around an
// empty f is taken off, and the fuzzing engine's own work may run beside
// f: f runs again (it must start afresh each time) before an input is
// said to break the bound. A parser's own allocation is the same at every
// run. Under the race detector f only runs: the pools give nothing back
// there (raceDetector), and the bound failed one run in six.
func allocBound(t *testing.T, limit uint64, f func()) {
	t.Helper()
	if raceDetector {
		f()
		return
	}
	if got, base, over := allocOver(limit, f); over {
		t.Fatalf("%d bytes allocated for an input (the harness's own %d), the bound is %d", got, base, limit)
	}
}

// allocOver is allocBound's measure: whether f allocated more than limit
// past the harness at each of three runs.
func allocOver(limit uint64, f func()) (got, base uint64, over bool) {
	for range 3 {
		base = allocated(func() {})
		if got = allocated(f); got <= base+limit {
			return got, base, false
		}
	}
	return got, base, true
}

var allocSink []byte

// allocBound sees one allocation of a length field's size, and one of a
// few bytes past its limit, where its slack of 64 KiB let either through.
func TestAllocBound(t *testing.T) {
	if raceDetector {
		t.Skip("no bound on allocations under the race detector")
	}
	for _, c := range []struct {
		size, limit int
		over        bool
	}{{65535, 0, true}, {65535, 64 << 10, false}, {64, 0, true}, {48, 64, false}, {300, paddingFrames * paddedFrameAlloc, false}} {
		got, base, over := allocOver(uint64(c.limit), func() { allocSink = make([]byte, c.size) }) //nolint:gosec // G115: the cases'
		if over != c.over {
			t.Errorf("%d bytes against a limit of %d: %d counted (the harness's %d), over %v", c.size, c.limit, got, base, over)
		}
	}
	allocSink = nil
}

// paddedFrameAlloc is what paddedStream.Read may allocate per padded
// frame: the io.LimitedReader of the padding it reads past.
const paddedFrameAlloc = 64

// splitReader gives its input in reads of the sizes cuts says, in turn
// (1 to 256 bytes each), as the network may; past upTo bytes (when not 0)
// in reads as long as asked.
type splitReader struct {
	b    []byte
	cuts []byte
	i    int
	upTo int
	read int
}

func (s *splitReader) Read(p []byte) (int, error) {
	if len(s.b) == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if len(s.cuts) > 0 && (s.upTo == 0 || s.read < s.upTo) {
		n = min(n, int(s.cuts[s.i%len(s.cuts)])+1)
		s.i++
	}
	n = copy(p, s.b[:min(n, len(s.b))])
	s.b = s.b[n:]
	s.read += n
	return n, nil
}

// unpad is the padded stream as upstream's framer reads it
// (naive_padding_framer.cc, NaivePaddingFramer::Read), on the whole input
// at once: the payload, and whether the input ended inside a frame.
func unpad(in []byte) (payload []byte, truncated bool) {
	for frame := 0; frame < paddingFrames; frame++ {
		if len(in) == 0 {
			return payload, false
		}
		if len(in) < paddedHeader {
			return payload, true
		}
		n, pad := int(binary.BigEndian.Uint16(in)), int(in[2])
		in = in[paddedHeader:]
		if len(in) < n {
			return append(payload, in...), true
		}
		payload, in = append(payload, in[:n]...), in[n:]
		if len(in) < pad {
			return payload, true
		}
		in = in[pad:]
	}
	return append(payload, in...), false
}

// FuzzPaddedStream: whatever a peer sends, paddedStream reads what
// upstream's framer reads from it, in reads of any size, and fails (does
// not end cleanly) on an input cut inside a frame; it allocates nothing for
// a length field. What it writes (payload, repeat+1 times: a write longer
// than a frame from a short input, which the engine minimizes fast) reads
// back as it was written, with frames of at most 64 KiB.
func FuzzPaddedStream(f *testing.F) {
	golden, _ := hex.DecodeString("0001006100050368656c6c6f000000000400" + "6162636400")
	f.Add(golden, []byte{0, 3}, []byte("payload"), uint8(0))
	f.Add([]byte{0, 0, 255}, []byte{}, []byte{}, uint8(0))
	f.Add([]byte{0xff, 0xff, 0xff, 1, 2, 3}, []byte{1}, bytes.Repeat([]byte{7}, 280), uint8(250))
	f.Add(bytes.Repeat([]byte{0, 1, 0, 'x'}, 12), []byte{0}, []byte(strings.Repeat("ab", 9)), uint8(1))
	f.Fuzz(func(t *testing.T, in, cuts, payload []byte, repeat uint8) {
		want, truncated := unpad(in)
		got := make([]byte, 0, len(in))
		buf := make([]byte, 4096)
		split := &splitReader{}
		s := &paddedStream{r: split}
		var err error
		allocBound(t, paddingFrames*paddedFrameAlloc, func() {
			got = got[:0]
			*split = splitReader{b: in, cuts: cuts}
			s.readFrames, s.remaining, s.skip = 0, 0, 0
			for range len(in) + 2 { // each read takes a byte at least, or ends
				var n int
				n, err = s.Read(buf[:1+len(got)%len(buf)])
				got = append(got, buf[:n]...)
				if err != nil {
					break
				}
			}
		})
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("the read did not end: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("read %x, upstream's framer reads %x", got, want)
		}
		if truncated != errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("an input cut inside a frame %v, the read's end %v", truncated, err)
		}

		// The round trip: payload written in pieces as cuts say, each
		// frame with the padding cuts gives, read back.
		payload = bytes.Repeat(payload, 1+int(repeat))
		var wire bytes.Buffer
		pads := append([]byte{0}, cuts...)
		i := 0
		w := &paddedStream{w: &wire, pad: func() byte { i++; return pads[i%len(pads)] }}
		for rest, j := payload, 0; len(rest) > 0; j++ {
			n := min(len(rest), 1+int(pads[j%len(pads)])*300)
			if _, err := w.Write(rest[:n]); err != nil {
				t.Fatal(err)
			}
			rest = rest[n:]
		}
		frames := wire.Bytes()
		for k := 0; k < paddingFrames && len(frames) > 0; k++ {
			size := paddedHeader + int(binary.BigEndian.Uint16(frames)) + int(frames[2])
			if size > paddedFrameMax {
				t.Fatalf("a frame of %d bytes", size)
			}
			frames = frames[size:]
		}
		// In reads of up to 256 bytes over the first frames, whole past
		// them: a byte at a time over 64 KiB is what slowed the target.
		back, err := io.ReadAll(&paddedStream{r: &splitReader{b: wire.Bytes(), cuts: cuts, upTo: paddedFrameMax * paddingFrames}})
		if err != nil || !bytes.Equal(back, payload) {
			t.Fatalf("wrote %d bytes, read back %d (%v)", len(payload), len(back), err)
		}
	})
}

// readCount counts what its reader gave.
type readCount struct {
	r io.Reader
	n int
}

func (c *readCount) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// addrLen is the length of an address of type t in its form (SOCKS or
// UoT's), name being its name.
func addrLen(t byte, socks bool, name string) int {
	v4, v6 := byte(0x00), byte(0x01)
	if socks {
		v4, v6 = 0x01, 0x04
	}
	switch t {
	case v4:
		return 1 + 4 + 2
	case v6:
		return 1 + 16 + 2
	}
	return 1 + 1 + len(name) + 2
}

// encodeAddr is a in its form, IPv4 as IPv4.
func encodeAddr(b []byte, a uotAddr, socks bool) []byte {
	v4, v6, name := byte(0x00), byte(0x01), byte(0x02)
	if socks {
		v4, v6, name = 0x01, 0x04, 0x03
	}
	switch {
	case a.name != "":
		b = append(append(b, name, byte(len(a.name))), a.name...)
	case a.ip.Is4():
		b = append(append(b, v4), a.ip.AsSlice()...)
	default:
		b = append(append(b, v6), a.ip.AsSlice()...)
	}
	return binary.BigEndian.AppendUint16(b, a.port)
}

type uotParsed struct {
	request bool // read whole
	connect bool
	dest    uotAddr
	packets []uotPacket
	err     error
}

type uotPacket struct {
	dest uotAddr
	data string
}

// parseUoT reads a stream as serveUoT and upstream do: the request, then
// packets until an error. It checks, item by item, that the parser read
// exactly the item's bytes and no more.
func parseUoT(t *testing.T, in []byte) uotParsed {
	t.Helper()
	c := &readCount{r: bytes.NewReader(in)}
	r := bufio.NewReaderSize(c, 4<<10)
	consumed := func() int { return c.n - r.Buffered() }
	var p uotParsed
	var typ byte
	if b, err := r.Peek(2); err == nil {
		typ = b[1]
	}
	if p.connect, p.dest, p.err = readRequest(r); p.err != nil {
		return p
	}
	p.request = true
	if n := consumed(); n != 1+addrLen(typ, true, p.dest.name) {
		t.Fatalf("the request took %d bytes, it has %d", n, 1+addrLen(typ, true, p.dest.name))
	}
	buf := make([]byte, uotMaxPayload)
	for range len(in) + 1 { // each packet takes two bytes at least, or ends
		start := consumed()
		if b, err := r.Peek(1); err == nil {
			typ = b[0]
		}
		dest, n, err := readPacketHead(r, p.connect)
		if err != nil {
			p.err = err
			return p
		}
		if n > uotMaxPayload {
			t.Fatalf("a packet of %d bytes taken", n)
		}
		if _, err := io.ReadFull(r, buf[:n]); err != nil {
			p.err = err
			return p
		}
		want := 2 + n
		if !p.connect {
			want += addrLen(typ, false, dest.name)
		}
		if got := consumed() - start; got != want {
			t.Fatalf("a packet took %d bytes, it has %d", got, want)
		}
		p.packets = append(p.packets, uotPacket{dest, string(buf[:n])})
	}
	t.Fatal("the packets did not end")
	return p
}

// uotFuzzStream allocations: a stream's state, and per packet its
// address's name and the context of the name's lookup.
const (
	uotStreamAlloc = 2 << 10
	uotPacketAlloc = 1 << 10
)

// uotUpstream is serveUoT's own path for a stream's packets: the request
// read, then upstream, which reads each packet into the pooled buffer and
// sends it. A connected stream sends to sink (a socket of loopback that
// reads nothing), as if its destination were that; an unconnected one
// reaches nothing: no address is allowed, and no name is looked up (no
// lookup token), so that no packet leaves for an address of the input's.
type uotUpstream struct {
	s          *Server
	sink, free *net.UDPConn
	to         netip.AddrPort
	in         bytes.Reader
	r          *bufio.Reader
}

func newUoTUpstream(f *testing.F) *uotUpstream {
	f.Helper()
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		f.Fatal(err)
	}
	to := sink.LocalAddr().(*net.UDPAddr).AddrPort()
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(to))
	if err != nil {
		f.Fatal(err)
	}
	free, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { sink.Close(); conn.Close(); free.Close() })
	s := &Server{Allow: func(netip.Addr) bool { return false }, Log: slog.New(slog.DiscardHandler)}
	s.lim.lookupBurst = 1e-9 // never a whole token
	u := &uotUpstream{s: s, sink: conn, free: free, to: to}
	u.r = bufio.NewReaderSize(&u.in, 4<<10)
	return u
}

// run reads in as serveUoT does; the error that ended it.
func (x *uotUpstream) run(in []byte) error {
	x.in.Reset(in)
	x.r.Reset(&x.in)
	connect, _, err := readRequest(x.r)
	if err != nil {
		return err
	}
	u := &uotStream{s: x.s, ctx: context.Background(), slot: &uotSlot{user: "u"}, names: map[string]uotResolved{},
		peers: map[netip.AddrPort]pairTimes{}}
	conn, to := x.free, netip.AddrPort{}
	if connect {
		conn, to = x.sink, x.to
		m := monoAt(time.Now())
		u.peers[to] = pairTimes{sent: m, any: m}
	}
	return u.upstream(x.r, conn, to)
}

// FuzzUoT: whatever a client sends on a UoT stream, the request and the
// packets are read item by item, each to its last byte and not past it; a
// packet longer than a client may send is refused before its data is
// read, and serveUoT's own path (upstream, with its socket) allocates no
// more than a stream's state and a few bytes per packet, nothing for a
// length field; an address type or isConnect it does not know is
// refused, a cut input is not. What was read, written again, reads the
// same.
func FuzzUoT(f *testing.F) {
	up := newUoTUpstream(f)
	echo := netip.MustParseAddrPort("127.0.0.1:5353")
	f.Add(append(append([]byte{0}, socksAddr(netip.MustParseAddrPort("0.0.0.0:0"))...),
		packet(append([]byte{0x00}, binary.BigEndian.AppendUint16(echo.Addr().AsSlice(), echo.Port())...), []byte("one"))...))
	f.Add(append(append([]byte{1}, socksName("echo.test", 53)...), packet(nil, []byte("a"))...))
	f.Add(append(append([]byte{0}, socksAddr(echo)...), packet(uotName("echo.test", 53), []byte("named"))...))
	f.Add(append(append([]byte{0}, socksAddr(echo)...), packet(v6(netip.MustParseAddrPort("[::ffff:127.0.0.1]:9")), nil)...))
	f.Add(append(append([]byte{1}, socksAddr(echo)...), 0xff, 0xff))
	f.Add([]byte{2, 0x01, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0, 0x09})
	f.Add([]byte{0, 0x03, 0})
	f.Fuzz(func(t *testing.T, in []byte) {
		p := parseUoT(t, in)
		if p.err == nil {
			t.Fatal("a stream read without an end")
		}
		var err error
		allocBound(t, uotStreamAlloc+uotPacketAlloc*uint64(len(p.packets)+1), func() { err = up.run(in) })
		if errors.Is(err, errRefused) != errors.Is(p.err, errRefused) {
			t.Fatalf("upstream ended with %v, the parser with %v", err, p.err)
		}
		// Refused: what the format does not have. Anything else is the
		// input's end, and only that.
		refused := errors.Is(p.err, errRefused)
		if !refused && !errors.Is(p.err, io.EOF) && !errors.Is(p.err, io.ErrUnexpectedEOF) && !errors.Is(p.err, bufio.ErrBufferFull) {
			t.Fatalf("ended with %v", p.err)
		}
		// The round trip of what was read whole.
		if !p.request {
			return
		}
		again := []byte{0}
		if p.connect {
			again[0] = 1
		}
		again = encodeAddr(again, p.dest, true)
		for _, pk := range p.packets {
			if !p.connect {
				again = encodeAddr(again, pk.dest, false)
			}
			again = binary.BigEndian.AppendUint16(again, uint16(len(pk.data))) //nolint:gosec // G115: under uotMaxPayload
			again = append(again, pk.data...)
		}
		q := parseUoT(t, again)
		if q.connect != p.connect || q.dest != p.dest || len(q.packets) != len(p.packets) || errors.Is(q.err, errRefused) {
			t.Fatalf("read again: %+v, first %+v", q, p)
		}
		for i := range p.packets {
			if q.packets[i] != p.packets[i] {
				t.Fatalf("packet %d read again: %+v, first %+v", i, q.packets[i], p.packets[i])
			}
		}
	})
}

// icmpEndAlloc is the error a refused ICMP stream ends with.
const icmpEndAlloc = 128

// FuzzICMP: whatever a client sends on an ICMP stream, each echo frame is
// read to its last byte and not past it: its data into the stream's one
// buffer of icmpMaxPayload, a longer echo read past without a byte kept;
// a kind or a family it does not know is refused, a cut input is not.
// What was read, written again (echoFrame), reads the same.
func FuzzICMP(f *testing.F) {
	f.Add(echoFrame(netip.MustParseAddr("192.0.2.1"), 1, 7, 1, []byte("ping")))
	f.Add(append(echoFrame(netip.MustParseAddr("2001:db8::1"), 64, 7, 2, nil), echoFrame(netip.MustParseAddr("192.0.2.1"), 0, 1, 1, []byte{1})...))
	f.Add(echoFrame(netip.MustParseAddr("192.0.2.1"), 1, 7, 3, make([]byte, icmpMaxPayload+1)))
	f.Add([]byte{1, 4, 192, 0, 2, 1, 1, 0, 1, 0, 1, 0xff, 0xff})
	f.Add([]byte{2, 4})
	f.Add([]byte{1, 5})
	f.Fuzz(func(t *testing.T, in []byte) {
		type frame struct {
			e    icmpEchoFrame
			data []byte
		}
		frames := make([]frame, 0, len(in)+1)
		kept := make([]byte, 0, len(in))
		var err error
		src := bytes.NewReader(in)
		c := &readCount{r: src}
		r := bufio.NewReaderSize(c, 4<<10)
		payload := make([]byte, icmpMaxPayload)
		// Nothing but the error that ends the stream: the frames are read
		// into the stream's one buffer.
		allocBound(t, icmpEndAlloc, func() {
			frames, kept = frames[:0], kept[:0]
			src.Reset(in)
			c.n = 0
			r.Reset(c)
			for range len(in) + 1 { // each frame takes a byte at least, or ends
				start := c.n - r.Buffered()
				var e icmpEchoFrame
				if e, err = readEcho(r, payload); err != nil {
					return
				}
				n := len(e.data)
				if e.big {
					n = int(binary.BigEndian.Uint16(in[start+len(e.dst.AsSlice())+7:]))
					if n <= icmpMaxPayload || len(e.data) != 0 {
						t.Fatalf("a big echo of %d bytes, %d kept", n, len(e.data))
					}
				}
				if got, want := c.n-r.Buffered()-start, 2+len(e.dst.AsSlice())+7+n; got != want {
					t.Fatalf("a frame took %d bytes, it has %d", got, want)
				}
				kept = append(kept, e.data...)
				frames = append(frames, frame{e, kept[len(kept)-len(e.data):]})
			}
			t.Fatal("the frames did not end")
		})
		if !errors.Is(err, errRefused) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, bufio.ErrBufferFull) {
			t.Fatalf("ended with %v", err)
		}
		var again []byte
		for _, f := range frames {
			data := f.data
			if f.e.big {
				data = make([]byte, icmpMaxPayload+1)
			}
			again = append(again, echoFrame(f.e.dst, byte(f.e.ttl), f.e.id, f.e.seq, data)...) //nolint:gosec // G115: a byte read
		}
		r = bufio.NewReader(iotest.HalfReader(bytes.NewReader(again)))
		for i, f := range frames {
			e, err := readEcho(r, payload)
			if err != nil || e.dst != f.e.dst || e.ttl != f.e.ttl || e.id != f.e.id || e.seq != f.e.seq || e.big != f.e.big || !bytes.Equal(e.data, f.data) {
				t.Fatalf("frame %d read again: %+v (%v), first %+v", i, e, err, f.e)
			}
		}
	})
}

// FuzzUDPDatagram: whatever a client puts in an HTTP datagram, parseUDP
// reads it without a panic and keeps nothing past it; what it takes is a
// destination with a port and data a client may send, and written again
// it reads the same. The data is the input's own, not a copy.
func FuzzUDPDatagram(f *testing.F) {
	f.Add(udpDatagram(udpDest(netip.MustParseAddrPort("192.0.2.1:53")), []byte("query")))
	f.Add(udpDatagram(udpDest(netip.MustParseAddrPort("[2001:db8::1]:443")), nil))
	f.Add(udpDatagram(udpDest(netip.MustParseAddrPort("[::ffff:192.0.2.1]:443")), []byte{1}))
	f.Add(udpDatagram(udpDestName("example.com", 3478), []byte("stun")))
	f.Add([]byte{0x40, 0x02, udpName, 1, 'a', 0, 1})
	f.Add([]byte{udpContext, udpName, 0})
	f.Add([]byte{0, udpIPv4})
	f.Add([]byte{0xc0})
	f.Fuzz(func(t *testing.T, in []byte) {
		dest, data, why := parseUDP(in)
		if why >= 0 {
			if why >= dropKinds || data != nil {
				t.Fatalf("dropped (%d) with %d bytes", why, len(data))
			}
			return
		}
		if dest.port == 0 || len(data) > uotMaxPayload || (dest.name == "") == !dest.ip.IsValid() || len(dest.name) > 255 {
			t.Fatalf("read %+v and %d bytes", dest, len(data))
		}
		if len(data) > 0 && &data[len(data)-1] != &in[len(in)-1] {
			t.Fatal("the data is not the input's end")
		}
		var again []byte
		if dest.name != "" {
			again = udpDatagram(udpDestName(dest.name, dest.port), data)
		} else {
			again = udpDatagram(udpDest(netip.AddrPortFrom(dest.ip, dest.port)), data)
			// The node's answer from there reads the same.
			if d2, data2, why2 := parseUDP(append(appendUDPHead(nil, netip.AddrPortFrom(dest.ip, dest.port)), data...)); why2 >= 0 || d2 != dest || !bytes.Equal(data2, data) {
				t.Fatalf("an answer from %+v read as %+v (%d)", dest, d2, why2)
			}
		}
		d2, data2, why2 := parseUDP(again)
		if why2 >= 0 || d2 != dest || !bytes.Equal(data2, data) {
			t.Fatalf("read again: %+v %d (%d), first %+v %d", d2, len(data2), why2, dest, len(data))
		}
	})
}

// fuzzStream is an H3Stream whose content is a fuzzer's input and which
// takes no datagram.
type fuzzStream struct{ bytes.Reader }

func (*fuzzStream) Write(b []byte) (int, error)                     { return len(b), nil }
func (*fuzzStream) SetReadDeadline(time.Time) error                 { return nil }
func (*fuzzStream) SetWriteDeadline(time.Time) error                { return nil }
func (*fuzzStream) SendDatagram([]byte) (bool, error)               { return false, nil }
func (*fuzzStream) ReceiveDatagram(context.Context) ([]byte, error) { return nil, io.EOF }
func (*fuzzStream) Close() error                                    { return nil }
func (*fuzzStream) Reset()                                          {}

// FuzzUDPCapsules: whatever a client sends in a datagram request's stream,
// the capsules are read one by one, each to its last byte and not past it:
// a DATAGRAM capsule's payload goes to upstream (here nothing is allowed
// and nothing looked up, so each is dropped and counted), a capsule of
// another type is skipped, one longer than capsuleMax is refused before
// its payload is read, one cut short is refused, and the end between two
// capsules is the client's clean end.
func FuzzUDPCapsules(f *testing.F) {
	capsule := func(typ uint64, payload []byte) []byte {
		return append(appendVarint(appendVarint(nil, typ), uint64(len(payload))), payload...)
	}
	dg := udpDatagram(udpDest(netip.MustParseAddrPort("192.0.2.1:53")), []byte("q"))
	f.Add(capsule(capsuleDatagram, dg))
	f.Add(append(capsule(0x2a, []byte("skip")), capsule(capsuleDatagram, udpDatagram(udpDestName("example.com", 53), nil))...))
	f.Add(capsule(capsuleDatagram, make([]byte, 5000)))
	f.Add(appendVarint([]byte{capsuleDatagram}, capsuleMax+1))
	f.Add(capsule(capsuleDatagram, dg)[:4])
	f.Add([]byte{0x40})
	f.Add([]byte{})
	s := &Server{Allow: func(netip.Addr) bool { return false }, Log: slog.New(slog.DiscardHandler)}
	s.lim.lookupBurst = 1e-9 // never a whole token
	free, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { free.Close() })
	f.Fuzz(func(t *testing.T, in []byte) {
		// The reference: the capsules as RFC 9297 §3.2 frames them.
		datagrams, want := 0, error(nil)
		for rest := in; len(rest) > 0; {
			typ, n := parseVarint(rest)
			if n == 0 {
				want = errRefused
				break
			}
			l, m := parseVarint(rest[n:])
			if m == 0 || l > capsuleMax {
				want = errRefused
				break
			}
			if uint64(len(rest)-n-m) < l {
				want = errRefused
				break
			}
			if typ == capsuleDatagram {
				datagrams++
			}
			rest = rest[n+m+int(l):]
		}
		st := &fuzzStream{}
		st.Reader.Reset(in)
		d := &udpRequest{s: s, conn: free, st: st, u: &uotStream{s: s, ctx: context.Background(), slot: &uotSlot{user: "u"},
			names: map[string]uotResolved{}, peers: map[netip.AddrPort]pairTimes{}}}
		got := d.readCapsules()
		if errors.Is(got, errRefused) != (want != nil) || (want == nil && got != nil) {
			t.Fatalf("ended with %v, want %v", got, want)
		}
		var dropped int64
		for i := range d.n.dropped {
			dropped += d.n.dropped[i].Load()
		}
		if dropped != int64(datagrams) || d.n.in.Load() != 0 {
			t.Fatalf("%d dropped and %d sent of %d datagrams", dropped, d.n.in.Load(), datagrams)
		}
	})
}
