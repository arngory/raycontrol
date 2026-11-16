package naive

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/arngory/raycontrol/internal/h3serve"
	"github.com/arngory/raycontrol/internal/probe"
	"github.com/arngory/raycontrol/internal/site"
)

// udpDest is a destination in the client's form of §3.2: an address of
// type 4 or 6.
func udpDest(ap netip.AddrPort) []byte {
	a := ap.Addr()
	b := []byte{udpIPv6}
	if a.Is4() {
		b[0] = udpIPv4
	}
	b = append(b, a.AsSlice()...)
	return binary.BigEndian.AppendUint16(b, ap.Port())
}

// udpDestName is a destination by name (type 3).
func udpDestName(name string, port uint16) []byte {
	b := append([]byte{udpName, byte(len(name))}, name...)
	return binary.BigEndian.AppendUint16(b, port)
}

// udpDatagram is an HTTP datagram of the client's: Context ID 2, the
// destination, the data.
func udpDatagram(dest, data []byte) []byte {
	return append(append([]byte{udpContext}, dest...), data...)
}

func TestParseUDP(t *testing.T) {
	v4 := netip.MustParseAddrPort("192.0.2.1:53")
	v6 := netip.MustParseAddrPort("[2001:db8::1]:443")
	for _, c := range []struct {
		name string
		in   []byte
		dest uotAddr
		data string
		why  int
	}{
		{"IPv4", udpDatagram(udpDest(v4), []byte("hi")), uotAddr{ip: v4.Addr(), port: 53}, "hi", -1},
		{"IPv6", udpDatagram(udpDest(v6), []byte("x")), uotAddr{ip: v6.Addr(), port: 443}, "x", -1},
		{"IPv4 in IPv6", udpDatagram(udpDest(netip.MustParseAddrPort("[::ffff:192.0.2.1]:53")), nil), uotAddr{ip: v4.Addr(), port: 53}, "", -1},
		{"a name", udpDatagram(udpDestName("example.com", 3478), []byte("stun")), uotAddr{name: "example.com", port: 3478}, "stun", -1},
		{"no data", udpDatagram(udpDest(v4), nil), uotAddr{ip: v4.Addr(), port: 53}, "", -1},
		// The Context ID in a longer form than it needs is the same ID.
		{"Context ID in two bytes", append([]byte{0x40, 0x02}, append(udpDest(v4), 'a')...), uotAddr{ip: v4.Addr(), port: 53}, "a", -1},
		{"Context ID 0", append([]byte{0}, udpDest(v4)...), uotAddr{}, "", dropContext},
		{"Context ID 4", append([]byte{4}, udpDest(v4)...), uotAddr{}, "", dropContext},
		{"empty", nil, uotAddr{}, "", dropBad},
		{"a varint cut", []byte{0x40}, uotAddr{}, "", dropBad},
		{"Context ID alone", []byte{udpContext}, uotAddr{}, "", dropBad},
		{"type 1 (UoT's)", []byte{udpContext, 1, 192, 0, 2, 1, 0, 53}, uotAddr{}, "", dropBad},
		{"type 0", []byte{udpContext, 0, 192, 0, 2, 1, 0, 53}, uotAddr{}, "", dropBad},
		{"IPv4 cut", udpDatagram(udpDest(v4)[:6], nil), uotAddr{}, "", dropBad},
		{"IPv6 cut", udpDatagram(udpDest(v6)[:18], nil), uotAddr{}, "", dropBad},
		{"empty name", []byte{udpContext, udpName, 0, 0, 53}, uotAddr{}, "", dropBad},
		{"name cut", udpDatagram(udpDestName("example.com", 53)[:8], nil), uotAddr{}, "", dropBad},
		// The longest names: 2 + 254 or 255 wraps around in a byte.
		{"a name of 253", udpDatagram(udpDestName(strings.Repeat("a", 253), 53), []byte("x")), uotAddr{name: strings.Repeat("a", 253), port: 53}, "x", -1},
		{"a name of 254", udpDatagram(udpDestName(strings.Repeat("a", 254), 53), []byte("x")), uotAddr{name: strings.Repeat("a", 254), port: 53}, "x", -1},
		{"a name of 255", udpDatagram(udpDestName(strings.Repeat("a", 255), 53), []byte("x")), uotAddr{name: strings.Repeat("a", 255), port: 53}, "x", -1},
		{"a name of 255 cut", udpDatagram(udpDestName(strings.Repeat("a", 255), 53)[:200], nil), uotAddr{}, "", dropBad},
		{"a name of 255 without port", udpDatagram(udpDestName(strings.Repeat("a", 255), 53)[:257], nil), uotAddr{}, "", dropBad},
		{"name without port", []byte{udpContext, udpName, 1, 'a', 0}, uotAddr{}, "", dropBad},
		{"port 0", udpDatagram(udpDest(netip.AddrPortFrom(v4.Addr(), 0)), []byte("x")), uotAddr{}, "", dropBad},
		{"port 0 by name", udpDatagram(udpDestName("example.com", 0), []byte("x")), uotAddr{}, "", dropBad},
		{"longest", udpDatagram(udpDest(v4), make([]byte, uotMaxPayload)), uotAddr{ip: v4.Addr(), port: 53}, string(make([]byte, uotMaxPayload)), -1},
		{"longer than a client sends", udpDatagram(udpDest(v4), make([]byte, uotMaxPayload+1)), uotAddr{}, "", dropLong},
	} {
		dest, data, why := parseUDP(c.in)
		if why != c.why {
			t.Errorf("%s: why %d, want %d", c.name, why, c.why)
			continue
		}
		if why < 0 && (dest != c.dest || string(data) != c.data) {
			t.Errorf("%s: %+v %q, want %+v %q", c.name, dest, data, c.dest, c.data)
		}
	}
}

// The node's answers carry their source as an address, never a name, and
// read back as what they say.
func TestAppendUDPHead(t *testing.T) {
	for _, ap := range []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:53"), netip.MustParseAddrPort("[2001:db8::1]:65535"),
		netip.MustParseAddrPort("[::ffff:198.51.100.7]:9")} {
		b := append(appendUDPHead(nil, ap), "data"...)
		dest, data, why := parseUDP(b)
		want := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		if why >= 0 || dest.name != "" || netip.AddrPortFrom(dest.ip, dest.port) != want || string(data) != "data" {
			t.Errorf("%v: %+v %q %d", ap, dest, data, why)
		}
		if want.Addr().Is4() && (b[1] != udpIPv4 || len(b) != 1+1+4+2+4) || want.Addr().Is6() && (b[1] != udpIPv6 || len(b) != 1+1+16+2+4) {
			t.Errorf("%v: % x", ap, b)
		}
		if len(b)-4 > udpHead-3 {
			t.Errorf("%v: a head of %d bytes, room for %d", ap, len(b)-4, udpHead-3)
		}
	}
}

func TestVarint(t *testing.T) {
	for _, c := range []struct {
		v    uint64
		size int
	}{{0, 1}, {63, 1}, {64, 2}, {16383, 2}, {16384, 4}, {1<<30 - 1, 4}, {1 << 30, 8}, {1<<62 - 1, 8}} {
		b := appendVarint(nil, c.v)
		if len(b) != c.size {
			t.Errorf("%d: %d bytes, want %d", c.v, len(b), c.size)
		}
		if v, n := parseVarint(append(b, 0xff)); v != c.v || n != c.size {
			t.Errorf("%d: parsed %d in %d bytes", c.v, v, n)
		}
		if v, err := readVarint(bytes.NewReader(b)); v != c.v || err != nil {
			t.Errorf("%d: read %d %v", c.v, v, err)
		}
		if _, n := parseVarint(b[:len(b)-1]); c.size > 1 && n != 0 {
			t.Errorf("%d: parsed from %d bytes", c.v, len(b)-1)
		}
		if _, err := readVarint(bytes.NewReader(b[:len(b)-1])); c.size > 1 && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("%d: read cut: %v", c.v, err)
		}
	}
	if _, err := readVarint(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Errorf("nothing: %v", err)
	}
	// RFC 9000 §A.1's examples.
	for hexed, want := range map[string]uint64{"c2197c5eff14e88c": 151288809941952652, "9d7f3e7d": 494878333, "7bbd": 15293, "25": 37, "4025": 37} {
		b := make([]byte, len(hexed)/2)
		for i := range b {
			b[i] = byte(strings.Index("0123456789abcdef", hexed[2*i:2*i+1])<<4 | strings.Index("0123456789abcdef", hexed[2*i+1:2*i+2]))
		}
		if v, n := parseVarint(b); v != want || n != len(b) {
			t.Errorf("%s: %d in %d bytes", hexed, v, n)
		}
	}
}

func TestReadCapsuleHead(t *testing.T) {
	read := func(b []byte) (uint64, uint64, error) {
		return readCapsuleHead(bufio.NewReader(bytes.NewReader(b)))
	}
	if typ, n, err := read(appendVarint([]byte{capsuleDatagram}, capsuleMax)); typ != 0 || n != capsuleMax || err != nil {
		t.Errorf("the longest: %d %d %v", typ, n, err)
	}
	if _, _, err := read(appendVarint([]byte{capsuleDatagram}, capsuleMax+1)); !errors.Is(err, errRefused) {
		t.Errorf("one byte longer: %v", err)
	}
	// Of any type: a capsule the node does not know is skipped, but read.
	if _, _, err := read(appendVarint(appendVarint(nil, 0x1c0fe323), 1<<40)); !errors.Is(err, errRefused) {
		t.Errorf("an unknown one of a terabyte: %v", err)
	}
	if _, _, err := read(nil); !errors.Is(err, io.EOF) || errors.Is(err, errRefused) {
		t.Errorf("between capsules: %v", err)
	}
	for _, cut := range [][]byte{{0x40}, {capsuleDatagram}, {capsuleDatagram, 0x40}} {
		if _, _, err := read(cut); !errors.Is(err, errRefused) {
			t.Errorf("% x: %v", cut, err)
		}
	}
}

func TestQUICLong(t *testing.T) {
	initial := func(version uint32) []byte {
		b := binary.BigEndian.AppendUint32([]byte{0xc3}, version)
		return append(append(b, 8), make([]byte, 1200)...)
	}
	for name, c := range map[string]struct {
		b    []byte
		want bool
	}{
		"v1 Initial":                  {initial(1), true},
		"v2 Initial":                  {initial(0x6b3343cf), true},
		"v1 Handshake":                {append([]byte{0xe0}, initial(1)[1:]...), true},
		"a draft version":             {initial(0xff00001d), false},
		"version 0":                   {initial(0), false},
		"a short header":              {append([]byte{0x43}, initial(1)[1:]...), false},
		"a connection ID of 21 bytes": {append(initial(1)[:5], 21), false},
		"cut":                         {initial(1)[:5], false},
		"DNS":                         {[]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0}, false},
	} {
		if got := quicLong(c.b); got != c.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

// h3Datagrams is cmd/rayd's naiveH3: h3serve's stream, as naive takes it.
func h3Datagrams(ctx context.Context, w http.ResponseWriter) (func() H3Stream, bool) {
	take, ok := h3serve.Datagrams(ctx, w)
	if !ok {
		return nil, false
	}
	return func() H3Stream { return take() }, true
}

// udpOpts are how a test's server and client of datagrams differ from
// rayd's: the server's flag, whether it announces datagrams, whether the
// client does.
type udpOpts struct {
	off            bool   // udp=off
	noAnnounce     bool   // the server without SETTINGS_H3_DATAGRAM
	clientNoDgrams bool   // the client without SETTINGS_H3_DATAGRAM
	window         uint64 // the client's receive window of a stream, when not 0
}

// udpServer is a naive server with udp=on for the users pw (u5) and other
// (u6), over HTTP/3 as rayd naive serves it (h3serve, with datagrams),
// whose UDP may reach 127.0.0.1 and ::1 only, with the names echo.test
// (127.0.0.2 first, which is not allowed, then 127.0.0.1) and trap.test
// (127.0.0.2 only); and a client of it on one QUIC connection.
func udpServer(t *testing.T, setup func(*Server), o ...udpOpts) (*Server, *udpClient) {
	t.Helper()
	var opts udpOpts
	if len(o) > 0 {
		opts = o[0]
	}
	users := filepath.Join(t.TempDir(), "users.json")
	writeUsersNamed(t, users, map[string]string{"pw": "u5-ab12", "other": "u6"})
	answer, _ := site.Responder(site.Answer404, "")
	h := &Server{Users: &Users{Path: users}, Answer: answer, UDP: !opts.off, H3: h3Datagrams, Log: slog.New(slog.DiscardHandler)}
	h.Allow = func(a netip.Addr) bool { return a == netip.MustParseAddr("127.0.0.1") || a == netip.IPv6Loopback() }
	h.Resolve = func(_ context.Context, name string) ([]netip.Addr, error) {
		switch name {
		case "echo.test":
			return []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")}, nil
		case "trap.test":
			return []netip.Addr{netip.MustParseAddr("127.0.0.2")}, nil
		}
		return nil, errors.New("no such name")
	}
	if setup != nil {
		setup(h)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert := testCert(t)
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	so := h3Options()
	so.Datagrams = !opts.noAnnounce
	go func() {
		done <- h3serve.Serve(ctx, pc, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }, h, so)
	}()
	qconf := &quic.Config{MaxIdleTimeout: 30 * time.Second, EnableDatagrams: !opts.clientNoDgrams}
	if opts.window > 0 {
		qconf.InitialStreamReceiveWindow, qconf.MaxStreamReceiveWindow = opts.window, opts.window
	}
	qc, err := quic.DialAddr(t.Context(), pc.LocalAddr().String(), testClientTLS(http3.NextProtoH3), qconf)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http3.Transport{EnableDatagrams: !opts.clientNoDgrams}
	c := &udpClient{t: t, cc: tr.NewClientConn(qc)}
	t.Cleanup(func() {
		_ = qc.CloseWithError(0, "")
		stop()
		if err := <-done; err != nil {
			t.Errorf("h3serve.Serve: %v", err)
		}
	})
	return h, c
}

// udpClient opens connect-udp requests on one QUIC connection.
type udpClient struct {
	t  *testing.T
	cc *http3.ClientConn
}

// udpRequestOf says how a request differs from a client's of §3.2.
type udpRequestOf struct {
	password string // "pw" when empty; "-" none
	path     string // the template with %2A when empty
	protocol string // connect-udp when empty
	version  string // niko-udp: 1 when empty; "-" none
	noPad    bool
	early    [][]byte // capsules sent before the answer is read
	noRead   bool     // the client does not read the stream's capsules
}

// udpReq is a request of the client's: its answer, and what came of it,
// datagrams and capsules alike.
type udpReq struct {
	t    *testing.T
	rs   *http3.RequestStream
	resp *http.Response
	got  chan udpGot
	end  chan error // how the stream's content ended
}

type udpGot struct {
	from    netip.AddrPort
	data    []byte
	capsule bool
}

// open sends a request and reads its answer; for a 200 it takes what
// comes after it.
func (c *udpClient) open(o udpRequestOf) *udpReq {
	c.t.Helper()
	rs, err := c.cc.OpenRequestStream(c.t.Context())
	if err != nil {
		c.t.Fatal(err)
	}
	path := o.path
	if path == "" {
		path = "/.well-known/masque/udp/%2A/%2A/"
	}
	req, err := http.NewRequest(http.MethodConnect, "https://naive.test"+path, nil)
	if err != nil {
		c.t.Fatal(err)
	}
	req.Proto = ConnectUDP
	if o.protocol != "" {
		req.Proto = o.protocol
	}
	req.Header.Set(capsuleProtocol, "?1")
	if o.version != "-" {
		v := o.version
		if v == "" {
			v = udpVersion
		}
		req.Header.Set(UDPHeader, v)
	}
	if !o.noPad {
		req.Header.Set("Padding", paddingHeader())
	}
	if pw := o.password; pw != "-" {
		if pw == "" {
			pw = "pw"
		}
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("niko:"+pw)))
	}
	if err := rs.SendRequestHeader(req); err != nil {
		c.t.Fatal(err)
	}
	q := &udpReq{t: c.t, rs: rs, got: make(chan udpGot, 256), end: make(chan error, 1)}
	for _, b := range o.early {
		q.capsule(capsuleDatagram, b)
	}
	if q.resp, err = rs.ReadResponse(); err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { rs.CancelRead(0); rs.CancelWrite(0) })
	if q.resp.StatusCode != http.StatusOK {
		return q
	}
	go func() {
		for {
			b, err := rs.ReceiveDatagram(context.Background())
			if err != nil {
				return
			}
			q.take(b, false)
		}
	}()
	if o.noRead {
		return q
	}
	go func() {
		r := bufio.NewReader(rs)
		for {
			typ, n, err := readCapsuleHead(r)
			if err != nil {
				q.end <- err
				return
			}
			b := make([]byte, n)
			if _, err := io.ReadFull(r, b); err != nil {
				q.end <- err
				return
			}
			if typ == capsuleDatagram {
				q.take(b, true)
			}
		}
	}()
	return q
}

func (q *udpReq) take(b []byte, capsule bool) {
	dest, data, why := parseUDP(b)
	if why >= 0 || dest.name != "" {
		q.t.Errorf("an answer that does not read: % x", b)
		return
	}
	q.got <- udpGot{from: netip.AddrPortFrom(dest.ip, dest.port), data: data, capsule: capsule}
}

// send sends data to dest as a QUIC datagram.
func (q *udpReq) send(dest, data []byte) {
	q.t.Helper()
	if err := q.rs.SendDatagram(udpDatagram(dest, data)); err != nil {
		q.t.Fatal(err)
	}
}

// capsule sends a capsule of the type with the payload.
func (q *udpReq) capsule(typ uint64, payload []byte) {
	q.t.Helper()
	b := appendVarint(appendVarint(nil, typ), uint64(len(payload)))
	if _, err := q.rs.Write(append(b, payload...)); err != nil {
		q.t.Fatal(err)
	}
}

// recv is the next answer, within 5 s.
func (q *udpReq) recv() udpGot {
	q.t.Helper()
	select {
	case g := <-q.got:
		return g
	case <-time.After(5 * time.Second):
		q.t.Fatal("no answer")
		return udpGot{}
	}
}

// quiet checks that nothing comes for a while.
func (q *udpReq) quiet(d time.Duration) {
	q.t.Helper()
	select {
	case g := <-q.got:
		q.t.Fatalf("an answer from %v: %q", g.from, g.data)
	case <-time.After(d):
	}
}

// ended is how the stream's content ended, within 5 s: nil for the
// node's clean end.
func (q *udpReq) ended() error {
	q.t.Helper()
	select {
	case err := <-q.end:
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	case <-time.After(5 * time.Second):
		q.t.Fatal("the stream did not end")
		return nil
	}
}

// isReset reports a stream the node reset (H3_INTERNAL_ERROR).
func isReset(err error) bool {
	var h3err *http3.Error
	return errors.As(err, &h3err) && h3err.Remote && h3err.ErrorCode == http3.ErrCodeInternalError
}

// UDP as HTTP/3 datagrams (spec/naive-udp-v1.md §3.2): the answer's
// headers, datagrams to an address and to a name both ways, answers from
// where the request sent only, the policy's refusals, the user's bytes.
func TestUDPEcho(t *testing.T) {
	echo := udpEcho(t)
	trap, trapped := udpTrap(t, "127.0.0.2:0")
	h, c := udpServer(t, nil)
	q := c.open(udpRequestOf{})
	if q.resp.StatusCode != http.StatusOK || q.resp.Header.Get(UDPHeader) != "1" || q.resp.Header.Get(capsuleProtocol) != "?1" ||
		q.resp.Header.Get("Padding") == "" {
		t.Fatalf("answer %s %v", q.resp.Status, q.resp.Header)
	}
	if h.lim.count() != 1 {
		t.Fatalf("%d places taken", h.lim.count())
	}
	q.send(udpDest(echo), []byte("one"))
	if g := q.recv(); g.from != echo || string(g.data) != "one" || g.capsule {
		t.Fatalf("%+v", g)
	}
	// The echo's other port answered first: it was never sent to.
	// echo.test's first address is not allowed, its second is the echo's.
	q.send(udpDestName("echo.test", echo.Port()), []byte("named"))
	if g := q.recv(); g.from != echo || string(g.data) != "named" {
		t.Fatalf("%+v", g)
	}
	// Not allowed, by address or by name; unreadable; another Context ID;
	// the probe name with no probe: all dropped, the request lives on.
	q.send(udpDest(trap), []byte("trap"))
	q.send(udpDestName("trap.test", trap.Port()), []byte("trap"))
	q.send(udpDestName("nowhere.test", 9), []byte("x"))
	q.send(udpDestName(probe.Name, 9), []byte("x"))
	_ = q.rs.SendDatagram([]byte{udpContext, 9, 1, 2})
	_ = q.rs.SendDatagram(append([]byte{0}, udpDest(echo)...))
	q.quiet(200 * time.Millisecond)
	if trapped() != 0 {
		t.Fatalf("%d datagrams reached what is not allowed", trapped())
	}
	q.send(udpDest(echo), []byte("still"))
	if g := q.recv(); string(g.data) != "still" {
		t.Fatalf("%+v", g)
	}
	q.quiet(100 * time.Millisecond)
	// The bytes count for the user's name, payloads only: "one", "named",
	// "still" each way. An answer counts once the connection's sender
	// handed it to QUIC, which may come after the client has it.
	eventually(t, "the datagrams are not counted", func() bool { return h.UDPStats().Out == 3 && h.UDPStats().In == 3 })
	snap := h.Users.Snapshot()
	if got := snap.Users["u5-ab12"]; got.Up != 13 || got.Down != 13 {
		t.Fatalf("traffic %+v", got)
	}
	st := h.UDPStats()
	if st.Requests != 1 || st.In != 3 || st.Out != 3 || st.Dropped < 6 || st.CapsulesIn != 0 || st.CapsulesOut != 0 {
		t.Fatalf("stats %+v", st)
	}
	// Each drop by its reason: the stranger's answers (the echo's other
	// port), what is not allowed (two addresses, a name with no address,
	// the probe name without a probe), the unreadable, another Context ID.
	for kind, least := range map[int]int64{dropStranger: 3, dropDenied: 4, dropBad: 1, dropContext: 1} {
		if got := h.udp.dropped[kind].Load(); got < least {
			t.Errorf("dropped as %s: %d, want %d at least", dropNames[kind], got, least)
		}
	}
	// The client's end is the request's: the node ends it cleanly and gives
	// the place back.
	_ = q.rs.Close()
	if err := q.ended(); err != nil {
		t.Fatalf("ended with %v", err)
	}
	eventually(t, "the place is not given back", func() bool { return h.lim.count() == 0 })
}

// A datagram that does not fit a QUIC packet goes as a capsule, both ways
// (§4.4); the first capsules go before the answer (early data, §3.2); a
// capsule of a type the node does not know is skipped.
func TestUDPCapsules(t *testing.T) {
	echo := udpEcho(t)
	_, c := udpServer(t, nil)
	big := bytes.Repeat([]byte{'b'}, 1400)
	q := c.open(udpRequestOf{early: [][]byte{udpDatagram(udpDest(echo), []byte("early")), udpDatagram(udpDest(echo), big)}})
	if q.resp.StatusCode != http.StatusOK {
		t.Fatal(q.resp.Status)
	}
	// The two come back by two ways, a datagram and a capsule: in either
	// order.
	for range 2 {
		g := q.recv()
		want := map[int]bool{len("early"): false, len(big): true}
		if c, ok := want[len(g.data)]; !ok || c != g.capsule || g.from != echo || (len(g.data) == len(big) && !bytes.Equal(g.data, big)) {
			t.Fatalf("%d bytes, capsule %v, from %v", len(g.data), g.capsule, g.from)
		}
	}
	// Too large for the client's datagram: quic-go says so.
	var tooLarge *quic.DatagramTooLargeError
	if err := q.rs.SendDatagram(udpDatagram(udpDest(echo), big)); !errors.As(err, &tooLarge) {
		t.Fatalf("a datagram of %d bytes: %v", len(big), err)
	}
	q.capsule(0x2a, []byte("not known"))
	q.capsule(capsuleDatagram, udpDatagram(udpDest(echo), big[:1300]))
	if g := q.recv(); len(g.data) != 1300 || !g.capsule {
		t.Fatalf("%d bytes, capsule %v", len(g.data), g.capsule)
	}
	// The longest a client sends: 65 507 bytes, in a capsule. The echo's
	// answer is past what the node passes back (1500), and dropped.
	q.capsule(capsuleDatagram, udpDatagram(udpDest(echo), make([]byte, uotMaxPayload)))
	q.quiet(300 * time.Millisecond)
	q.send(udpDest(echo), []byte("after"))
	if g := q.recv(); string(g.data) != "after" {
		t.Fatalf("%q", g.data)
	}
	// A capsule longer than any is unreadable: the stream is reset, as
	// soon as its head is read (the rest of it may not be written).
	_, _ = q.rs.Write(appendVarint([]byte{capsuleDatagram}, capsuleMax+1))
	_, _ = q.rs.Write(make([]byte, capsuleMax+1))
	if err := q.ended(); !isReset(err) {
		t.Fatalf("a capsule of %d bytes: %v", capsuleMax+1, err)
	}
}

// The QUIC rule (§4.4): a pair whose first datagram is a QUIC packet of a
// long header takes capsules of 1252 bytes at most, either way.
func TestUDPQUICRule(t *testing.T) {
	echo := udpEcho(t)
	// A destination that answers each datagram with 1400 bytes.
	loud, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer loud.Close()
	go func() {
		buf := make([]byte, 70000)
		for {
			_, from, err := loud.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			_, _ = loud.WriteToUDPAddrPort(bytes.Repeat([]byte{'L'}, 1400), from)
		}
	}()
	loudAt := loud.LocalAddr().(*net.UDPAddr).AddrPort()
	initial := func(n int) []byte {
		b := binary.BigEndian.AppendUint32([]byte{0xc3}, 1)
		b = append(b, 8)
		return append(b, make([]byte, n-len(b))...)
	}
	_, c := udpServer(t, nil)
	q := c.open(udpRequestOf{})
	// QUIC's first: the pair is marked. A capsule past 1252 bytes does not
	// go; one of 1252 does, and its echo comes back as a capsule.
	q.capsule(capsuleDatagram, udpDatagram(udpDest(echo), initial(1250)))
	if g := q.recv(); len(g.data) != 1250 || !g.capsule {
		t.Fatalf("%d bytes, capsule %v", len(g.data), g.capsule)
	}
	q.capsule(capsuleDatagram, udpDatagram(udpDest(echo), initial(1253)))
	q.quiet(200 * time.Millisecond)
	q.capsule(capsuleDatagram, udpDatagram(udpDest(echo), initial(quicCapsuleMax)))
	if g := q.recv(); len(g.data) != quicCapsuleMax {
		t.Fatalf("%d bytes", len(g.data))
	}
	// The loud one, QUIC's first: its answers of 1400 bytes are dropped.
	q.send(udpDest(loudAt), initial(100))
	q.quiet(200 * time.Millisecond)
	// Another request, whose pair with it starts with no QUIC: its answers
	// come as capsules.
	q2 := c.open(udpRequestOf{})
	q2.send(udpDest(loudAt), []byte("hello"))
	if g := q2.recv(); len(g.data) != 1400 || !g.capsule || g.from != loudAt {
		t.Fatalf("%d bytes, capsule %v", len(g.data), g.capsule)
	}
}

// What a client that cannot use the feature gets is the site's answer, as
// any other request: no password or a wrong one, no Padding, the flag off,
// another path, version or :protocol, a client without HTTP/3 datagrams, a
// server that does not announce them (§3.3, §7).
func TestUDPSiteAnswer(t *testing.T) {
	site := func(t *testing.T, q *udpReq) {
		t.Helper()
		if q.resp.StatusCode != http.StatusNotFound || q.resp.Header.Get(UDPHeader) != "" || q.resp.Header.Get("Padding") != "" ||
			q.resp.Header.Get(capsuleProtocol) != "" {
			t.Fatalf("%s %v", q.resp.Status, q.resp.Header)
		}
	}
	// Another :protocol is never a tunnel, whatever its :authority.
	var dials atomic.Int32
	_, c := udpServer(t, func(h *Server) {
		h.Dial = func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("no")
		}
	})
	for name, o := range map[string]udpRequestOf{
		"no password":          {password: "-"},
		"a wrong password":     {password: "wrong"},
		"no Padding":           {noPad: true},
		"another path":         {path: "/.well-known/masque/udp/192.0.2.1/53/"},
		"a path of one target": {path: "/"},
		"no version":           {version: "-"},
		"version 2":            {version: "2"},
		"another protocol":     {protocol: "websocket"},
	} {
		t.Run(name, func(t *testing.T) { site(t, c.open(o)) })
	}
	// "*" itself is the same path as %2A.
	if q := c.open(udpRequestOf{path: "/.well-known/masque/udp/*/*/"}); q.resp.StatusCode != http.StatusOK {
		t.Fatalf("*: %s", q.resp.Status)
	}
	rs, err := c.cc.OpenRequestStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodConnect, "https://192.0.2.1:443/", nil)
	req.Proto = "websocket"
	req.Header.Set("Padding", paddingHeader())
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("niko:pw")))
	if err := rs.SendRequestHeader(req); err != nil {
		t.Fatal(err)
	}
	if resp, err := rs.ReadResponse(); err != nil || resp.StatusCode != http.StatusNotFound || dials.Load() != 0 {
		t.Fatalf("websocket to an address: %v %v, %d dials", resp, err, dials.Load())
	}
	for name, o := range map[string]udpOpts{
		"udp=off":                    {off: true},
		"udp=off, nothing announced": {off: true, noAnnounce: true},
		"a client without datagrams": {clientNoDgrams: true},
		"a server without datagrams": {noAnnounce: true},
	} {
		t.Run(name, func(t *testing.T) {
			h, c := udpServer(t, nil, o)
			site(t, c.open(udpRequestOf{}))
			if h.lim.count() != 0 || h.UDPStats() != (UDPStats{}) {
				t.Fatalf("%d places, %+v", h.lim.count(), h.UDPStats())
			}
		})
	}
}

// Places are UoT's (§7): 256 a user, UoT's streams and datagram requests
// together. At the limit with none quiet a request gets 429 before any
// 200, with Padding; another user does not; a quiet one gives way, and is
// reset.
func TestUDPPlaces(t *testing.T) {
	echo := udpEcho(t)
	h, c := udpServer(t, nil)
	q := c.open(udpRequestOf{})
	if q.resp.StatusCode != http.StatusOK {
		t.Fatal(q.resp.Status)
	}
	q.send(udpDest(echo), []byte("x"))
	q.recv()
	// The rest of the user's places, as UoT streams take them.
	for range uotPerUser - 1 {
		if s, _ := h.lim.uotTake("u5", func(error) {}); s == nil {
			t.Fatal("no place")
		}
	}
	over := c.open(udpRequestOf{})
	if over.resp.StatusCode != http.StatusTooManyRequests || over.resp.Header.Get("Padding") == "" || over.resp.Header.Get(UDPHeader) != "" {
		t.Fatalf("over the limit: %s %v", over.resp.Status, over.resp.Header)
	}
	if got := h.Refused()["u5"][refusedUDP]; got != 1 {
		t.Fatalf("refusals %v", h.Refused())
	}
	if q := c.open(udpRequestOf{password: "other"}); q.resp.StatusCode != http.StatusOK {
		t.Fatalf("another user: %s", q.resp.Status)
	}
	if st := h.UDPStats(); st.Requests != 2 || st.Refused != 1 {
		t.Fatalf("%+v", st)
	}
	// Quiet past quietAfter, the request gives way to a new one, and ends
	// cleanly, as an idle one does: the client must not take it for a
	// failure of the path.
	h.lim.mu.Lock()
	for s := range h.lim.users["u5"].slots {
		if s.stream != nil {
			s.last.Store(mono() - int64(quietAfter) - int64(time.Second))
		}
	}
	h.lim.mu.Unlock()
	if q := c.open(udpRequestOf{}); q.resp.StatusCode != http.StatusOK {
		t.Fatalf("with a quiet one: %s", q.resp.Status)
	}
	if err := q.ended(); err != nil {
		t.Fatalf("the quiet one ended with %v", err)
	}
	if got := h.Refused()["u5"][refusedEvicted]; got != 1 {
		t.Fatalf("evictions %v", h.Refused())
	}
}

// A user gone from the users file loses the requests: reset, not ended
// (§3.2); another user's stays.
func TestUDPRevoked(t *testing.T) {
	echo := udpEcho(t)
	h, c := udpServer(t, func(h *Server) { h.Users.every = 20 * time.Millisecond })
	go h.Users.Watch(t.Context())
	q := c.open(udpRequestOf{})
	other := c.open(udpRequestOf{password: "other"})
	q.send(udpDest(echo), []byte("x"))
	q.recv()
	time.Sleep(30 * time.Millisecond)
	writeNamed(t, h.Users.Path, map[string]string{"other": "u6"})
	if err := q.ended(); !isReset(err) {
		t.Fatalf("revoked: %v", err)
	}
	other.send(udpDest(echo), []byte("y"))
	if g := other.recv(); string(g.data) != "y" {
		t.Fatalf("%q", g.data)
	}
	eventually(t, "the place is kept", func() bool { return h.lim.count() == 1 })
}

// A request silent both ways for the idle time ends cleanly (§3.2): the
// client opens a new one for the next packet.
func TestUDPIdle(t *testing.T) {
	echo := udpEcho(t)
	h, c := udpServer(t, func(h *Server) { h.uotIdle = 400 * time.Millisecond })
	q := c.open(udpRequestOf{})
	start := time.Now()
	for range 4 {
		q.send(udpDest(echo), []byte("keep"))
		q.recv()
		time.Sleep(150 * time.Millisecond)
	}
	if err := q.ended(); err != nil {
		t.Fatalf("idle: %v", err)
	}
	if d := time.Since(start); d < 800*time.Millisecond {
		t.Fatalf("ended after %v, kept alive", d)
	}
	eventually(t, "the place is kept", func() bool { return h.lim.count() == 0 })
}

// The probe name reaches the probe's endpoint, on its port only (§7, §9.4):
// the one address of loopback a datagram reaches.
func TestUDPProbe(t *testing.T) {
	echo := udpEchoAt(t, netip.MustParseAddr("127.0.0.1"))
	_, c := udpServer(t, func(h *Server) {
		h.Allow = func(netip.Addr) bool { return false }
		h.Probe = echo.String()
	})
	q := c.open(udpRequestOf{})
	q.send(udpDestName(probe.Name, echo.Port()), []byte("probe"))
	if g := q.recv(); g.from != echo || string(g.data) != "probe" {
		t.Fatalf("%+v", g)
	}
	q.send(udpDestName(probe.Name, echo.Port()+1), []byte("other port"))
	q.send(udpDest(echo), []byte("by address"))
	q.quiet(200 * time.Millisecond)
}

// A client that reads none of its capsules (flow control) and destinations
// that send more than it takes: what waits for it is bounded, the oldest
// capsules and the newest datagrams dropped; at its end the stream's
// writer, stuck in a capsule, gives up within a second, the stream is
// reset and the place is given back.
func TestUDPClientNotReading(t *testing.T) {
	// A destination that answers each datagram with 64 of 1400 bytes:
	// capsules all.
	loud, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer loud.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			_, from, err := loud.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			for range 64 {
				_, _ = loud.WriteToUDPAddrPort(bytes.Repeat([]byte{'L'}, 1400), from)
			}
		}
	}()
	loudAt := loud.LocalAddr().(*net.UDPAddr).AddrPort()
	h, c := udpServer(t, nil, udpOpts{window: 16 << 10})
	q := c.open(udpRequestOf{noRead: true})
	for range 20 {
		q.send(udpDest(loudAt), []byte("go"))
		time.Sleep(5 * time.Millisecond)
	}
	eventually(t, "nothing dropped", func() bool { return h.UDPStats().Dropped > 0 })
	time.Sleep(200 * time.Millisecond)
	// At most the stream's window went, of 1280 capsules.
	if out := h.UDPStats().CapsulesOut; out > 16 {
		t.Fatalf("%d capsules past a window of 16 KiB", out)
	}
	start := time.Now()
	_ = q.rs.Close()
	eventually(t, "the place is held", func() bool { return h.lim.count() == 0 })
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("the place was held %v", d)
	}
	// The node reset the stream: its writer had half a capsule, maybe.
	_, err = q.rs.Read(make([]byte, 1))
	for err == nil {
		_, err = q.rs.Read(make([]byte, 64<<10))
	}
	if !isReset(err) {
		t.Fatalf("ended with %v", err)
	}
}
