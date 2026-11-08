package naive

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// fakeNet is the network the node's ICMP sockets reach in the tests: a
// destination some hops away answers an echo with enough TTL, the router
// at the TTL (198.51.100.<hop>, 2001:db8::<hop>) says time exceeded for
// the rest. Nothing leaves the host.
type fakeNet struct {
	mu      sync.Mutex
	hops    map[netip.Addr]int  // destinations that answer, and how far
	unreach map[netip.Addr]byte // destinations the first router calls unreachable, with its code
	hold    bool                // answers wait for release
	held    []fakeAnswer
	sent    []fakeEcho
	conns   []*fakePing
}

type fakeEcho struct {
	dst     netip.Addr
	ttl     int
	seq     uint16 // the node's
	payload []byte
	v6      bool // the socket's family
}

type fakeAnswer struct {
	c    *fakePing
	ev   icmpEvent
	data []byte
}

type fakePing struct {
	net    *fakeNet
	v6     bool
	events chan fakeAnswer
	closed chan struct{}
	once   sync.Once
}

func newFakeNet() *fakeNet {
	return &fakeNet{hops: map[netip.Addr]int{}, unreach: map[netip.Addr]byte{}}
}

func (n *fakeNet) open(v6 bool) (icmpConn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := &fakePing{net: n, v6: v6, events: make(chan fakeAnswer, 1024), closed: make(chan struct{})}
	n.conns = append(n.conns, c)
	return c, nil
}

func router(v6 bool, hop int) netip.Addr {
	if v6 {
		return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: byte(hop)})
	}
	return netip.AddrFrom4([4]byte{198, 51, 100, byte(hop)})
}

func (c *fakePing) send(dst netip.Addr, ttl int, seq uint16, payload []byte) error {
	n := c.net
	n.mu.Lock()
	defer n.mu.Unlock()
	select {
	case <-c.closed:
		return net.ErrClosed
	default:
	}
	n.sent = append(n.sent, fakeEcho{dst: dst, ttl: ttl, seq: seq, payload: slices.Clone(payload), v6: c.v6})
	a := fakeAnswer{c: c, ev: icmpEvent{dst: dst, seq: seq}}
	hops, answers := n.hops[dst]
	if code, ok := n.unreach[dst]; ok {
		a.ev.kind, a.ev.code, a.ev.from = icmpUnreachable, code, router(c.v6, 1)
	} else if !answers {
		return nil // silent
	} else if ttl < hops {
		a.ev.kind, a.ev.from = icmpTimeExceeded, router(c.v6, ttl)
	} else {
		a.ev.kind, a.ev.from, a.data = icmpReply, dst, slices.Clone(payload)
	}
	if n.hold {
		n.held = append(n.held, a)
	} else {
		c.events <- a
	}
	return nil
}

func (c *fakePing) recv(b []byte) (icmpEvent, error) {
	select {
	case a := <-c.events:
		a.ev.n = copy(b[icmpHead:], a.data)
		return a.ev, nil
	case <-c.closed:
		return icmpEvent{}, net.ErrClosed
	}
}

func (c *fakePing) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (n *fakeNet) setHold() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.hold = true
}

// release lets the held answers come, the last first.
func (n *fakeNet) release() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for i := len(n.held) - 1; i >= 0; i-- {
		n.held[i].c.events <- n.held[i]
	}
	n.held, n.hold = nil, false
}

// inject makes the socket of the family get ev, as from the network.
func (n *fakeNet) inject(v6 bool, ev icmpEvent, data []byte) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, c := range n.conns {
		if c.v6 == v6 {
			c.events <- fakeAnswer{c: c, ev: ev, data: data}
			return
		}
	}
	panic("no socket of the family")
}

func (n *fakeNet) echoes() []fakeEcho {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.sent)
}

func (l *icmpLimits) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total
}

// icmpServer is a naive server with ICMP on, over the fake network; Public
// says which destinations are allowed, as on a node.
func icmpServer(t *testing.T, idle time.Duration) (*Server, *fakeNet, func(host string) (*http.Response, *paddedStream, func())) {
	t.Helper()
	fake := newFakeNet()
	h, connect := tunnelServer(t, func(s *Server) {
		s.ICMP, s.icmpIdle, s.icmpOpen = true, idle, fake.open
	})
	return h, fake, connect
}

// echoFrame is a client's echo; an IPv4 address in IPv6 goes as IPv6.
func echoFrame(dst netip.Addr, ttl byte, id, seq uint16, payload []byte) []byte {
	b := []byte{icmpEcho, 4}
	if dst.Is6() {
		b[1] = 6
	}
	b = append(b, dst.AsSlice()...)
	b = append(b, ttl)
	b = binary.BigEndian.AppendUint16(b, id)
	b = binary.BigEndian.AppendUint16(b, seq)
	b = binary.BigEndian.AppendUint16(b, uint16(len(payload)))
	return append(b, payload...)
}

// serverFrame is a frame the node sent.
type serverFrame struct {
	kind, code byte
	from       netip.Addr
	id, seq    uint16
	data       string
}

func (f serverFrame) String() string {
	return fmt.Sprintf("kind %d code %d from %s id %d seq %d data %q", f.kind, f.code, f.from, f.id, f.seq, f.data)
}

// readFrame reads the next frame, within 5 s.
func readFrame(t *testing.T, r io.Reader) serverFrame {
	t.Helper()
	type result struct {
		f   serverFrame
		err error
	}
	got := make(chan result, 1)
	go func() {
		var f serverFrame
		var h [3]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			got <- result{err: err}
			return
		}
		f.kind, f.code = h[0], h[1]
		size := map[byte]int{4: 4, 6: 16}[h[2]]
		if size == 0 {
			got <- result{err: fmt.Errorf("address family %d", h[2])}
			return
		}
		b := make([]byte, size+6)
		if _, err := io.ReadFull(r, b); err != nil {
			got <- result{err: err}
			return
		}
		f.from, _ = netip.AddrFromSlice(b[:size])
		f.id, f.seq = binary.BigEndian.Uint16(b[size:]), binary.BigEndian.Uint16(b[size+2:])
		data := make([]byte, binary.BigEndian.Uint16(b[size+4:]))
		_, err := io.ReadFull(r, data)
		f.data = string(data)
		got <- result{f, err}
	}()
	select {
	case x := <-got:
		if x.err != nil {
			t.Fatal(x.err)
		}
		return x.f
	case <-time.After(5 * time.Second):
		t.Fatal("no frame came back")
		return serverFrame{}
	}
}

func mtu(n int) string { return string(binary.BigEndian.AppendUint16(nil, uint16(n))) }

// ICMP through naive (spec/icmp-v1.md): replies, time exceeded and
// unreachable with the client's id and seq, the node's own answers
// (prohibited, too big), what is not passed on, resets, idle time.
//
// The wire's numbers, written apart from the code's constants:
const (
	wireReply, wireExceeded, wireUnreachable     = 1, 2, 3
	wireTooBig, wireProhibited4, wireProhibited6 = 4, 13, 1
)

func TestICMP(t *testing.T) {
	google, quad9, refused := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("1.1.1.1")
	cf := netip.MustParseAddr("2606:4700:4700::1111")
	h, fake, connect := icmpServer(t, time.Second)
	fake.hops[google], fake.hops[quad9], fake.hops[cf] = 10, 10, 8
	fake.unreach[refused] = 1

	_, s, done := connect(ICMPName + ":0")
	defer done()
	write := func(b []byte) {
		t.Helper()
		if _, err := s.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	expect := func(what string, want serverFrame) {
		t.Helper()
		if got := readFrame(t, s); got != want {
			t.Fatalf("%s:\n got %s\nwant %s", what, got, want)
		}
	}
	write([]byte{icmpVersion})

	write(echoFrame(google, 0, 0x1234, 1, []byte("ping")))
	expect("reply", serverFrame{wireReply, 0, google, 0x1234, 1, "ping"})
	write(echoFrame(google, 200, 0x1234, 2, nil))
	expect("reply with TTL 200", serverFrame{wireReply, 0, google, 0x1234, 2, ""})
	write(echoFrame(google, 3, 0x1234, 3, []byte("trace")))
	expect("time exceeded", serverFrame{wireExceeded, 0, router(false, 3), 0x1234, 3, ""})
	write(echoFrame(refused, 30, 7, 4, nil))
	expect("unreachable", serverFrame{wireUnreachable, 1, router(false, 1), 7, 4, ""})
	write(echoFrame(cf, 64, 9, 5, []byte("six")))
	expect("IPv6 reply", serverFrame{wireReply, 0, cf, 9, 5, "six"})
	write(echoFrame(cf, 2, 9, 6, nil))
	expect("IPv6 time exceeded", serverFrame{wireExceeded, 0, router(true, 2), 9, 6, ""})
	// The longest echo goes; a longer one is too big, with the largest IP
	// packet the node sends; the stream lives on.
	long := strings.Repeat("x", icmpMaxPayload)
	write(echoFrame(google, 64, 1, 7, []byte(long)))
	expect("the longest echo", serverFrame{wireReply, 0, google, 1, 7, long})
	write(echoFrame(google, 64, 1, 8, bytes.Repeat([]byte("y"), 1472)))
	expect("too big", serverFrame{wireUnreachable, wireTooBig, google, 1, 8, mtu(1480)})
	write(echoFrame(cf, 64, 1, 9, bytes.Repeat([]byte("y"), 65535)))
	expect("IPv6 too big", serverFrame{wireUnreachable, wireTooBig, cf, 1, 9, mtu(1500)})
	// Not public: prohibited, in the destination's name; nothing sent.
	for i, dst := range []string{"10.0.0.1", "127.0.0.1", "100.64.0.1", "192.168.1.1", "169.254.169.254", "255.255.255.255", "224.0.0.1", "0.0.0.0",
		"::1", "fe80::1", "fc00::1", "ff02::1", "64:ff9b::808:808", "2002:808:808::1", "::ffff:8.8.8.8", "::808:808"} {
		a := netip.MustParseAddr(dst)
		code := byte(wireProhibited4)
		if a.Is6() {
			code = wireProhibited6
		}
		write(echoFrame(a, 64, 2, uint16(i), []byte("no")))
		expect(dst, serverFrame{wireUnreachable, code, a, 2, uint16(i), ""})
		// Too big as well: prohibited first.
		write(echoFrame(a, 64, 2, uint16(i), bytes.Repeat([]byte("z"), 2000)))
		expect(dst+", too big", serverFrame{wireUnreachable, code, a, 2, uint16(i), ""})
	}
	type sent struct {
		dst string
		ttl int
		v6  bool
	}
	var got []sent
	seqs := map[uint16]bool{}
	for _, e := range fake.echoes() {
		got = append(got, sent{e.dst.String(), e.ttl, e.v6})
		seqs[e.seq] = true
	}
	want := []sent{{"8.8.8.8", 64, false}, {"8.8.8.8", 64, false}, {"8.8.8.8", 3, false}, {"1.1.1.1", 30, false},
		{cf.String(), 64, true}, {cf.String(), 2, true}, {"8.8.8.8", 64, false}}
	if !slices.Equal(got, want) || len(seqs) != len(want) {
		t.Fatalf("sent %v (%d seqs), want %v", got, len(seqs), want)
	}

	// The same seq of two ids, answered the other way round: each answer
	// to its own echo. The kernel puts its own ID in each echo: only the
	// node's seq tells them apart.
	fake.setHold()
	write(echoFrame(google, 64, 1, 7, []byte("a")))
	write(echoFrame(quad9, 64, 2, 7, []byte("b")))
	eventually(t, "echoes not sent", func() bool { return len(fake.echoes()) == len(want)+2 })
	fake.release()
	expect("the later echo first", serverFrame{wireReply, 0, quad9, 2, 7, "b"})
	expect("the earlier echo", serverFrame{wireReply, 0, google, 1, 7, "a"})

	// What answers no echo of the stream is not passed on: another
	// source, an error about another destination, an unknown seq, the
	// other family, an answer that came already.
	fake.setHold()
	write(echoFrame(google, 64, 3, 30, []byte("late")))
	eventually(t, "echo not sent", func() bool { return len(fake.echoes()) == len(want)+3 })
	ours := fake.echoes()[len(want)+2].seq
	fake.inject(false, icmpEvent{kind: icmpReply, from: quad9, dst: quad9, seq: ours}, []byte("spoof"))
	fake.inject(false, icmpEvent{kind: icmpTimeExceeded, from: router(false, 1), dst: quad9, seq: ours}, nil)
	fake.inject(false, icmpEvent{kind: icmpReply, from: google, dst: google, seq: ours + 1000}, nil)
	fake.inject(true, icmpEvent{kind: icmpReply, from: cf, dst: cf, seq: ours}, nil)
	fake.release()
	expect("the real answer", serverFrame{wireReply, 0, google, 3, 30, "late"})
	fake.inject(false, icmpEvent{kind: icmpReply, from: google, dst: google, seq: ours}, []byte("dup"))
	write(echoFrame(google, 64, 3, 31, []byte("next")))
	expect("after the strays", serverFrame{wireReply, 0, google, 3, 31, "next"})

	// Idle: the stream ends by itself, cleanly.
	if reset(t, s) {
		t.Fatal("an idle stream was reset")
	}
	done()

	// Resets: another version, a frame that cannot be read as one.
	for name, send := range map[string][]byte{
		"version 0": {0},
		"version 2": {2},
		"kind 2":    append([]byte{1}, append([]byte{2}, echoFrame(google, 64, 1, 1, nil)[1:]...)...),
		"af 5":      {1, icmpEcho, 5, 8, 8, 8, 8, 64, 0, 1, 0, 1, 0, 0},
		"af 0":      {1, icmpEcho, 0},
	} {
		_, s, done := connect(ICMPName + ":0")
		_, _ = s.Write(send)
		if !reset(t, s) {
			t.Errorf("%s: not reset", name)
		}
		done()
	}
	eventually(t, "streams still counted", func() bool { return h.icmp.count() == 0 })

	// ICMP off: the name resets the stream.
	_, off := tunnelServer(t, func(*Server) {})
	_, s, done = off(ICMPName + ":0")
	_, _ = s.Write(append([]byte{icmpVersion}, echoFrame(google, 64, 1, 1, nil)...))
	if !reset(t, s) {
		t.Error("ICMP off: not reset")
	}
	done()
}

// A user's streams: icmpPerUser at most, the next one reset; their slots
// come back.
func TestICMPStreamLimit(t *testing.T) {
	h, _, connect := icmpServer(t, time.Minute)
	var dones []func()
	for range icmpPerUser {
		_, s, done := connect(ICMPName + ":0")
		_, _ = s.Write([]byte{icmpVersion})
		dones = append(dones, done)
	}
	eventually(t, "streams not counted", func() bool { return h.icmp.count() == icmpPerUser })
	_, s, done := connect(ICMPName + ":0")
	_, _ = s.Write([]byte{icmpVersion})
	if !reset(t, s) {
		t.Error("over the user's limit: not reset")
	}
	done()
	for _, done := range dones {
		done()
	}
	eventually(t, "slots not given back", func() bool { return h.icmp.count() == 0 })
}

// A client that never says its version does not hold its slot past the
// idle time.
func TestICMPSilentClient(t *testing.T) {
	h, _, connect := icmpServer(t, 300*time.Millisecond)
	_, _, done := connect(ICMPName + ":0")
	defer done()
	eventually(t, "stream not counted", func() bool { return h.icmp.count() == 1 })
	eventually(t, "a silent stream held its slot", func() bool { return h.icmp.count() == 0 })
}

func TestICMPLimits(t *testing.T) {
	var l icmpLimits
	a, b := [32]byte{1}, [32]byte{2}
	for range icmpPerUser {
		if !l.take(a) {
			t.Fatal("under the user's limit")
		}
	}
	if l.take(a) {
		t.Fatal("over the user's limit")
	}
	if !l.take(b) {
		t.Fatal("another user")
	}
	l.put(a)
	if !l.take(a) {
		t.Fatal("after one ended")
	}
	// Echoes: the burst, then the rate.
	n := 0
	for range 3 * icmpBurst {
		if l.echo(a) {
			n++
		}
	}
	if n != icmpBurst || icmpBurst != 60 {
		t.Fatalf("echoes: %d, want the burst 60", n)
	}
	l.users[a].echoes.at = l.users[a].echoes.at.Add(-time.Second)
	n = 0
	for range 3 * icmpRate {
		if l.echo(a) {
			n++
		}
	}
	if n != icmpRate || icmpRate != 30 {
		t.Fatalf("echoes a second later: %d, want 30", n)
	}
	// Closing streams gives no tokens back; the users go once they have
	// refilled.
	for range icmpPerUser {
		l.put(a)
	}
	l.put(b)
	if !l.take(a) || l.echo(a) {
		t.Fatal("a user back got new tokens")
	}
	l.put(a)
	l.sweep(time.Now())
	if l.users[a] == nil || l.users[b] != nil {
		t.Fatalf("swept: a kept %v (spent its tokens), b kept %v (spent none)", l.users[a] != nil, l.users[b] != nil)
	}
	l.sweep(time.Now().Add(time.Minute))
	if len(l.users) != 0 || l.total != 0 {
		t.Fatalf("not forgotten: %d users, %d streams", len(l.users), l.total)
	}
	for i := range icmpPerService {
		if !l.take([32]byte{byte(i), byte(i >> 8), 7}) {
			t.Fatal("under the service's limit")
		}
	}
	if l.take([32]byte{9, 9, 9}) {
		t.Fatal("over the service's limit")
	}
}

// syncBuffer is a stream's client side that only collects.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Len()
}

func icmpTestStream(t *testing.T) (*icmpStream, *fakeNet, *syncBuffer) {
	t.Helper()
	fake := newFakeNet()
	s := &Server{icmpOpen: fake.open}
	user := [32]byte{1}
	if !s.icmp.take(user) {
		t.Fatal("no slot")
	}
	w := &syncBuffer{}
	st := &icmpStream{s: s, user: user, w: w, pending: map[uint16]icmpPend{}}
	t.Cleanup(func() { <-st.close() })
	return st, fake, w
}

// Every echo takes a token first: the node's own answers too, so they
// never outpace the echoes; with none, nothing is sent or answered.
func TestICMPPacing(t *testing.T) {
	st, fake, w := icmpTestStream(t)
	google := netip.MustParseAddr("8.8.8.8")
	for range 2 * icmpBurst {
		if err := st.echo(netip.MustParseAddr("10.0.0.1"), 64, 1, 1, nil, false); err != nil {
			t.Fatal(err)
		}
	}
	const prohibited = 3 + 4 + 6 // an IPv4 frame without data
	if w.Len() != icmpBurst*prohibited {
		t.Fatalf("answers: %d bytes, want %d frames", w.Len(), icmpBurst)
	}
	st.s.icmp.mu.Lock()
	st.s.icmp.users[st.user].echoes = bucket{0, time.Now()}
	st.s.icmp.mu.Unlock()
	_ = st.echo(google, 64, 1, 2, []byte("x"), false)
	_ = st.echo(google, 64, 1, 3, nil, true)
	if len(fake.echoes()) != 0 || w.Len() != icmpBurst*prohibited {
		t.Fatalf("without tokens: %d sent, %d bytes answered", len(fake.echoes()), w.Len())
	}
}

// icmpPending echoes wait at most; one waiting icmpWait is forgotten, and
// its late answer not passed on. The node's seqs skip those in use.
func TestICMPPending(t *testing.T) {
	st, fake, _ := icmpTestStream(t)
	google := netip.MustParseAddr("8.8.8.8") // silent: no answers
	refill := func() {
		st.s.icmp.mu.Lock()
		st.s.icmp.users[st.user].echoes = bucket{icmpBurst, time.Now()}
		st.s.icmp.mu.Unlock()
	}
	for i := range icmpPending + 1 {
		refill()
		_ = st.echo(google, 64, 1, uint16(i), nil, false)
	}
	if n := len(fake.echoes()); n != icmpPending || icmpPending != 64 {
		t.Fatalf("sent %d, want 64 waiting at most", n)
	}
	// Aged: forgotten when room is needed.
	age := func() {
		st.mu.Lock()
		for k, p := range st.pending {
			p.at -= int64(icmpWait) + 1
			st.pending[k] = p
		}
		st.mu.Unlock()
	}
	age()
	refill()
	_ = st.echo(google, 64, 1, 100, nil, false)
	if n := len(fake.echoes()); n != icmpPending+1 || len(st.pending) != 1 {
		t.Fatalf("after the wait: %d sent, %d waiting", n, len(st.pending))
	}
	// A late answer is forgotten, not passed on; one in time is.
	last := fake.echoes()[icmpPending]
	ev := icmpEvent{kind: icmpReply, from: google, dst: google, seq: last.seq}
	age()
	if _, ok := st.answered(ev); ok || len(st.pending) != 0 {
		t.Fatal("a late answer passed")
	}
	refill()
	_ = st.echo(google, 64, 5, 6, nil, false)
	ev.seq = fake.echoes()[icmpPending+1].seq
	if p, ok := st.answered(ev); !ok || p.id != 5 || p.seq != 6 {
		t.Fatalf("an answer in time: %v %+v", ok, p)
	}
	if _, ok := st.answered(ev); ok {
		t.Fatal("an answer passed twice")
	}
	// Wrapping round, the node's seq skips one still waiting.
	st.mu.Lock()
	st.seq = 65535
	st.pending[0] = icmpPend{dst: google, at: mono()}
	st.mu.Unlock()
	refill()
	_ = st.echo(google, 64, 1, 1, nil, false)
	if s := fake.echoes()[icmpPending+2].seq; s != 1 {
		t.Fatalf("seq %d, want 1 past the one waiting", s)
	}
}

// A stream whose client stopped reading is reset, not ended, whichever
// side writes: the node's own answers here.
func TestICMPStuckReset(t *testing.T) {
	fake := newFakeNet()
	s := &Server{icmpOpen: fake.open, icmpIdle: 200 * time.Millisecond}
	user := [32]byte{3}
	s.icmp.take(user)
	pr, pw := io.Pipe()
	defer pw.Close()
	go func() {
		_, _ = pw.Write(append([]byte{icmpVersion}, echoFrame(netip.MustParseAddr("10.0.0.1"), 64, 1, 1, nil)...))
	}()
	st := &stuckStream{Reader: pr, deadline: make(chan struct{})}
	if err := s.serveICMP(context.Background(), user, st, st); !errors.Is(err, errRefused) {
		t.Fatalf("a stuck stream ended with %v, not a reset", err)
	}
}

// errCmsg is the control message of an error from the error queue:
// sock_extended_err and the offender's sockaddr.
func errCmsg(level, typ int, origin, icmpType, code byte, offender []byte) []byte {
	data := make([]byte, 16, 16+len(offender))
	binary.NativeEndian.PutUint32(data, uint32(syscall.EHOSTUNREACH))
	data[4], data[5], data[6] = origin, icmpType, code
	data = append(data, offender...)
	b := make([]byte, unix.CmsgSpace(len(data)))
	l := unix.CmsgLen(len(data))
	if unix.SizeofCmsghdr == 16 {
		binary.NativeEndian.PutUint64(b, uint64(l))
		binary.NativeEndian.PutUint32(b[8:], uint32(level))
		binary.NativeEndian.PutUint32(b[12:], uint32(typ))
	} else {
		binary.NativeEndian.PutUint32(b, uint32(l))
		binary.NativeEndian.PutUint32(b[4:], uint32(level))
		binary.NativeEndian.PutUint32(b[8:], uint32(typ))
	}
	copy(b[unix.CmsgLen(0):], data)
	return b
}

func sockaddrBytes(a netip.Addr) []byte {
	if a.Is4() {
		b := make([]byte, unix.SizeofSockaddrInet4)
		binary.NativeEndian.PutUint16(b, unix.AF_INET)
		copy(b[4:], a.AsSlice())
		return b
	}
	b := make([]byte, unix.SizeofSockaddrInet6)
	binary.NativeEndian.PutUint16(b, unix.AF_INET6)
	copy(b[8:], a.AsSlice())
	return b
}

// The error queue's errors: time exceeded and unreachable for the client,
// the rest not; the router from SO_EE_OFFENDER, the destination from the
// address, the node's seq from the quoted echo.
func TestParseICMPError(t *testing.T) {
	r4, r6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
	to4 := &unix.SockaddrInet4{Addr: [4]byte{8, 8, 8, 8}}
	to6 := &unix.SockaddrInet6{Addr: netip.MustParseAddr("2606:4700:4700::1111").As16()}
	echo4, echo6 := []byte{8, 0, 0xaa, 0xbb, 0x12, 0x34, 0x56, 0x78}, []byte{128, 0, 0xaa, 0xbb, 0x12, 0x34, 0x56, 0x78}
	ip, ip6 := unix.IPPROTO_IP, unix.IPPROTO_IPV6
	for _, c := range []struct {
		name  string
		v6    bool
		quote []byte
		oob   []byte
		kind  byte
		code  byte
	}{
		{"time exceeded", false, echo4, errCmsg(ip, unix.IP_RECVERR, unix.SO_EE_ORIGIN_ICMP, 11, 0, sockaddrBytes(r4)), icmpTimeExceeded, 0},
		{"unreachable", false, echo4, errCmsg(ip, unix.IP_RECVERR, unix.SO_EE_ORIGIN_ICMP, 3, 13, sockaddrBytes(r4)), icmpUnreachable, 13},
		{"fragmentation needed", false, echo4, errCmsg(ip, unix.IP_RECVERR, unix.SO_EE_ORIGIN_ICMP, 3, 4, sockaddrBytes(r4)), icmpUnreachable, 4},
		{"parameter problem", false, echo4, errCmsg(ip, unix.IP_RECVERR, unix.SO_EE_ORIGIN_ICMP, 12, 0, sockaddrBytes(r4)), 0, 0},
		{"source quench", false, echo4, errCmsg(ip, unix.IP_RECVERR, unix.SO_EE_ORIGIN_ICMP, 4, 0, sockaddrBytes(r4)), 0, 0},
		{"local", false, echo4, errCmsg(ip, unix.IP_RECVERR, unix.SO_EE_ORIGIN_LOCAL, 11, 0, sockaddrBytes(r4)), 0, 0},
		{"no offender", false, echo4, errCmsg(ip, unix.IP_RECVERR, unix.SO_EE_ORIGIN_ICMP, 11, 0, nil), 0, 0},
		{"not an echo", false, []byte{0, 0, 0, 0, 0, 0, 0x56, 0x78}, errCmsg(ip, unix.IP_RECVERR, unix.SO_EE_ORIGIN_ICMP, 11, 0, sockaddrBytes(r4)), 0, 0},
		{"short quote", false, echo4[:6], errCmsg(ip, unix.IP_RECVERR, unix.SO_EE_ORIGIN_ICMP, 11, 0, sockaddrBytes(r4)), 0, 0},
		{"IPv6 time exceeded", true, echo6, errCmsg(ip6, unix.IPV6_RECVERR, unix.SO_EE_ORIGIN_ICMP6, 3, 0, sockaddrBytes(r6)), icmpTimeExceeded, 0},
		{"IPv6 unreachable", true, echo6, errCmsg(ip6, unix.IPV6_RECVERR, unix.SO_EE_ORIGIN_ICMP6, 1, 4, sockaddrBytes(r6)), icmpUnreachable, 4},
		{"IPv6 packet too big", true, echo6, errCmsg(ip6, unix.IPV6_RECVERR, unix.SO_EE_ORIGIN_ICMP6, 2, 0, sockaddrBytes(r6)), 0, 0},
		{"IPv6, an IPv4 error", true, echo6, errCmsg(ip, unix.IP_RECVERR, unix.SO_EE_ORIGIN_ICMP, 11, 0, sockaddrBytes(r4)), 0, 0},
		{"IPv6, an IPv4 echo", true, echo4, errCmsg(ip6, unix.IPV6_RECVERR, unix.SO_EE_ORIGIN_ICMP6, 3, 0, sockaddrBytes(r6)), 0, 0},
	} {
		to, router, dst := unix.Sockaddr(to4), r4, netip.MustParseAddr("8.8.8.8")
		if c.v6 {
			to, router, dst = to6, r6, netip.MustParseAddr("2606:4700:4700::1111")
		}
		ev := parseICMPError(c.v6, c.quote, c.oob, to)
		want := icmpEvent{}
		if c.kind != 0 {
			want = icmpEvent{kind: c.kind, code: c.code, from: router, dst: dst, seq: 0x5678}
		}
		if ev != want {
			t.Errorf("%s: %+v, want %+v", c.name, ev, want)
		}
	}
	// Two control messages: the error is found after another one.
	oob := append(errCmsg(ip, unix.IP_TTL, 0, 0, 0, nil), errCmsg(ip, unix.IP_RECVERR, unix.SO_EE_ORIGIN_ICMP, 11, 0, sockaddrBytes(r4))...)
	if ev := parseICMPError(false, echo4, oob, to4); ev.kind != icmpTimeExceeded {
		t.Errorf("after another control message: %+v", ev)
	}
}

func TestParseICMPReply(t *testing.T) {
	from := &unix.SockaddrInet4{Addr: [4]byte{8, 8, 8, 8}}
	m := []byte{0, 0, 0xaa, 0xbb, 0x12, 0x34, 0x56, 0x78, 'h', 'i'}
	if ev := parseICMPReply(false, m, from); ev != (icmpEvent{kind: icmpReply, from: netip.MustParseAddr("8.8.8.8"), dst: netip.MustParseAddr("8.8.8.8"), seq: 0x5678, n: 2}) {
		t.Errorf("reply: %+v", ev)
	}
	for name, c := range map[string]struct {
		v6 bool
		m  []byte
	}{
		"a request":         {false, append([]byte{8}, m[1:]...)},
		"short":             {false, m[:7]},
		"IPv6, an IPv4 one": {true, m},
	} {
		if ev := parseICMPReply(c.v6, c.m, from); ev.kind != 0 {
			t.Errorf("%s: %+v", name, ev)
		}
	}
	m[0] = 129
	if ev := parseICMPReply(true, m, &unix.SockaddrInet6{Addr: netip.IPv6Loopback().As16()}); ev.kind != icmpReply || ev.from != netip.IPv6Loopback() {
		t.Errorf("IPv6 reply: %+v", ev)
	}
}

// pingOrSkip opens a real ping socket, or skips the test: the test's group
// must be in net.ipv4.ping_group_range.
func pingOrSkip(t *testing.T, v6 bool) *pingSocket {
	t.Helper()
	c, err := openPing(v6)
	if err != nil {
		r, _ := os.ReadFile("/proc/sys/net/ipv4/ping_group_range")
		t.Skipf("no ICMP socket (%v): group %d, net.ipv4.ping_group_range %q; sysctl -w net.ipv4.ping_group_range='0 2147483647' lets this test run",
			err, os.Getgid(), strings.TrimSpace(string(r)))
	}
	t.Cleanup(func() { _ = c.Close() })
	return c.(*pingSocket)
}

// recvWithin reads the socket's next event, within 5 s.
func recvWithin(t *testing.T, p *pingSocket, b []byte) icmpEvent {
	t.Helper()
	_ = p.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		ev, err := p.recv(b)
		var errno syscall.Errno
		switch {
		case errors.As(err, &errno):
			continue
		case err != nil:
			t.Fatal(err)
		case ev.kind != 0:
			return ev
		}
	}
}

func sockopt(t *testing.T, p *pingSocket, level, opt int) int {
	t.Helper()
	v := -1
	if err := p.raw.Control(func(fd uintptr) { v, _ = unix.GetsockoptInt(int(fd), level, opt) }); err != nil {
		t.Fatal(err)
	}
	return v
}

// A real ping socket: errors to the queue, no broadcast, the TTL set, the
// echo and its reply with the node's seq (the kernel answers 127.0.0.1).
func TestPingSocket(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[v6], func(t *testing.T) {
			if v6 {
				if _, err := os.Stat("/proc/sys/net/ipv6"); err != nil {
					t.Skip("no IPv6 on this host")
				}
			}
			p := pingOrSkip(t, v6)
			dst, level, recverr, ttl := netip.MustParseAddr("127.0.0.1"), unix.IPPROTO_IP, unix.IP_RECVERR, unix.IP_TTL
			if v6 {
				dst, level, recverr, ttl = netip.IPv6Loopback(), unix.IPPROTO_IPV6, unix.IPV6_RECVERR, unix.IPV6_UNICAST_HOPS
			}
			if sockopt(t, p, level, recverr) != 1 || sockopt(t, p, unix.SOL_SOCKET, unix.SO_BROADCAST) != 0 {
				t.Fatal("not RECVERR, or SO_BROADCAST")
			}
			if err := p.send(dst, 7, 4242, []byte("hello")); err != nil {
				if v6 {
					t.Skipf("no IPv6 loopback: %v", err)
				}
				t.Fatal(err)
			}
			if got := sockopt(t, p, level, ttl); got != 7 {
				t.Fatalf("TTL %d, want 7", got)
			}
			b := make([]byte, icmpHead+icmpMaxPayload)
			ev := recvWithin(t, p, b)
			if ev.kind != icmpReply || ev.from != dst || ev.dst != dst || ev.seq != 4242 || string(b[icmpHead:icmpHead+ev.n]) != "hello" {
				t.Fatalf("reply %+v %q", ev, b[icmpHead:icmpHead+ev.n])
			}
		})
	}
}

// Errors through the real error queue: a raw socket (root) sends the ping
// socket time exceeded and unreachable from 127.0.0.1, quoting an echo of
// its to 203.0.113.9; nothing leaves the host.
func TestPingSocketErrors(t *testing.T) {
	p := pingOrSkip(t, false)
	raw, err := net.ListenPacket("ip4:icmp", "127.0.0.1")
	if err != nil {
		t.Skipf("no raw ICMP socket to forge errors with (%v): root runs this test", err)
	}
	defer raw.Close()
	var ident int
	_ = p.raw.Control(func(fd uintptr) {
		if sa, err := unix.Getsockname(int(fd)); err == nil {
			ident = sa.(*unix.SockaddrInet4).Port
		}
	})
	dst := netip.MustParseAddr("203.0.113.9")
	b := make([]byte, icmpHead+icmpMaxPayload)
	for _, c := range []struct {
		typ  icmp.Type
		code int
		kind byte
	}{
		{ipv4.ICMPTypeTimeExceeded, 0, icmpTimeExceeded},
		{ipv4.ICMPTypeDestinationUnreachable, 1, icmpUnreachable},
	} {
		// The quoted echo: its IP header and its first 8 bytes.
		inner := []byte{0x45, 0, 0, 28, 0, 0, 0, 0, 1, 1, 0, 0, 127, 0, 0, 1}
		inner = append(inner, dst.AsSlice()...)
		inner = append(inner, 8, 0, 0, 0, byte(ident>>8), byte(ident), 0x0b, 0xad)
		var body icmp.MessageBody = &icmp.TimeExceeded{Data: inner}
		if c.typ == ipv4.ICMPTypeDestinationUnreachable {
			body = &icmp.DstUnreach{Data: inner}
		}
		m, err := (&icmp.Message{Type: c.typ, Code: c.code, Body: body}).Marshal(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := raw.WriteTo(m, &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}); err != nil {
			t.Fatal(err)
		}
		ev := recvWithin(t, p, b)
		want := icmpEvent{kind: c.kind, code: byte(c.code), from: netip.MustParseAddr("127.0.0.1"), dst: dst, seq: 0x0bad}
		if ev != want {
			t.Fatalf("%v: %+v, want %+v", c.typ, ev, want)
		}
	}
}

// The whole way with real sockets: a client's echo to 127.0.0.1 (allowed
// here) comes back with its id and seq.
func TestICMPRealSocket(t *testing.T) {
	pingOrSkip(t, false)
	lo := netip.MustParseAddr("127.0.0.1")
	_, connect := tunnelServer(t, func(s *Server) {
		s.ICMP, s.Allow = true, func(a netip.Addr) bool { return a == lo }
	})
	_, s, done := connect(ICMPName + ":0")
	defer done()
	if _, err := s.Write(append([]byte{icmpVersion}, echoFrame(lo, 5, 0xbeef, 77, []byte("through naive"))...)); err != nil {
		t.Fatal(err)
	}
	if got := readFrame(t, s); got != (serverFrame{wireReply, 0, lo, 0xbeef, 77, "through naive"}) {
		t.Fatalf("reply %s", got)
	}
}
