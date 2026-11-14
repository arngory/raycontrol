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
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeNet is the network the node's ICMP sockets reach in the tests: a
// destination some hops away answers an echo with enough TTL, the router
// at the TTL (198.51.100.<hop>, 2001:db8::<hop>) says time exceeded for
// the rest. Nothing leaves the host.
type fakeNet struct {
	mu      sync.Mutex
	hops    map[netip.Addr]int    // destinations that answer, and how far
	unreach map[netip.Addr]byte   // destinations the first router calls unreachable, with its code
	pathMTU map[netip.Addr]int    // the node's path MTU there: a larger echo is not sent
	narrow  map[netip.Addr]uint32 // the next-hop MTU of the router at hop 2: it says too big to larger echoes
	hold    bool                  // answers wait for release
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
	return &fakeNet{hops: map[netip.Addr]int{}, unreach: map[netip.Addr]byte{}, pathMTU: map[netip.Addr]int{}, narrow: map[netip.Addr]uint32{}}
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
	size := 8 + len(payload) + 20
	if c.v6 {
		size += 20
	}
	if mtu, ok := n.pathMTU[dst]; ok && size > mtu {
		return errTooBig{mtu} // as the kernel with IP_PMTUDISC_DO
	}
	n.sent = append(n.sent, fakeEcho{dst: dst, ttl: ttl, seq: seq, payload: slices.Clone(payload), v6: c.v6})
	a := fakeAnswer{c: c, ev: icmpEvent{dst: dst, seq: seq}}
	hops, answers := n.hops[dst]
	mtu, narrow := n.narrow[dst]
	switch {
	case narrow && ttl >= 2 && size > int(mtu):
		a.ev.kind, a.ev.from, a.ev.mtu = icmpTooBig, router(c.v6, 2), mtu
	case n.unreach[dst] != 0:
		a.ev.kind, a.ev.code, a.ev.from = icmpUnreachable, n.unreach[dst], router(c.v6, 1)
	case !answers:
		return nil // silent
	case ttl < hops:
		a.ev.kind, a.ev.from = icmpTimeExceeded, router(c.v6, ttl)
	default:
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
// says which destinations and routers are allowed, as on a node.
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

// parseFrame reads one frame.
func parseFrame(r io.Reader) (serverFrame, error) {
	var f serverFrame
	var h [3]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return f, err
	}
	f.kind, f.code = h[0], h[1]
	size := map[byte]int{4: 4, 6: 16}[h[2]]
	if size == 0 {
		return f, fmt.Errorf("address family %d", h[2])
	}
	b := make([]byte, size+6)
	if _, err := io.ReadFull(r, b); err != nil {
		return f, err
	}
	f.from, _ = netip.AddrFromSlice(b[:size])
	f.id, f.seq = binary.BigEndian.Uint16(b[size:]), binary.BigEndian.Uint16(b[size+2:])
	data := make([]byte, binary.BigEndian.Uint16(b[size+4:]))
	_, err := io.ReadFull(r, data)
	f.data = string(data)
	return f, err
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
		f, err := parseFrame(r)
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

// The wire's numbers (spec/icmp-v1.md §2), written apart from the code's
// constants.
const (
	wireReply, wireExceeded, wireUnreachable, wireTooBig = 1, 2, 3, 4
	wireProhibited4, wireProhibited6                     = 13, 1
)

// ICMP through naive (spec/icmp-v1.md): replies, time exceeded,
// unreachable and packet too big with the client's id and seq, the node's
// own answers (prohibited, too big), what is not passed on (private
// routers among it), resets, idle time.
func TestICMP(t *testing.T) {
	overProtos(t, func(t *testing.T) {
		google, quad9, refused := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("1.1.1.1")
		cf := netip.MustParseAddr("2606:4700:4700::1111")
		small, narrow, narrow6 := netip.MustParseAddr("9.9.9.10"), netip.MustParseAddr("9.9.9.11"), netip.MustParseAddr("2606:4700:4700::1001")
		h, fake, connect := icmpServer(t, time.Second)
		fake.hops[google], fake.hops[quad9], fake.hops[cf] = 10, 10, 8
		fake.hops[small], fake.hops[narrow], fake.hops[narrow6] = 10, 10, 10
		fake.unreach[refused] = 1
		fake.pathMTU[small] = 1300
		fake.narrow[narrow], fake.narrow[narrow6] = 1400, 1280

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
		expect("too big", serverFrame{wireTooBig, 0, google, 1, 8, mtu(1480)})
		write(echoFrame(cf, 64, 1, 9, bytes.Repeat([]byte("y"), 65535)))
		expect("IPv6 too big", serverFrame{wireTooBig, 0, cf, 1, 9, mtu(1500)})
		// Larger than the node's path: too big with its MTU, from the
		// destination; a router's too big: from the router, with its MTU.
		write(echoFrame(small, 64, 1, 10, bytes.Repeat([]byte("p"), 1300)))
		expect("path too small", serverFrame{wireTooBig, 0, small, 1, 10, mtu(1300)})
		write(echoFrame(narrow, 64, 1, 11, bytes.Repeat([]byte("p"), 1400)))
		expect("a router's too big", serverFrame{wireTooBig, 0, router(false, 2), 1, 11, mtu(1400)})
		write(echoFrame(narrow6, 64, 1, 12, bytes.Repeat([]byte("p"), 1300)))
		expect("a router's IPv6 too big", serverFrame{wireTooBig, 0, router(true, 2), 1, 12, mtu(1280)})
		write(echoFrame(narrow, 64, 1, 13, []byte("fits")))
		expect("small enough", serverFrame{wireReply, 0, narrow, 1, 13, "fits"})
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
			{cf.String(), 64, true}, {cf.String(), 2, true}, {"8.8.8.8", 64, false},
			{"9.9.9.11", 64, false}, {narrow6.String(), 64, true}, {"9.9.9.11", 64, false}}
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
		// other family. Nor is an error from a router the node may not reach
		// (a private address, the node's loopback): such hops stay silent.
		// Nor an answer that came already.
		fake.setHold()
		write(echoFrame(google, 64, 3, 30, []byte("late")))
		eventually(t, "echo not sent", func() bool { return len(fake.echoes()) == len(want)+3 })
		ours := fake.echoes()[len(want)+2].seq
		fake.inject(false, icmpEvent{kind: icmpReply, from: quad9, dst: quad9, seq: ours}, []byte("spoof"))
		fake.inject(false, icmpEvent{kind: icmpTimeExceeded, from: router(false, 1), dst: quad9, seq: ours}, nil)
		fake.inject(false, icmpEvent{kind: icmpReply, from: google, dst: google, seq: ours + 1000}, nil)
		fake.inject(true, icmpEvent{kind: icmpReply, from: cf, dst: cf, seq: ours}, nil)
		for _, private := range []string{"10.1.2.3", "100.64.0.1", "192.168.0.1", "127.0.0.1"} {
			from := netip.MustParseAddr(private)
			fake.inject(false, icmpEvent{kind: icmpTimeExceeded, from: from, dst: google, seq: ours}, nil)
			fake.inject(false, icmpEvent{kind: icmpUnreachable, code: 1, from: from, dst: google, seq: ours}, nil)
			fake.inject(false, icmpEvent{kind: icmpTooBig, from: from, dst: google, seq: ours, mtu: 1400}, nil)
		}
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
	})
}

// A user's streams: icmpPerUser at most, the next one reset; their slots
// come back.
func TestICMPStreamLimit(t *testing.T) {
	overProtos(t, func(t *testing.T) {
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
	})
}

// A client that never says its version does not hold its slot past the
// idle time.
func TestICMPSilentClient(t *testing.T) {
	overProtos(t, func(t *testing.T) {
		h, _, connect := icmpServer(t, 300*time.Millisecond)
		_, _, done := connect(ICMPName + ":0")
		defer done()
		eventually(t, "stream not counted", func() bool { return h.icmp.count() == 1 })
		eventually(t, "a silent stream held its slot", func() bool { return h.icmp.count() == 0 })
	})
}

func TestICMPLimits(t *testing.T) {
	var l icmpLimits
	a, b := "u1", "u2"
	var as []*icmpUser
	for range icmpPerUser {
		u := l.take(a)
		if u == nil {
			t.Fatal("under the user's limit")
		}
		as = append(as, u)
	}
	if l.take(a) != nil {
		t.Fatal("over the user's limit")
	}
	ub := l.take(b)
	if ub == nil || ub == as[0] || as[0] != as[icmpPerUser-1] {
		t.Fatal("another user, or one user's streams apart")
	}
	u := as[0]
	l.put(u)
	if l.take(a) != u {
		t.Fatal("after one ended")
	}
	// Echoes: the burst, then the rate; the service's lock is not taken.
	l.mu.Lock()
	n := make(chan int, 1)
	go func() {
		k := 0
		for range 3 * icmpBurst {
			if u.echo() {
				k++
			}
		}
		n <- k
	}()
	select {
	case k := <-n:
		if k != icmpBurst || icmpBurst != 60 {
			t.Errorf("echoes: %d, want the burst 60", k)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an echo waits for the service's lock")
	}
	l.mu.Unlock()
	u.mu.Lock()
	u.echoes.at = u.echoes.at.Add(-time.Second)
	u.mu.Unlock()
	k := 0
	for range 3 * icmpRate {
		if u.echo() {
			k++
		}
	}
	if k != icmpRate || icmpRate != 30 {
		t.Fatalf("echoes a second later: %d, want 30", k)
	}
	// Closing streams gives no tokens back; the users go once they have
	// refilled.
	for range icmpPerUser {
		l.put(u)
	}
	l.put(ub)
	if u2 := l.take(a); u2 != u || u2.echo() {
		t.Fatal("a user back got new tokens")
	}
	l.put(u)
	l.sweep(time.Now())
	if l.users[a] == nil || l.users[b] != nil {
		t.Fatalf("swept: a kept %v (spent its tokens), b kept %v (spent none)", l.users[a] != nil, l.users[b] != nil)
	}
	l.sweep(time.Now().Add(time.Minute))
	if len(l.users) != 0 || l.total != 0 {
		t.Fatalf("not forgotten: %d users, %d streams", len(l.users), l.total)
	}
	for i := range icmpPerService {
		if l.take("u"+strconv.Itoa(1000+i)) == nil {
			t.Fatal("under the service's limit")
		}
	}
	if l.take("u999") != nil {
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

func (b *syncBuffer) frames(t *testing.T) []serverFrame {
	t.Helper()
	b.mu.Lock()
	r := bytes.NewReader(b.b.Bytes())
	b.mu.Unlock()
	var out []serverFrame
	for r.Len() > 0 {
		f, err := parseFrame(r)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, f)
	}
	return out
}

func icmpTestStream(t testing.TB) (*icmpStream, *fakeNet, *syncBuffer) {
	t.Helper()
	fake := newFakeNet()
	s := &Server{icmpOpen: fake.open}
	u := s.icmp.take("u1")
	if u == nil {
		t.Fatal("no slot")
	}
	w := &syncBuffer{}
	st := newICMPStream(s, u, w)
	t.Cleanup(func() { <-st.close() })
	return st, fake, w
}

// refill gives the stream's user a full bucket of echoes.
func refill(st *icmpStream) {
	st.user.mu.Lock()
	st.user.echoes = bucket{icmpBurst, time.Now()}
	st.user.mu.Unlock()
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
	st.user.mu.Lock()
	st.user.echoes = bucket{0, time.Now()}
	st.user.mu.Unlock()
	fake.pathMTU[google] = 100
	_ = st.echo(google, 64, 1, 2, []byte("x"), false)
	_ = st.echo(google, 64, 1, 3, nil, true)
	_ = st.echo(google, 64, 1, 4, make([]byte, 200), false)
	if len(fake.echoes()) != 0 || w.Len() != icmpBurst*prohibited {
		t.Fatalf("without tokens: %d sent, %d bytes answered", len(fake.echoes()), w.Len())
	}
}

// An echo larger than the node's path: "too big" with the path's MTU, in
// the destination's name, neither dropped nor left waiting.
func TestICMPPathTooBig(t *testing.T) {
	st, fake, w := icmpTestStream(t)
	dst, dst6 := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2606:4700:4700::1111")
	fake.pathMTU[dst], fake.pathMTU[dst6] = 1300, 1280
	_ = st.echo(dst, 64, 5, 6, make([]byte, 1300), false)
	_ = st.echo(dst6, 64, 5, 7, make([]byte, 1300), false)
	want := []serverFrame{{wireTooBig, 0, dst, 5, 6, mtu(1300)}, {wireTooBig, 0, dst6, 5, 7, mtu(1280)}}
	if got := w.frames(t); !slices.Equal(got, want) {
		t.Fatalf("frames %v, want %v", got, want)
	}
	if st.dropped.Load() != 0 || len(st.pending) != 0 || len(fake.echoes()) != 0 {
		t.Fatalf("dropped %d, waiting %d, sent %d", st.dropped.Load(), len(st.pending), len(fake.echoes()))
	}
}

// icmpPending echoes wait at most; one waiting icmpWait is forgotten, and
// its late answer not passed on. The node's seqs skip those in use.
func TestICMPPending(t *testing.T) {
	st, fake, _ := icmpTestStream(t)
	google := netip.MustParseAddr("8.8.8.8") // silent: no answers
	for i := range icmpPending + 1 {
		refill(st)
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
	refill(st)
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
	refill(st)
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
	refill(st)
	_ = st.echo(google, 64, 1, 1, nil, false)
	if s := fake.echoes()[icmpPending+2].seq; s != 1 {
		t.Fatalf("seq %d, want 1 past the one waiting", s)
	}
}

// Each stream's seqs start anywhere: a stranger guesses none.
func TestICMPSeqStart(t *testing.T) {
	firsts := map[uint16]bool{}
	for range 8 {
		st, fake, _ := icmpTestStream(t)
		_ = st.echo(netip.MustParseAddr("8.8.8.8"), 64, 1, 1, nil, false)
		firsts[fake.echoes()[0].seq] = true
	}
	if len(firsts) < 2 || firsts[1] && len(firsts) < 8 {
		t.Fatalf("first seqs of 8 streams: %v", firsts)
	}
}

// The idle times go by the monotonic clock: the wall clock may step.
func TestIdleClock(t *testing.T) {
	st, _, _ := icmpTestStream(t)
	u := &uotStream{slot: &uotSlot{}}
	u.touch()
	for name, last := range map[string]int64{"ICMP": st.last.Load(), "UoT": u.slot.last.Load()} {
		if d := mono() - last; d < 0 || d > int64(time.Minute) {
			t.Errorf("%s: last %d, mono %d", name, last, mono())
		}
	}
}

// A stream whose client stopped reading is reset, not ended, whichever
// side writes: the node's own answers here.
func TestICMPStuckReset(t *testing.T) {
	fake := newFakeNet()
	s := &Server{icmpOpen: fake.open, icmpIdle: 200 * time.Millisecond}
	u := s.icmp.take("u3")
	pr, pw := io.Pipe()
	defer pw.Close()
	go func() {
		_, _ = pw.Write(append([]byte{icmpVersion}, echoFrame(netip.MustParseAddr("10.0.0.1"), 64, 1, 1, nil)...))
	}()
	st := &stuckStream{Reader: pr, deadline: make(chan struct{})}
	if err := s.serveICMP(context.Background(), u, nil, st, st); !errors.Is(err, errRefused) {
		t.Fatalf("a stuck stream ended with %v, not a reset", err)
	}
}
