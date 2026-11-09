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
	"os/exec"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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
		if l.take([32]byte{byte(i), byte(i >> 8), 7}) == nil {
			t.Fatal("under the service's limit")
		}
	}
	if l.take([32]byte{9, 9, 9}) != nil {
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
	u := s.icmp.take([32]byte{1})
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
	u := &uotStream{}
	u.touch()
	for name, last := range map[string]int64{"ICMP": st.last.Load(), "UoT": u.last.Load()} {
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
	u := s.icmp.take([32]byte{3})
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

// errCmsg is the control message of an error from the error queue:
// sock_extended_err (info: a "too big"'s MTU) and the offender's sockaddr.
func errCmsg(level, typ int, origin, icmpType, code byte, info uint32, offender []byte) []byte {
	data := make([]byte, 16, 16+len(offender))
	binary.NativeEndian.PutUint32(data, uint32(syscall.EHOSTUNREACH))
	data[4], data[5], data[6] = origin, icmpType, code
	binary.NativeEndian.PutUint32(data[8:], info)
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

// The error queue's errors: time exceeded, unreachable and packet too big
// (IPv4's fragmentation needed among them, never as unreachable) for the
// client, the rest not; the router from SO_EE_OFFENDER, the MTU from
// ee_info, the destination from the address, the node's seq from the
// quoted echo.
func TestParseICMPError(t *testing.T) {
	r4, r6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
	to4 := &unix.SockaddrInet4{Addr: [4]byte{8, 8, 8, 8}}
	to6 := &unix.SockaddrInet6{Addr: netip.MustParseAddr("2606:4700:4700::1111").As16()}
	echo4, echo6 := []byte{8, 0, 0xaa, 0xbb, 0x12, 0x34, 0x56, 0x78}, []byte{128, 0, 0xaa, 0xbb, 0x12, 0x34, 0x56, 0x78}
	ip, ip6 := unix.IPPROTO_IP, unix.IPPROTO_IPV6
	v4err := func(origin, typ, code byte, info uint32) []byte {
		return errCmsg(ip, unix.IP_RECVERR, origin, typ, code, info, sockaddrBytes(r4))
	}
	v6err := func(typ, code byte, info uint32) []byte {
		return errCmsg(ip6, unix.IPV6_RECVERR, unix.SO_EE_ORIGIN_ICMP6, typ, code, info, sockaddrBytes(r6))
	}
	for _, c := range []struct {
		name  string
		v6    bool
		quote []byte
		oob   []byte
		kind  byte
		code  byte
		mtu   uint32
	}{
		{"time exceeded", false, echo4, v4err(unix.SO_EE_ORIGIN_ICMP, 11, 0, 0), wireExceeded, 0, 0},
		{"unreachable", false, echo4, v4err(unix.SO_EE_ORIGIN_ICMP, 3, 13, 0), wireUnreachable, 13, 0},
		{"port unreachable", false, echo4, v4err(unix.SO_EE_ORIGIN_ICMP, 3, 3, 0), wireUnreachable, 3, 0},
		{"fragmentation needed", false, echo4, v4err(unix.SO_EE_ORIGIN_ICMP, 3, 4, 1400), wireTooBig, 0, 1400},
		{"parameter problem", false, echo4, v4err(unix.SO_EE_ORIGIN_ICMP, 12, 0, 0), 0, 0, 0},
		{"source quench", false, echo4, v4err(unix.SO_EE_ORIGIN_ICMP, 4, 0, 0), 0, 0, 0},
		{"local", false, echo4, v4err(unix.SO_EE_ORIGIN_LOCAL, 11, 0, 0), 0, 0, 0},
		{"local too big", false, echo4, v4err(unix.SO_EE_ORIGIN_LOCAL, 0, 0, 1300), 0, 0, 0},
		{"no offender", false, echo4, errCmsg(ip, unix.IP_RECVERR, unix.SO_EE_ORIGIN_ICMP, 11, 0, 0, nil), 0, 0, 0},
		{"not an echo", false, []byte{0, 0, 0, 0, 0, 0, 0x56, 0x78}, v4err(unix.SO_EE_ORIGIN_ICMP, 11, 0, 0), 0, 0, 0},
		{"short quote", false, echo4[:6], v4err(unix.SO_EE_ORIGIN_ICMP, 11, 0, 0), 0, 0, 0},
		{"IPv6 time exceeded", true, echo6, v6err(3, 0, 0), wireExceeded, 0, 0},
		{"IPv6 unreachable", true, echo6, v6err(1, 4, 0), wireUnreachable, 4, 0},
		{"IPv6 packet too big", true, echo6, v6err(2, 0, 1280), wireTooBig, 0, 1280},
		{"IPv6 parameter problem", true, echo6, v6err(4, 0, 0), 0, 0, 0},
		{"IPv6, an IPv4 error", true, echo6, v4err(unix.SO_EE_ORIGIN_ICMP, 11, 0, 0), 0, 0, 0},
		{"IPv6, an IPv4 echo", true, echo4, v6err(3, 0, 0), 0, 0, 0},
	} {
		to, router, dst := unix.Sockaddr(to4), r4, netip.MustParseAddr("8.8.8.8")
		if c.v6 {
			to, router, dst = to6, r6, netip.MustParseAddr("2606:4700:4700::1111")
		}
		ev := parseICMPError(c.v6, c.quote, c.oob, to)
		want := icmpEvent{}
		if c.kind != 0 {
			want = icmpEvent{kind: c.kind, code: c.code, from: router, dst: dst, seq: 0x5678, mtu: c.mtu}
		}
		if ev != want {
			t.Errorf("%s: %+v, want %+v", c.name, ev, want)
		}
	}
	// Two control messages: the error is found after another one.
	oob := append(errCmsg(ip, unix.IP_TTL, 0, 0, 0, 0, nil), v4err(unix.SO_EE_ORIGIN_ICMP, 11, 0, 0)...)
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
		t.Skipf("no ICMP socket (%v): group %d, net.ipv4.ping_group_range %q; under unshare -n with ping_group_range '0 2147483647' this test runs",
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

// identOf is the kernel's ID in the socket's echoes: its port.
func identOf(t *testing.T, p *pingSocket) int {
	t.Helper()
	ident := -1
	_ = p.raw.Control(func(fd uintptr) {
		if sa, err := unix.Getsockname(int(fd)); err == nil {
			ident = sa.(*unix.SockaddrInet4).Port
		}
	})
	if ident < 0 {
		t.Fatal("no ident")
	}
	return ident
}

// rawICMP is a raw socket on from (a loopback address), to forge ICMP
// errors with; it skips the test without root.
func rawICMP(t *testing.T, from string) net.PacketConn {
	t.Helper()
	raw, err := net.ListenPacket("ip4:icmp", from)
	if err != nil {
		t.Skipf("no raw ICMP socket to forge errors with (%v): root runs this test", err)
	}
	t.Cleanup(func() { raw.Close() })
	return raw
}

// forgeError sends 127.0.0.1 an ICMP error from raw's address: typ and
// code, the next-hop MTU of a fragmentation needed, quoting an echo of
// ident's to dst with seq, from 127.0.0.1. Nothing leaves the host.
func forgeError(t *testing.T, raw net.PacketConn, typ, code byte, nextMTU uint16, ident int, dst netip.Addr, seq uint16) {
	t.Helper()
	forgeErrorAbout(t, raw, typ, code, nextMTU, ident, netip.MustParseAddr("127.0.0.1"), dst, seq)
}

// forgeErrorAbout is forgeError about an echo from src: the kernel learns a
// path MTU only for a source it routes from.
func forgeErrorAbout(t *testing.T, raw net.PacketConn, typ, code byte, nextMTU uint16, ident int, src, dst netip.Addr, seq uint16) {
	t.Helper()
	inner := []byte{0x45, 0, 0, 28, 0, 0, 0x40, 0, 1, 1, 0, 0}
	inner = append(inner, src.AsSlice()...)
	inner = append(inner, dst.AsSlice()...)
	inner = append(inner, 8, 0, 0, 0, byte(ident>>8), byte(ident), byte(seq>>8), byte(seq))
	m := []byte{typ, code, 0, 0, 0, 0}
	m = binary.BigEndian.AppendUint16(m, nextMTU)
	m = append(m, inner...)
	var sum uint32
	for i := 0; i+1 < len(m); i += 2 {
		sum += uint32(m[i])<<8 | uint32(m[i+1])
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(m[2:4], ^uint16(sum))
	if _, err := raw.WriteTo(m, &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}); err != nil {
		t.Fatal(err)
	}
}

// A real ping socket: errors to the queue, no fragments, no broadcast, the
// TTL set, the echo and its reply with the node's seq (the kernel answers
// 127.0.0.1).
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
			pmtu, do := unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO
			if v6 {
				dst, level, recverr, ttl = netip.IPv6Loopback(), unix.IPPROTO_IPV6, unix.IPV6_RECVERR, unix.IPV6_UNICAST_HOPS
				pmtu, do = unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO
			}
			if sockopt(t, p, level, recverr) != 1 || sockopt(t, p, level, pmtu) != do || sockopt(t, p, unix.SOL_SOCKET, unix.SO_BROADCAST) != 0 {
				t.Fatal("not RECVERR, not PMTUDISC_DO, or SO_BROADCAST")
			}
			b := make([]byte, icmpHead+icmpMaxPayload)
			for i, hops := range []int{7, 7, 3} {
				if err := p.send(dst, hops, uint16(4242+i), []byte("hello")); err != nil {
					if v6 {
						t.Skipf("no IPv6 loopback: %v", err)
					}
					t.Fatal(err)
				}
				if got := sockopt(t, p, level, ttl); got != hops {
					t.Fatalf("TTL %d, want %d", got, hops)
				}
				ev := recvWithin(t, p, b)
				if ev.kind != icmpReply || ev.from != dst || ev.dst != dst || ev.seq != uint16(4242+i) || string(b[icmpHead:icmpHead+ev.n]) != "hello" {
					t.Fatalf("reply %+v %q", ev, b[icmpHead:icmpHead+ev.n])
				}
			}
		})
	}
}

// Errors through the real error queue: a raw socket (root) sends the ping
// socket time exceeded, unreachable and fragmentation needed from
// 127.0.0.1, quoting an echo of its to 203.0.113.9; nothing leaves the
// host.
func TestPingSocketErrors(t *testing.T) {
	p := pingOrSkip(t, false)
	raw := rawICMP(t, "127.0.0.1")
	ident := identOf(t, p)
	dst, lo := netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("127.0.0.1")
	b := make([]byte, icmpHead+icmpMaxPayload)
	for _, c := range []struct {
		typ, code byte
		nextMTU   uint16
		want      icmpEvent
	}{
		{11, 0, 0, icmpEvent{kind: wireExceeded, from: lo, dst: dst, seq: 0x0bad}},
		{3, 1, 0, icmpEvent{kind: wireUnreachable, code: 1, from: lo, dst: dst, seq: 0x0bad}},
		{3, 4, 1400, icmpEvent{kind: wireTooBig, from: lo, dst: dst, seq: 0x0bad, mtu: 1400}},
	} {
		forgeError(t, raw, c.typ, c.code, c.nextMTU, ident, dst, 0x0bad)
		if ev := recvWithin(t, p, b); ev != c.want {
			t.Fatalf("type %d code %d: %+v, want %+v", c.typ, c.code, ev, c.want)
		}
	}
}

// An error the socket got and nobody read yet (sk_err) fails the next
// send once: the echo still goes out, and the error still comes.
func TestPingSocketSendAfterError(t *testing.T) {
	p := pingOrSkip(t, false)
	raw := rawICMP(t, "127.0.0.1")
	dst, lo := netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("127.0.0.1")
	b := make([]byte, icmpHead+icmpMaxPayload)
	for i := range 20 {
		forgeError(t, raw, 11, 0, 0, identOf(t, p), dst, uint16(i))
		time.Sleep(5 * time.Millisecond) // queued
		if err := p.send(lo, 64, uint16(1000+i), []byte("x")); err != nil {
			t.Fatalf("echo %d with an error queued: %v", i, err)
		}
		got := map[byte]uint16{}
		for len(got) < 2 {
			ev := recvWithin(t, p, b)
			got[ev.kind] = ev.seq
		}
		if got[icmpTimeExceeded] != uint16(i) || got[icmpReply] != uint16(1000+i) {
			t.Fatalf("echo %d: %v", i, got)
		}
	}
}

// Errors from routers the node may not reach are not passed on: a forged
// time exceeded and fragmentation needed from 127.0.0.2 (not allowed
// here) stay silent, the same from 127.0.0.3 (allowed) come.
func TestICMPPrivateRouters(t *testing.T) {
	pingOrSkip(t, false)
	allowed := netip.MustParseAddr("127.0.0.3")
	s := &Server{Allow: func(a netip.Addr) bool { return a == allowed }}
	u := s.icmp.take([32]byte{4})
	w := &syncBuffer{}
	st := newICMPStream(s, u, w)
	defer func() { <-st.close() }()
	p := st.conn(false).(*pingSocket)
	ident := identOf(t, p)
	dst := netip.MustParseAddr("203.0.113.9")
	s1, _ := st.expect(1, 10, dst)
	s2, _ := st.expect(1, 11, dst)
	s3, _ := st.expect(1, 12, dst)
	private, public := rawICMP(t, "127.0.0.2"), rawICMP(t, "127.0.0.3")
	forgeError(t, private, 11, 0, 0, ident, dst, s1)
	forgeError(t, private, 3, 4, 1400, ident, dst, s3)
	forgeError(t, public, 11, 0, 0, ident, dst, s2)
	forgeError(t, public, 3, 4, 1400, ident, dst, s3)
	eventually(t, "no answers", func() bool { return w.Len() >= 2*13 })
	time.Sleep(50 * time.Millisecond) // nothing more comes
	want := []serverFrame{{wireExceeded, 0, allowed, 1, 11, ""}, {wireTooBig, 0, allowed, 1, 12, mtu(1400)}}
	if got := w.frames(t); !slices.Equal(got, want) {
		t.Fatalf("frames %v, want %v", got, want)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.pending[s1]; !ok {
		t.Fatal("a private router's error took the echo")
	}
}

// The path's MTU, as the kernel sends: an echo larger than the node's
// interface, or than a router's fragmentation needed lowered it to, is not
// sent but answered "too big" with that MTU. A veth of MTU 1300 in a
// private network namespace.
func TestPingSocketTooBig(t *testing.T) {
	if os.Getenv("RAYCONTROL_NETNS_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("set RAYCONTROL_NETNS_TEST=1 and run as root under unshare -n")
	}
	for _, args := range [][]string{
		{"link", "add", "rcicmp0", "type", "veth", "peer", "name", "rcicmp1"},
		{"link", "set", "rcicmp0", "mtu", "1300", "up"},
		{"link", "set", "rcicmp1", "up"},
		{"addr", "add", "198.51.100.1/24", "dev", "rcicmp0"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "rcicmp0").Run() })
	p := pingOrSkip(t, false)
	dst := netip.MustParseAddr("198.51.100.9")
	var tb errTooBig
	if err := p.send(dst, 64, 1, make([]byte, icmpMaxPayload)); !errors.As(err, &tb) || tb.mtu != 1300 {
		t.Fatalf("larger than the interface: %v", err)
	}
	if err := p.send(dst, 64, 2, make([]byte, 1300-28)); err != nil {
		t.Fatalf("as large as the interface: %v", err)
	}
	// A router says 1200: the error comes with it, and the kernel learns it.
	raw := rawICMP(t, "127.0.0.1")
	forgeErrorAbout(t, raw, 3, 4, 1200, identOf(t, p), netip.MustParseAddr("198.51.100.1"), dst, 2)
	b := make([]byte, icmpHead+icmpMaxPayload)
	if ev := recvWithin(t, p, b); ev.kind != icmpTooBig || ev.mtu != 1200 || ev.seq != 2 {
		t.Fatalf("fragmentation needed: %+v", ev)
	}
	if err := p.send(dst, 64, 3, make([]byte, 1250)); !errors.As(err, &tb) || tb.mtu != 1200 {
		t.Fatalf("larger than the learned MTU: %v", err)
	}
	// Through a stream: the client learns it, the echo is no loss.
	s := &Server{Allow: func(a netip.Addr) bool { return a == dst }}
	w := &syncBuffer{}
	st := newICMPStream(s, s.icmp.take([32]byte{5}), w)
	defer func() { <-st.close() }()
	_ = st.echo(dst, 64, 7, 8, make([]byte, 1250), false)
	if got := w.frames(t); !slices.Equal(got, []serverFrame{{wireTooBig, 0, dst, 7, 8, mtu(1200)}}) || st.dropped.Load() != 0 {
		t.Fatalf("frames %v, dropped %d", got, st.dropped.Load())
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
