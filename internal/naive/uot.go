package naive

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"
)

// UDP over TCP, version 2 (spec/naive-uot-v1.md): sing-box's naive outbound
// with udp_over_tcp sends CONNECT to UoTName and carries UDP in the stream
// (github.com/sagernet/sing/common/uot): a request, then length-prefixed
// packets, with each packet's address when the request does not fix one.
const (
	UoTName       = "sp.v2.udp-over-tcp.arpa"
	uotLegacyName = "sp.udp-over-tcp.arpa" // v1: not served

	uotIdle       = 2 * time.Minute
	uotMaxPayload = 65507 // a client's packet
	// uotMaxAnswer bounds the answers passed on: sing reads a UoT packet
	// into its copy buffer, the TUN's MTU and headroom (Niko: 1500 or 9000),
	// and a longer one ends the client's whole stream. Longer answers are
	// dropped, as a path with that MTU would drop them.
	uotMaxAnswer = 1500
	// One stream per UDP socket of an app (a browser holds tens), for all
	// the devices that share the user's password.
	uotPerUser    = 256
	uotPerService = 4096
	uotNames      = 64 // names a stream keeps (uotResolved)
	uotNameMiss   = 30 * time.Second
	uotLookupWait = 5 * time.Second // a packet's wait for its name
	uotPeers      = 4096            // addresses a stream sent to, whose answers come back

	// A user's new destinations, all streams together: each is a conntrack
	// entry the perimeter keeps. Name lookups are limits' (TCP's too).
	uotPeerRate, uotPeerBurst = 100, 200
)

// errRefused ends a stream with a reset: the client sees an error, not an
// empty answer.
var errRefused = errors.New("naive: refused")

// uotAddr is a destination as the client names it: an address or a name.
type uotAddr struct {
	ip   netip.Addr
	name string
	port uint16
}

func (a uotAddr) String() string {
	if a.name != "" {
		return net.JoinHostPort(a.name, fmt.Sprint(a.port))
	}
	return netip.AddrPortFrom(a.ip, a.port).String()
}

// readAddr reads an address: the SOCKS form in the request (ATYP 1, 3, 4),
// UoT's own in the packets (0, 1, 2 for IPv4, IPv6, a name).
func readAddr(r *bufio.Reader, socks bool) (uotAddr, error) {
	t, err := r.ReadByte()
	if err != nil {
		return uotAddr{}, err
	}
	var v4, v6, name byte = 0x00, 0x01, 0x02
	if socks {
		v4, v6, name = 0x01, 0x04, 0x03
	}
	var a uotAddr
	switch t {
	case v4:
		b, err := next(r, 4)
		if err != nil {
			return a, err
		}
		a.ip = netip.AddrFrom4([4]byte(b))
	case v6:
		b, err := next(r, 16)
		if err != nil {
			return a, err
		}
		a.ip = netip.AddrFrom16([16]byte(b)).Unmap()
	case name:
		n, err := r.ReadByte()
		if err != nil {
			return a, err
		}
		if n == 0 {
			return a, fmt.Errorf("%w: an empty name", errRefused)
		}
		b, err := next(r, int(n))
		if err != nil {
			return a, err
		}
		a.name = string(b)
	default:
		return a, fmt.Errorf("%w: address type %#x", errRefused, t)
	}
	p, err := next(r, 2)
	if err != nil {
		return a, err
	}
	a.port = binary.BigEndian.Uint16(p)
	return a, nil
}

// next is the reader's next n bytes, valid until it reads again: nothing is
// allocated per packet.
func next(r *bufio.Reader, n int) ([]byte, error) {
	b, err := r.Peek(n)
	if err != nil {
		return nil, err
	}
	_, _ = r.Discard(n)
	return b, nil
}

// appendAddr writes an answer's source in UoT's form.
func appendAddr(b []byte, ap netip.AddrPort) []byte {
	a := ap.Addr().Unmap()
	if a.Is4() {
		b = append(b, 0x00)
	} else {
		b = append(b, 0x01)
	}
	b = append(b, a.AsSlice()...)
	return binary.BigEndian.AppendUint16(b, ap.Port())
}

// uotStream is one UoT stream's state.
type uotStream struct {
	s       *Server
	ctx     context.Context
	slot    *uotSlot
	traffic *Traffic // the payloads sent and passed back count (nil: for nobody)
	names   map[string]uotResolved
	answers uotQueue // on their way to the client

	mu sync.Mutex
	// peers are where the client sent, and the pair's times: answers come
	// from these only, and each is a conntrack entry until it ends.
	peers  map[netip.AddrPort]pairTimes
	pruned time.Time
	aged   time.Time
}

// pairTimes are a pair's last packet sent, last either way (monoAt: the
// wall clock may step back, and a step back would hold every pair), and
// whether an answer came.
type pairTimes struct {
	sent, any int64
	answered  bool
}

// end is when conntrack lets the pair go: 30 s after the last packet sent
// while unanswered, 120 s after the last either way once answered.
func (p pairTimes) end() int64 {
	if p.answered {
		return p.any + int64(pairAnswered)
	}
	return p.sent + int64(pairUnanswered)
}

// age drops the pairs whose time ran out, once a second at most, and says
// how many are left.
func (u *uotStream) age(now time.Time) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	if now.Sub(u.aged) >= ageEvery {
		u.aged = now
		m := monoAt(now)
		for p, t := range u.peers {
			if m >= t.end() {
				delete(u.peers, p)
			}
		}
	}
	return len(u.peers)
}

// ends are when the stream's pairs end, for the user's journal.
func (u *uotStream) ends() []int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]int64, 0, len(u.peers))
	for _, t := range u.peers {
		out = append(out, t.end())
	}
	return out
}

// heard notes an answer from a pair, and reports whether it is one.
func (u *uotStream) heard(ap netip.AddrPort) bool {
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	now := monoAt(u.s.lim.clock())
	u.mu.Lock()
	defer u.mu.Unlock()
	t, ok := u.peers[ap]
	if ok {
		t.any, t.answered = now, true
		u.peers[ap] = t
	}
	return ok
}

// uotResolved is what a stream knows of a name until a moment, so that
// its packets to it neither wait nor take the process's cache's lock: an
// allowed address, until the shared cache's answer expires; or (ip not
// valid) a lookup that timed out or got SERVFAIL, which the shared cache
// does not keep (spec/conn-limit-v1.md §10.1, 8), for uotNameMiss.
// Anything else (no such name, no allowed address, no lookup token) is the
// shared cache's to know, or no one's.
type uotResolved struct {
	ip    netip.Addr
	until time.Time
}

func (u *uotStream) touch() { u.slot.last.Store(mono()) }

// sent notes a packet sent to a pair the stream has.
func (u *uotStream) sent(ap netip.AddrPort, now int64) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	t, ok := u.peers[ap]
	if ok {
		t.sent, t.any = now, now
		u.peers[ap] = t
	}
	return ok
}

// mayReach reports whether the client may send to ap: a destination it sent
// to before, or a new one while the stream has room and the user's limits
// let it (limits.newPair).
func (u *uotStream) mayReach(ap netip.AddrPort) bool {
	now := u.s.lim.clock()
	m := monoAt(now)
	if u.sent(ap, m) {
		return true
	}
	u.mu.Lock()
	if len(u.peers) >= uotPeers && now.Sub(u.pruned) > time.Second {
		// Those whose time ran out go, as conntrack forgets them.
		u.pruned = now
		for p, t := range u.peers {
			if m >= t.end() {
				delete(u.peers, p)
			}
		}
	}
	full := len(u.peers) >= uotPeers
	u.mu.Unlock()
	// Not under u.mu: limits ages the user's streams under its own lock.
	if full || !u.s.lim.newPair(u.slot) {
		return false
	}
	u.mu.Lock()
	u.peers[ap] = pairTimes{sent: m, any: m}
	u.mu.Unlock()
	return true
}

// resolve is the address a destination may be reached at: its own, or the
// first allowed one of its name; false for none.
func (u *uotStream) resolve(a uotAddr) (netip.AddrPort, bool) {
	if a.name == "" {
		return netip.AddrPortFrom(a.ip, a.port), a.port != 0 && u.s.allowed(a.ip)
	}
	if a.port == 0 {
		return netip.AddrPort{}, false
	}
	now := u.s.lim.clock()
	if n, ok := u.names[a.name]; ok && now.Before(n.until) {
		if n.ip.IsValid() {
			return netip.AddrPortFrom(n.ip, a.port), true
		}
		// A failure of the stream's own: the shared cache may know the name
		// since, no lookup otherwise.
		ip, until, ok := u.cachedName(a.name, now)
		if !ok {
			return netip.AddrPort{}, false
		}
		delete(u.names, a.name)
		if !until.IsZero() {
			u.remember(a.name, uotResolved{ip, until}, now)
		}
		return netip.AddrPortFrom(ip, a.port), ip.IsValid()
	}
	ip, until, ok := u.cachedName(a.name, now)
	if !ok {
		ip, until = u.lookup(a.name, now)
	}
	if !until.IsZero() {
		u.remember(a.name, uotResolved{ip, until}, now)
	}
	return netip.AddrPortFrom(ip, a.port), ip.IsValid()
}

// cachedName is a name's first allowed address in the process's cache, and
// until when the stream may keep it (zero: not); ok false when the cache
// does not know the name.
func (u *uotStream) cachedName(name string, now time.Time) (netip.Addr, time.Time, bool) {
	addrs, until, err, ok := u.s.names.get(name, now)
	if !ok {
		return netip.Addr{}, time.Time{}, false
	}
	ip, until := u.firstAllowed(addrs, until, err)
	return ip, until, true
}

// lookup looks a name up through the process's cache, a miss paying the
// user's lookup token: its first allowed address, and until when the
// stream may keep what came of it (zero: not).
func (u *uotStream) lookup(name string, now time.Time) (netip.Addr, time.Time) {
	if !domainName(name) {
		return netip.Addr{}, time.Time{}
	}
	ctx, cancel := context.WithTimeout(u.ctx, uotLookupWait)
	addrs, until, err := u.s.lookupNameUntil(ctx, u.slot.user, name, false)
	cancel()
	if err != nil && lookupFailed(err) {
		return netip.Addr{}, now.Add(uotNameMiss)
	}
	return u.firstAllowed(addrs, until, err)
}

func (u *uotStream) firstAllowed(addrs []netip.Addr, until time.Time, err error) (netip.Addr, time.Time) {
	if err != nil {
		return netip.Addr{}, time.Time{}
	}
	for _, ip := range addrs {
		if ip = ip.Unmap(); u.s.allowed(ip) {
			return ip, until
		}
	}
	return netip.Addr{}, time.Time{}
}

// remember keeps what the stream knows of a name: within uotNames, those
// expired going first.
func (u *uotStream) remember(name string, r uotResolved, now time.Time) {
	if _, ok := u.names[name]; !ok && len(u.names) >= uotNames {
		for n, x := range u.names {
			if !now.Before(x.until) {
				delete(u.names, n)
			}
		}
		if len(u.names) >= uotNames {
			return
		}
	}
	u.names[name] = r
}

// lookupFailed reports whether a lookup timed out or got SERVFAIL: what the
// shared cache does not keep and a stream does, for itself.
func lookupFailed(err error) bool {
	var d *net.DNSError
	if errors.As(err, &d) {
		return !d.IsNotFound && (d.IsTimeout || d.IsTemporary)
	}
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded)
}

func (s *Server) allowed(ip netip.Addr) bool {
	if s.Allow != nil {
		return s.Allow(ip)
	}
	return Public(ip)
}

func (s *Server) resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	if s.Resolve != nil {
		return s.Resolve(ctx, name)
	}
	return PublicResolver().LookupNetIP(ctx, "ip", fqdn(name))
}

// deadlines are the stream's, as http.ResponseController sets them.
type deadlines interface {
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// serveUoT carries the stream's UDP until the client ends it, the idle time
// runs out or ctx is done; errRefused when the stream must be reset. Only
// this goroutine's helper writes to the stream, and it is done when this
// returns.
func (s *Server) serveUoT(ctx context.Context, slot *uotSlot, traffic *Traffic, stream io.ReadWriter, dl deadlines) error {
	idle := s.uotIdle
	if idle == 0 {
		idle = uotIdle
	}
	// Small: a packet's data is read past the buffer.
	r := bufio.NewReaderSize(stream, 4<<10)
	// A client that does not say where to holds no slot past the idle time.
	_ = dl.SetReadDeadline(time.Now().Add(idle))
	connect, err := r.ReadByte()
	if err != nil {
		return nil
	}
	if connect > 1 {
		return fmt.Errorf("%w: isConnect %d", errRefused, connect)
	}
	dest, err := readAddr(r, true)
	if err != nil {
		if errors.Is(err, errRefused) {
			return err
		}
		return nil
	}
	_ = dl.SetReadDeadline(time.Time{})
	u := &uotStream{s: s, ctx: ctx, slot: slot, traffic: traffic, names: map[string]uotResolved{}, peers: map[netip.AddrPort]pairTimes{}}
	u.touch()
	s.lim.uotRun(slot, u)

	// The errors say why, never where: no destination in the log.
	var to netip.AddrPort
	if connect == 1 {
		var ok bool
		if to, ok = u.resolve(dest); !ok {
			return fmt.Errorf("%w: the destination is not allowed", errRefused)
		}
		if !u.mayReach(to) {
			return fmt.Errorf("%w: too many new destinations", errRefused)
		}
	}
	conn, err := uotSocket(ctx, to)
	if err != nil {
		return fmt.Errorf("%w: no socket", errRefused)
	}
	defer func() { _ = conn.Close() }()

	up := make(chan error, 1)
	go func() { up <- u.upstream(r, conn, to) }()
	// The answers: one helper takes them off the socket as they come, the
	// other writes them to the stream as the client takes them, and between
	// the two the newest ones wait (uotQueue).
	u.answers.wake = make(chan struct{}, 1)
	heard := make(chan struct{})
	go func() {
		defer close(heard)
		u.receive(conn, to)
	}()
	down := make(chan struct{})
	go func() {
		defer close(down)
		u.deliver(stream)
	}()

	tick := time.NewTicker(idle / 8)
	defer tick.Stop()
	var result error
loop:
	for {
		select {
		case err := <-up:
			if errors.Is(err, errRefused) {
				result = err
			}
			break loop
		case <-down:
			break loop
		case <-ctx.Done():
			break loop
		case <-tick.C:
			if mono()-slot.last.Load() > int64(idle) {
				break loop
			}
		}
	}
	// The socket goes: the helpers stop (the one that reads it closes the
	// queue of the one that writes); nothing writes to the stream once this
	// returns. A write the client does not take (flow control) would hold
	// the stream and its slot: past a second it fails.
	_ = conn.Close()
	<-heard
	select {
	case <-down:
	case <-time.After(time.Second):
		_ = dl.SetWriteDeadline(time.Now())
		<-down
		// Reset, not ended: HTTP/3 would close the stream cleanly.
		result = fmt.Errorf("%w: the client does not read", errRefused)
	}
	return result
}

// uotSocket is a stream's UDP socket: connected to to, or unconnected when
// to is not valid. Never with SO_BROADCAST.
func uotSocket(ctx context.Context, to netip.AddrPort) (*net.UDPConn, error) {
	if to.IsValid() {
		d := net.Dialer{Control: noBroadcast}
		c, err := d.DialContext(ctx, "udp", to.String())
		if err != nil {
			return nil, err
		}
		return c.(*net.UDPConn), nil
	}
	lc := net.ListenConfig{Control: noBroadcast}
	c, err := lc.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		return nil, err
	}
	return c.(*net.UDPConn), nil
}

// noBroadcast takes SO_BROADCAST, which Go sets on every UDP socket, off:
// a subnet's broadcast address looks public and would reach the node and
// its neighbours.
func noBroadcast(_, _ string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 0)
	}); err != nil {
		return err
	}
	return serr
}

// uotBufs hold a client's packet while it is sent.
var uotBufs = sync.Pool{New: func() any { return new([uotMaxPayload]byte) }}

// upstream sends the client's packets; errRefused for a stream to reset.
// to is the destination of a connected stream, invalid otherwise.
func (u *uotStream) upstream(r *bufio.Reader, conn *net.UDPConn, to netip.AddrPort) error {
	connected := to.IsValid()
	for {
		var dest uotAddr
		if !connected {
			var err error
			if dest, err = readAddr(r, false); err != nil {
				return err
			}
		}
		l, err := next(r, 2)
		if err != nil {
			return err
		}
		n := int(binary.BigEndian.Uint16(l))
		if n > uotMaxPayload {
			return fmt.Errorf("%w: a packet of %d bytes", errRefused, n)
		}
		buf := uotBufs.Get().(*[uotMaxPayload]byte)
		err = u.send(r, conn, to, dest, buf[:n])
		uotBufs.Put(buf)
		if err != nil {
			return err
		}
	}
}

// send reads one packet's data into b and sends it; an error ends the stream.
func (u *uotStream) send(r *bufio.Reader, conn *net.UDPConn, connectedTo netip.AddrPort, dest uotAddr, b []byte) error {
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	u.touch()
	var err error
	n := 0
	if connectedTo.IsValid() {
		// A destination that answers "unreachable" fails a write or two:
		// the stream lives on, as UDP would. A pair whose time ran out is a
		// new one, as conntrack's entry is.
		if u.mayReach(connectedTo) {
			n, err = conn.Write(b)
		}
	} else if to, ok := u.resolve(dest); ok && u.mayReach(to) {
		n, err = conn.WriteToUDPAddrPort(b, to)
	} // else not allowed, no address or no room: dropped
	if err == nil {
		u.traffic.addUp(n) // the payload, as it went to the destination
	}
	if errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// headRoom is the most an answer's head takes: an IPv6 source and the length.
const headRoom = 1 + 16 + 2 + 2

// uotQueued is how many answers a stream holds for a client that takes
// them slower than they come: about what the socket's receive buffer held
// of full packets (some 90 of 212 KiB) when the answers waited there, and a
// burst of a QUIC or a video sender. Behind a path of 10 Mbit/s that is
// 0.15 s of full packets.
const uotQueued = 128

// uotAnswer is an answer framed for the stream at buf[start:end], its head
// right before its data. One byte more than an answer may take: a longer
// one fills it, and goes.
type uotAnswer struct {
	buf        [headRoom + uotMaxAnswer + 1]byte
	start, end int
}

var uotAnswers = sync.Pool{New: func() any { return new(uotAnswer) }}

// uotQueue holds a stream's answers between the socket and the stream:
// the newest uotQueued, in order. When the client's path takes them slower
// than they come (its connection is congested, or it does not read), the
// oldest one goes for each new one. Waiting in the kernel's buffers instead,
// every answer came late by all that waited before it, without a bound that
// meant anything; UDP that is dropped is what its senders are made for, and
// of two answers the later one is worth more.
type uotQueue struct {
	wake chan struct{} // one place: there are answers, or none will come

	mu      sync.Mutex
	ring    [uotQueued]*uotAnswer
	head, n int
	closed  bool
	in      int64 // answers put
	dropped int64 // of them, the ones that gave way
}

// put adds an answer, the oldest giving way to it in a full queue.
func (q *uotQueue) put(a *uotAnswer) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		uotAnswers.Put(a)
		return
	}
	var old *uotAnswer
	if q.n == len(q.ring) {
		old = q.ring[q.head]
		q.head = (q.head + 1) % len(q.ring)
		q.n--
		q.dropped++
	}
	q.ring[(q.head+q.n)%len(q.ring)] = a
	q.n++
	q.in++
	q.mu.Unlock()
	if old != nil {
		uotAnswers.Put(old)
	}
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// take takes the oldest answers into batch, waiting for one: the first,
// and those after it that fit a write of room bytes with it. nil once the
// queue is closed.
func (q *uotQueue) take(batch []*uotAnswer, room int) []*uotAnswer {
	for {
		q.mu.Lock()
		for q.n > 0 {
			a := q.ring[q.head]
			if room -= a.end - a.start; room < 0 && len(batch) > 0 {
				break
			}
			batch = append(batch, a)
			q.ring[q.head] = nil
			q.head = (q.head + 1) % len(q.ring)
			q.n--
		}
		closed := q.closed
		q.mu.Unlock()
		if len(batch) > 0 {
			return batch
		}
		if closed {
			return nil
		}
		<-q.wake
	}
}

// close ends the queue: what waits in it goes, get gives nil.
func (q *uotQueue) close() {
	q.mu.Lock()
	q.closed = true
	for q.n > 0 {
		uotAnswers.Put(q.ring[q.head])
		q.ring[q.head] = nil
		q.head = (q.head + 1) % len(q.ring)
		q.n--
	}
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// receive takes the answers off the socket as they come and queues them
// for the stream, framed; it closes the queue when the socket ends. It
// never waits for the client: the socket's buffer stays empty, and what the
// client is late for is dropped in the queue, oldest first.
func (u *uotStream) receive(conn *net.UDPConn, connectedTo netip.AddrPort) {
	defer u.answers.close()
	connected := connectedTo.IsValid()
	var head [headRoom]byte
	a := uotAnswers.Get().(*uotAnswer)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(a.buf[headRoom:])
		if err != nil {
			var errno syscall.Errno
			if errors.As(err, &errno) {
				continue // an ICMP error on a connected socket: UDP goes on
			}
			uotAnswers.Put(a)
			return
		}
		if connected {
			from = connectedTo
		}
		if !u.heard(from) || n > uotMaxAnswer {
			continue
		}
		h := head[:0]
		if !connected {
			h = appendAddr(h, from)
		}
		h = binary.BigEndian.AppendUint16(h, uint16(n)) //nolint:gosec // G115: n ≤ uotMaxAnswer
		a.start, a.end = headRoom-len(h), headRoom+n
		copy(a.buf[a.start:headRoom], h)
		u.answers.put(a)
		a = uotAnswers.Get().(*uotAnswer)
	}
}

// uotBatch is the most one write to the stream carries: HTTP/2's largest
// frame unless the client asks for larger ones. The answers that wait
// together go in one write, one after another as the stream has them
// anyway (spec/naive-uot-v1.md §2: packets in a stream of bytes). HTTP/2
// gives each stream of a connection a frame in turn: a stream that sent an
// answer a turn had one packet for each 16 KiB of a download beside it.
const uotBatch = 16 << 10

var uotBatches = sync.Pool{New: func() any { return new([uotBatch]byte) }}

// deliver passes the queued answers on until the queue is closed or the
// stream takes no more: an answer alone in a write of its own (one padded
// frame while naive pads), those that waited together in one write of
// uotBatch at most. An answer counts, for the stream's idle time and for
// the user's bytes, when the client's side took it: one that only came
// does not keep the stream of a client that stopped reading.
func (u *uotStream) deliver(w io.Writer) {
	var room [uotQueued]*uotAnswer
	for {
		batch := u.answers.take(room[:0], uotBatch)
		if batch == nil {
			return
		}
		var err error
		if len(batch) == 1 {
			_, err = w.Write(batch[0].buf[batch[0].start:batch[0].end])
		} else {
			b := uotBatches.Get().(*[uotBatch]byte)
			n := 0
			for _, a := range batch {
				n += copy(b[n:], a.buf[a.start:a.end])
			}
			_, err = w.Write(b[:n])
			uotBatches.Put(b)
		}
		n := 0
		for i, a := range batch {
			n += a.end - headRoom
			uotAnswers.Put(a)
			room[i] = nil
		}
		if err != nil {
			return
		}
		u.touch()
		u.traffic.addDown(n) // the payloads, as they came from the destination
	}
}
