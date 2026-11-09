package naive

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// ping and traceroute through naive (spec/icmp-v1.md): a stream to
// ICMPName carries the client's echoes; the node sends them from its own
// unprivileged ICMP sockets with the client's TTL and passes back the
// replies, time exceeded, unreachable and packet too big.
const (
	ICMPName    = "icmp.niko.arpa"
	icmpVersion = 1

	icmpIdle = 2 * time.Minute
	// The longest echo data the node sends; a longer echo is answered
	// "packet too big" with the largest IP packet it sends (the client's
	// ping -s 1472 finds the MTU that way).
	icmpMaxPayload = 1452
	icmpMTU4       = icmpMaxPayload + 8 + 20
	icmpMTU6       = icmpMaxPayload + 8 + 40
	icmpMaxTTL     = 64 // and the TTL of 0
	// Echoes waiting for an answer, per stream; one unanswered for
	// icmpWait is forgotten (the client counts its own timeout).
	icmpPending = 64
	icmpWait    = 5 * time.Second
	// Streams: one per client core, a few cores per user's password.
	icmpPerUser    = 4
	icmpPerService = 1024
	// A user's echoes, all streams together: mtr sends a probe per hop a
	// second, and paths have 15 to 30 hops.
	icmpRate, icmpBurst = 30, 60
)

// Frame kinds, and the codes of the node's own answers.
const (
	icmpEcho         = 1 // the client's
	icmpReply        = 1
	icmpTimeExceeded = 2
	icmpUnreachable  = 3 // with the ICMP or ICMPv6 code as it came
	icmpTooBig       = 4 // packet too big: the data is the MTU, u16
	icmpMTUSize      = 2

	icmpProhibited4 = 13 // communication administratively prohibited
	icmpProhibited6 = 1  // the same in ICMPv6
)

// icmpHead is room for the longest head of a server frame: kind, code, af,
// an IPv6 address, id, seq, length. A socket reads the answer's data at
// b[icmpHead:], and the head goes right before it.
const icmpHead = 1 + 1 + 1 + 16 + 2 + 2 + 2

// icmpLimits counts the ICMP streams, per user and in all. The service's
// map is for a stream's start and end only: a stream keeps its user.
type icmpLimits struct {
	mu    sync.Mutex
	total int
	users map[[32]byte]*icmpUser
	swept time.Time
}

// icmpUser is a user's ICMP streams and echo tokens, under a lock of its
// own: each echo takes it, and nothing else. It is not swept while it has
// streams, and its tokens outlive the last one until they refill.
type icmpUser struct {
	mu      sync.Mutex
	streams int
	echoes  bucket
}

// take is the user's for a new stream; nil over the user's or the
// service's limit.
func (l *icmpLimits) take(user [32]byte) *icmpUser {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.swept) > 10*time.Second {
		l.sweep(now)
	}
	if l.total >= icmpPerService {
		return nil
	}
	u := l.users[user]
	if u == nil {
		if l.users == nil {
			l.users = map[[32]byte]*icmpUser{}
		}
		u = &icmpUser{echoes: bucket{icmpBurst, now}}
		l.users[user] = u
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.streams >= icmpPerUser {
		return nil
	}
	u.streams++
	l.total++
	return u
}

func (l *icmpLimits) put(u *icmpUser) {
	l.mu.Lock()
	defer l.mu.Unlock()
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.streams > 0 {
		u.streams--
		l.total--
	}
}

// sweep forgets the users without streams whose tokens have refilled.
func (l *icmpLimits) sweep(now time.Time) {
	l.swept = now
	for k, u := range l.users {
		u.mu.Lock()
		idle := u.streams == 0 && u.echoes.full(now, icmpRate, icmpBurst)
		u.mu.Unlock()
		if idle {
			delete(l.users, k)
		}
	}
}

// echo takes one of the user's tokens: false when there is none.
func (u *icmpUser) echo() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.echoes.take(time.Now(), icmpRate, icmpBurst)
}

// icmpConn is a stream's ICMP socket of one family: pingSocket on the node,
// a fake in tests.
type icmpConn interface {
	// send sends an echo request to dst with the node's seq, ttl hops out;
	// errTooBig when the path does not take it whole.
	send(dst netip.Addr, ttl int, seq uint16, payload []byte) error
	// recv reads what comes next: a reply's data lands at b[icmpHead:]. An
	// event of kind 0 is nothing to pass on.
	recv(b []byte) (icmpEvent, error)
	Close() error
}

// errTooBig is an echo larger than the path takes: the node does not
// fragment. mtu is the path's, as the kernel knows it.
type errTooBig struct{ mtu int }

func (e errTooBig) Error() string { return fmt.Sprintf("message too long for the path MTU %d", e.mtu) }

// icmpEvent is a reply or an error, as the node's socket got it.
type icmpEvent struct {
	kind, code byte
	from       netip.Addr // who answered: the destination, or a router
	dst        netip.Addr // the echo's destination
	seq        uint16     // the node's
	n          int        // the reply's data, at b[icmpHead:]
	mtu        uint32     // packet too big: the router's next-hop MTU
}

// icmpPend is an echo waiting for its answer: whose it was and where to.
type icmpPend struct {
	id, seq uint16 // the client's
	dst     netip.Addr
	at      int64 // mono
}

// icmpStream is one ICMP stream's state.
type icmpStream struct {
	s       *Server
	user    *icmpUser
	traffic *Traffic     // echo and reply data count (nil: for nobody)
	w       io.Writer    // the client's side: one frame per write
	last    atomic.Int64 // mono: the last frame either way

	echoes, answers, dropped atomic.Int64 // for the log: counts only

	mu      sync.Mutex
	conns   [2]icmpConn // IPv4, IPv6: opened with the first echo of each
	closed  bool
	writers sync.WaitGroup      // the sockets' readers and each write
	pending map[uint16]icmpPend // by the node's seq
	seq     uint16              // the node's last
}

func newICMPStream(s *Server, user *icmpUser, w io.Writer) *icmpStream {
	st := &icmpStream{s: s, user: user, w: w, pending: map[uint16]icmpPend{}}
	// The node's seqs start anywhere: a stranger guesses none.
	var b [2]byte
	_, _ = rand.Read(b[:])
	st.seq = binary.BigEndian.Uint16(b[:])
	st.touch()
	return st
}

func (st *icmpStream) touch() { st.last.Store(mono()) }

// serveICMP carries the stream's echoes until the client ends it, the idle
// time runs out or ctx is done; errRefused when the stream must be reset.
// Nothing writes to the stream once this returns.
func (s *Server) serveICMP(ctx context.Context, user *icmpUser, traffic *Traffic, stream io.ReadWriter, dl deadlines) error {
	idle := s.icmpIdle
	if idle == 0 {
		idle = icmpIdle
	}
	r := bufio.NewReaderSize(stream, 4<<10)
	// A client that does not say which version holds no slot past the
	// idle time.
	_ = dl.SetReadDeadline(time.Now().Add(idle))
	v, err := r.ReadByte()
	if err != nil {
		return nil
	}
	if v != icmpVersion {
		return fmt.Errorf("%w: ICMP version %d", errRefused, v)
	}
	_ = dl.SetReadDeadline(time.Time{})
	st := newICMPStream(s, user, stream)
	st.traffic = traffic

	up := make(chan error, 1)
	go func() { up <- st.upstream(r) }()
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
		case <-ctx.Done():
			break loop
		case <-tick.C:
			if mono()-st.last.Load() > int64(idle) {
				break loop
			}
		}
	}
	// The sockets go, their readers stop, and no write starts. A write the
	// client does not take (flow control) fails past a second, and the
	// stream is reset.
	writers := st.close()
	select {
	case <-writers:
	case <-time.After(time.Second):
		_ = dl.SetWriteDeadline(time.Now())
		<-writers
		result = fmt.Errorf("%w: the client does not read", errRefused)
	}
	// Counts only: no destination, no router in the log.
	s.logger().Debug("naive: ICMP stream ended", "echoes", st.echoes.Load(), "answers", st.answers.Load(), "dropped", st.dropped.Load())
	return result
}

// close closes the sockets; the channel closes once the writes under way
// are done. No socket opens and no write starts after it.
func (st *icmpStream) close() <-chan struct{} {
	st.mu.Lock()
	st.closed = true
	for _, c := range st.conns {
		if c != nil {
			_ = c.Close()
		}
	}
	st.mu.Unlock()
	done := make(chan struct{})
	go func() {
		st.writers.Wait()
		close(done)
	}()
	return done
}

// upstream reads the client's frames and sends their echoes; errRefused
// for a stream to reset: only a frame that cannot be read as one.
//
//	[u8 kind = 1][u8 af = 4 | 6][dst][u8 ttl][u16 id][u16 seq][u16 len][payload]
func (st *icmpStream) upstream(r *bufio.Reader) error {
	payload := make([]byte, icmpMaxPayload)
	for {
		kind, err := r.ReadByte()
		if err != nil {
			return err
		}
		if kind != icmpEcho {
			return fmt.Errorf("%w: frame kind %d", errRefused, kind)
		}
		af, err := r.ReadByte()
		if err != nil {
			return err
		}
		size := 0
		switch af {
		case 4:
			size = 4
		case 6:
			size = 16
		default:
			return fmt.Errorf("%w: address family %d", errRefused, af)
		}
		h, err := next(r, size+1+2+2+2)
		if err != nil {
			return err
		}
		dst, _ := netip.AddrFromSlice(h[:size])
		ttl := int(h[size])
		id := binary.BigEndian.Uint16(h[size+1:])
		seq := binary.BigEndian.Uint16(h[size+3:])
		n := int(binary.BigEndian.Uint16(h[size+5:]))
		// Longer than the node sends: read past, answered "too big".
		big := n > icmpMaxPayload
		if big {
			_, err = r.Discard(n)
			n = 0
		} else {
			_, err = io.ReadFull(r, payload[:n])
		}
		if err != nil {
			return err
		}
		st.touch()
		if ttl == 0 || ttl > icmpMaxTTL {
			ttl = icmpMaxTTL
		}
		if err := st.echo(dst, ttl, id, seq, payload[:n], big); err != nil {
			return err
		}
	}
}

// echo sends one echo, or answers it in the node's name: a destination not
// allowed is prohibited, an echo longer than the node or the path takes is
// too big. Each first takes one of the user's tokens, so that no answer
// outpaces the echoes. An error only when the stream cannot be written.
func (st *icmpStream) echo(dst netip.Addr, ttl int, id, seq uint16, payload []byte, big bool) error {
	if !st.user.echo() {
		st.dropped.Add(1)
		return nil
	}
	// IPv4 in IPv6 is no ICMPv6 destination; the rest as for TCP and UDP.
	if dst.Is4In6() || !st.s.allowed(dst) {
		code := byte(icmpProhibited4)
		if dst.Is6() {
			code = icmpProhibited6
		}
		var b [icmpHead]byte
		return st.answer(b[:], icmpUnreachable, code, dst, id, seq, 0)
	}
	if big {
		mtu := icmpMTU4
		if dst.Is6() {
			mtu = icmpMTU6
		}
		return st.tooBig(dst, id, seq, mtu)
	}
	c := st.conn(dst.Is6())
	if c == nil {
		st.dropped.Add(1)
		return nil
	}
	ours, ok := st.expect(id, seq, dst)
	if !ok {
		st.dropped.Add(1)
		return nil
	}
	if err := c.send(dst, ttl, ours, payload); err != nil {
		st.forget(ours)
		// Larger than the path: the node does not fragment, the client
		// learns the MTU (ping -M do).
		var tb errTooBig
		if errors.As(err, &tb) {
			return st.tooBig(dst, id, seq, tb.mtu)
		}
		// No route, a closed socket: the client times out, as it would.
		st.dropped.Add(1)
		return nil
	}
	st.echoes.Add(1)
	st.traffic.addUp(len(payload)) // the echo's data, as it went out
	return nil
}

// tooBig answers "packet too big" with the MTU.
func (st *icmpStream) tooBig(from netip.Addr, id, seq uint16, mtu int) error {
	var b [icmpHead + icmpMTUSize]byte
	binary.BigEndian.PutUint16(b[icmpHead:], uint16(min(max(mtu, 0), 0xffff))) //nolint:gosec // G115: clamped
	return st.answer(b[:], icmpTooBig, 0, from, id, seq, icmpMTUSize)
}

// answer writes a frame whose data is at b[icmpHead:icmpHead+n], its head
// right before it; net.ErrClosed once the stream is closing.
//
//	[u8 kind][u8 code][u8 af][from][u16 id][u16 seq][u16 len][payload]
func (st *icmpStream) answer(b []byte, kind, code byte, from netip.Addr, id, seq uint16, n int) error {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return net.ErrClosed
	}
	st.writers.Add(1)
	st.mu.Unlock()
	defer st.writers.Done()

	af := byte(6)
	if from.Is4() {
		af = 4
	}
	var head [icmpHead]byte
	h := append(head[:0], kind, code, af)
	h = append(h, from.AsSlice()...)
	h = binary.BigEndian.AppendUint16(h, id)
	h = binary.BigEndian.AppendUint16(h, seq)
	h = binary.BigEndian.AppendUint16(h, uint16(n)) //nolint:gosec // G115: n ≤ icmpMaxPayload
	start := icmpHead - len(h)
	copy(b[start:icmpHead], h)
	st.touch()
	if _, err := st.w.Write(b[start : icmpHead+n]); err != nil {
		return err
	}
	st.answers.Add(1)
	return nil
}

// conn is the stream's socket for the family, opened (and its reader
// started) with the family's first echo; nil when it does not open.
func (st *icmpStream) conn(v6 bool) icmpConn {
	i := 0
	if v6 {
		i = 1
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.conns[i] != nil || st.closed {
		return st.conns[i]
	}
	open := st.s.icmpOpen
	if open == nil {
		open = openPing
	}
	c, err := open(v6)
	if err != nil {
		// ping_group_range without the service's group, no IPv6 on the
		// node: each echo of the family is dropped.
		st.s.icmpWarn.note(st.s.logger(), err)
		return nil
	}
	st.conns[i] = c
	st.writers.Add(1)
	go func() {
		defer st.writers.Done()
		st.downstream(c)
	}()
	return c
}

// expect takes a seq of the node's for the client's echo: false when the
// stream has icmpPending echoes waiting.
func (st *icmpStream) expect(id, seq uint16, dst netip.Addr) (uint16, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := mono()
	if len(st.pending) >= icmpPending {
		for k, p := range st.pending {
			if now-p.at > int64(icmpWait) {
				delete(st.pending, k)
			}
		}
		if len(st.pending) >= icmpPending {
			return 0, false
		}
	}
	for {
		st.seq++
		if _, ok := st.pending[st.seq]; !ok {
			break
		}
	}
	st.pending[st.seq] = icmpPend{id: id, seq: seq, dst: dst, at: now}
	return st.seq, true
}

func (st *icmpStream) forget(seq uint16) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.pending, seq)
}

// answered finds whose echo an event answers, and forgets it: an answer
// comes once, for an echo still waiting, about its own destination.
func (st *icmpStream) answered(ev icmpEvent) (icmpPend, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	p, ok := st.pending[ev.seq]
	if !ok || p.dst != ev.dst {
		return p, false
	}
	delete(st.pending, ev.seq)
	return p, mono()-p.at <= int64(icmpWait)
}

// downstream passes a socket's answers on, each in one write (one padded
// frame while naive pads), until the socket closes.
func (st *icmpStream) downstream(c icmpConn) {
	buf := make([]byte, icmpHead+icmpMaxPayload)
	for {
		ev, err := c.recv(buf)
		if err != nil {
			var errno syscall.Errno
			if errors.As(err, &errno) {
				continue
			}
			return
		}
		switch {
		case ev.kind == 0 || ev.n > icmpMaxPayload || (ev.kind != icmpReply && ev.n != 0):
			continue
		case ev.kind != icmpReply && !st.s.allowed(ev.from):
			// A router with a private address, the node itself: silent,
			// as the destinations they stand for would be.
			continue
		}
		p, ok := st.answered(ev)
		if !ok {
			continue
		}
		n := ev.n
		if ev.kind == icmpTooBig {
			binary.BigEndian.PutUint16(buf[icmpHead:], uint16(min(ev.mtu, 0xffff))) //nolint:gosec // G115: clamped
			n = icmpMTUSize
		}
		if err := st.answer(buf, ev.kind, ev.code, ev.from, p.id, p.seq, n); err != nil {
			return
		}
		if ev.kind == icmpReply {
			st.traffic.addDown(n) // a reply's data, as it came back
		}
	}
}

func (s *Server) logger() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.DiscardHandler)
}

// icmpWarn says, at most once a minute, that ICMP sockets do not open:
// usually net.ipv4.ping_group_range without the service's group.
type icmpWarn struct {
	mu     sync.Mutex
	last   time.Time
	missed int
}

func (w *icmpWarn) note(log *slog.Logger, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.missed++
	if time.Since(w.last) < time.Minute {
		return
	}
	log.Warn("naive: ICMP sockets do not open (is the service's group in net.ipv4.ping_group_range? rayctl apply widens it)",
		"count", w.missed, "err", err)
	w.last, w.missed = time.Now(), 0
}

// pingSocket is an unprivileged ICMP socket (SOCK_DGRAM with IPPROTO_ICMP
// or IPPROTO_ICMPV6, "ping sockets"): no raw sockets and no CAP_NET_RAW,
// but the process's group must be in net.ipv4.ping_group_range (IPv6
// too). The kernel puts its own ID in each echo (the socket's port) and
// passes it only the replies with that ID; errors come to the error queue.
// One goroutine sends, another receives: each has its own fields.
type pingSocket struct {
	v6  bool
	c   *net.UDPConn
	raw syscall.RawConn

	// send's: the echo as it goes (its header, then the data), the TTL
	// set last and the one to set.
	out          [8 + icmpMaxPayload]byte
	ttl, nextTTL int
	setTTL       func(fd uintptr) // made once: no closure per echo
	ttlErr       error

	// recv's: the read made once, where it reads to and what it found;
	// the error queue's control data, and the echo it quotes (the
	// kernel's ID and the node's seq are in its first 8 bytes).
	read  func(fd uintptr) bool
	rb    []byte
	ev    icmpEvent
	rerr  error
	oob   [128]byte
	quote [8]byte
}

// openPing opens a ping socket. It is made as icmp.ListenPacket makes one
// ("udp4", "udp6"), but kept as a *net.UDPConn: the error queue needs the
// descriptor, which icmp.PacketConn does not give.
func openPing(v6 bool) (icmpConn, error) {
	family, proto, level := unix.AF_INET, unix.IPPROTO_ICMP, unix.IPPROTO_IP
	recverr, pmtu, dontFrag := unix.IP_RECVERR, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO
	var bound unix.Sockaddr = &unix.SockaddrInet4{}
	if v6 {
		family, proto, level = unix.AF_INET6, unix.IPPROTO_ICMPV6, unix.IPPROTO_IPV6
		recverr, pmtu, dontFrag = unix.IPV6_RECVERR, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO
		bound = &unix.SockaddrInet6{}
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	// Errors to the error queue: time exceeded, unreachable and packet too
	// big come there, quoting the echo. Never fragmented: an echo larger
	// than the path fails, and the client learns the MTU. Never broadcast:
	// a subnet's broadcast address looks public. Bound: the kernel picks
	// the socket's ID now.
	if err := errors.Join(
		os.NewSyscallError("setsockopt", unix.SetsockoptInt(fd, level, recverr, 1)),
		os.NewSyscallError("setsockopt", unix.SetsockoptInt(fd, level, pmtu, dontFrag)),
		os.NewSyscallError("setsockopt", unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 0)),
		os.NewSyscallError("bind", unix.Bind(fd, bound)),
	); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "icmp")
	pc, err := net.FilePacketConn(f)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	c, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("naive: an ICMP socket as %T", pc)
	}
	raw, err := c.SyscallConn()
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	p := &pingSocket{v6: v6, c: c, raw: raw}
	p.setTTL, p.read = p.setTTLOn, p.readOn
	p.out[0] = byte(ipv4.ICMPTypeEcho)
	if v6 {
		p.out[0] = byte(ipv6.ICMPTypeEchoRequest)
	}
	return p, nil
}

func (p *pingSocket) Close() error { return p.c.Close() }

func (p *pingSocket) setTTLOn(fd uintptr) {
	if p.v6 {
		p.ttlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, p.nextTTL)
	} else {
		p.ttlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, p.nextTTL)
	}
}

// send sets the TTL (hop limit) when it changes, then sends: one goroutine
// sends on a socket, so the option holds for its echo. The kernel sets the
// echo's ID and checksum.
func (p *pingSocket) send(dst netip.Addr, ttl int, seq uint16, payload []byte) error {
	if ttl != p.ttl {
		p.nextTTL = ttl
		if err := p.raw.Control(p.setTTL); err != nil {
			return err
		}
		if p.ttlErr != nil {
			return os.NewSyscallError("setsockopt", p.ttlErr)
		}
		p.ttl = ttl
	}
	b := p.out[:8+len(payload)]
	binary.BigEndian.PutUint16(b[6:8], seq)
	copy(b[8:], payload)
	to := netip.AddrPortFrom(dst, 0)
	_, err := p.c.WriteToUDPAddrPort(b, to)
	// An ICMP error the socket got fails the next send with its errno
	// (sk_err), once: that send took it, so one more tells a real failure
	// (no route, too big) from it.
	var errno syscall.Errno
	if errors.As(err, &errno) && errno != unix.EAGAIN && errno != unix.ENOBUFS {
		_, err = p.c.WriteToUDPAddrPort(b, to)
	}
	if errors.Is(err, unix.EMSGSIZE) {
		if mtu, merr := pathMTU(p.v6, dst); merr == nil {
			return errTooBig{mtu}
		}
	}
	return err
}

// pathMTU is the path MTU to dst as the kernel knows it, a router's "too
// big" learned: IP_MTU (IPV6_MTU) of a UDP socket connected there, which
// sends nothing. The ping socket does not tell it: it is not connected.
func pathMTU(v6 bool, dst netip.Addr) (int, error) {
	family, level, opt := unix.AF_INET, unix.IPPROTO_IP, unix.IP_MTU
	var to unix.Sockaddr = &unix.SockaddrInet4{Port: 9, Addr: dst.As4()}
	if v6 {
		family, level, opt = unix.AF_INET6, unix.IPPROTO_IPV6, unix.IPV6_MTU
		to = &unix.SockaddrInet6{Port: 9, Addr: dst.As16()}
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Connect(fd, to); err != nil {
		return 0, err
	}
	return unix.GetsockoptInt(fd, level, opt)
}

// recv reads a reply, or else an error from the error queue, before it
// waits: an error wakes a reader too (POLLERR), and one that came while a
// send or a reply read took its errno is still in the queue.
func (p *pingSocket) recv(b []byte) (icmpEvent, error) {
	p.rb, p.ev, p.rerr = b, icmpEvent{}, nil
	if err := p.raw.Read(p.read); err != nil {
		return icmpEvent{}, err
	}
	return p.ev, p.rerr
}

func (p *pingSocket) readOn(fd uintptr) bool {
	// The data's place: right after the frame's head, past the ICMP
	// header (type, code, checksum, ID, seq).
	m := p.rb[icmpHead-8:]
	n, _, flags, from, err := unix.Recvmsg(int(fd), m, nil, unix.MSG_DONTWAIT)
	if err == nil {
		if flags&unix.MSG_TRUNC == 0 {
			p.ev = parseICMPReply(p.v6, m[:n], from)
		}
		return true
	}
	// EAGAIN, or the errno of an ICMP error whose message is queued: the
	// error queue either way.
	n, oobn, _, to, err := unix.Recvmsg(int(fd), p.quote[:], p.oob[:], unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
	switch {
	case err == nil:
		p.ev = parseICMPError(p.v6, p.quote[:n], p.oob[:oobn], to)
	case errors.Is(err, unix.EAGAIN):
		return false
	default:
		p.rerr = err
	}
	return true
}

// parseICMPReply reads an echo reply as a ping socket gives it: the ICMP
// message, no IP header.
func parseICMPReply(v6 bool, m []byte, from unix.Sockaddr) icmpEvent {
	reply := byte(ipv4.ICMPTypeEchoReply)
	if v6 {
		reply = byte(ipv6.ICMPTypeEchoReply)
	}
	a := sockaddrAddr(from)
	if len(m) < 8 || m[0] != reply || !a.IsValid() {
		return icmpEvent{}
	}
	return icmpEvent{kind: icmpReply, code: m[1], from: a, dst: a, seq: binary.BigEndian.Uint16(m[6:8]), n: len(m) - 8}
}

// parseICMPError reads an error from the error queue: the ICMP error in
// the control data (sock_extended_err: its type, code and info, the
// next-hop MTU of a "too big"; then SO_EE_OFFENDER, the router's address),
// the echo it quotes in the data, and the echo's destination as the source
// address.
func parseICMPError(v6 bool, quote, oob []byte, to unix.Sockaddr) icmpEvent {
	level, typ, origin := unix.IPPROTO_IP, unix.IP_RECVERR, byte(unix.SO_EE_ORIGIN_ICMP)
	echo := byte(ipv4.ICMPTypeEcho)
	if v6 {
		level, typ, origin = unix.IPPROTO_IPV6, unix.IPV6_RECVERR, byte(unix.SO_EE_ORIGIN_ICMP6)
		echo = byte(ipv6.ICMPTypeEchoRequest)
	}
	if len(quote) < 8 || quote[0] != echo {
		return icmpEvent{}
	}
	dst := sockaddrAddr(to)
	for rest := oob; len(rest) > 0; {
		h, data, r, err := unix.ParseOneSocketControlMessage(rest)
		if err != nil {
			break
		}
		rest = r
		// sock_extended_err: errno (4), origin, type, code, pad, info (4),
		// data (4); the offender's sockaddr after it.
		if int(h.Level) != level || int(h.Type) != typ || len(data) < 16 || data[4] != origin {
			continue
		}
		ev := icmpEvent{code: data[6], dst: dst, seq: binary.BigEndian.Uint16(quote[6:8])}
		ev.kind = icmpKind(v6, data[5], data[6])
		if ev.kind == icmpTooBig {
			ev.code, ev.mtu = 0, binary.NativeEndian.Uint32(data[8:12])
		}
		ev.from = offender(data[16:])
		if ev.kind == 0 || !ev.from.IsValid() || !dst.IsValid() {
			continue
		}
		return ev
	}
	return icmpEvent{}
}

// icmpKind is the frame kind of an ICMP (ICMPv6) error: 0 for one the
// client does not get (parameter problem, source quench, redirect).
func icmpKind(v6 bool, typ, code byte) byte {
	if v6 {
		switch typ {
		case byte(ipv6.ICMPTypeTimeExceeded):
			return icmpTimeExceeded
		case byte(ipv6.ICMPTypeDestinationUnreachable):
			return icmpUnreachable
		case byte(ipv6.ICMPTypePacketTooBig):
			return icmpTooBig
		}
		return 0
	}
	switch {
	case typ == byte(ipv4.ICMPTypeTimeExceeded):
		return icmpTimeExceeded
	case typ == byte(ipv4.ICMPTypeDestinationUnreachable) && code == 4: // fragmentation needed
		return icmpTooBig
	case typ == byte(ipv4.ICMPTypeDestinationUnreachable):
		return icmpUnreachable
	}
	return 0
}

// offender reads SO_EE_OFFENDER: a sockaddr_in or sockaddr_in6.
func offender(b []byte) netip.Addr {
	if len(b) < 2 {
		return netip.Addr{}
	}
	switch binary.NativeEndian.Uint16(b) {
	case unix.AF_INET:
		if len(b) >= 8 {
			return netip.AddrFrom4([4]byte(b[4:8]))
		}
	case unix.AF_INET6:
		if len(b) >= 24 {
			return netip.AddrFrom16([16]byte(b[8:24]))
		}
	}
	return netip.Addr{}
}

func sockaddrAddr(sa unix.Sockaddr) netip.Addr {
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrFrom4(a.Addr)
	case *unix.SockaddrInet6:
		return netip.AddrFrom16(a.Addr)
	}
	return netip.Addr{}
}
