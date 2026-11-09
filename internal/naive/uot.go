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
	uotNames      = 64 // names resolved per stream, kept
	uotNameMiss   = 30 * time.Second
	uotPeers      = 4096 // addresses a stream sent to, whose answers come back

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

	mu sync.Mutex
	// peers are where the client sent, and the pair's times: answers come
	// from these only, and each is a conntrack entry until it ends.
	peers  map[netip.AddrPort]pairTimes
	pruned time.Time
	aged   time.Time
}

// pairTimes are a pair's last packet sent, last either way (unix
// nanoseconds), and whether an answer came.
type pairTimes struct {
	sent, any int64
	answered  bool
}

// end is when conntrack lets the pair go: 30 s after the last packet sent
// while unanswered, 120 s after the last either way once answered.
func (p pairTimes) end() time.Time {
	if p.answered {
		return time.Unix(0, p.any).Add(pairAnswered)
	}
	return time.Unix(0, p.sent).Add(pairUnanswered)
}

// age drops the pairs whose time ran out, once a second at most, and says
// how many are left.
func (u *uotStream) age(now time.Time) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	if now.Sub(u.aged) >= ageEvery {
		u.aged = now
		for p, t := range u.peers {
			if !now.Before(t.end()) {
				delete(u.peers, p)
			}
		}
	}
	return len(u.peers)
}

// ends are when the stream's pairs end, for the user's journal.
func (u *uotStream) ends() []time.Time {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]time.Time, 0, len(u.peers))
	for _, t := range u.peers {
		out = append(out, t.end())
	}
	return out
}

// heard notes an answer from a pair, and reports whether it is one.
func (u *uotStream) heard(ap netip.AddrPort) bool {
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	now := u.s.lim.clock().UnixNano()
	u.mu.Lock()
	defer u.mu.Unlock()
	t, ok := u.peers[ap]
	if ok {
		t.any, t.answered = now, true
		u.peers[ap] = t
	}
	return ok
}

// uotResolved is a name the stream does not look up again until a moment.
type uotResolved struct {
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
	if u.sent(ap, now.UnixNano()) {
		return true
	}
	u.mu.Lock()
	if len(u.peers) >= uotPeers && now.Sub(u.pruned) > time.Second {
		// Those whose time ran out go, as conntrack forgets them.
		u.pruned = now
		for p, t := range u.peers {
			if !now.Before(t.end()) {
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
	u.peers[ap] = pairTimes{sent: now.UnixNano(), any: now.UnixNano()}
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
	// A miss the shared cache does not keep (a timeout, SERVFAIL) is kept
	// here, for the stream alone: its next packets do not ask again.
	if n, ok := u.names[a.name]; ok && u.s.lim.clock().Before(n.until) {
		return netip.AddrPort{}, false
	}
	ip := u.lookup(a.name)
	if !ip.IsValid() && len(u.names) < uotNames {
		u.names[a.name] = uotResolved{until: u.s.lim.clock().Add(uotNameMiss)}
	}
	return netip.AddrPortFrom(ip, a.port), ip.IsValid()
}

// lookup is the first allowed address of a name, or none: through the
// process's cache, a miss paying the user's lookup token.
func (u *uotStream) lookup(name string) netip.Addr {
	ctx, cancel := context.WithTimeout(u.ctx, 5*time.Second)
	ips, err := u.s.lookupName(ctx, u.slot.user, name, false)
	cancel()
	if err != nil {
		return netip.Addr{}
	}
	for _, ip := range ips {
		if ip = ip.Unmap(); u.s.allowed(ip) {
			return ip
		}
	}
	return netip.Addr{}
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
	down := make(chan struct{})
	go func() {
		defer close(down)
		u.downstream(conn, stream, to)
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
	// The socket goes: the helpers stop; nothing writes to the stream once
	// this returns. A write the client does not take (flow control) would
	// hold the stream and its slot: past a second it fails.
	_ = conn.Close()
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

// downstream passes the answers on, each in one write (one padded frame
// while naive pads).
func (u *uotStream) downstream(conn *net.UDPConn, w io.Writer, connectedTo netip.AddrPort) {
	connected := connectedTo.IsValid()
	// One more than an answer may take: a longer one fills it, and goes.
	buf := make([]byte, headRoom+uotMaxAnswer+1)
	var head [headRoom]byte
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf[headRoom:])
		if err != nil {
			var errno syscall.Errno
			if errors.As(err, &errno) {
				continue // an ICMP error on a connected socket: UDP goes on
			}
			return
		}
		if connected {
			from = connectedTo
		}
		if !u.heard(from) || n > uotMaxAnswer {
			continue
		}
		u.touch()
		h := head[:0]
		if !connected {
			h = appendAddr(h, from)
		}
		h = binary.BigEndian.AppendUint16(h, uint16(n)) //nolint:gosec // G115: n ≤ uotMaxAnswer
		start := headRoom - len(h)
		copy(buf[start:headRoom], h)
		if _, err := w.Write(buf[start : headRoom+n]); err != nil {
			return
		}
		u.traffic.addDown(n) // the payload, as it came from the destination
	}
}
