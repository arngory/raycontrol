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
	"sync/atomic"
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
	uotPeerAge    = 2 * time.Minute

	// A user's new destinations and name lookups, all streams together:
	// each destination is a conntrack entry the perimeter keeps, each name
	// a query to the resolvers TCP shares.
	uotPeerRate, uotPeerBurst     = 100, 200
	uotLookupRate, uotLookupBurst = 20, 50
)

// errRefused ends a stream with a reset: the client sees an error, not an
// empty answer.
var errRefused = errors.New("naive: refused")

// uotLimits counts the UoT streams, per user and in all, and paces each
// user's new destinations and name lookups.
type uotLimits struct {
	mu    sync.Mutex
	total int
	users map[[32]byte]*uotUser
}

type uotUser struct {
	streams        int
	peers, lookups bucket
}

func (l *uotLimits) take(user [32]byte) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	u := l.users[user]
	if l.total >= uotPerService || (u != nil && u.streams >= uotPerUser) {
		return false
	}
	if u == nil {
		if l.users == nil {
			l.users = map[[32]byte]*uotUser{}
		}
		now := time.Now()
		u = &uotUser{peers: bucket{uotPeerBurst, now}, lookups: bucket{uotLookupBurst, now}}
		l.users[user] = u
	}
	l.total++
	u.streams++
	return true
}

func (l *uotLimits) put(user [32]byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	u := l.users[user]
	if u == nil {
		return
	}
	l.total--
	if u.streams--; u.streams <= 0 {
		delete(l.users, user)
	}
}

// newPeer and lookup take one of the user's tokens: false when there is none.
func (l *uotLimits) newPeer(user [32]byte) bool {
	return l.spend(user, func(u *uotUser) *bucket { return &u.peers }, uotPeerRate, uotPeerBurst)
}

func (l *uotLimits) lookup(user [32]byte) bool {
	return l.spend(user, func(u *uotUser) *bucket { return &u.lookups }, uotLookupRate, uotLookupBurst)
}

func (l *uotLimits) spend(user [32]byte, which func(*uotUser) *bucket, rate, burst float64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	u := l.users[user]
	return u != nil && which(u).take(time.Now(), rate, burst)
}

// bucket is a token bucket: rate tokens a second, up to burst.
type bucket struct {
	tokens float64
	at     time.Time
}

func (b *bucket) take(now time.Time, rate, burst float64) bool {
	b.tokens = min(burst, b.tokens+now.Sub(b.at).Seconds()*rate)
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

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
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return a, err
		}
		a.ip = netip.AddrFrom4(b)
	case v6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return a, err
		}
		a.ip = netip.AddrFrom16(b).Unmap()
	case name:
		n, err := r.ReadByte()
		if err != nil {
			return a, err
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return a, err
		}
		if n == 0 {
			return a, fmt.Errorf("%w: an empty name", errRefused)
		}
		a.name = string(b)
	default:
		return a, fmt.Errorf("%w: address type %#x", errRefused, t)
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return a, err
	}
	a.port = binary.BigEndian.Uint16(p[:])
	return a, nil
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
	s     *Server
	ctx   context.Context
	user  [32]byte
	names map[string]uotResolved
	last  atomic.Int64 // unix nanoseconds of the last packet either way

	mu     sync.Mutex
	peers  map[netip.AddrPort]int64 // where the client sent, and when: answers come from these only
	pruned time.Time
}

// uotResolved is a name's first allowed address, or none until a moment.
type uotResolved struct {
	ip    netip.Addr
	until time.Time
}

func (u *uotStream) touch() { u.last.Store(time.Now().UnixNano()) }

// mayReach reports whether the client may send to ap: a destination it sent
// to before, or a new one while the stream has room and the user tokens.
func (u *uotStream) mayReach(ap netip.AddrPort) bool {
	now := time.Now()
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, ok := u.peers[ap]; ok {
		u.peers[ap] = now.UnixNano()
		return true
	}
	if len(u.peers) >= uotPeers && now.Sub(u.pruned) > time.Second {
		// Those the client has not sent to for a while go, as conntrack
		// forgets them.
		u.pruned = now
		for p, at := range u.peers {
			if now.Sub(time.Unix(0, at)) > uotPeerAge {
				delete(u.peers, p)
			}
		}
	}
	if len(u.peers) >= uotPeers || !u.s.uot.newPeer(u.user) {
		return false
	}
	u.peers[ap] = now.UnixNano()
	return true
}

func (u *uotStream) answers(ap netip.AddrPort) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	_, ok := u.peers[netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())]
	return ok
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
	if n, ok := u.names[a.name]; ok && (n.ip.IsValid() || time.Now().Before(n.until)) {
		return netip.AddrPortFrom(n.ip, a.port), n.ip.IsValid()
	}
	if !u.s.uot.lookup(u.user) {
		return netip.AddrPort{}, false
	}
	ip := u.lookup(a.name)
	if _, ok := u.names[a.name]; ok || len(u.names) < uotNames {
		u.names[a.name] = uotResolved{ip: ip, until: time.Now().Add(uotNameMiss)} // until: a miss only
	}
	return netip.AddrPortFrom(ip, a.port), ip.IsValid()
}

// lookup is the first allowed address of a name, or none.
func (u *uotStream) lookup(name string) netip.Addr {
	ctx, cancel := context.WithTimeout(u.ctx, 5*time.Second)
	ips, err := u.s.resolve(ctx, name)
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
	ips, err := uotResolver.LookupNetIP(ctx, "ip", name)
	if err != nil {
		s.warn.note(s.Log, err)
	}
	return ips, err
}

// uotResolver looks UDP destinations up as TCP's are (PublicResolver).
var uotResolver = PublicResolver()

// deadlines are the stream's, as http.ResponseController sets them.
type deadlines interface {
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// serveUoT carries the stream's UDP until the client ends it, the idle time
// runs out or ctx is done; errRefused when the stream must be reset. Only
// this goroutine's helper writes to the stream, and it is done when this
// returns.
func (s *Server) serveUoT(ctx context.Context, user [32]byte, stream io.ReadWriter, dl deadlines) error {
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
	u := &uotStream{s: s, ctx: ctx, user: user, names: map[string]uotResolved{}, peers: map[netip.AddrPort]int64{}}
	u.touch()

	var conn *net.UDPConn
	if connect == 1 {
		to, ok := u.resolve(dest)
		if !ok {
			return fmt.Errorf("%w: %s", errRefused, dest)
		}
		d := net.Dialer{Control: noBroadcast}
		c, err := d.DialContext(ctx, "udp", to.String())
		if err != nil {
			return fmt.Errorf("%w: %w", errRefused, err)
		}
		conn = c.(*net.UDPConn)
	} else {
		lc := net.ListenConfig{Control: noBroadcast}
		c, err := lc.ListenPacket(ctx, "udp", ":0")
		if err != nil {
			return fmt.Errorf("%w: %w", errRefused, err)
		}
		conn = c.(*net.UDPConn)
	}
	defer func() { _ = conn.Close() }()

	up := make(chan error, 1)
	go func() { up <- u.upstream(r, conn, connect == 1) }()
	down := make(chan struct{})
	go func() {
		defer close(down)
		u.downstream(conn, stream, connect == 1)
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
			if time.Since(time.Unix(0, u.last.Load())) > idle {
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
	}
	return result
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
func (u *uotStream) upstream(r *bufio.Reader, conn *net.UDPConn, connected bool) error {
	for {
		var dest uotAddr
		if !connected {
			var err error
			if dest, err = readAddr(r, false); err != nil {
				return err
			}
		}
		var l [2]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return err
		}
		n := int(binary.BigEndian.Uint16(l[:]))
		if n > uotMaxPayload {
			return fmt.Errorf("%w: a packet of %d bytes", errRefused, n)
		}
		buf := uotBufs.Get().(*[uotMaxPayload]byte)
		err := u.send(r, conn, connected, dest, buf[:n])
		uotBufs.Put(buf)
		if err != nil {
			return err
		}
	}
}

// send reads one packet's data into b and sends it; an error ends the stream.
func (u *uotStream) send(r *bufio.Reader, conn *net.UDPConn, connected bool, dest uotAddr, b []byte) error {
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	u.touch()
	var err error
	if connected {
		// A destination that answers "unreachable" fails a write or two:
		// the stream lives on, as UDP would.
		_, err = conn.Write(b)
	} else if to, ok := u.resolve(dest); ok && u.mayReach(to) {
		_, err = conn.WriteToUDPAddrPort(b, to)
	} // else not allowed, no address or no room: dropped
	if errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// headRoom is the most an answer's head takes: an IPv6 source and the length.
const headRoom = 1 + 16 + 2 + 2

// downstream passes the answers on, each in one write (one padded frame
// while naive pads).
func (u *uotStream) downstream(conn *net.UDPConn, w io.Writer, connected bool) {
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
		if n > uotMaxAnswer || (!connected && !u.answers(from)) {
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
	}
}
