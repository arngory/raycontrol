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
	uotMaxPayload = 65507
	uotPerUser    = 64
	uotPerService = 4096
	uotNames      = 64   // names resolved per stream, kept
	uotPeers      = 4096 // addresses a stream sent to, whose answers come back
)

// errRefused ends a stream with a reset: the client sees an error, not an
// empty answer.
var errRefused = errors.New("naive: refused")

// uotLimits counts the UoT streams, per user and in all.
type uotLimits struct {
	mu    sync.Mutex
	total int
	users map[[32]byte]int
}

func (l *uotLimits) take(user [32]byte) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= uotPerService || l.users[user] >= uotPerUser {
		return false
	}
	if l.users == nil {
		l.users = map[[32]byte]int{}
	}
	l.total++
	l.users[user]++
	return true
}

func (l *uotLimits) put(user [32]byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.users[user]--; l.users[user] <= 0 {
		delete(l.users, user)
	}
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
	names map[string]netip.Addr
	last  atomic.Int64 // unix nanoseconds of the last packet either way

	mu    sync.Mutex
	peers map[netip.AddrPort]bool // where the client sent: answers come from these only
}

func (u *uotStream) touch() { u.last.Store(time.Now().UnixNano()) }

func (u *uotStream) sent(ap netip.AddrPort) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.peers) < uotPeers {
		u.peers[ap] = true
	}
}

func (u *uotStream) answers(ap netip.AddrPort) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.peers[netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())]
}

// resolve is the address a destination may be reached at: its own, or the
// first allowed one of its name; false for none.
func (u *uotStream) resolve(a uotAddr) (netip.AddrPort, bool) {
	if a.name == "" {
		return netip.AddrPortFrom(a.ip, a.port), a.port != 0 && u.s.allowed(a.ip)
	}
	if ip, ok := u.names[a.name]; ok {
		return netip.AddrPortFrom(ip, a.port), a.port != 0
	}
	ctx, cancel := context.WithTimeout(u.ctx, 5*time.Second)
	ips, err := u.s.resolve(ctx, a.name)
	cancel()
	if err != nil {
		return netip.AddrPort{}, false
	}
	for _, ip := range ips {
		if ip = ip.Unmap(); u.s.allowed(ip) {
			if len(u.names) < uotNames {
				u.names[a.name] = ip
			}
			return netip.AddrPortFrom(ip, a.port), a.port != 0
		}
	}
	return netip.AddrPort{}, false
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
	return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
}

// serveUoT carries the stream's UDP until the client ends it, the idle time
// runs out or ctx is done; errRefused when the stream must be reset. Only
// this goroutine's helper writes to the stream, and it is done when this
// returns.
func (s *Server) serveUoT(ctx context.Context, stream io.ReadWriter) error {
	r := bufio.NewReaderSize(stream, 64<<10)
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
	u := &uotStream{s: s, ctx: ctx, names: map[string]netip.Addr{}, peers: map[netip.AddrPort]bool{}}
	u.touch()

	var conn *net.UDPConn
	if connect == 1 {
		to, ok := u.resolve(dest)
		if !ok {
			return fmt.Errorf("%w: %s", errRefused, dest)
		}
		if conn, err = net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(to)); err != nil {
			return fmt.Errorf("%w: %w", errRefused, err)
		}
	} else if conn, err = net.ListenUDP("udp", nil); err != nil {
		return fmt.Errorf("%w: %w", errRefused, err)
	}
	defer func() { _ = conn.Close() }()

	up := make(chan error, 1)
	go func() { up <- u.upstream(r, conn, connect == 1) }()
	down := make(chan struct{})
	go func() {
		defer close(down)
		u.downstream(conn, stream, connect == 1)
	}()

	idle := s.uotIdle
	if idle == 0 {
		idle = uotIdle
	}
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
	// this returns.
	_ = conn.Close()
	<-down
	return result
}

// upstream sends the client's packets; errRefused for a stream to reset.
func (u *uotStream) upstream(r *bufio.Reader, conn *net.UDPConn, connected bool) error {
	buf := make([]byte, uotMaxPayload)
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
		if _, err := io.ReadFull(r, buf[:n]); err != nil {
			return err
		}
		u.touch()
		if connected {
			// A destination that answers "unreachable" fails a write or
			// two: the stream lives on, as UDP would.
			if _, err := conn.Write(buf[:n]); errors.Is(err, net.ErrClosed) {
				return err
			}
			continue
		}
		to, ok := u.resolve(dest)
		if !ok {
			continue // not allowed, or no address: dropped
		}
		u.sent(to)
		if _, err := conn.WriteToUDPAddrPort(buf[:n], to); errors.Is(err, net.ErrClosed) {
			return err
		}
	}
}

// downstream passes the answers on, each in one write (one padded frame
// while naive pads).
func (u *uotStream) downstream(conn *net.UDPConn, w io.Writer, connected bool) {
	buf := make([]byte, uotMaxPayload)
	out := make([]byte, 0, uotMaxPayload+32)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if errors.Is(err, syscall.ECONNREFUSED) {
			continue // the destination's port is closed: UDP goes on
		}
		if err != nil {
			return
		}
		if !connected && !u.answers(from) {
			continue
		}
		u.touch()
		out = out[:0]
		if !connected {
			out = appendAddr(out, from)
		}
		out = binary.BigEndian.AppendUint16(out, uint16(n)) //nolint:gosec // G115: n ≤ uotMaxPayload
		out = append(out, buf[:n]...)
		if _, err := w.Write(out); err != nil {
			return
		}
	}
}
