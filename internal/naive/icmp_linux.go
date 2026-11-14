package naive

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

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
