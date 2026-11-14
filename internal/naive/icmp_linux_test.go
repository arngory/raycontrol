package naive

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The node's ping sockets against the kernel (icmp_linux.go); the stream's
// tests over a fake network are in icmp_test.go.

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
	u := s.icmp.take("u4")
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
	st := newICMPStream(s, s.icmp.take("u5"), w)
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
