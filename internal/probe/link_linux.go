package probe

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"unsafe"

	"golang.org/x/sys/unix"
)

func spread(v []uint64) Spread {
	if len(v) == 0 {
		return Spread{}
	}
	slices.Sort(v)
	return Spread{Min: v[0], Median: v[len(v)/2], Max: v[len(v)-1]}
}

// aggregate sums up the connections from addr to the ports.
func aggregate(conns []tcpConn, addr netip.Addr, ports []uint16) LinkStats {
	st := LinkStats{Address: addr.String()}
	var rtts, rates []uint64
	for _, c := range conns {
		if c.Remote.Addr() != addr || !slices.Contains(ports, c.Local.Port()) {
			continue
		}
		st.Connections++
		rtts = append(rtts, uint64(c.Info.Rtt))
		rates = append(rates, c.Info.Delivery_rate*8)
		if st.MinRTTus == 0 || (c.Info.Min_rtt != 0 && c.Info.Min_rtt < st.MinRTTus) {
			st.MinRTTus = c.Info.Min_rtt
		}
		st.Retrans += uint64(c.Info.Total_retrans)
		st.SegsOut += uint64(c.Info.Segs_out)
	}
	st.RTTus, st.DeliveryBps = spread(rtts), spread(rates)
	if st.SegsOut > 0 {
		st.RetransRate = float64(st.Retrans) / float64(st.SegsOut)
	}
	return st
}

// tcpConn is an established TCP socket of the host, with TCP_INFO.
type tcpConn struct {
	Local, Remote netip.AddrPort
	Info          unix.TCPInfo
}

// tcpConnections lists the host's established TCP sockets through
// sock_diag (what ss -ti shows); no privilege is needed.
func tcpConnections() ([]tcpConn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	var out []tcpConn
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		conns, err := dumpTCP(fd, family)
		if err != nil {
			return nil, err
		}
		out = append(out, conns...)
	}
	return out, nil
}

// inet_diag_req_v2 and inet_diag_msg (linux/inet_diag.h).
const (
	sockDiagByFamily = 20
	inetDiagInfo     = 2
	diagReqLen       = 56
	diagMsgLen       = 72
)

func dumpTCP(fd int, family uint8) ([]tcpConn, error) {
	req := make([]byte, unix.NLMSG_HDRLEN+diagReqLen)
	binary.NativeEndian.PutUint32(req[0:], uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:], sockDiagByFamily)
	binary.NativeEndian.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(req[8:], 1)
	r := req[unix.NLMSG_HDRLEN:]
	r[0], r[1], r[2] = family, unix.IPPROTO_TCP, 1<<(inetDiagInfo-1)
	binary.NativeEndian.PutUint32(r[4:], 1<<unix.BPF_TCP_ESTABLISHED)
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	var out []tcpConn
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, err
		}
		msgs, err := syscallParse(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				return out, nil
			case unix.NLMSG_ERROR:
				return nil, unix.EINVAL
			case sockDiagByFamily:
				if c, ok := parseDiag(m.Data); ok {
					out = append(out, c)
				}
			}
		}
	}
}

func syscallParse(b []byte) ([]netlinkMessage, error) {
	var out []netlinkMessage
	for len(b) >= unix.NLMSG_HDRLEN {
		l := int(binary.NativeEndian.Uint32(b))
		if l < unix.NLMSG_HDRLEN || l > len(b) {
			return nil, unix.EINVAL
		}
		out = append(out, netlinkMessage{Header: unix.NlMsghdr{Len: uint32(l), Type: binary.NativeEndian.Uint16(b[4:])},
			Data: b[unix.NLMSG_HDRLEN:l]})
		b = b[min(len(b), (l+unix.NLMSG_ALIGNTO-1)&^(unix.NLMSG_ALIGNTO-1)):]
	}
	return out, nil
}

type netlinkMessage struct {
	Header unix.NlMsghdr
	Data   []byte
}

func parseDiag(d []byte) (tcpConn, bool) {
	if len(d) < diagMsgLen {
		return tcpConn{}, false
	}
	family := d[0]
	id := d[4:52] // sport(2) dport(2) src(16) dst(16) if(4) cookie(8)
	sport, dport := binary.BigEndian.Uint16(id[0:]), binary.BigEndian.Uint16(id[2:])
	addr := func(b []byte) netip.Addr {
		if family == unix.AF_INET {
			return netip.AddrFrom4([4]byte(b[:4]))
		}
		return netip.AddrFrom16([16]byte(b[:16])).Unmap()
	}
	c := tcpConn{Local: netip.AddrPortFrom(addr(id[4:20]), sport), Remote: netip.AddrPortFrom(addr(id[20:36]), dport)}
	found := false
	for a := d[diagMsgLen:]; len(a) >= 4; {
		l, t := int(binary.NativeEndian.Uint16(a)), binary.NativeEndian.Uint16(a[2:])
		if l < 4 || l > len(a) {
			break
		}
		if t == inetDiagInfo {
			// Older kernels send a shorter tcp_info: the rest stays zero.
			info := a[4:l]
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&c.Info)), unsafe.Sizeof(c.Info)), info) //nolint:gosec // G103: the kernel's tcp_info into x/sys's struct of the same layout
			found = true
		}
		a = a[min(len(a), (l+3)&^3):]
	}
	return c, found
}

// tcpInfo is the TCP_INFO of a request's connection (ConnContext), or nil.
func tcpInfo(ctx context.Context) *TCPInfo {
	c, _ := ctx.Value(connKey{}).(net.Conn)
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		return nil
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return nil
	}
	var info *unix.TCPInfo
	_ = raw.Control(func(fd uintptr) {
		info, err = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	})
	if err != nil || info == nil {
		return nil
	}
	return &TCPInfo{RTTus: info.Rtt, RTTVarus: info.Rttvar, MinRTTus: info.Min_rtt, Retrans: info.Total_retrans,
		DeliveryBps: info.Delivery_rate * 8, Cwnd: info.Snd_cwnd, PMTU: info.Pmtu}
}
