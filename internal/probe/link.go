package probe

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// PathLink gives the server's view of the requester's current connections.
const PathLink = "/probe/v1/link"

// LinkStats are the server's numbers for the TCP connections from the
// requester's address to the node's tunnel port (443): aggregates only, as
// several people may share an address behind carrier-grade NAT.
type LinkStats struct {
	Address     string  `json:"address"` // as the node sees the requester
	Connections int     `json:"connections"`
	RTTus       Spread  `json:"rtt_us"`
	MinRTTus    uint32  `json:"min_rtt_us"`
	Retrans     uint64  `json:"retrans"`  // segments retransmitted, all connections
	SegsOut     uint64  `json:"segs_out"` // segments sent, all connections
	RetransRate float64 `json:"retrans_rate"`
	DeliveryBps Spread  `json:"delivery_bps"`
	// Hysteria2: the sessions of the address on each Hysteria2 service, by
	// service ID (niko-server's session stats).
	Hysteria2 map[string]json.RawMessage `json:"hysteria2,omitempty"`
}

// Spread is the minimum, median and maximum over the connections.
type Spread struct {
	Min    uint64 `json:"min"`
	Median uint64 `json:"median"`
	Max    uint64 `json:"max"`
}

func spread(v []uint64) Spread {
	if len(v) == 0 {
		return Spread{}
	}
	slices.Sort(v)
	return Spread{Min: v[0], Median: v[len(v)/2], Max: v[len(v)-1]}
}

// link answers with the stats of the requester's address. Through a tunnel
// the request comes from the node itself, which says nothing of the
// channel: 409.
func (s *Server) link(w http.ResponseWriter, r *http.Request, device string) {
	// A dump of the host's sockets: once in 5 s per device.
	s.mu.Lock()
	if s.lastLink == nil {
		s.lastLink = map[string]time.Time{}
	}
	now := s.clock()
	if now.Sub(s.lastLink[device]) < 5*time.Second {
		s.mu.Unlock()
		w.Header().Set("Retry-After", "5")
		http.Error(w, "once in 5 seconds", http.StatusTooManyRequests)
		return
	}
	s.lastLink[device] = now
	s.mu.Unlock()
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	addr := ap.Addr().Unmap()
	if addr.IsLoopback() {
		http.Error(w, "the link of a tunnel is measured directly, not through it", http.StatusConflict)
		return
	}
	ports := s.LinkPorts
	if len(ports) == 0 {
		ports = []uint16{443}
	}
	conns, err := tcpConnections()
	if err != nil {
		s.Log.Warn("probe: sock_diag", "err", err)
		http.Error(w, "no connection data", http.StatusServiceUnavailable)
		return
	}
	st := aggregate(conns, addr, ports)
	if s.Hysteria != nil {
		for id, path := range s.Hysteria() {
			if raw, err := hysteriaStats(path, addr); err == nil {
				if st.Hysteria2 == nil {
					st.Hysteria2 = map[string]json.RawMessage{}
				}
				st.Hysteria2[id] = raw
			} else {
				s.Log.Debug("probe: hysteria2 stats", "service", id, "err", err)
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

// hysteriaStats asks a Hysteria2 backend for the sessions of addr: the
// address on a line in, its JSON out.
func hysteriaStats(path string, addr netip.Addr) (json.RawMessage, error) {
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte(addr.String() + "\n")); err != nil {
		return nil, err
	}
	var raw json.RawMessage
	err = json.NewDecoder(io.LimitReader(c, 1<<16)).Decode(&raw)
	return raw, err
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
