package perimeter

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// The guard's sweep (spec/conn-limit-v1.md §6.3): the entries a far end
// keeps alive after the connection ended, which neither a process nor a
// limit sees. An entry goes when no socket has it:
//
//   - outbound UDP with the data plane's mark: no UDP socket on its local
//     port (/proc/net/udp, udp6);
//   - outbound TCP with the mark, closing (FIN_WAIT, CLOSE_WAIT, LAST_ACK,
//     TIME_WAIT, CLOSE): no TCP socket on its local port, one in TIME_WAIT
//     included (/proc/net/tcp, tcp6);
//   - inbound TCP without the mark, closing, to an address of the node: no
//     socket with its four addresses and ports (the port has a listener).
//
// NATed entries (a relay's, the ACME window's, UDP rotation's) are never
// touched: their socket has another tuple. A port taken again by another
// socket counts as live: the look-up by port errs that way. The sockets are
// read after each dump: a socket made before the dump was read, whose entry
// the dump has, is in them (read before, a connection opened in between
// would lose its entry: the sweep never touches a live one).

// Sweeper sweeps the table of the network namespace it runs in.
type Sweeper struct {
	// Net is the directory of the sockets (/proc/thread-self/net when
	// empty: the calling thread's namespace, which /proc/net, the main
	// thread's, need not be).
	Net string
	// Local are the node's addresses; the interfaces' when nil.
	Local func() (map[netip.Addr]bool, error)
	// table opens the conntrack table: ctnetlink when nil (tests: a fake).
	table func() (ctTable, error)
}

// ctTable is the conntrack table as the sweep uses it.
type ctTable interface {
	dump(family uint8, value, mask uint32) ([]ctEntry, error)
	delete(e ctEntry) error
	Close() error
}

func (s *Sweeper) open() (ctTable, error) {
	if s.table != nil {
		return s.table()
	}
	return dialConntrack()
}

// sockets are the sockets of the namespace as the sweep looks them up.
type sockets struct {
	udpPorts, tcpPorts map[uint16]bool
	tcpQuads           map[[2]netip.AddrPort]bool // local, remote
}

// Sweep removes the entries without a socket.
func (s *Sweeper) Sweep(ctx context.Context) (SweepResult, error) {
	var r SweepResult
	local, err := s.local()
	if err != nil {
		return r, err
	}
	c, err := s.open()
	if err != nil {
		return r, err
	}
	defer func() { _ = c.Close() }()
	var errs []error
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		for _, marked := range []bool{true, false} {
			if ctx.Err() != nil {
				return r, ctx.Err()
			}
			value := uint32(0)
			if marked {
				value = dataPlaneMarkBit
			}
			entries, err := c.dump(family, value, dataPlaneMarkBit)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			// After the dump: every socket whose entry it has is here.
			socks, err := s.sockets()
			if err != nil {
				return r, err
			}
			for _, e := range entries {
				kind := orphan(e, socks, local)
				if kind == "" {
					continue
				}
				if err := c.delete(e); err != nil {
					errs = append(errs, err)
					continue
				}
				switch kind {
				case "udp":
					r.UDP++
				case "tcp-out":
					r.TCPOut++
				case "tcp-in":
					r.TCPIn++
				}
			}
		}
	}
	return r, errors.Join(errs...)
}

// closing are the TCP states of an entry whose connection is ending.
func closing(state uint8) bool {
	switch state {
	case tcpFinWait, tcpCloseWait, tcpLastAck, tcpTimeWait, tcpClose:
		return true
	}
	return false
}

// orphan says what kind of orphan an entry is ("udp", "tcp-out",
// "tcp-in"), "" when it is not one.
func orphan(e ctEntry, socks sockets, local map[netip.Addr]bool) string {
	if e.Status&(ipsSrcNAT|ipsDstNAT) != 0 {
		return ""
	}
	src, dst := e.Orig.Src, e.Orig.Dst
	srcLocal, dstLocal := local[src.Addr().Unmap()], local[dst.Addr().Unmap()]
	if e.Mark&dataPlaneMarkBit != 0 {
		if !srcLocal || dstLocal {
			return "" // the data plane's own way out only
		}
		switch e.Orig.Proto {
		case unix.IPPROTO_UDP:
			if !socks.udpPorts[src.Port()] {
				return "udp"
			}
		case unix.IPPROTO_TCP:
			if e.hasState && closing(e.TCPState) && !socks.tcpPorts[src.Port()] {
				return "tcp-out"
			}
		}
		return ""
	}
	if e.Orig.Proto != unix.IPPROTO_TCP || !e.hasState || !closing(e.TCPState) || !dstLocal || srcLocal {
		return ""
	}
	if socks.tcpQuads[[2]netip.AddrPort{unmapAP(dst), unmapAP(src)}] {
		return ""
	}
	return "tcp-in"
}

func unmapAP(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func (s *Sweeper) net() string {
	if s.Net != "" {
		return s.Net
	}
	return "/proc/thread-self/net"
}

func (s *Sweeper) local() (map[netip.Addr]bool, error) {
	if s.Local != nil {
		return s.Local()
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := map[netip.Addr]bool{}
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out[p.Addr().Unmap()] = true
		}
	}
	return out, nil
}

// sockets reads the namespace's sockets: after a dump, so that a socket
// made before the dump returned, whose entry it may have, is among them.
func (s *Sweeper) sockets() (sockets, error) {
	socks := sockets{udpPorts: map[uint16]bool{}, tcpPorts: map[uint16]bool{}, tcpQuads: map[[2]netip.AddrPort]bool{}}
	for _, name := range []string{"udp", "udp6", "tcp", "tcp6"} {
		f, err := os.Open(filepath.Join(s.net(), name)) //nolint:gosec // G304: /proc/thread-self/net, four names
		if errors.Is(err, os.ErrNotExist) && strings.HasSuffix(name, "6") {
			continue // no IPv6
		}
		if err != nil {
			return socks, err
		}
		err = readSockets(f, strings.HasPrefix(name, "tcp"), socks)
		f.Close()
		if err != nil {
			return socks, err
		}
	}
	return socks, nil
}

// readSockets reads one of /proc/net/{tcp,udp}{,6}: "sl local remote st
// ...", addresses in hexadecimal, 32-bit words in the host's order, ports
// big-endian.
func readSockets(r io.Reader, tcp bool, socks sockets) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), 1<<20)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		local, err1 := parseProcAddr(f[1])
		remote, err2 := parseProcAddr(f[2])
		if err1 != nil || err2 != nil {
			continue
		}
		if !tcp {
			socks.udpPorts[local.Port()] = true
			continue
		}
		socks.tcpPorts[local.Port()] = true
		if f[3] != "0A" { // not LISTEN
			socks.tcpQuads[[2]netip.AddrPort{local, remote}] = true
		}
	}
	return sc.Err()
}

// parseProcAddr reads "0100007F:0035" or its IPv6 form; an IPv4-mapped
// address comes back as IPv4.
func parseProcAddr(s string) (netip.AddrPort, error) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, errors.New("no port")
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	raw, err := hex.DecodeString(h)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, errors.New("bad address")
	}
	// Each 32-bit word as the kernel printed it, in the host's order.
	for i := 0; i < len(raw); i += 4 {
		binary.BigEndian.PutUint32(raw[i:], binary.NativeEndian.Uint32(raw[i:]))
	}
	a, _ := netip.AddrFromSlice(raw)
	return netip.AddrPortFrom(a.Unmap(), uint16(port)), nil
}
