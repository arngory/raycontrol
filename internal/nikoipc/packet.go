package nikoipc

import (
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// Mode "packet" (IPC.md): one SOCK_SEQPACKET message per datagram, both ways:
//
//	magic "NU" | version 1 | client (19) | local (19) | payload
//
// The front sends the datagrams of the flows it routed here; answers go
// back the same way, from the local address the client wrote to.
const (
	packetVersion = 1
	packetHeader  = 3 + 2*addrSize
	maxDatagram   = 65535
)

func encodePacket(buf []byte, client, local netip.AddrPort, payload []byte) []byte {
	buf = append(buf[:0], 'N', 'U', packetVersion)
	var a [addrSize]byte
	putAddr(a[:], client)
	buf = append(buf, a[:]...)
	putAddr(a[:], local)
	buf = append(buf, a[:]...)
	return append(buf, payload...)
}

func decodePacket(msg []byte) (client, local netip.AddrPort, payload []byte, err error) {
	if len(msg) < packetHeader || msg[0] != 'N' || msg[1] != 'U' || msg[2] != packetVersion {
		return client, local, nil, errBadMessage
	}
	if client, err = getAddr(msg[3 : 3+addrSize]); err != nil {
		return
	}
	if local, err = getAddr(msg[3+addrSize : packetHeader]); err != nil {
		return
	}
	return client, local, msg[packetHeader:], nil
}

// PacketConn is a backend's end of mode packet: a net.PacketConn whose
// peers are the clients the front saw. QUIC servers run on it as on a
// UDP socket.
type PacketConn struct {
	ln       *net.UnixListener
	frontUID int
	log      *slog.Logger

	in     chan datagram
	closed chan struct{}
	once   sync.Once

	mu       sync.Mutex
	front    *net.UnixConn
	locals   map[netip.AddrPort]netip.AddrPort
	deadline time.Time
}

type datagram struct {
	client  netip.AddrPort
	payload []byte
}

// ListenPacket creates the SOCK_SEQPACKET socket at path (mode 0660) and
// takes datagrams from the front only.
func ListenPacket(path string, frontUID int, log *slog.Logger) (*PacketConn, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil { //nolint:gosec // G302: the front connects through the directory's group
		_ = ln.Close()
		return nil, err
	}
	c := &PacketConn{ln: ln, frontUID: frontUID, log: log, in: make(chan datagram, 4096), closed: make(chan struct{}),
		locals: map[netip.AddrPort]netip.AddrPort{}}
	go c.acceptLoop()
	return c, nil
}

func (c *PacketConn) acceptLoop() {
	for {
		conn, err := c.ln.AcceptUnix()
		if err != nil {
			select {
			case <-c.closed:
				return
			default:
			}
			c.log.Warn("packet socket accept", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if uid := peerUID(conn); uid != c.frontUID {
			c.log.Warn("refused a connection to the packet socket", "uid", uid, "want", c.frontUID)
			_ = conn.Close()
			continue
		}
		_ = conn.SetReadBuffer(4 << 20)
		_ = conn.SetWriteBuffer(4 << 20)
		c.mu.Lock()
		c.front = conn
		c.mu.Unlock()
		go c.readLoop(conn)
	}
}

func (c *PacketConn) readLoop(conn *net.UnixConn) {
	defer func() { _ = conn.Close() }()
	buf := make([]byte, packetHeader+maxDatagram)
	for {
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}
		client, local, payload, err := decodePacket(buf[:n])
		if err != nil {
			continue
		}
		c.mu.Lock()
		if len(c.locals) > 65536 {
			clear(c.locals)
		}
		c.locals[client] = local
		c.mu.Unlock()
		select {
		case c.in <- datagram{client, append([]byte(nil), payload...)}:
		default: // behind: dropped, as a full UDP socket would
		}
	}
}

func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mu.Lock()
	deadline := c.deadline
	c.mu.Unlock()
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return 0, nil, os.ErrDeadlineExceeded
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timeout = t.C
	}
	select {
	case d := <-c.in:
		return copy(b, d.payload), net.UDPAddrFromAddrPort(d.client), nil
	case <-timeout:
		return 0, nil, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("nikoipc: not a UDP address")
	}
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	client := ua.AddrPort()
	client = netip.AddrPortFrom(client.Addr().Unmap(), client.Port())
	c.mu.Lock()
	front, local := c.front, c.locals[client]
	c.mu.Unlock()
	if front == nil {
		return len(b), nil // lost, as on a network
	}
	if !local.IsValid() {
		local = netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
	}
	_, _ = front.Write(encodePacket(make([]byte, 0, packetHeader+len(b)), client, local, b))
	return len(b), nil
}

func (c *PacketConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		_ = c.ln.Close()
		c.mu.Lock()
		if c.front != nil {
			_ = c.front.Close()
		}
		c.mu.Unlock()
	})
	return nil
}

func (c *PacketConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv6unspecified, Port: 443} }

func (c *PacketConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *PacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

func (c *PacketConn) SetWriteDeadline(time.Time) error { return nil }

// Front plays the front for tests: it sends a client's datagram to the
// backend at path and returns what comes back.
func Front(conn *net.UnixConn, client, local netip.AddrPort, payload []byte) error {
	_, err := conn.Write(encodePacket(nil, client, local, payload))
	return err
}

// Answer decodes a message the backend sent the front.
func Answer(msg []byte) (client, local netip.AddrPort, payload []byte, err error) {
	return decodePacket(msg)
}
