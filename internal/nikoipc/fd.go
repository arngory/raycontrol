// Package nikoipc is raycontrol's side of the niko-server IPC (arngory/
// niko-server docs/IPC.md, version 1) for the data-plane processes that
// rayd runs itself: mode "fd", where the front passes each accepted TCP
// connection as its socket (SCM_RIGHTS) with the bytes it already read.
package nikoipc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	fdMagic  = "NKT1"
	addrSize = 19
	// The largest handoff: header, route and name of 255 bytes, addresses
	// and the front's prefetch (64 KiB at most).
	maxHandoff = 4 + 2 + 255 + 2*addrSize + 1 + 255 + 4 + 64<<10
)

var errBadMessage = errors.New("nikoipc: malformed fd message")

// Handoff is what travels with a passed socket.
type Handoff struct {
	Route    string
	Src, Dst netip.AddrPort
	SNI      string
	Prefetch []byte
}

func getAddr(b []byte) (netip.AddrPort, error) {
	addr := netip.AddrFrom16([16]byte(b[1:17]))
	switch b[0] {
	case 4:
		if !addr.Is4In6() {
			return netip.AddrPort{}, errBadMessage
		}
		addr = addr.Unmap()
	case 6:
	default:
		return netip.AddrPort{}, errBadMessage
	}
	return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(b[17:19])), nil
}

func putAddr(b []byte, addr netip.AddrPort) {
	b[0] = 6
	if addr.Addr().Unmap().Is4() {
		b[0] = 4
	}
	a16 := addr.Addr().As16()
	copy(b[1:17], a16[:])
	binary.BigEndian.PutUint16(b[17:19], addr.Port())
}

// Encode is the front's message for a passed socket (tests play the front).
func (h Handoff) Encode() []byte {
	b := append([]byte(fdMagic), 0, byte(len(h.Route)))
	b = append(b, h.Route...)
	var a [addrSize]byte
	putAddr(a[:], h.Src)
	b = append(b, a[:]...)
	putAddr(a[:], h.Dst)
	b = append(b, a[:]...)
	b = append(b, byte(len(h.SNI)))
	b = append(b, h.SNI...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(h.Prefetch)))
	return append(b, h.Prefetch...)
}

// DecodeHandoff reads the front's message.
func DecodeHandoff(msg []byte) (Handoff, error) {
	var h Handoff
	if len(msg) < 6 || string(msg[:4]) != fdMagic {
		return h, errBadMessage
	}
	n := int(msg[5])
	rest := msg[6:]
	if len(rest) < n+2*addrSize+1 {
		return h, errBadMessage
	}
	h.Route, rest = string(rest[:n]), rest[n:]
	var err error
	if h.Src, err = getAddr(rest[:addrSize]); err != nil {
		return h, err
	}
	if h.Dst, err = getAddr(rest[addrSize : 2*addrSize]); err != nil {
		return h, err
	}
	rest = rest[2*addrSize:]
	n = int(rest[0])
	if len(rest) < 1+n+4 {
		return h, errBadMessage
	}
	h.SNI, rest = string(rest[1:1+n]), rest[1+n:]
	if binary.BigEndian.Uint32(rest[:4]) != uint32(len(rest)-4) {
		return h, errBadMessage
	}
	h.Prefetch = rest[4:]
	return h, nil
}

// Listener is a backend's end of mode "fd": a net.Listener whose
// connections are the sockets the front passes, the front's prefetch
// read first and RemoteAddr the client's.
type Listener struct {
	ln       *net.UnixListener
	frontUID int
	log      *slog.Logger

	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

// ListenFD creates the SOCK_SEQPACKET socket at path, mode 0660 (its
// directory decides who reaches it), and takes passed sockets from the
// front only: the peer's UID must be frontUID.
func ListenFD(path string, frontUID int, log *slog.Logger) (*Listener, error) {
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
	l := &Listener{ln: ln, frontUID: frontUID, log: log, conns: make(chan net.Conn), closed: make(chan struct{})}
	go l.acceptLoop()
	return l, nil
}

func (l *Listener) acceptLoop() {
	for {
		c, err := l.ln.AcceptUnix()
		if err != nil {
			select {
			case <-l.closed:
				return
			default:
			}
			l.log.Warn("fd socket accept", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if uid := peerUID(c); uid != l.frontUID {
			l.log.Warn("refused a connection to the fd socket", "uid", uid, "want", l.frontUID)
			_ = c.Close()
			continue
		}
		_ = c.SetReadBuffer(4 << 20)
		go l.readLoop(c)
	}
}

func peerUID(c *net.UnixConn) int {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1
	}
	uid := -1
	_ = raw.Control(func(fd uintptr) {
		if cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
			uid = int(cred.Uid)
		}
	})
	return uid
}

func (l *Listener) readLoop(c *net.UnixConn) {
	defer func() { _ = c.Close() }()
	buf := make([]byte, maxHandoff)
	oob := make([]byte, syscall.CmsgSpace(4*4))
	for {
		n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
		if err != nil || (n == 0 && oobn == 0) {
			return
		}
		fds := receivedFDs(oob[:oobn])
		h, err := DecodeHandoff(buf[:n])
		if err != nil || len(fds) != 1 {
			l.log.Warn("bad handoff from the front", "sockets", len(fds), "err", err)
			for _, fd := range fds {
				_ = syscall.Close(fd)
			}
			continue
		}
		file := os.NewFile(uintptr(fds[0]), "front")
		conn, err := net.FileConn(file)
		file.Close()
		if err != nil {
			l.log.Warn("passed socket", "err", err)
			continue
		}
		passed := &Conn{Conn: conn, r: io.MultiReader(bytes.NewReader(bytes.Clone(h.Prefetch)), conn), remote: h.Src, sni: h.SNI}
		select {
		case l.conns <- passed:
		case <-l.closed:
			conn.Close()
			return
		}
	}
}

func receivedFDs(oob []byte) []int {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	var fds []int
	for i := range msgs {
		if got, err := syscall.ParseUnixRights(&msgs[i]); err == nil {
			fds = append(fds, got...)
		}
	}
	return fds
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *Listener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		_ = l.ln.Close()
	})
	return nil
}

func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Conn is a passed connection: the front's prefetch comes first.
type Conn struct {
	net.Conn
	r      io.Reader
	remote netip.AddrPort
	sni    string
}

func (c *Conn) Read(b []byte) (int, error) { return c.r.Read(b) }

// RemoteAddr is the client's address, as the front saw it.
func (c *Conn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.remote) }

// ServerName is the SNI the front routed by.
func (c *Conn) ServerName() string { return c.sni }

// CloseWrite half-closes the TCP connection.
func (c *Conn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// Pass plays the front: it sends conn's socket and the handoff to the
// backend at path (tests, and a reference for the protocol).
func Pass(backend *net.UnixConn, conn *net.TCPConn, h Handoff) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sendErr error
	err = raw.Control(func(fd uintptr) {
		_, _, sendErr = backend.WriteMsgUnix(h.Encode(), syscall.UnixRights(int(fd)), nil)
	})
	return errors.Join(err, sendErr)
}
