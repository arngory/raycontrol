package perimeter

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/arngory/raycontrol/internal/spa"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	nflog "github.com/florianl/go-nflog/v2"
)

// Handler checks one SPA packet from src.
type Handler func(src netip.Addr, pkt []byte)

// parseUDP extracts the source address and the UDP payload from an IPv4 or
// IPv6 packet as NFLOG delivers it. IPv6 extension headers are not followed:
// a SPA packet never carries them.
func parseUDP(pkt []byte) (netip.Addr, []byte, bool) {
	if len(pkt) < 1 {
		return netip.Addr{}, nil, false
	}
	var src netip.Addr
	var rest []byte
	switch pkt[0] >> 4 {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl+8 || pkt[9] != 17 {
			return src, nil, false
		}
		src = netip.AddrFrom4([4]byte(pkt[12:16]))
		rest = pkt[ihl:]
	case 6:
		if len(pkt) < 40+8 || pkt[6] != 17 {
			return src, nil, false
		}
		src = netip.AddrFrom16([16]byte(pkt[8:24]))
		rest = pkt[40:]
	default:
		return src, nil, false
	}
	ulen := int(binary.BigEndian.Uint16(rest[4:6]))
	if ulen < 8 || ulen > len(rest) {
		return src, nil, false
	}
	return src, rest[8:ulen], true
}

// ReadNFLOG delivers SPA packets logged by the firewall to group until ctx
// ends. The kernel has already dropped them, so no socket is ever bound on
// the UDP slot ports.
func ReadNFLOG(ctx context.Context, group uint16, h Handler, log *slog.Logger) error {
	// QThresh 1 pushes every packet at once: by default the kernel batches for
	// up to a second, longer than a client waits before connecting.
	nf, err := nflog.Open(&nflog.Config{Group: group, Copymode: nflog.CopyPacket, Bufsize: 2048, QThresh: 1})
	if err != nil {
		return err
	}
	defer nf.Close()
	err = nf.RegisterWithErrorFunc(ctx, func(a nflog.Attribute) int {
		if a.Payload == nil {
			return 0
		}
		if src, payload, ok := parseUDP(*a.Payload); ok {
			h(src, payload)
		}
		return 0
	}, func(err error) int {
		if ctx.Err() == nil {
			log.Warn("nflog read", "err", err)
		}
		return 0
	})
	if err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

// TCPCarrier accepts SPA v2 sent as the first data of a TCP connection on
// the slot ports (for networks that drop unknown UDP). It reads the packet
// up to EOF, hands it over and resets the connection without answering.
type TCPCarrier struct {
	Handler Handler
	LenMax  func() int
	Log     *slog.Logger
	// ReadTimeout bounds how long one connection may take to send.
	ReadTimeout time.Duration

	mu        sync.Mutex
	listeners map[uint16]net.Listener
	busy      chan struct{} // bounds connections being read at once
}

// maxInFlight caps concurrent TCP carrier connections; the firewall already
// limits SYNs per source, this protects against many sources at once.
const maxInFlight = 256

// Reconcile listens on exactly the given ports.
func (c *TCPCarrier) Reconcile(ports []uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.listeners == nil {
		c.listeners = map[uint16]net.Listener{}
		c.busy = make(chan struct{}, maxInFlight)
	}
	want := map[uint16]bool{}
	for _, p := range ports {
		want[p] = true
		if c.listeners[p] != nil {
			continue
		}
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(int(p)))
		if err != nil {
			c.Log.Warn("spa tcp listen", "port", p, "err", err)
			continue
		}
		c.listeners[p] = ln
		go c.serve(ln)
	}
	for p, ln := range c.listeners {
		if !want[p] {
			ln.Close()
			delete(c.listeners, p)
		}
	}
}

// Close stops all listeners.
func (c *TCPCarrier) Close() { c.Reconcile(nil) }

func (c *TCPCarrier) serve(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				c.Log.Warn("spa tcp accept", "err", err)
			}
			return
		}
		select {
		case c.busy <- struct{}{}:
			go func() {
				defer func() { <-c.busy }()
				c.handle(conn)
			}()
		default:
			conn.Close()
		}
	}
}

func (c *TCPCarrier) handle(conn net.Conn) {
	defer func() {
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0) // reset, never a graceful close
		}
		conn.Close()
	}()
	timeout := c.ReadTimeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	addr, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return
	}
	var hdr [5]byte
	n, err := io.ReadFull(conn, hdr[:])
	if n == 0 {
		return
	}
	if n == len(hdr) && spa.IsTLSCarrier(hdr[:]) {
		// A ClientHello carrier (spa-v2.md §10.1) says its length: read
		// exactly the record and answer at once. A client that sent a
		// ClientHello waits for the server's answer instead of closing,
		// and must not hold a slot until the timeout.
		rec := int(binary.BigEndian.Uint16(hdr[3:5]))
		if len(hdr)+rec > spa.TLSCarrierMax {
			return
		}
		data := make([]byte, len(hdr)+rec)
		copy(data, hdr[:])
		if _, err := io.ReadFull(conn, data[len(hdr):]); err != nil {
			return
		}
		if data, err = spa.FromTLSCarrier(data); err == nil {
			c.Handler(addr.Addr().Unmap(), data)
		}
		return
	}
	// A bare packet ends where the connection does. One byte more than the
	// maximum shows an oversized packet.
	data := hdr[:n]
	if err == nil {
		var rest []byte
		rest, err = io.ReadAll(io.LimitReader(conn, int64(c.LenMax()+1-n)))
		data = append(data, rest...)
	}
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !isTimeout(err) {
		return
	}
	c.Handler(addr.Addr().Unmap(), data)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
