package naive

import (
	"context"
	"net"
	"sync"
	"syscall"
)

// notSentLowat bounds what the kernel holds of an HTTP/2 connection that it
// has not sent yet (TCP_NOTSENT_LOWAT), while the connection carries
// datagrams: UoT or ICMP streams. Without it a connection that sends
// faster than its path carries fills the socket's send buffer, megabytes
// once the buffer has grown, and every tunnel's next byte waits behind all
// of it: seconds for a UDP answer or a ping behind a download. With it the
// kernel takes this much unsent and no more, the rest waits in the tunnels
// (one write each, which HTTP/2 takes in turn), and what cannot wait is
// dropped there (uotQueue).
//
// 128 KiB is two of the kernel's largest segments to hand to the network
// at once (64 KiB with TSO), so a path is fed as before; behind one of
// 10 Mbit/s it is 0.1 s, where megabytes were seconds.
//
// Only while there are datagrams: the bound makes the sender wait for the
// socket more often, which on loopback, where the processor is the limit,
// cost four parallel downloads of a connection about 7 % (4.4 to
// 4.0 Gbit/s; one download nothing). A connection of TCP tunnels alone is
// as it was.
const notSentLowat = 128 << 10

// connSocket is an HTTP/2 connection's socket, as its streams know it.
type connSocket struct {
	rc syscall.RawConn

	mu        sync.Mutex
	datagrams int // UoT and ICMP streams open on the connection
	own       int // the socket's bound before the first of them
}

type connSocketKey struct{}

// connContext gives a connection's requests its socket (http.Server's
// ConnContext). c is the TLS connection; one that is over no socket of its
// own (a test's pipe) has none.
func connContext(ctx context.Context, c net.Conn) context.Context {
	if t, ok := c.(interface{ NetConn() net.Conn }); ok {
		c = t.NetConn()
	}
	sc, ok := c.(syscall.Conn)
	if !ok {
		return ctx
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return ctx
	}
	return context.WithValue(ctx, connSocketKey{}, &connSocket{rc: rc})
}

// datagramStream notes a UoT or ICMP stream on the request's connection,
// until done: the first one bounds the socket's unsent bytes, the last one's
// end gives the socket its own bound back. Nothing for a connection with no
// socket of its own (HTTP/3: QUIC sends each stream's frames as it can).
func datagramStream(ctx context.Context) (done func()) {
	c, _ := ctx.Value(connSocketKey{}).(*connSocket)
	if c == nil {
		return func() {}
	}
	c.add(1)
	return func() { c.add(-1) }
}

func (c *connSocket) add(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	was := c.datagrams
	c.datagrams += n
	// A socket that does not take the option (closed by now) is left as it
	// is. Its own bound is what the system gave it (0 where it reads as not
	// set: the system's then).
	_ = c.rc.Control(func(fd uintptr) {
		switch {
		case was == 0 && c.datagrams > 0:
			c.own, _ = lowat(fd)
			_ = setLowat(fd, notSentLowat)
		case was > 0 && c.datagrams == 0:
			_ = setLowat(fd, c.own)
		}
	})
}
