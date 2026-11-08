package naive

import (
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
)

// A ping socket's echo and reply to 127.0.0.1, the TTL changing each time
// as mtr's do: what one echo costs the node in syscalls and allocations.
func BenchmarkPingSocket(b *testing.B) {
	c, err := openPing(false)
	if err != nil {
		b.Skipf("no ICMP socket: %v", err)
	}
	p := c.(*pingSocket)
	defer p.Close()
	lo := netip.MustParseAddr("127.0.0.1")
	payload := make([]byte, 56)
	buf := make([]byte, icmpHead+icmpMaxPayload)
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		if err := p.send(lo, 1+i%30, uint16(i), payload); err != nil {
			b.Fatal(err)
		}
		for {
			ev, err := p.recv(buf)
			if err != nil {
				b.Fatal(err)
			}
			if ev.kind == icmpReply && ev.seq == uint16(i) {
				break
			}
		}
	}
}

// A stream's echo on the way out: the token, the destination, the seq;
// the socket discards it.
func BenchmarkICMPEcho(b *testing.B) {
	st, _, _ := icmpTestStream(b)
	st.s.icmpOpen = func(bool) (icmpConn, error) { return discardConn{make(chan struct{})}, nil }
	dst := netip.MustParseAddr("8.8.8.8")
	payload := make([]byte, 56)
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		refill(st)
		if err := st.echo(dst, 1+i%30, 1, uint16(i), payload, false); err != nil {
			b.Fatal(err)
		}
		st.forget(st.seq)
	}
}

type discardConn struct{ closed chan struct{} }

func (discardConn) send(netip.Addr, int, uint16, []byte) error { return nil }
func (c discardConn) recv([]byte) (icmpEvent, error) {
	<-c.closed
	return icmpEvent{}, net.ErrClosed
}
func (c discardConn) Close() error { close(c.closed); return nil }

// Many users' streams at once, their frames mostly without tokens: what
// each frame costs while others come.
func BenchmarkICMPEchoParallel(b *testing.B) {
	s := &Server{icmpOpen: func(bool) (icmpConn, error) { return discardConn{make(chan struct{})}, nil }}
	var next atomic.Uint32
	dst := netip.MustParseAddr("8.8.8.8")
	payload := make([]byte, 56)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		n := next.Add(1)
		st := newICMPStream(s, s.icmp.take([32]byte{byte(n), byte(n >> 8)}), io.Discard)
		defer func() { <-st.close() }()
		for i := 0; pb.Next(); i++ {
			_ = st.echo(dst, 1+i%30, 1, uint16(i), payload, false)
			st.forget(st.seq)
		}
	})
}
