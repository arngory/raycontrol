package naive

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func testAnswer(seq, size int) *uotAnswer {
	a := uotAnswers.Get().(*uotAnswer)
	a.start, a.end = headRoom-2, headRoom+size
	binary.BigEndian.PutUint16(a.buf[a.start:], uint16(size))
	binary.BigEndian.PutUint32(a.buf[headRoom:], uint32(seq))
	return a
}

func seqOf(a *uotAnswer) int { return int(binary.BigEndian.Uint32(a.buf[headRoom:])) }

// The queue keeps the newest answers in order, gives them in batches that
// fit one write, and gives nothing once closed.
func TestUoTQueue(t *testing.T) {
	q := &uotQueue{wake: make(chan struct{}, 1)}
	const sent = 3*uotQueued + 7
	for i := range sent {
		q.put(testAnswer(i, 4))
	}
	if q.n != uotQueued || q.dropped != sent-uotQueued || q.in != sent {
		t.Fatalf("%d queued, %d dropped of %d", q.n, q.dropped, q.in)
	}
	// Small answers: all that wait fit one write.
	var room [uotQueued]*uotAnswer
	batch := q.take(room[:0], uotBatch)
	if len(batch) != uotQueued {
		t.Fatalf("a batch of %d", len(batch))
	}
	for i, a := range batch {
		if want := sent - uotQueued + i; seqOf(a) != want {
			t.Fatalf("answer %d of the batch is %d, want %d: the oldest must go, the order stay", i, seqOf(a), want)
		}
	}
	// Full ones: a write's worth, whole packets only, the rest next time.
	for i := range 30 {
		q.put(testAnswer(i, uotMaxAnswer))
	}
	next := 0
	for q.n > 0 {
		batch := q.take(room[:0], uotBatch)
		size := 0
		for _, a := range batch {
			if seqOf(a) != next {
				t.Fatalf("answer %d came as %d", next, seqOf(a))
			}
			next++
			size += a.end - a.start
		}
		if size > uotBatch || len(batch) == 0 {
			t.Fatalf("a batch of %d answers, %d bytes", len(batch), size)
		}
	}
	if next != 30 {
		t.Fatalf("%d answers of 30 came", next)
	}
	// A waiting take ends with the queue; a put after it is dropped.
	done := make(chan []*uotAnswer)
	go func() { done <- q.take(nil, uotBatch) }()
	q.close()
	select {
	case b := <-done:
		if b != nil {
			t.Fatalf("a closed queue gave %d answers", len(b))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("take did not end with the queue")
	}
	q.put(testAnswer(1, 4))
	if q.n != 0 {
		t.Fatal("a closed queue took an answer")
	}
}

// gatedStream is a client that takes nothing until its gate opens: a
// write waits there. What it then takes is kept, write by write.
type gatedStream struct {
	io.Reader
	gate    chan struct{}
	waiting chan struct{} // closed when the first write waits
	once    sync.Once

	mu     sync.Mutex
	writes [][]byte
}

func (g *gatedStream) Write(b []byte) (int, error) {
	g.once.Do(func() { close(g.waiting) })
	<-g.gate
	g.mu.Lock()
	g.writes = append(g.writes, bytes.Clone(b))
	g.mu.Unlock()
	return len(b), nil
}

func (g *gatedStream) SetReadDeadline(time.Time) error  { return nil }
func (g *gatedStream) SetWriteDeadline(time.Time) error { return nil }

func (g *gatedStream) taken() [][]byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([][]byte(nil), g.writes...)
}

// uotSource is a destination that sends on its own: a UDP socket that
// learns where a stream's socket is from the stream's first packet.
func uotSource(t *testing.T) (*net.UDPConn, func() netip.AddrPort) {
	t.Helper()
	src, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { src.Close() })
	return src, func() netip.AddrPort {
		t.Helper()
		_ = src.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, from, err := src.ReadFromUDPAddrPort(make([]byte, 64))
		if err != nil {
			t.Fatal(err)
		}
		return from
	}
}

// uotRequest is a connected stream's request to dst and one packet, so
// that the destination hears of the stream.
func uotRequest(dst netip.AddrPort) []byte {
	b := append([]byte{1}, socksAddr(dst)...)
	return append(b, 0, 1, '?')
}

// Answers a client does not take wait in the stream's queue, the newest
// uotQueued of them: the client then gets those, in order and in one
// write, not the thousand that came before. Before the queue they waited
// in the socket's and the connection's buffers, each late by all the
// others.
func TestUoTAnswersDropOldest(t *testing.T) {
	src, heard := uotSource(t)
	dst := src.LocalAddr().(*net.UDPAddr).AddrPort()
	s := &Server{Allow: func(a netip.Addr) bool { return a == dst.Addr() }}
	slot, _ := s.lim.uotTake("u3", func(error) {})
	pr, pw := io.Pipe()
	defer pw.Close()
	go func() { _, _ = pw.Write(uotRequest(dst)) }()
	st := &gatedStream{Reader: pr, gate: make(chan struct{}), waiting: make(chan struct{})}
	traffic := new(Traffic)
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- s.serveUoT(ctx, slot, traffic, st, st) }()
	stream := heard()

	answer := func(seq int) {
		t.Helper()
		if _, err := src.WriteToUDPAddrPort(binary.BigEndian.AppendUint64(nil, uint64(seq)), stream); err != nil {
			t.Fatal(err)
		}
	}
	// The first answer waits in the client's write; the rest come behind.
	answer(0)
	select {
	case <-st.waiting:
	case <-time.After(5 * time.Second):
		t.Fatal("the first answer was not passed on")
	}
	const sent = 1000
	queue := func() (in, dropped int64, n int) {
		s.lim.mu.Lock()
		q := &slot.stream.answers
		s.lim.mu.Unlock()
		q.mu.Lock()
		defer q.mu.Unlock()
		return q.in, q.dropped, q.n
	}
	for seq := 1; seq <= sent; seq++ {
		answer(seq)
		if seq%50 == 0 {
			// Not faster than the stream reads its socket: this is about
			// the queue, not the kernel's buffer.
			eventually(t, "the answers were not read off the socket", func() bool { in, _, _ := queue(); return in == int64(seq)+1 })
		}
	}
	if in, dropped, n := queue(); in != sent+1 || n != uotQueued || dropped != sent-uotQueued {
		t.Fatalf("%d answers came, %d wait, %d dropped", in, n, dropped)
	}

	close(st.gate)
	eventually(t, "the queued answers were not passed on", func() bool { return len(st.taken()) == 2 })
	writes := st.taken()
	var seqs []int
	for _, w := range writes {
		for len(w) > 0 {
			n := int(binary.BigEndian.Uint16(w))
			if n != 8 || len(w) < 2+n {
				t.Fatalf("a write is no whole packets: % x", w)
			}
			seqs = append(seqs, int(binary.BigEndian.Uint64(w[2:])))
			w = w[2+n:]
		}
	}
	if len(seqs) != 1+uotQueued || seqs[0] != 0 {
		t.Fatalf("%d answers came to the client, the first %d", len(seqs), seqs[0])
	}
	for i, seq := range seqs[1:] {
		if want := sent - uotQueued + 1 + i; seq != want {
			t.Fatalf("answer %d after the wait is %d, want %d: the newest %d in order", i, seq, want, uotQueued)
		}
	}
	// Only what the client took counts as the user's bytes.
	if got := traffic.downN.Load(); got != int64(8*len(seqs)) {
		t.Fatalf("%d bytes counted for %d answers of 8", got, len(seqs))
	}
	cancel()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream did not end")
	}
}

// A client that stopped reading does not keep its stream because the
// destination keeps sending: an answer that only came is no sign of life.
func TestUoTStuckClientBusyDestination(t *testing.T) {
	src, heard := uotSource(t)
	dst := src.LocalAddr().(*net.UDPAddr).AddrPort()
	s := &Server{Allow: func(a netip.Addr) bool { return a == dst.Addr() }, uotIdle: 300 * time.Millisecond}
	slot, _ := s.lim.uotTake("u3", func(error) {})
	pr, pw := io.Pipe()
	defer pw.Close()
	go func() { _, _ = pw.Write(uotRequest(dst)) }()
	st := &stuckStream{Reader: pr, deadline: make(chan struct{})}
	served := make(chan error, 1)
	start := time.Now()
	go func() { served <- s.serveUoT(context.Background(), slot, nil, st, st) }()
	stream := heard()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
				_, _ = src.WriteToUDPAddrPort([]byte("still here"), stream)
			}
		}
	}()
	select {
	case err := <-served:
		if !errors.Is(err, errRefused) {
			t.Fatalf("a stuck stream ended with %v, not a reset", err)
		}
		// The idle time, its check (an eighth of it) and the second a
		// write gets.
		if d := time.Since(start); d > 3*time.Second {
			t.Fatalf("the stream ended after %v", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a destination that keeps sending held the stream of a client that does not read")
	}
}
