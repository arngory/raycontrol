package h3serve

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// stalling is a server's socket that drops what it sends while stall is
// set: a client that acknowledges nothing.
type stalling struct {
	net.PacketConn
	stall atomic.Bool
}

func (s *stalling) WriteTo(b []byte, a net.Addr) (int, error) {
	if s.stall.Load() {
		return len(b), nil
	}
	return s.PacketConn.WriteTo(b, a)
}

// newStalling is a server's socket of loopback that can stall.
func newStalling(t *testing.T) *stalling {
	t.Helper()
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return &stalling{PacketConn: raw}
}

// serveStalling serves h with datagrams on pc, and gives a client's
// connection to it; the server ends with the test.
func serveStalling(t *testing.T, pc *stalling, h http.Handler) *http3.ClientConn {
	t.Helper()
	cert := selfSigned(t)
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, pc, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }, h,
			Options{Idle: time.Minute, MaxStreams: 100, PendingStreams: 10, MaxHeaderBytes: 16 << 10, Datagrams: true})
	}()
	qc, err := quic.DialAddr(t.Context(), pc.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true, //nolint:gosec // G402: the test's own server
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{http3.NextProtoH3}},
		&quic.Config{EnableDatagrams: true, MaxIdleTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = qc.CloseWithError(0, "")
		stop()
		<-done
	})
	return (&http3.Transport{EnableDatagrams: true}).NewClientConn(qc)
}

// connectUDP opens a connect-udp request on cc, and does not wait for its
// answer.
func connectUDP(t *testing.T, cc *http3.ClientConn) *http3.RequestStream {
	t.Helper()
	rs, err := cc.OpenRequestStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodConnect, "https://h3.test/x", nil)
	req.Proto = "connect-udp"
	if err := rs.SendRequestHeader(req); err != nil {
		t.Fatal(err)
	}
	return rs
}

// stall fills the connection's queue in quic-go with datagrams of st
// while the client acknowledges nothing, until the sender waits there:
// what it hears of stops growing. full is a datagram of a whole packet.
func stall(pc *stalling, st *Stream, full []byte, heard func() int) {
	pc.stall.Store(true)
	for i := range 400 {
		_, _ = st.SendDatagram(full, -i)
		time.Sleep(time.Millisecond)
	}
	for last := -1; last != heard(); {
		last = heard()
		time.Sleep(300 * time.Millisecond)
	}
}

// A request never waits for its datagrams, however stalled its connection:
// with quic-go's queue full and the sender waiting there, SendDatagram
// returns at once; the stream's queue keeps the newest StreamQueued, the
// oldest giving way, and counts what it dropped; its end drops the rest.
// "Too large" is told before anything is copied, from the limit learned of
// quic-go.
func TestSenderNeverWaits(t *testing.T) {
	pc := newStalling(t)
	type result struct {
		took             time.Duration
		kept             []int
		droppedBefore    int64
		queuedBefore     int // fillers still in the queue
		dropped, atClose int64
		limit            int
		tooLarge         bool
	}
	results := make(chan result, 1)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		take, ok := Datagrams(r.Context(), w)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		st := take()
		var mu sync.Mutex
		heard := 0
		st.OnSent(func(int) {
			mu.Lock()
			heard++
			mu.Unlock()
		})
		heardNow := func() int {
			mu.Lock()
			defer mu.Unlock()
			return heard
		}
		var res result
		res.limit = st.snd.limit()
		res.tooLarge, _ = st.SendDatagram(make([]byte, res.limit), 0) // the quarter stream ID too
		// Datagrams of a whole packet each: a probe quic-go sends while
		// nothing is acknowledged takes one or two, not a queue's worth.
		full := make([]byte, res.limit-len(st.qid))
		stall(pc, st, full, heardNow)
		res.droppedBefore = st.Dropped()
		st.mu.Lock()
		res.queuedBefore = st.n
		st.mu.Unlock()
		start := time.Now()
		for i := 1; i <= 200; i++ {
			if tooLarge, err := st.SendDatagram(full, i); tooLarge || err != nil {
				t.Errorf("marked %d: %v %v", i, tooLarge, err)
			}
		}
		res.took = time.Since(start)
		st.mu.Lock()
		for i := range st.n {
			res.kept = append(res.kept, st.ring[(st.head+i)%len(st.ring)].n)
		}
		st.mu.Unlock()
		res.dropped = st.Dropped()
		st.Reset()
		res.atClose = st.Dropped()
		results <- res
	})
	connectUDP(t, serveStalling(t, pc, h))
	var res result
	select {
	case res = <-results:
	case <-time.After(30 * time.Second):
		t.Fatal("the handler waited")
	}
	// IPv4: packets of 1250 bytes, less what QUIC takes.
	if res.limit <= 1100 || res.limit >= MaxPacketSize || !res.tooLarge {
		t.Errorf("the limit learned: %d; a datagram of it with its stream ID too large: %v", res.limit, res.tooLarge)
	}
	if res.took > 100*time.Millisecond {
		t.Errorf("200 datagrams queued in %v", res.took)
	}
	// The newest are kept, in order. The sender waits, but a probe of
	// quic-go's may still let a datagram or two go meanwhile.
	const slack = 4
	kept := len(res.kept)
	if kept < StreamQueued-slack || kept > StreamQueued || res.kept[kept-1] != 200 {
		t.Errorf("kept %v, want the newest %d", res.kept, StreamQueued)
	}
	for i := 1; i < kept; i++ {
		if res.kept[i] != res.kept[i-1]+1 {
			t.Errorf("kept %v: not the newest in order", res.kept)
			break
		}
	}
	// Every datagram queued is kept, or pushed one out: the fillers still
	// there, then the marked ones.
	if got, want := res.dropped-res.droppedBefore, int64(res.queuedBefore+200-kept); got < want-slack || got > want {
		t.Errorf("%d dropped of %d fillers and 200 marked, %d kept, want %d", got, res.queuedBefore, kept, want)
	}
	if got := res.atClose - res.dropped; got > int64(kept) || got < int64(kept)-slack {
		t.Errorf("%d dropped at the end, %d were kept", got, kept)
	}
}

// A request that ends while the connection's sender waits for good leaves
// nothing with it: its queue empties and it leaves the sender's turn,
// which holds the open requests only, however many came and went. (A
// stream that ended stayed in the turn until the sender came to it, which
// a stalled sender never does.)
func TestSenderForgetsEndedStreams(t *testing.T) {
	pc := newStalling(t)
	var snd *sender
	stalled := make(chan struct{})
	var first sync.Once
	ended := make(chan struct{}, 64)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		take, ok := Datagrams(r.Context(), w)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		st := take()
		full := make([]byte, st.snd.limit()-len(st.qid))
		isFirst := false
		first.Do(func() { isFirst = true })
		if isFirst {
			// The first stays open, and stalls the sender.
			var heard atomic.Int64
			st.OnSent(func(int) { heard.Add(1) })
			stall(pc, st, full, func() int { return int(heard.Load()) })
			snd = st.snd
			close(stalled)
			<-r.Context().Done()
			return
		}
		for range 3 {
			_, _ = st.SendDatagram(full, 0)
		}
		st.Reset()
		ended <- struct{}{}
	})
	cc := serveStalling(t, pc, h)
	connectUDP(t, cc)
	select {
	case <-stalled:
	case <-time.After(30 * time.Second):
		t.Fatal("not stalled")
	}
	const n = 50
	for range n {
		connectUDP(t, cc)
		select {
		case <-ended:
		case <-time.After(10 * time.Second):
			t.Fatal("a request did not end")
		}
	}
	snd.mu.Lock()
	inTurn := len(snd.ready)
	snd.mu.Unlock()
	// The first, when it is not in the sender's hand.
	if inTurn > 1 {
		t.Errorf("%d streams in the sender's turn after %d ended, one open", inTurn, n)
	}
}
