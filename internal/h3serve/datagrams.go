package h3serve

import (
	"context"
	"errors"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// The HTTP datagrams (RFC 9297) of a connection's requests go out from one
// goroutine of the connection's, its sender. quic-go's SendDatagram waits
// while the connection's own queue (32 datagrams) is full, and a client
// that keeps sending but acknowledges nothing keeps it full for as long as
// it keeps the connection: each packet of its starts the idle time anew. A
// request that waited there outlived itself, with all it held; one after
// another, without a bound. So no request waits: it puts its datagrams in a
// queue of its own, StreamQueued long, whose oldest gives way to a new one,
// and the sender takes from the requests' queues in turn and alone waits
// for quic-go. A sender that waits for good holds one datagram, and the
// queues of the requests still open; a request that ends takes its queue
// with it, and the sender ends with the connection. No watchdog: what it
// holds is the connection's, bounded, and holds up nothing but the
// datagrams of the client that does not acknowledge them.
const (
	// StreamQueued is how many datagrams a request's queue holds.
	StreamQueued = 32
	// SettingsWait bounds how long a request waits for its client's
	// SETTINGS (Datagrams): a client sends them first thing, before any
	// request.
	SettingsWait = HeaderTimeout
	// datagramBuf is room for the longest QUIC datagram payload quic-go
	// sends: its packets are 1452 bytes at most (MaxPacketBufferSize).
	datagramBuf = 1452
)

// sender sends a connection's datagrams (above).
type sender struct {
	qc *quic.Conn // set by serveConn before any request is served

	once sync.Once
	max  atomic.Int64 // the largest QUIC datagram payload; 0: none

	mu    sync.Mutex    // under a stream's own, where both are held
	ready []*Stream     // streams with datagrams waiting, in turn
	wake  chan struct{} // one place: a stream became ready
}

type senderKey struct{}

func newSender() *sender { return &sender{wake: make(chan struct{}, 1)} }

// probe is longer than any QUIC datagram quic-go sends (datagramBuf): it
// only ever learns the limit.
var probe [1 << 16]byte

// limit is the largest payload of a QUIC datagram of the connection, the
// quarter stream ID included; 0 when the client takes none. It is learned
// once, from quic-go: SendDatagram checks the size before it queues
// anything, and refuses an oversized datagram with the limit, the least of
// the client's max_datagram_frame_size and what the connection's packets
// carry. That is constant: the packets are of a size chosen at the
// connection's start, and no search of the path's MTU changes it (Config).
// Asking quic-go, rather than working the number out, holds whatever its
// packets' overhead is in a later version. A limit that shrank all the
// same is learned again at the next datagram too large (run).
func (s *sender) limit() int {
	s.once.Do(func() {
		if tl, ok := errors.AsType[*quic.DatagramTooLargeError](s.qc.SendDatagram(probe[:])); ok {
			s.max.Store(tl.MaxDatagramPayloadSize)
		}
	})
	return int(s.max.Load())
}

// push puts a stream with datagrams waiting at the end of the turn. Under
// the stream's lock: its place in the turn follows its turn flag.
func (s *sender) push(d *Stream) {
	s.mu.Lock()
	s.ready = append(s.ready, d)
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// remove takes a stream that ended out of the turn, if it is there: a
// sender that waits for quic-go for good takes nothing from the turn, and
// what is there stays as long. Under the stream's lock.
func (s *sender) remove(d *Stream) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i := slices.Index(s.ready, d); i >= 0 {
		s.ready = slices.Delete(s.ready, i, i+1)
	}
}

// next is the stream whose turn it is, waiting for one; nil once the
// connection ended.
func (s *sender) next() *Stream {
	for {
		s.mu.Lock()
		if len(s.ready) > 0 {
			d := s.ready[0]
			s.ready[0] = nil
			s.ready = s.ready[1:]
			if len(s.ready) == 0 {
				s.ready = nil // the array goes
			}
			s.mu.Unlock()
			return d
		}
		s.mu.Unlock()
		select {
		case <-s.wake:
		case <-s.qc.Context().Done():
			return nil
		}
	}
}

// run sends the requests' datagrams, a stream's one at a time in turn,
// until the connection ends.
func (s *sender) run() {
	for {
		d := s.next()
		if d == nil {
			return
		}
		b, n, sent := d.pop()
		if b == nil {
			continue // it ended, or had nothing left
		}
		err := s.qc.SendDatagram(b.b[:b.len])
		datagramBufs.Put(b)
		if tl, ok := errors.AsType[*quic.DatagramTooLargeError](err); ok {
			s.max.Store(tl.MaxDatagramPayloadSize)
			d.dropped.Add(1)
			continue
		}
		if err == nil && sent != nil {
			sent(n)
		}
	}
}

// datagram is a QUIC datagram payload waiting: the quarter stream ID, then
// the HTTP datagram.
type datagram struct {
	b   [datagramBuf]byte
	len int
}

var datagramBufs = sync.Pool{New: func() any { return new(datagram) }}

// queued is a datagram in a stream's queue, with the number its sender
// hears of when it goes.
type queued struct {
	d *datagram
	n int
}

// Datagrams gives a request's HTTP/3 stream with its datagrams (RFC 9297):
// ok false when w is no HTTP/3 server's of this package, when the server
// does not announce datagrams (Options.Datagrams), when the client's
// SETTINGS, waited for while ctx lasts and SettingsWait at most, do not
// have SETTINGS_H3_DATAGRAM, or when its transport parameters take no
// datagram. take writes the answer's header (200 unless the handler wrote
// another status) and gives the stream over: the handler ends it, with
// Stream.Close or Stream.Reset.
func Datagrams(ctx context.Context, w http.ResponseWriter) (take func() *Stream, ok bool) {
	snd, _ := ctx.Value(senderKey{}).(*sender)
	hw, isH3 := w.(interface {
		http3.HTTPStreamer
		http3.Settingser
	})
	if snd == nil || snd.qc == nil || !isH3 {
		return nil, false
	}
	t := time.NewTimer(SettingsWait)
	defer t.Stop()
	select {
	case <-hw.ReceivedSettings():
	case <-ctx.Done():
		return nil, false
	case <-t.C:
		return nil, false
	}
	if st := hw.Settings(); st == nil || !st.EnableDatagrams || snd.limit() <= 0 {
		return nil, false
	}
	return func() *Stream {
		s := hw.HTTPStream()
		return &Stream{s: s, snd: snd, qid: quicvarint.Append(nil, uint64(s.StreamID()/4))}
	}, true
}

// Stream is a request's HTTP/3 stream, taken over for its datagrams: its
// content (inside DATA frames, which carry capsules) and its HTTP
// datagrams, the payload after the quarter stream ID. Its datagrams wait in
// a queue of its own for the connection's sender (above).
type Stream struct {
	s   *http3.Stream
	snd *sender
	qid []byte // the quarter stream ID, which each datagram begins with

	dropped atomic.Int64

	mu      sync.Mutex
	ring    [StreamQueued]queued
	head, n int
	turn    bool // in the sender's turn
	closed  bool
	sent    func(n int)
}

func (d *Stream) Read(b []byte) (int, error)         { return d.s.Read(b) }
func (d *Stream) Write(b []byte) (int, error)        { return d.s.Write(b) }
func (d *Stream) SetReadDeadline(t time.Time) error  { return d.s.SetReadDeadline(t) }
func (d *Stream) SetWriteDeadline(t time.Time) error { return d.s.SetWriteDeadline(t) }

// SendDatagram queues b, one HTTP datagram, for the connection's sender,
// and never waits: in a full queue the oldest gives way. tooLarge, with
// nothing queued and nothing copied, when b does not fit a QUIC packet of
// the connection; an error once the stream's sending side ended. n is what
// OnSent hears of when the datagram goes.
func (d *Stream) SendDatagram(b []byte, n int) (tooLarge bool, err error) {
	if err := context.Cause(d.s.Context()); err != nil {
		return false, err
	}
	if l := len(d.qid) + len(b); l > d.snd.limit() || l > datagramBuf {
		return true, nil
	}
	dg := datagramBufs.Get().(*datagram)
	dg.len = copy(dg.b[:], d.qid)
	dg.len += copy(dg.b[dg.len:], b)
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		datagramBufs.Put(dg)
		return false, net.ErrClosed
	}
	var old *datagram
	if d.n == len(d.ring) {
		old = d.ring[d.head].d
		d.ring[d.head] = queued{}
		d.head = (d.head + 1) % len(d.ring)
		d.n--
	}
	d.ring[(d.head+d.n)%len(d.ring)] = queued{d: dg, n: n}
	d.n++
	if !d.turn {
		d.turn = true
		d.snd.push(d)
	}
	d.mu.Unlock()
	if old != nil {
		datagramBufs.Put(old)
		d.dropped.Add(1)
	}
	return false, nil
}

// pop takes the oldest datagram for the sender (next took the stream out
// of the turn), and puts the stream at the end of the turn again when more
// wait; nil when none does.
func (d *Stream) pop() (dg *datagram, n int, sent func(int)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.n == 0 || d.closed {
		d.turn = false
		return nil, 0, nil
	}
	q := d.ring[d.head]
	d.ring[d.head] = queued{}
	d.head = (d.head + 1) % len(d.ring)
	d.n--
	d.turn = d.n > 0
	if d.turn {
		d.snd.push(d)
	}
	return q.d, q.n, d.sent
}

// OnSent sets what hears of each datagram quic-go took for sending, from
// the connection's sender: the n it was queued with. A datagram that the
// sender had taken when the stream ended may still be heard of after.
func (d *Stream) OnSent(f func(n int)) {
	d.mu.Lock()
	d.sent = f
	d.mu.Unlock()
}

// Dropped is how many of the stream's datagrams did not go: pushed out of
// its queue by newer ones, left in it when the stream ended, or refused by
// quic-go after all.
func (d *Stream) Dropped() int64 { return d.dropped.Load() }

// ReceiveDatagram waits for the next datagram of the stream; an error once
// ctx ends or the stream's receiving side does.
func (d *Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return d.s.ReceiveDatagram(ctx)
}

// end empties the stream's queue and takes it out of the sender's turn:
// nothing more of it goes, and nothing of it is left with the sender but a
// datagram it has taken.
func (d *Stream) end() {
	d.mu.Lock()
	d.closed = true
	d.sent = nil
	if d.turn {
		d.turn = false
		d.snd.remove(d)
	}
	left := d.n
	for d.n > 0 {
		datagramBufs.Put(d.ring[d.head].d)
		d.ring[d.head] = queued{}
		d.head = (d.head + 1) % len(d.ring)
		d.n--
	}
	d.mu.Unlock()
	d.dropped.Add(int64(left))
}

// Close ends the stream cleanly: FIN, and nothing more read, as http3 ends
// a request whose handler returned. What waits in its queue is dropped.
func (d *Stream) Close() error {
	d.end()
	d.s.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	return d.s.Close()
}

// Reset resets the stream both ways, as http3 resets a request whose
// handler aborted (http.ErrAbortHandler). What waits in its queue is
// dropped.
func (d *Stream) Reset() {
	d.end()
	d.s.CancelRead(quic.StreamErrorCode(http3.ErrCodeInternalError))
	d.s.CancelWrite(quic.StreamErrorCode(http3.ErrCodeInternalError))
}
