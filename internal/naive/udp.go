package naive

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/arngory/raycontrol/internal/probe"
)

// UDP as HTTP/3 datagrams (spec/naive-udp-v1.md): one extended CONNECT
// with :protocol connect-udp (RFC 9298) per UDP socket of an app; HTTP
// datagrams (RFC 9297) with Context ID 2 carry the destination in each
// datagram, [address type][address][port][data] (§3.2); what does not fit
// a QUIC packet goes as a DATAGRAM capsule in the request's stream (§4.4).
// The policy is UoT's (uotStream): places shared with UoT's streams, pairs,
// names, the user's bytes, revocation; only the frames are new (§7).
const (
	// ConnectUDP is the request's :protocol, UDPPath its path: RFC 9298's
	// template with the target *, as bind-16 §2 has it for a request
	// without one target. "%2A" and "*" are the same path once decoded.
	ConnectUDP = "connect-udp"
	UDPPath    = "/.well-known/masque/udp/*/*/"
	// UDPHeader registers Context ID 2 with the format of §3.2, in the
	// request and in its 200: version 1. Any other value is a version the
	// node does not know.
	UDPHeader  = "Niko-Udp"
	udpVersion = "1"
	udpContext = 2
	// capsuleProtocol is RFC 9297 §3.4's header: the stream carries
	// capsules.
	capsuleProtocol = "Capsule-Protocol"

	// The address types of §3.2: from the client an IPv4 or IPv6 address
	// or a name, from the node the answer's source, IPv4 or IPv6.
	udpIPv4, udpIPv6, udpName = 4, 6, 3

	// capsuleQueued answers too large for a QUIC packet wait for the
	// stream, capsuleWait at most from when they came (§4.4): an older one
	// is dropped, stale UDP being worse than lost UDP, and in a full queue
	// the oldest gives way. A capsule whose write has begun is written
	// whole: one cut in half would end the stream. The answers that fit a
	// QUIC datagram wait in the stream's own queue of the connection's
	// sender (h3serve.StreamQueued: 32, the oldest giving way), which never
	// makes a request wait.
	capsuleQueued = 32
	capsuleWait   = 100 * time.Millisecond

	capsuleDatagram = 0x00
	// capsuleMax bounds a capsule's payload (§3.2): the longest HTTP
	// datagram a client may send, the Context ID in its longest form (8
	// bytes), a name of 255 bytes, the port and a client's longest UDP
	// payload. A longer capsule of any type resets the stream.
	capsuleMax = 8 + 1 + 1 + 255 + 2 + uotMaxPayload
	// quicCapsuleMax is the most a capsule carries for a pair marked as
	// QUIC's, either way (§4.4): 1280 − 28, what QUIC stacks start with.
	// The handshake and the full packets of a nested QUIC pass; its probes
	// of the path past what a QUIC packet carries are lost, as on a real
	// path.
	quicCapsuleMax = 1252

	// udpHead is room before an answer's data for its longest head: a
	// capsule's type and length (two bytes up to 16383), the Context ID,
	// the address type, an IPv6 address and the port.
	udpHead = 1 + 2 + 1 + 1 + 16 + 2
)

// H3Stream is an HTTP/3 request stream taken over for its datagrams: its
// content, which carries capsules (inside DATA frames, both ways), and its
// HTTP datagrams, the payload after the quarter stream ID. internal/naive
// does not import quic-go: cmd/rayd makes one of quic-go's stream
// (h3serve.Datagrams).
type H3Stream interface {
	io.ReadWriter
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	// SendDatagram queues b, one HTTP datagram, for the connection's
	// sender and never waits: in the stream's full queue the oldest gives
	// way. tooLarge, with nothing queued, when b does not fit a QUIC packet
	// of the connection; an error once the stream's sending side ended. n
	// is what OnSent hears of when it goes.
	SendDatagram(b []byte, n int) (tooLarge bool, err error)
	// OnSent sets what hears of each datagram the sender handed to QUIC:
	// the n it was queued with, from the sender's goroutine, possibly after
	// the stream ended.
	OnSent(func(n int))
	// Dropped is how many of the stream's datagrams did not go: pushed
	// out of its queue, or left in it at the end.
	Dropped() int64
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	// Close ends the stream cleanly (FIN); Reset resets it both ways. What
	// waits in its queue is dropped.
	Close() error
	Reset()
}

// H3 gives a request's HTTP/3 stream: ok false when there is none to give
// (HTTP/2, or a connection without HTTP/3 datagrams both ways: the server's
// SETTINGS_H3_DATAGRAM and the client's, waited for while ctx lasts). take
// writes the answer's header, 200 and what w's header holds, and gives the
// stream over to the handler, which ends it.
type H3 func(ctx context.Context, w http.ResponseWriter) (take func() H3Stream, ok bool)

// The kinds of datagrams dropped, for the log at a request's end (§7):
// why, never where.
const (
	dropBad      = iota // unreadable: short, an unknown address type, an empty name, port 0
	dropContext         // another Context ID: dropped without a word (RFC 9298 §5)
	dropDenied          // not an allowed address, or a name with none
	dropLimit           // a new destination past the limits (newPair, uotPeers)
	dropStranger        // an answer not from a pair
	dropLong            // past the ceiling: 65 507 bytes from the client, 1500 from a destination
	dropQueue           // a queue to the client is full, or the request ended with answers in it
	dropQUIC            // the QUIC rule (§4.4)
	dropLate            // a capsule that waited past capsuleWait
	dropWrite           // the write to the destination failed: no route (IPv6 on a node without it), the kernel's egress rules
	dropKinds
)

var dropNames = [dropKinds]string{"bad", "context", "denied", "limit", "stranger", "long", "queue", "quic", "late", "write"}

// udpCounts are datagrams: sent to the destinations (in) and passed to the
// client (out), of them those that went as capsules, and those dropped.
type udpCounts struct {
	in, out, capsulesIn, capsulesOut atomic.Int64
	dropped                          [dropKinds]atomic.Int64
}

// udpTotals are the process's datagram requests: answered 200, refused
// (429, 503), and their datagrams.
type udpTotals struct {
	requests, refused atomic.Int64
	udpCounts
}

// UDPStats are the datagram requests since the process started, as the
// stats socket gives them (TrafficSnapshot.UDP): nothing of who or where.
type UDPStats struct {
	Requests    int64 `json:"requests"` // answered 200
	Refused     int64 `json:"refused"`  // answered 429 or 503
	In          int64 `json:"in"`       // datagrams sent on to destinations
	Out         int64 `json:"out"`      // answers passed to clients
	CapsulesIn  int64 `json:"capsules_in"`
	CapsulesOut int64 `json:"capsules_out"`
	Dropped     int64 `json:"dropped"` // either way, whatever the reason
}

// UDPStats are the server's datagram requests since it started.
func (s *Server) UDPStats() UDPStats {
	t := &s.udp
	st := UDPStats{Requests: t.requests.Load(), Refused: t.refused.Load(), In: t.in.Load(), Out: t.out.Load(),
		CapsulesIn: t.capsulesIn.Load(), CapsulesOut: t.capsulesOut.Load()}
	for i := range t.dropped {
		st.Dropped += t.dropped[i].Load()
	}
	return st
}

// extendedConnect reports a CONNECT with a :protocol (RFC 8441, RFC 9220):
// HTTP/3 has it as the request's Proto, HTTP/2 (where Go's server takes
// it at all) as a header. naive's TCP CONNECT has none.
func extendedConnect(r *http.Request) bool {
	return (r.Proto != "HTTP/2.0" && r.Proto != "HTTP/3.0") || r.Header.Get(":protocol") != ""
}

// serveUDP answers a connect-udp request (§3.2, §7). To anyone who cannot
// use it, it is not there: the flag off, not HTTP/3, another path or
// version, no Padding, no password, a client without HTTP/3 datagrams get
// the site's answer, as any other request does. An authenticated request
// that cannot be served is told why before any 200: 429 at the limit of
// places, 503 without a socket.
func (s *Server) serveUDP(w http.ResponseWriter, r *http.Request) {
	if !s.UDP || s.H3 == nil || r.ProtoMajor != 3 || r.URL == nil || r.URL.Path != UDPPath ||
		r.Header.Get(UDPHeader) != udpVersion || r.Header.Get("Padding") == "" {
		s.Answer.ServeHTTP(w, r)
		return
	}
	pw, _ := password(r)
	a, ok := s.Users.admit(r.Context(), pw)
	if !ok {
		s.Answer.ServeHTTP(w, r)
		return
	}
	defer a.leave()
	take, ok := s.H3(a.ctx, w)
	if !ok {
		s.Answer.ServeHTTP(w, r)
		return
	}
	reply, _ := paddingType(r.Header)
	// A place among the user's UoT streams (spec/conn-limit-v1.md §2):
	// the quietest stream or request may give way, as for UoT.
	uctx, cancel := context.WithCancelCause(a.ctx)
	defer cancel(nil)
	slot, _ := s.lim.uotTake(a.key, cancel)
	if slot == nil {
		s.udp.refused.Add(1)
		s.logger().Debug("naive: too many UDP requests")
		refuse(w, http.StatusTooManyRequests, "", reply)
		return
	}
	defer s.lim.uotPut(slot)
	// One socket per request: the app's socket has one port of the node,
	// and answers come from where it sent only (port-restricted cone).
	open := s.udpSocket
	if open == nil {
		open = func(ctx context.Context) (*net.UDPConn, error) { return uotSocket(ctx, netip.AddrPort{}) }
	}
	conn, err := open(uctx)
	if err != nil {
		s.udp.refused.Add(1)
		s.logger().Debug("naive: no UDP socket", "err", err)
		refuse(w, http.StatusServiceUnavailable, "", reply)
		return
	}
	defer func() { _ = conn.Close() }()
	answerPadding(w, reply)
	w.Header().Set(capsuleProtocol, "?1")
	w.Header().Set(UDPHeader, udpVersion)
	st := take()
	s.udp.requests.Add(1)
	s.carryUDP(uctx, slot, a.traffic, conn, st)
}

// udpRequest is one datagram request's state: the policy is a uotStream's.
type udpRequest struct {
	s    *Server
	u    *uotStream
	conn *net.UDPConn
	st   H3Stream
	n    *udpCounts // its own allocation: the connection's sender holds it (sent)

	// sendMu: one client's datagram is sent at a time, from the stream's
	// capsules or from its QUIC datagrams; the stream's names (uotStream)
	// are one sender's, as UoT's.
	sendMu sync.Mutex
	// capsules go from the socket's reader to the stream's writer.
	capsules chan *udpAnswer
	done     chan struct{} // closed at the end: what waits is dropped
	failed   chan error    // the stream takes no more
}

// udpAnswer is an answer framed for the client at buf[dg:end], its data
// from buf[udpHead:], with room for a capsule's head before it.
type udpAnswer struct {
	buf     [udpHead + uotMaxAnswer + 1]byte
	dg, end int
	n       int   // its data
	quic    bool  // from a pair marked as QUIC's
	at      int64 // mono: when it came from the destination
}

// An answer that fits a QUIC datagram is copied into the stream's queue
// at once (h3serve.Stream.SendDatagram), and its buffer reads the next
// one. The bound of a request's answers is then its stream's queue, 32
// datagrams of 1.4 KiB at most, and capsuleQueued capsules of 1.5 KiB:
// under 100 KiB for a client that reads nothing and destinations that send
// as fast as they can (UoT's stream: 198 KiB); nothing of it outlives the
// request but a datagram its connection's sender has taken.
var udpAnswers = sync.Pool{New: func() any { return new(udpAnswer) }}

func (d *udpRequest) drop(kind int) { d.dropN(kind, 1) }

func (d *udpRequest) dropN(kind int, n int64) {
	if n > 0 {
		d.n.dropped[kind].Add(n)
		d.s.udp.dropped[kind].Add(n)
	}
}

// sentUp counts a datagram sent to its destination.
func (d *udpRequest) sentUp(capsule bool, n int) {
	d.n.in.Add(1)
	d.s.udp.in.Add(1)
	if capsule {
		d.n.capsulesIn.Add(1)
		d.s.udp.capsulesIn.Add(1)
	}
	d.u.traffic.addUp(n) // the payload, as it went to the destination
}

// passedDown is what counts an answer the client's side took: the
// request's idle time, its counts, the user's bytes. It holds none of the
// request's state but those: the connection's sender may call it after the
// request ended (H3Stream.OnSent).
func passedDown(slot *uotSlot, n *udpCounts, totals *udpTotals, traffic *Traffic) func(capsule bool, size int) {
	return func(capsule bool, size int) {
		slot.last.Store(mono())
		n.out.Add(1)
		totals.out.Add(1)
		if capsule {
			n.capsulesOut.Add(1)
			totals.capsulesOut.Add(1)
		}
		traffic.addDown(size) // the payload, as it came from the destination
	}
}

// fail notes that the stream takes no more.
func (d *udpRequest) fail(err error) {
	select {
	case d.failed <- err:
	default:
	}
}

// carryUDP carries a request's datagrams until the client ends it, the
// idle time runs out, the stream fails or ctx is done, and ends the
// stream: cleanly at the client's end, the idle time and an eviction for a
// new request, reset otherwise (the user revoked, a capsule that cannot be
// read, a client gone or not reading). Nothing reads or writes the stream once
// it returns, and nothing of the request is left waiting: its queues are
// empty, and the connection's sender is all that may still send one of its
// datagrams.
func (s *Server) carryUDP(ctx context.Context, slot *uotSlot, traffic *Traffic, conn *net.UDPConn, st H3Stream) {
	idle := s.uotIdle
	if idle == 0 {
		idle = uotIdle
	}
	// The lookups and the reader of datagrams end with it.
	rctx, stop := context.WithCancel(ctx)
	defer stop()
	u := &uotStream{s: s, ctx: rctx, slot: slot, traffic: traffic, names: map[string]uotResolved{}, peers: map[netip.AddrPort]pairTimes{}}
	u.touch()
	s.lim.uotRun(slot, u)
	d := &udpRequest{s: s, u: u, conn: conn, st: st, n: new(udpCounts), capsules: make(chan *udpAnswer, capsuleQueued),
		done: make(chan struct{}), failed: make(chan error, 1)}
	down := passedDown(slot, d.n, &s.udp, traffic)
	st.OnSent(func(n int) { down(false, n) })

	var readers sync.WaitGroup
	up := make(chan error, 1)
	readers.Go(func() { up <- d.readCapsules() })
	readers.Go(func() { d.readDatagrams(rctx) })
	readers.Go(d.receive)
	written := make(chan struct{})
	go func() {
		defer close(written)
		d.writeCapsules(down)
	}()

	tick := time.NewTicker(idle / 8)
	defer tick.Stop()
	reset := false
loop:
	for {
		select {
		case err := <-up:
			// The client's end (FIN) is the request's; a capsule that
			// cannot be read, or a stream that broke, resets it.
			reset = err != nil
			break loop
		case <-d.failed:
			reset = true
			break loop
		case <-ctx.Done():
			// Revoked, gone or shut down; an eviction ends cleanly.
			reset = !errors.Is(context.Cause(ctx), errEvicted)
			break loop
		case <-tick.C:
			if mono()-slot.last.Load() > int64(idle) {
				break loop
			}
		}
	}
	// The readers stop: the socket goes, the lookups and the datagrams'
	// wait end, a read of the stream fails.
	close(d.done)
	stop()
	_ = conn.Close()
	_ = st.SetReadDeadline(time.Now())
	readers.Wait()
	// The capsules' writer stops. A capsule the client does not take (flow
	// control) holds it: past a second its write fails, and the stream,
	// which may have half a capsule, is reset.
	select {
	case <-written:
	case <-time.After(time.Second):
		_ = st.SetWriteDeadline(time.Now())
		<-written
		reset = true
	}
	// What waits is dropped: the capsules here, the datagrams with the
	// stream's end.
	for left := true; left; {
		select {
		case a := <-d.capsules:
			d.drop(dropQueue)
			udpAnswers.Put(a)
		default:
			left = false
		}
	}
	// A quiet request that gave way to a new one ends as an idle one does:
	// cleanly, so the client takes it for the end of the socket, not for a
	// failure of the path (§3.2). Revocation and the rest reset.
	if reset || (context.Cause(ctx) != nil && !errors.Is(context.Cause(ctx), errEvicted)) {
		st.Reset()
	} else {
		_ = st.Close()
	}
	d.dropN(dropQueue, st.Dropped())
	// Counts only: no destination, no source in the log.
	args := []any{"in", d.n.in.Load(), "capsules_in", d.n.capsulesIn.Load(), "out", d.n.out.Load(), "capsules_out", d.n.capsulesOut.Load(),
		"reset", reset}
	for i := range d.n.dropped {
		if n := d.n.dropped[i].Load(); n > 0 {
			args = append(args, "dropped_"+dropNames[i], n)
		}
	}
	s.logger().Debug("naive: UDP request ended", args...)
}

// readDatagrams sends the client's QUIC datagrams on until ctx ends or the
// stream's receiving side does.
func (d *udpRequest) readDatagrams(ctx context.Context) {
	for {
		b, err := d.st.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		d.upstream(b, false)
	}
}

// readCapsules reads the client's capsules and sends the datagrams of
// DATAGRAM capsules on; others are skipped (RFC 9297 §3.2). nil at the
// client's end between two capsules; errRefused for one that cannot be
// read (too long, cut short); a read's error otherwise.
func (d *udpRequest) readCapsules() error {
	r := bufio.NewReaderSize(d.st, 4<<10)
	for {
		typ, n, err := readCapsuleHead(r)
		if errors.Is(err, io.EOF) {
			return nil // the client's end, between two capsules
		}
		if err != nil {
			return err
		}
		if typ != capsuleDatagram {
			if _, err := r.Discard(int(n)); err != nil {
				return fmt.Errorf("%w: a capsule cut short", errRefused)
			}
			continue
		}
		if int(n) <= r.Size() {
			b, err := next(r, int(n))
			if err != nil {
				return fmt.Errorf("%w: a capsule cut short", errRefused)
			}
			d.upstream(b, true)
			continue
		}
		// A long one: a buffer of the pool's while it is read, which the
		// client may make last (a head, then nothing) until the idle time
		// or eviction, as UoT's stream holds its packet's (uotBufs).
		buf := capsuleBufs.Get().(*[capsuleMax]byte)
		_, err = io.ReadFull(r, buf[:n])
		if err == nil {
			d.upstream(buf[:n], true)
		}
		capsuleBufs.Put(buf)
		if err != nil {
			return fmt.Errorf("%w: a capsule cut short", errRefused)
		}
	}
}

// capsuleBufs hold a long capsule while it is read and its datagram sent.
var capsuleBufs = sync.Pool{New: func() any { return new([capsuleMax]byte) }}

// readCapsuleHead reads a capsule's type and length: io.EOF at the end of
// the stream between capsules, errRefused for one longer than capsuleMax
// or a head cut short.
func readCapsuleHead(r *bufio.Reader) (typ, n uint64, err error) {
	typ, err = readVarint(r)
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, 0, fmt.Errorf("%w: a capsule cut short", errRefused)
		}
		return 0, 0, err
	}
	if n, err = readVarint(r); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, 0, fmt.Errorf("%w: a capsule cut short", errRefused)
		}
		return 0, 0, err
	}
	if n > capsuleMax {
		return 0, 0, fmt.Errorf("%w: a capsule of %d bytes", errRefused, n)
	}
	return typ, n, nil
}

// upstream sends one of the client's HTTP datagrams on, from a QUIC
// datagram or a capsule; what is not to be sent is dropped and counted.
func (d *udpRequest) upstream(b []byte, capsule bool) {
	// Any datagram of the client keeps the request, as any packet keeps a
	// UoT stream.
	d.u.touch()
	dest, data, why := parseUDP(b)
	if why >= 0 {
		d.drop(why)
		return
	}
	d.sendMu.Lock()
	defer d.sendMu.Unlock()
	to, ok := d.destination(dest)
	if !ok {
		d.drop(dropDenied)
		return
	}
	// The pair is QUIC's when its first datagram is (§4.4): an address
	// pair, which a name's pair is through the address it resolved to. The
	// rule comes before the pair: a capsule it drops makes none, and takes
	// no token for a new destination.
	quic := quicLong(data)
	if capsule && len(data) > quicCapsuleMax {
		if has, marked := d.u.pair(to); marked || (!has && quic) {
			d.drop(dropQUIC)
			return
		}
	}
	if !d.u.reach(to, quic) {
		d.drop(dropLimit)
		return
	}
	// A destination that answers "unreachable" fails a write or two: the
	// request lives on, as UDP would. What did not go is a drop: the
	// counts add up to what came.
	if n, err := d.conn.WriteToUDPAddrPort(data, to); err == nil {
		d.sentUp(capsule, n)
	} else {
		d.drop(dropWrite)
	}
}

// destination is where a client's datagram goes: the probe's endpoint for
// the probe name on its port (spec/probe-v1.md §1.1, the only address of
// loopback a datagram reaches), an allowed address otherwise.
func (d *udpRequest) destination(dest uotAddr) (netip.AddrPort, bool) {
	if dest.name == probe.Name {
		ap, err := netip.ParseAddrPort(d.s.Probe)
		if err != nil || ap.Port() != dest.port {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
	}
	return d.u.resolve(dest)
}

// receive takes the answers off the socket as they come and passes them
// on, framed: to the stream's queue of datagrams, which copies them, or,
// too large for a QUIC packet, to the capsules' writer. It never waits for
// the client; it stops when the socket ends.
func (d *udpRequest) receive() {
	a := udpAnswers.Get().(*udpAnswer)
	defer func() { udpAnswers.Put(a) }()
	var head [udpHead]byte
	for {
		n, from, err := d.conn.ReadFromUDPAddrPort(a.buf[udpHead:])
		if err != nil {
			var errno syscall.Errno
			if errors.As(err, &errno) {
				continue // an ICMP error: UDP goes on
			}
			return
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		ok, quic := d.u.hear(from)
		switch {
		case !ok:
			d.drop(dropStranger)
			continue
		case n > uotMaxAnswer:
			d.drop(dropLong)
			continue
		}
		h := appendUDPHead(head[:0], from)
		a.dg, a.end, a.n, a.quic, a.at = udpHead-len(h), udpHead+n, n, quic, mono()
		copy(a.buf[a.dg:udpHead], h)
		tooLarge, err := d.st.SendDatagram(a.buf[a.dg:a.end], n)
		switch {
		case err != nil:
			d.drop(dropQueue)
			d.fail(err)
			continue
		case !tooLarge:
			continue // copied: the buffer reads the next one
		case quic && n > quicCapsuleMax:
			d.drop(dropQUIC)
			continue
		}
		d.queueCapsule(a)
		a = udpAnswers.Get().(*udpAnswer)
	}
}

// queueCapsule queues an answer for the capsules' writer; in a full queue
// the oldest gives way. The reader is the only one that queues, so a place
// freed is its own.
func (d *udpRequest) queueCapsule(a *udpAnswer) {
	for {
		select {
		case d.capsules <- a:
			return
		default:
		}
		select {
		case old := <-d.capsules:
			d.drop(dropQueue)
			udpAnswers.Put(old)
		default:
		}
	}
}

// writeCapsules writes the queued capsules to the stream, each whole, until
// the request ends; one that came from its destination more than
// capsuleWait ago is dropped. A write that fails ends the request.
func (d *udpRequest) writeCapsules(down func(capsule bool, size int)) {
	for {
		var a *udpAnswer
		select {
		case <-d.done:
			return
		default:
		}
		select {
		case <-d.done:
			return
		case a = <-d.capsules:
		}
		if time.Duration(mono()-a.at) > capsuleWait {
			d.drop(dropLate)
			udpAnswers.Put(a)
			continue
		}
		var h [3]byte
		head := appendVarint(append(h[:0], capsuleDatagram), uint64(a.end-a.dg)) //nolint:gosec // G115: under 16384
		start := a.dg - len(head)
		copy(a.buf[start:a.dg], head)
		_, err := d.st.Write(a.buf[start:a.end])
		n := a.n
		udpAnswers.Put(a)
		if err != nil {
			d.fail(err)
			return
		}
		down(true, n)
	}
}

// parseUDP reads one of the client's HTTP datagrams (§3.2): after the
// Context ID, the destination and the data, which stays b's. why is a drop
// kind when it is not one to send, -1 otherwise.
//
//	[Context ID (varint) = 2][u8 type = 4 | 6 | 3][4 | 16 | u8 length + name][u16 port][data]
func parseUDP(b []byte) (dest uotAddr, data []byte, why int) {
	id, n := parseVarint(b)
	if n == 0 {
		return dest, nil, dropBad
	}
	if id != udpContext {
		return dest, nil, dropContext
	}
	b = b[n:]
	if len(b) < 1 {
		return dest, nil, dropBad
	}
	switch b[0] {
	case udpIPv4:
		if len(b) < 1+4+2 {
			return dest, nil, dropBad
		}
		dest.ip = netip.AddrFrom4([4]byte(b[1:5]))
		b = b[5:]
	case udpIPv6:
		if len(b) < 1+16+2 {
			return dest, nil, dropBad
		}
		dest.ip = netip.AddrFrom16([16]byte(b[1:17])).Unmap()
		b = b[17:]
	case udpName:
		// The length as an int: 2 + a byte of 254 or 255 wrapped around
		// as a byte, and a long name cut b the wrong way round.
		if len(b) < 2 || b[1] == 0 || len(b) < 2+int(b[1])+2 {
			return dest, nil, dropBad
		}
		l := int(b[1])
		dest.name = string(b[2 : 2+l])
		b = b[2+l:]
	default:
		return dest, nil, dropBad
	}
	dest.port = binary.BigEndian.Uint16(b)
	if dest.port == 0 {
		return dest, nil, dropBad
	}
	if data = b[2:]; len(data) > uotMaxPayload {
		return dest, nil, dropLong
	}
	return dest, data, -1
}

// appendUDPHead appends an answer's head (§3.2): the Context ID and its
// source, IPv4 or IPv6, never a name.
func appendUDPHead(b []byte, from netip.AddrPort) []byte {
	b = append(b, udpContext)
	if a := from.Addr().Unmap(); a.Is4() {
		b = append(b, udpIPv4)
		b = append(b, a.AsSlice()...)
	} else {
		b = append(b, udpIPv6)
		b = append(b, a.AsSlice()...)
	}
	return binary.BigEndian.AppendUint16(b, from.Port())
}

// quicLong reports a QUIC packet with a long header of version 1 or 2
// (RFC 9000 §17.2, RFC 9369 §3): the form bit, the version, and a
// destination connection ID QUIC allows.
func quicLong(b []byte) bool {
	if len(b) < 6 || b[0]&0x80 == 0 {
		return false
	}
	v := binary.BigEndian.Uint32(b[1:5])
	return (v == 1 || v == 0x6b3343cf) && b[5] <= 20
}

// appendVarint appends v as a QUIC variable-length integer (RFC 9000
// §16), in its shortest form; v below 2^62.
func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v < 1<<30:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	}
	return binary.BigEndian.AppendUint64(b, v|0xc0<<56)
}

// parseVarint reads a QUIC variable-length integer at the front of b, in
// any of its lengths: its value and how many bytes it took, 0 when b is
// short.
func parseVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for _, c := range b[1:n] {
		v = v<<8 | uint64(c)
	}
	return v, n
}

// readVarint reads a QUIC variable-length integer: io.EOF before its
// first byte, io.ErrUnexpectedEOF within it.
func readVarint(r io.ByteReader) (uint64, error) {
	c, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	n := 1 << (c >> 6)
	v := uint64(c & 0x3f)
	for range n - 1 {
		c, err := r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, io.ErrUnexpectedEOF
			}
			return 0, err
		}
		v = v<<8 | uint64(c)
	}
	return v, nil
}
