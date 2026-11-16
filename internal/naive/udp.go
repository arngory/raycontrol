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

	// udpQueued answers wait for SendDatagram, which blocks while the
	// connection's own queue is full (32 in quic-go): a full queue drops
	// the new one (§7). Without it the answers would wait in the socket's
	// buffer, hundreds of them, each late by all before it.
	udpQueued = 32
	// capsuleQueued answers too large for a QUIC packet wait for the
	// stream, capsuleWait at most (§4.4): an older one is dropped, stale UDP
	// being worse than lost UDP. A capsule whose write has begun is
	// written whole: one cut in half would end the stream.
	capsuleQueued = 32
	capsuleWait   = 100 * time.Millisecond

	capsuleDatagram = 0x00
	// capsuleMax bounds a capsule's payload (§3.2): the Context ID, a name
	// of 255 bytes, the port and a client's longest UDP payload. A longer
	// capsule of any type resets the stream.
	capsuleMax = 1 + 1 + 1 + 255 + 2 + uotMaxPayload
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
	// SendDatagram queues b as one QUIC datagram, waiting while the
	// connection's queue is full; tooLarge, with nothing sent, when it
	// does not fit a QUIC packet of the connection.
	SendDatagram(b []byte) (tooLarge bool, err error)
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	// Close ends the stream cleanly (FIN); Reset resets it both ways.
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
	dropQueue           // the queue to the client is full
	dropQUIC            // the QUIC rule (§4.4)
	dropLate            // a capsule that waited past capsuleWait
	dropKinds
)

var dropNames = [dropKinds]string{"bad", "context", "denied", "limit", "stranger", "long", "queue", "quic", "late"}

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
	conn, err := uotSocket(uctx, netip.AddrPort{})
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
	// The stream is the handler's now: ended here, cleanly or by a reset.
	// Reset: the user revoked (left the users file), the request gave way
	// to a new one, a capsule that cannot be read, a client gone or not
	// reading. Clean: the client's end, the idle time.
	if s.carryUDP(uctx, slot, a.traffic, conn, st) || context.Cause(uctx) != nil {
		st.Reset()
		return
	}
	_ = st.Close()
}

// udpRequest is one datagram request's state: the policy is a uotStream's.
type udpRequest struct {
	s    *Server
	u    *uotStream
	conn *net.UDPConn
	st   H3Stream
	n    udpCounts

	// sendMu: one client's datagram is sent at a time, from the stream's
	// capsules or from its QUIC datagrams; the stream's names (uotStream)
	// are one sender's, as UoT's.
	sendMu sync.Mutex
	// answers go from the socket's reader to the one that passes them to
	// SendDatagram; capsules from it to the stream's writer.
	answers  chan *udpAnswer
	capsules chan *udpAnswer
	done     chan struct{} // closed at the end: what waits is dropped
	failed   chan error    // a writer's end: the stream does not take more
}

// udpAnswer is an answer framed for the client at buf[dg:end], its data
// from buf[udpHead:], with room for a capsule's head before it.
type udpAnswer struct {
	buf     [udpHead + uotMaxAnswer + 1]byte
	dg, end int
	n       int   // its data
	quic    bool  // from a pair marked as QUIC's
	at      int64 // mono: when it was queued as a capsule
}

// The bound of a request's answers is udpQueued + capsuleQueued of them,
// 1.5 KiB each: under 100 KiB for a client that reads nothing and
// destinations that send as fast as they can (UoT's stream: 198 KiB).
var udpAnswers = sync.Pool{New: func() any { return new(udpAnswer) }}

func (d *udpRequest) drop(kind int) {
	d.n.dropped[kind].Add(1)
	d.s.udp.dropped[kind].Add(1)
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

// passedDown counts an answer the client's side took.
func (d *udpRequest) passedDown(capsule bool, n int) {
	d.u.touch()
	d.n.out.Add(1)
	d.s.udp.out.Add(1)
	if capsule {
		d.n.capsulesOut.Add(1)
		d.s.udp.capsulesOut.Add(1)
	}
	d.u.traffic.addDown(n) // the payload, as it came from the destination
}

// fail notes that a writer stopped: the stream takes no more.
func (d *udpRequest) fail(err error) {
	select {
	case d.failed <- err:
	default:
	}
}

// carryUDP carries a request's datagrams until the client ends it, the
// idle time runs out, a writer fails or ctx is done; reset says the stream
// must be reset, not ended. Nothing reads or writes the stream once it
// returns, but a SendDatagram that waits for the connection's queue,
// which ends by itself (the queue drains, or the connection ends).
func (s *Server) carryUDP(ctx context.Context, slot *uotSlot, traffic *Traffic, conn *net.UDPConn, st H3Stream) (reset bool) {
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
	d := &udpRequest{s: s, u: u, conn: conn, st: st, answers: make(chan *udpAnswer, udpQueued),
		capsules: make(chan *udpAnswer, capsuleQueued), done: make(chan struct{}), failed: make(chan error, 1)}

	var readers sync.WaitGroup
	up := make(chan error, 1)
	readers.Go(func() { up <- d.readCapsules() })
	readers.Go(func() { d.readDatagrams(rctx) })
	readers.Go(d.receive)
	delivered := make(chan struct{})
	go func() {
		defer close(delivered)
		d.deliver()
	}()
	written := make(chan struct{})
	go func() {
		defer close(written)
		d.writeCapsules()
	}()

	tick := time.NewTicker(idle / 8)
	defer tick.Stop()
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
			reset = true
			break loop
		case <-tick.C:
			if mono()-slot.last.Load() > int64(idle) {
				break loop
			}
		}
	}
	// The readers stop: the socket goes (its reader closes the answers),
	// the lookups and the datagrams' wait end, a read of the stream fails.
	close(d.done)
	stop()
	_ = conn.Close()
	_ = st.SetReadDeadline(time.Now())
	readers.Wait()
	// The writers drop what waits. A capsule the client does not take
	// (flow control) holds the stream's writer: past a second it fails,
	// and the stream, which may have half a capsule, is reset. A
	// SendDatagram that waits for the connection is left to end by itself.
	grace, graceEnd := context.WithTimeout(context.Background(), time.Second)
	defer graceEnd()
	select {
	case <-written:
	case <-grace.Done():
		_ = st.SetWriteDeadline(time.Now())
		<-written
		reset = true
	}
	select {
	case <-delivered:
	case <-grace.Done():
	}
	// Counts only: no destination, no source in the log.
	args := []any{"in", d.n.in.Load(), "capsules_in", d.n.capsulesIn.Load(), "out", d.n.out.Load(), "capsules_out", d.n.capsulesOut.Load()}
	for i := range d.n.dropped {
		if n := d.n.dropped[i].Load(); n > 0 {
			args = append(args, "dropped_"+dropNames[i], n)
		}
	}
	s.logger().Debug("naive: UDP request ended", args...)
	return reset
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

// capsuleBufs hold a long capsule while its datagram is sent.
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
	// pair, which a name's pair is through the address it resolved to.
	if !d.u.reach(to, quicLong(data)) {
		d.drop(dropLimit)
		return
	}
	if capsule && len(data) > quicCapsuleMax && d.u.quicPair(to) {
		d.drop(dropQUIC)
		return
	}
	// A destination that answers "unreachable" fails a write or two: the
	// request lives on, as UDP would.
	if n, err := d.conn.WriteToUDPAddrPort(data, to); err == nil {
		d.sentUp(capsule, n)
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

// receive takes the answers off the socket as they come and queues them
// for the client, framed; it closes the queue when the socket ends. It
// never waits for the client: a full queue drops the new answer.
func (d *udpRequest) receive() {
	defer close(d.answers)
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
		a.dg, a.end, a.n, a.quic = udpHead-len(h), udpHead+n, n, quic
		copy(a.buf[a.dg:udpHead], h)
		select {
		case d.answers <- a:
			a = udpAnswers.Get().(*udpAnswer)
		default:
			d.drop(dropQueue)
		}
	}
}

// deliver passes the queued answers to the client as QUIC datagrams, and
// those too large for one to the stream's writer, until the queue is
// closed, the request ends or the stream takes no more datagrams.
func (d *udpRequest) deliver() {
	defer close(d.capsules)
	for {
		a := nextAnswer(d.done, d.answers)
		if a == nil {
			return // the request ended, or the socket did
		}
		tooLarge, err := d.st.SendDatagram(a.buf[a.dg:a.end])
		switch {
		case err != nil:
			udpAnswers.Put(a)
			d.fail(err)
			return
		case !tooLarge:
			d.passedDown(false, a.n)
			udpAnswers.Put(a)
			continue
		case a.quic && a.n > quicCapsuleMax:
			d.drop(dropQUIC)
			udpAnswers.Put(a)
			continue
		}
		a.at = mono()
		select {
		case d.capsules <- a:
		default:
			d.drop(dropQueue)
			udpAnswers.Put(a)
		}
	}
}

// writeCapsules writes the queued capsules to the stream, each whole, until
// the queue is closed or the request ends; one that waited past
// capsuleWait is dropped. A write that fails ends the request.
func (d *udpRequest) writeCapsules() {
	for {
		a := nextAnswer(d.done, d.capsules)
		if a == nil {
			return // the request ended, or no more come
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
		d.passedDown(true, n)
	}
}

// nextAnswer is the next answer of q, waiting for one; nil once done is closed,
// which goes first, or q is.
func nextAnswer(done <-chan struct{}, q <-chan *udpAnswer) *udpAnswer {
	select {
	case <-done:
		return nil
	default:
	}
	select {
	case <-done:
		return nil
	case a := <-q:
		return a
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
		if len(b) < 2 || b[1] == 0 || len(b) < 2+int(b[1])+2 {
			return dest, nil, dropBad
		}
		dest.name = string(b[2 : 2+b[1]])
		b = b[2+b[1]:]
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
