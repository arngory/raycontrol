// Package naive serves NaiveProxy over HTTP/2 for the node's clients
// (docs/decisions.md, R2-14): an authenticated CONNECT with naive's
// padding opens a tunnel; anything else gets the site's answer, never 407.
// TLS is the caller's, the site's (site.TLSConfigFor: a probe's handshake
// goes as the site's does); a request over a key exchange other than
// X25519MLKEM768 is answered as the site answers it (site.PostQuantum).
package naive

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/arngory/raycontrol/internal/memlimit"
	"github.com/arngory/raycontrol/internal/probe"
	"github.com/arngory/raycontrol/internal/site"
)

// Server handles the requests of one naive service.
type Server struct {
	Users *Users
	// Answer serves whatever is not an authenticated naive CONNECT: the
	// site's answer (an empty 404 by default).
	Answer http.Handler
	// Dial reaches the destination; PublicDialer when nil.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Probe is where the probe name leads (the subscription endpoint on
	// loopback, R4-16); that name and no other address reaches it.
	Probe string
	// Allow says which addresses UDP over TCP and ICMP may reach (Public
	// when nil); Resolve looks UDP's names up (the system's resolver when
	// nil).
	Allow   func(netip.Addr) bool
	Resolve func(ctx context.Context, name string) ([]netip.Addr, error)
	// ICMP carries ping and traceroute through ICMPName (spec/icmp-v1.md):
	// off unless the service has icmp=on.
	ICMP bool
	// UDP carries UDP as HTTP/3 datagrams (spec/naive-udp-v1.md, udp.go):
	// off unless the service has udp=on. H3 gives a request's HTTP/3
	// stream (cmd/rayd: h3serve.Datagrams); without it no request is one.
	UDP bool
	H3  H3
	Log *slog.Logger

	// lim are the per-user limits (spec/conn-limit-v1.md §3.1), names the
	// process's cache of names.
	lim      limits
	names    names
	uotIdle  time.Duration // uotIdle when 0 (tests make it short)
	dialWait time.Duration // dialTimeout when 0 (tests make it short)
	// dialAddr dials one address of a destination; the public dialer when
	// nil (tests have their own, under the server's own choice of
	// addresses). minAttempt is the least time an address gets; the
	// constant when 0.
	dialAddr   func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
	minAttempt time.Duration

	icmp     icmpLimits
	icmpIdle time.Duration                   // icmpIdle when 0
	icmpOpen func(v6 bool) (icmpConn, error) // openPing when nil
	icmpWarn icmpWarn

	udp       udpTotals
	udpSocket func(ctx context.Context) (*net.UDPConn, error) // a request's socket; uotSocket's unconnected one when nil

	// Memory is the process's memory (memlimit.Start's), the TCP tunnels'
	// budget's base (MemoryBudget, pressure.go); memlimit.Read's at the
	// first tunnel when nil. H3Conn gives an HTTP/3 request's connection
	// (cmd/rayd: h3serve.Conn), whose window caps its tunnels' charge; a
	// tunnel over HTTP/3 without it is charged on its own.
	Memory  *memlimit.Limits
	H3Conn  func(ctx context.Context) any
	mem     tunnels
	memOnce sync.Once
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Not over X25519MLKEM768 (TLS 1.2, a classical group, no TLS): the
	// site's answer, whatever the request and its password; the handshake
	// that let it in is the site's. A tunnel is post-quantum or none.
	if !site.PostQuantum(r) {
		s.Answer.ServeHTTP(w, r)
		return
	}
	if r.Method == http.MethodConnect && r.Proto == ConnectUDP {
		s.serveUDP(w, r)
		return
	}
	// HTTP/2 (TCP) or HTTP/3 (QUIC); naive never speaks HTTP/1 to a
	// server, nor an extended CONNECT of another protocol: the site's
	// answer, never a tunnel.
	if r.Method != http.MethodConnect || r.ProtoMajor < 2 || extendedConnect(r) || r.Header.Get("Padding") == "" {
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
	if !s.tunnel(w, r, a) {
		return
	}
	// The user left the users file (disabled, expired, over the traffic
	// limit, a credential past its grace): the stream is reset, not ended.
	if errors.Is(context.Cause(a.ctx), errRevoked) {
		panic(http.ErrAbortHandler)
	}
}

// tunnel serves an authenticated CONNECT until it ends or a.ctx is done;
// false when it answered without a tunnel (the site's answer, 429, the
// honest connect's 502 and 504).
func (s *Server) tunnel(w http.ResponseWriter, r *http.Request, a admitted) bool {
	ctx := a.ctx
	target := r.Host
	// An authenticated stream: its HTTP/2 connection is a client's, cut
	// once it leaves the server's data unacknowledged for clientTimeout.
	if c, _ := r.Context().Value(connSocketKey{}).(*connSocket); c != nil {
		if err := c.userTimeout(); err != nil {
			s.Log.Debug("naive: TCP_USER_TIMEOUT not set", "err", err)
		}
	}
	// The padding the client asked for (padding.go): what every answer
	// from here on says, a refusal's as a 200's.
	reply, padded := paddingType(r.Header)
	// A target that is no host and port, or whose host is neither an
	// address nor a domain name (a megabyte's :authority, say), is a bad
	// target: nothing of it is looked up, kept or charged. It gets the
	// site's answer; but a client that asked for the dial's outcome
	// (niko-ack, ack.go) and whose password was taken must not read the
	// site's 404 as that password refused: it gets the honest connect's
	// refusal, as for any target the node will not dial.
	host, _, err := net.SplitHostPort(target)
	if err == nil {
		if _, perr := netip.ParseAddr(host); perr != nil && !domainName(host) {
			err = errBadName
		}
	}
	if err != nil {
		if r.Header.Get(AckHeader) == "1" {
			refuse(w, http.StatusBadGateway, ackDenied, reply)
			return false
		}
		s.Answer.ServeHTTP(w, r)
		return false
	}
	// TCP's limits come before the 200 (spec/conn-limit-v1.md §3.1): a
	// place, a token for the attempt (waiting while the client is there),
	// no debt of failed dials, and a lookup token for a name the cache
	// does not know. A refusal is 429: the client's log says why.
	tcp := host != UoTName && host != uotLegacyName && host != ICMPName
	// With the limits off a lookup takes no token: paid from the start.
	paid := s.lim.off.Load()
	var mem *tunnelMem
	if tcp {
		// The tunnel's memory (pressure.go): charged from here to its end,
		// refused before any 200 when the node is at its budget and the
		// user at its share, whatever the limits' switch; reset under
		// pressure (errEvicted).
		var evict context.CancelCauseFunc
		ctx, evict = context.WithCancelCause(ctx)
		defer evict(nil)
		tm := s.tunnels().admit(a.key, s.connOf(r), r.ProtoMajor == 3, evict)
		if tm == nil {
			s.lim.refuse(a.key, refusedMemory)
			s.Log.Debug("naive: tunnels at the memory budget")
			refuse(w, http.StatusTooManyRequests, "", reply)
			return false
		}
		defer s.mem.leave(tm)
		mem = tm
		done, kind := s.lim.tcpStart(ctx, a.key)
		if kind == "" && !s.lim.off.Load() && s.Dial == nil && (s.Probe == "" || host != probe.Name) {
			if _, err := netip.ParseAddr(host); err != nil && !s.cached(host) {
				if !s.lim.lookup(a.key) {
					done()
					kind = refusedLookup
				}
				paid = true
			}
		}
		// The wait ended with the stream (the client gone, the user
		// revoked, the stream reset under pressure): a reset, as for any
		// stream ended before its 200; no refusal counted for it.
		if kind != "" && ctx.Err() != nil {
			panic(http.ErrAbortHandler)
		}
		if kind != "" {
			// Not who or where: no user and no destination in the log.
			s.Log.Debug("naive: too many connections", "limit", kind)
			refuse(w, http.StatusTooManyRequests, "", reply)
			return false
		}
		defer done()
	}
	// 200 before the destination answers: waiting for it would cost each
	// connection up to a round trip more. A destination that cannot be
	// reached resets the stream (spec/naive-uot-v1.md §4): the client sees
	// an error, not an empty answer. A client that asked for the dial's
	// outcome (niko-ack, ack.go) gets its answer after the dial instead; a
	// UoT or an ICMP stream has none to wait for.
	ack := tcp && r.Header.Get(AckHeader) == "1"
	var in *paddedStream
	accept := func() bool {
		answerPadding(w, reply)
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			return false
		}
		flusher.Flush()
		in = &paddedStream{r: r.Body, w: w, f: flusher}
		if !padded {
			in.unpadded()
		}
		return true
	}
	if !ack && !accept() {
		return true
	}

	switch host {
	case UoTName:
		uctx, cancel := context.WithCancelCause(ctx)
		defer cancel(nil)
		slot, _ := s.lim.uotTake(a.key, cancel)
		if slot == nil {
			s.Log.Debug("naive: too many UDP streams")
			panic(http.ErrAbortHandler)
		}
		defer s.lim.uotPut(slot)
		// Datagrams on the connection: its socket holds little unsent.
		defer datagramStream(ctx)()
		err := s.serveUoT(uctx, slot, a.traffic, in, http.NewResponseController(w))
		if err != nil {
			s.Log.Debug("naive: UDP refused", "err", err)
			panic(http.ErrAbortHandler)
		}
		return true
	case uotLegacyName:
		panic(http.ErrAbortHandler)
	case ICMPName:
		if !s.ICMP {
			s.Log.Debug("naive: ICMP is off")
			panic(http.ErrAbortHandler)
		}
		// The user's streams and echoes, whichever of the user's
		// credentials opened the stream.
		u := s.icmp.take(a.key)
		if u == nil {
			s.Log.Debug("naive: too many ICMP streams")
			panic(http.ErrAbortHandler)
		}
		defer s.icmp.put(u)
		defer datagramStream(ctx)()
		if err := s.serveICMP(ctx, u, a.traffic, in, http.NewResponseController(w)); err != nil {
			s.Log.Debug("naive: ICMP refused", "err", err)
			panic(http.ErrAbortHandler)
		}
		return true
	}

	dctx, cancel := context.WithTimeout(ctx, s.dialTimeout())
	out, err := s.dialUser(dctx, a.key, target, paid)
	ranOut := expired(dctx) // the dial had its whole time
	cancel()
	if err != nil {
		// With niko-ack the dial's outcome is the answer, and nothing is
		// written after it; a client that is gone, or a user revoked
		// meanwhile, gets the reset. Not where: no destination in the log,
		// and none in the answer.
		if ack && ctx.Err() == nil {
			status, reason := ackRefusal(err, ranOut)
			refuse(w, status, reason, reply)
			s.Log.Debug("naive: destination unreachable", "status", status)
			return false
		}
		s.Log.Debug("naive: destination unreachable")
		panic(http.ErrAbortHandler)
	}
	defer out.Close()
	if ack && !accept() {
		return true
	}
	// The client's end of the upload only half-closes the destination; the
	// tunnel lasts until the destination is done sending, or the stream
	// ends. Nothing writes to w once this returns. The bytes count at the
	// destination's side, as each write goes (traffic-limit-v1 §2.3).
	// Each write's start is noted (pressure.go): a write that does not
	// return is a tunnel that holds memory and does not move.
	// Over HTTP/3 the upload's reads are noted too: what came out of order
	// waits unseen in QUIC's packets while the read does.
	s.mem.run(mem, out)
	var up io.Reader = in
	if r.ProtoMajor == 3 {
		up = stampReader{in, &mem.rd}
	}
	go func() {
		_, _ = io.Copy(stampWriter{countWriter{out, a.traffic.up()}, &mem.up}, up)
		s.mem.uploaded(mem)
		if cw, ok := out.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	// down gets how the destination's side ended: nil for its end (FIN),
	// and for a download the client's side stopped; its error when it
	// broke off (a reset, its path's timeout).
	down := make(chan error, 1)
	go func() {
		from := &brokenReader{r: countReader{out, a.traffic.down()}}
		_, _ = io.Copy(stampWriter{in, &mem.down}, from)
		down <- from.err
	}()
	select {
	case err := <-down:
		// A destination that broke off resets the stream, as one that
		// could not be reached does (spec/naive-uot-v1.md §4): ended
		// cleanly, the client took what came for all there was. Only the
		// destination's end is the stream's end. What broke is not said:
		// the error names the destination.
		if err != nil {
			s.Log.Debug("naive: destination broke off")
			panic(http.ErrAbortHandler)
		}
	case <-ctx.Done():
		_ = out.Close()
		// A client that does not read holds the download in a write
		// (flow control), and with it the stream of a revoked user: past
		// a second it fails, as UoT's and ICMP's. How the copy ended does
		// not matter here: the close or the deadline ended it.
		select {
		case <-down: //nolint:errcheck // only its end is waited for
		case <-time.After(time.Second):
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now())
			<-down //nolint:errcheck // only its end is waited for
		}
		// Reset under pressure: a reset, never the end of what was cut
		// off.
		if errors.Is(context.Cause(ctx), errEvicted) {
			panic(http.ErrAbortHandler)
		}
	}
	return true
}

// connOf is the connection a request came on, for its tunnel's charge:
// HTTP/2's socket, HTTP/3's connection (H3Conn); nil when not known.
func (s *Server) connOf(r *http.Request) any {
	if r.ProtoMajor == 3 {
		if s.H3Conn != nil {
			if c := s.H3Conn(r.Context()); c != nil {
				return c
			}
		}
		return nil
	}
	if c, _ := r.Context().Value(connSocketKey{}).(*connSocket); c != nil {
		return c
	}
	return nil
}

// brokenReader keeps the error its reader ended with, if it was not its
// end: what a copy does not tell apart from the writer's errors.
type brokenReader struct {
	r   io.Reader
	err error
}

func (b *brokenReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if err != nil && err != io.EOF {
		b.err = err
	}
	return n, err
}

// password is Proxy-Authorization's: Basic, any user name.
func password(r *http.Request) (string, bool) {
	h := r.Header.Get("Proxy-Authorization")
	scheme, b64, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", false
	}
	_, pw, ok := strings.Cut(string(raw), ":")
	return pw, ok
}

// PublicDialer reaches public unicast addresses only: not the node itself,
// not loopback, private, link-local, CGNAT or multicast ranges. A client
// may not use naive to get at what only the node's own address reaches.
// Names are looked up with the public resolvers.
func PublicDialer() *net.Dialer {
	return &net.Dialer{Timeout: dialTimeout, Resolver: PublicResolver(), Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		if !Public(ap.Addr()) {
			return errNotPublic
		}
		return nil
	}}
}

var (
	cgnat = netip.MustParsePrefix("100.64.0.0/10")
	// Not the internet, apart from the private ranges: IPv6 prefixes that
	// carry IPv4 addresses (NAT64, 6to4, IPv4-compatible):
	// 64:ff9b::a9fe:a9fe is 169.254.169.254 where NAT64 is routed.
	notPublic = []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("::/96"),
		// Not private to Go, but not the internet either, as Xray's routing
		// and the perimeter's local sets have them (R4-38): "this network",
		// IETF protocol assignments, benchmarking, reserved.
		netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("240.0.0.0/4"),
		// Azure's platform address (WireServer), public but the host's.
		netip.MustParsePrefix("168.63.129.16/32")}
	local struct {
		once  sync.Once
		addrs map[netip.Addr]bool
	}
)

// Public reports whether an address is a public unicast address and not one
// of the node's own.
func Public(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || cgnat.Contains(a) {
		return false
	}
	for _, p := range notPublic {
		if p.Contains(a) {
			return false
		}
	}
	local.once.Do(func() {
		local.addrs = map[netip.Addr]bool{}
		addrs, _ := net.InterfaceAddrs()
		for _, x := range addrs {
			if p, err := netip.ParsePrefix(x.String()); err == nil {
				local.addrs[p.Addr().Unmap()] = true
			}
		}
	})
	return !local.addrs[a]
}

// resolvers are where naive looks names up: public ones, as Xray does
// (render: DoH to 1.1.1.1 and 9.9.9.9). The host's resolver may be
// systemd-resolved's stub on loopback or a provider's in a private range,
// which the unit's IPAddressDeny keeps out of reach: every destination by
// name would fail.
var resolvers = []string{"1.1.1.1:53", "9.9.9.9:53", "[2606:4700:4700::1111]:53"}

// resolverWait is the longest a query waits for a resolver before the next
// one is asked (resolv.conf's 5 s would hold each connection that long).
const resolverWait = 2 * time.Second

// publicDNS is naive's one resolver, for TCP's destinations and UDP's.
var publicDNS = newPublicDNS(resolvers, resolverWait)

// PublicResolver asks the public resolvers, whatever the host's resolv.conf
// names: the one that answered last first, the next one when it does not
// answer within resolverWait.
func PublicResolver() *net.Resolver { return publicDNS.r }

// SetResolverLog is where a resolver that does not answer is told.
func SetResolverLog(log *slog.Logger) { publicDNS.log.Store(log) }

type pubDNS struct {
	addrs []string
	wait  time.Duration
	cur   atomic.Uint32  // the one asked first
	good  []atomic.Int64 // when each one last answered well (mono)
	moves atomic.Int32   // resolvers passed over since any answered well
	r     *net.Resolver
	log   atomic.Pointer[slog.Logger]
	warn  resolverWarn
}

// mono is a monotonic time in nanoseconds: the wall clock may step back.
func mono() int64 { return int64(time.Since(monoStart)) }

// monoAt is mono at t: t's monotonic reading where it has one (time.Now's),
// its wall time otherwise (a test's fake clock).
func monoAt(t time.Time) int64 { return int64(t.Sub(monoStart)) }

var monoStart = time.Now()

func newPublicDNS(addrs []string, wait time.Duration) *pubDNS {
	p := &pubDNS{addrs: addrs, wait: wait, good: make([]atomic.Int64, len(addrs))}
	p.r = &net.Resolver{PreferGo: true, Dial: p.dial}
	return p
}

func (p *pubDNS) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	d := net.Dialer{Timeout: p.wait}
	var err error
	for range p.addrs {
		i := p.cur.Load() % uint32(len(p.addrs)) //nolint:gosec // G115: a handful of resolvers
		since := mono()
		c, derr := d.DialContext(ctx, network, p.addrs[i])
		if derr == nil {
			rc := &resolverConn{Conn: c, p: p, i: i}
			rc.sent.Store(since)
			if _, ok := c.(net.PacketConn); ok {
				// Go frames queries by what Dial returns: a stream would
				// get TCP's length prefix over UDP.
				rc.packet = true
				return resolverPacketConn{rc}, nil
			}
			return rc, nil
		}
		// The caller gave up (Go's own per-query timeout is a deadline,
		// not a cancel): no resolver's fault.
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, derr
		}
		p.failed(i, since, derr)
		err = derr
	}
	return nil, err
}

func (p *pubDNS) answered(i uint32) {
	m := mono()
	p.good[i].Store(m)
	p.moves.Store(0)
}

// failed passes resolver i over, unless it has answered well since this
// query went to it (the query's trouble, a broken domain say, not the
// resolver's) or another query has passed it over already. One resolver
// passed over is the next one's work, not the operator's: only when none
// has answered well through a whole round is it warned about. On a quiet
// node a single broken name may still move the choice on: harmless, the
// next resolver answers as well.
func (p *pubDNS) failed(i uint32, since int64, err error) {
	if p.good[i].Load() > since {
		return
	}
	if !p.cur.CompareAndSwap(i, (i+1)%uint32(len(p.addrs))) { //nolint:gosec // G115: a handful of resolvers
		return
	}
	log := p.log.Load()
	if p.moves.Add(1) >= int32(len(p.addrs)) { //nolint:gosec // G115: a handful of resolvers
		p.warn.note(log, p.addrs[i], err)
	} else if log != nil {
		log.Debug("naive: a public resolver passed over", "resolver", p.addrs[i], "err", err)
	}
}

// resolverConn is a query's connection to one resolver. A resolver that
// times out, refuses, or cannot be sent to fails; so does one answering
// SERVFAIL or REFUSED (Go would ask it again on every retry), unless it has
// answered others well meanwhile. A query its caller gave up on fails none.
type resolverConn struct {
	net.Conn
	p      *pubDNS
	i      uint32
	packet bool
	sent   atomic.Int64  // when the query went (mono)
	id     atomic.Uint32 // the query's ID, with 1<<16 once known
	// Over TCP the answer's head comes after Go's 2-byte length, in as
	// many reads as it takes: kept until it is whole.
	head [6]byte
	got  int
}

// fail passes the resolver over; failed's compare-and-swap moves on once
// however many queries to it fail.
func (c *resolverConn) fail(err error) {
	c.p.failed(c.i, c.sent.Load(), err)
}

// transport is an error of the way to the resolver, not of the caller.
func transport(err error) bool {
	var errno syscall.Errno
	return errors.Is(err, os.ErrDeadlineExceeded) || errors.As(err, &errno)
}

func (c *resolverConn) Write(b []byte) (int, error) {
	c.sent.Store(mono())
	if msg := b; c.packet || len(b) >= 4 {
		if !c.packet {
			msg = b[2:] // after the length
		}
		if len(msg) >= 2 {
			c.id.Store(uint32(binary.BigEndian.Uint16(msg)) | 1<<16)
		}
	}
	n, err := c.Conn.Write(b)
	if err != nil && transport(err) {
		c.fail(err)
	}
	return n, err
}

func (c *resolverConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	switch {
	case err != nil && transport(err):
		c.fail(err)
	case c.packet && n >= 4:
		c.answer(b[:4])
	case !c.packet && n > 0 && c.got < len(c.head):
		c.got += copy(c.head[c.got:], b[:n])
		if c.got == len(c.head) {
			c.answer(c.head[2:])
		}
	}
	return n, err
}

// answer weighs an answer's head (ID, flags): an answer to this query,
// good or failing.
func (c *resolverConn) answer(h []byte) {
	if h[2]&0x80 == 0 || c.id.Load() != uint32(binary.BigEndian.Uint16(h))|1<<16 {
		return // not an answer to this query
	}
	switch h[3] & 0x0f {
	case 0, 3: // NOERROR, NXDOMAIN
		c.p.answered(c.i)
	case 2, 5: // SERVFAIL, REFUSED
		c.fail(errors.New("answers SERVFAIL or REFUSED"))
	}
}

// resolverPacketConn is a resolverConn over UDP, a PacketConn as its
// socket is.
type resolverPacketConn struct{ *resolverConn }

func (c resolverPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.Conn.(net.PacketConn).ReadFrom(b)
}

func (c resolverPacketConn) WriteTo(b []byte, a net.Addr) (int, error) {
	return c.Conn.(net.PacketConn).WriteTo(b, a)
}

func (c *resolverConn) SetDeadline(t time.Time) error {
	if limit := time.Now().Add(c.p.wait); t.IsZero() || t.After(limit) {
		t = limit
	}
	return c.Conn.SetDeadline(t)
}

// fqdn is a name with its final dot, so that the host's search domains,
// which are not the client's, never go to the public resolvers; an
// address stays as it is.
func fqdn(host string) string {
	if host == "" || strings.HasSuffix(host, ".") {
		return host
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return host
	}
	return host + "."
}

// resolverWarn says, at most once a minute, that no public resolver
// answers: names cannot be looked up on the node. No name goes in the log.
type resolverWarn struct {
	mu     sync.Mutex
	last   time.Time
	missed int
}

func (w *resolverWarn) note(log *slog.Logger, resolver string, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.missed++
	if log == nil || time.Since(w.last) < time.Minute {
		return
	}
	log.Warn("naive: no public resolver answers", "count", w.missed, "last", resolver, "err", err)
	w.last, w.missed = time.Now(), 0
}
