// Package naive serves NaiveProxy over HTTP/2 for the node's clients
// (docs/08-decisions.md, R2-14): an authenticated CONNECT with naive's
// padding opens a tunnel; anything else gets the site's answer, never 407.
// TLS (1.3, X25519MLKEM768 only) is the caller's.
package naive

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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

	"github.com/arngory/raycontrol/internal/probe"
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
	Log  *slog.Logger

	uot     uotLimits
	uotIdle time.Duration // uotIdle when 0 (tests make it short)

	icmp     icmpLimits
	icmpIdle time.Duration                   // icmpIdle when 0
	icmpOpen func(v6 bool) (icmpConn, error) // openPing when nil
	icmpWarn icmpWarn
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// HTTP/2 (TCP) or HTTP/3 (QUIC); naive never speaks HTTP/1 to a server.
	if r.Method != http.MethodConnect || r.ProtoMajor < 2 || r.Header.Get("Padding") == "" {
		s.Answer.ServeHTTP(w, r)
		return
	}
	user, ok := s.authorized(r)
	if !ok {
		s.Answer.ServeHTTP(w, r)
		return
	}
	target := r.Host
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		s.Answer.ServeHTTP(w, r)
		return
	}
	// 200 before the destination answers: waiting for it would cost each
	// connection up to a round trip more. A destination that cannot be
	// reached resets the stream (spec/naive-uot-v1.md §4): the client sees
	// an error, not an empty answer.
	w.Header().Set("Padding", paddingHeader())
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}
	flusher.Flush()
	in := &paddedStream{r: r.Body, w: w, f: flusher}

	switch host {
	case UoTName:
		if !s.uot.take(user) {
			s.Log.Debug("naive: too many UDP streams")
			panic(http.ErrAbortHandler)
		}
		defer s.uot.put(user)
		err := s.serveUoT(r.Context(), user, in, http.NewResponseController(w))
		if err != nil {
			s.Log.Debug("naive: UDP refused", "err", err)
			panic(http.ErrAbortHandler)
		}
		return
	case uotLegacyName:
		panic(http.ErrAbortHandler)
	case ICMPName:
		if !s.ICMP {
			s.Log.Debug("naive: ICMP is off")
			panic(http.ErrAbortHandler)
		}
		if !s.icmp.take(user) {
			s.Log.Debug("naive: too many ICMP streams")
			panic(http.ErrAbortHandler)
		}
		defer s.icmp.put(user)
		if err := s.serveICMP(r.Context(), user, in, http.NewResponseController(w)); err != nil {
			s.Log.Debug("naive: ICMP refused", "err", err)
			panic(http.ErrAbortHandler)
		}
		return
	}

	dial := s.Dial
	if dial == nil {
		dial = dialPublic
	}
	if host, _, _ := net.SplitHostPort(target); s.Probe != "" && host == probe.Name {
		var d net.Dialer
		dial, target = d.DialContext, s.Probe
	}
	dctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	out, err := dial(dctx, "tcp", target)
	cancel()
	if err != nil {
		s.Log.Debug("naive: destination unreachable") // not where: no destination in the log
		panic(http.ErrAbortHandler)
	}
	defer out.Close()
	// The client's end of the upload only half-closes the destination; the
	// tunnel lasts until the destination is done sending, or the stream
	// ends. Nothing writes to w once this returns.
	go func() {
		_, _ = io.Copy(out, in)
		if cw, ok := out.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	down := make(chan struct{})
	go func() {
		_, _ = io.Copy(in, out)
		close(down)
	}()
	select {
	case <-down:
	case <-r.Context().Done():
		_ = out.Close()
		<-down
	}
}

// authorized checks Proxy-Authorization: Basic, any user name, the password
// being one of the users' credentials; the user is the password's hash.
func (s *Server) authorized(r *http.Request) (user [32]byte, ok bool) {
	h := r.Header.Get("Proxy-Authorization")
	scheme, b64, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return user, false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return user, false
	}
	_, password, ok := strings.Cut(string(raw), ":")
	if !ok || !s.Users.Accepts(password) {
		return user, false
	}
	return sha256.Sum256([]byte(password)), true
}

// Users are the accepted passwords, as SHA-256 hashes in a JSON file that
// rayd rewrites when credentials rotate; the file is read again when it
// changes, without a restart.
type Users struct {
	Path string

	mu      sync.Mutex
	checked time.Time
	mtime   time.Time
	hashes  map[[32]byte]bool
}

// HashPassword is how the users file names a password.
func HashPassword(p string) string {
	sum := sha256.Sum256([]byte(p))
	return hex.EncodeToString(sum[:])
}

// Accepts reports whether the password is a current credential.
func (u *Users) Accepts(password string) bool {
	if password == "" {
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if time.Since(u.checked) > 5*time.Second || u.hashes == nil {
		u.checked = time.Now()
		if st, err := os.Stat(u.Path); err == nil && !st.ModTime().Equal(u.mtime) {
			if h, err := readUsers(u.Path); err == nil {
				u.hashes, u.mtime = h, st.ModTime()
			}
		}
	}
	return u.hashes[sha256.Sum256([]byte(password))]
}

func readUsers(path string) (map[[32]byte]bool, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the unit's own file
	if err != nil {
		return nil, err
	}
	var list []string
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	out := make(map[[32]byte]bool, len(list))
	for _, h := range list {
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != 32 {
			return nil, errors.New("naive: bad hash in the users file")
		}
		out[[32]byte(raw)] = true
	}
	return out, nil
}

// PublicDialer reaches public unicast addresses only: not the node itself,
// not loopback, private, link-local, CGNAT or multicast ranges. A client
// may not use naive to get at what only the node's own address reaches.
// Names are looked up with the public resolvers.
func PublicDialer() *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, Resolver: PublicResolver(), Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		if !Public(ap.Addr()) {
			return errors.New("naive: destination not public")
		}
		return nil
	}}
}

var (
	cgnat = netip.MustParsePrefix("100.64.0.0/10")
	// IPv6 prefixes that carry IPv4 addresses (NAT64, 6to4, IPv4-compatible):
	// 64:ff9b::a9fe:a9fe is 169.254.169.254 where NAT64 is routed.
	carriesV4 = []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("::/96")}
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
	for _, p := range carriesV4 {
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

// The padding of naive's first frames each way (as NaiveProxy and the
// sing-box inbound do): [length 2][padding length 1][data][zeros].
const paddingFrames = 8

// randByte draws padding sizes: an observer must not predict them.
func randByte() byte {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return b[0]
}

func paddingHeader() string {
	b := make([]byte, 30+int(randByte()%32))
	for i := range b {
		if i < 16 {
			b[i] = "!#$()+<>?@[]^`{}"[randByte()%16]
		} else {
			b[i] = '~'
		}
	}
	return string(b)
}

// ClientStream is the client's side of the tunnel: what it writes into the
// CONNECT request body and reads from the response, padded the same way.
func ClientStream(response io.Reader, request io.Writer) io.ReadWriter {
	return &paddedStream{r: response, w: request}
}

// PaddingHeader is a value for the Padding header of a CONNECT.
func PaddingHeader() string { return paddingHeader() }

// paddedStream is the tunnel inside the CONNECT stream.
type paddedStream struct {
	r io.Reader
	w io.Writer
	f http.Flusher

	readFrames, writeFrames int
	remaining, skip         int
	mu                      sync.Mutex // writes
}

func (p *paddedStream) Read(b []byte) (int, error) {
	for {
		if p.remaining > 0 {
			if len(b) > p.remaining {
				b = b[:p.remaining]
			}
			n, err := p.r.Read(b)
			p.remaining -= n
			return n, err
		}
		if p.skip > 0 {
			if _, err := io.CopyN(io.Discard, p.r, int64(p.skip)); err != nil {
				return 0, err
			}
			p.skip = 0
		}
		if p.readFrames >= paddingFrames {
			return p.r.Read(b)
		}
		var h [3]byte
		if _, err := io.ReadFull(p.r, h[:]); err != nil {
			return 0, err
		}
		p.readFrames++
		p.remaining, p.skip = int(binary.BigEndian.Uint16(h[:2])), int(h[2])
	}
}

func (p *paddedStream) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	written := 0
	for len(b) > 0 {
		chunk := b
		if p.writeFrames < paddingFrames && len(chunk) > 65535 {
			chunk = chunk[:65535]
		}
		var err error
		if p.writeFrames < paddingFrames {
			pad := int(randByte())
			frame := make([]byte, 3+len(chunk)+pad)
			binary.BigEndian.PutUint16(frame, uint16(len(chunk)))
			frame[2] = byte(pad)
			copy(frame[3:], chunk)
			_, err = p.w.Write(frame)
			p.writeFrames++
		} else {
			_, err = p.w.Write(chunk)
		}
		if err != nil {
			return written, err
		}
		if p.f != nil {
			p.f.Flush()
		}
		written += len(chunk)
		b = b[len(chunk):]
	}
	return written, nil
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

// dialPublic is PublicDialer's dial, a name as fully qualified.
func dialPublic(ctx context.Context, network, address string) (net.Conn, error) {
	if host, port, err := net.SplitHostPort(address); err == nil {
		address = net.JoinHostPort(fqdn(host), port)
	}
	return PublicDialer().DialContext(ctx, network, address)
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
