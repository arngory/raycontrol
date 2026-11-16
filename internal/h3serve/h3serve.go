// Package h3serve is rayd's HTTP/3 server: naive-quic's (rayd naive) and
// DoH3's (rayd), on the datagrams the front passes. Both are one server to
// whoever has no password and no token: the same transport parameters, the
// same HTTP/3 SETTINGS, connection IDs of the same length and a stateless
// reset from both. What differs is what each one's key and handler make of
// a request, and, on a naive service with udp=on, the two lines that
// announce HTTP/3 datagrams (Options.Datagrams; spec/naive-udp-v1.md §7,
// §10.1). The numbers are the caller's (cmd/rayd: naive's limits and
// render's idle time); the package imports nothing of the node's, so that
// naive's own tests serve over it as rayd does.
package h3serve

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	// ConnIDLen is the length of the server's connection IDs. The token
	// of a stateless reset is a function of the connection ID and the
	// service's key, which never changes, and the server tells the token
	// of any ID that is not live to whoever sends a packet with it: with
	// quic-go's default of 4 bytes the tokens are a table of 2^32 entries
	// that an admitted address can read out, and with it end any
	// connection whose packets it sees. 8 bytes, what large public
	// deployments use, is 2^64.
	ConnIDLen = 8

	// HeaderTimeout is how long a request stream has for its header, as
	// ReadHeaderTimeout gives a TLS handshake and an HTTP/1 request over
	// TCP. Not an HTTP/2 one: net/http does not apply it there, and a
	// header block left without END_HEADERS waits for the idle time.
	HeaderTimeout = 10 * time.Second

	// MaxPacketSize bounds the server's datagrams (the UDP payload) to a
	// client on IPv4: what Chrome sends and what the servers it talks to
	// send it. A session of Chrome's is not a proxy's
	// (SessionUsage::kDestination) and takes 1250 bytes; captures of Chrome
	// 157 against Google's and Cloudflare's servers saw none longer either
	// way (spec/naive-udp-v1.md §4.5). With quic-go's own 1280, and with its
	// search of the path's MTU upward, which runs where the socket can set
	// DF (to 1452), the node's packets were longer than any a real server
	// sends a browser, and the probes break on tunnels that drop what does
	// not fit.
	MaxPacketSize = 1250
	// MaxPacketSizeIPv6 is the same to a client on IPv6. Chrome takes 20
	// bytes off its packets when its socket is IPv6
	// (net/quic/quic_chromium_client_session.cc: kAdditionalOverheadForIPv6),
	// and a quiche server, which starts at 1000, sends what the client's
	// Initial measured (quic_connection.cc, ProcessValidatedPacket): 1230.
	// 1250 there is also 1298 bytes of IP, over the 1280 that IPv6 promises,
	// and with no search of the path a tunnel of 1280 dropped every full
	// packet of the server's.
	MaxPacketSizeIPv6 = MaxPacketSize - 20
)

// PacketSize is the server's packet size to a client at addr:
// MaxPacketSizeIPv6 to an IPv6 address that is not IPv4's, MaxPacketSize
// to any other. The front passes an IPv4 client's address as IPv4
// (nikoipc), a dual-stack socket as IPv4 in IPv6: both are IPv4 here.
func PacketSize(addr net.Addr) int {
	if ua, ok := addr.(*net.UDPAddr); ok && ua.IP.To4() == nil && len(ua.IP) == net.IPv6len {
		return MaxPacketSizeIPv6
	}
	return MaxPacketSize
}

// Options are what a server takes of its caller.
type Options struct {
	// ResetKey makes the tokens of stateless resets (RFC 9000 §10.3); nil:
	// none are sent. With the same key at every start, a client whose
	// connection the process does not know (it started anew) gets a reset
	// it believes at its next packet, not silence until its idle time.
	ResetKey *quic.StatelessResetKey
	// HeaderWait is HeaderTimeout when 0 (tests make it short).
	HeaderWait time.Duration
	// Idle closes a connection silent for that long, or without a request
	// for that long; no keepalive is the server's.
	Idle time.Duration
	// MaxStreams are the requests a connection carries at once,
	// PendingStreams those of them that may be without a complete header,
	// MaxHeaderBytes the bound of a request's header.
	MaxStreams     int64
	PendingStreams int
	MaxHeaderBytes int
	// Datagrams announces HTTP/3 datagrams (RFC 9297): the transport
	// parameter max_datagram_frame_size and SETTINGS_H3_DATAGRAM, which
	// whoever completes a handshake sees. naive with udp=on
	// (spec/naive-udp-v1.md); off, the server is as it was without them.
	Datagrams bool
}

// Config is the QUIC side of a server: packets of PacketSize to each
// client, chosen once per connection, and no search of the path's MTU.
// What the server accepts is the same for both: quic-go's 1452.
func Config(o Options) *quic.Config {
	v4 := &quic.Config{MaxIdleTimeout: o.Idle, KeepAlivePeriod: 0, MaxIncomingStreams: o.MaxStreams,
		InitialPacketSize: MaxPacketSize, DisablePathMTUDiscovery: true, EnableDatagrams: o.Datagrams}
	v6 := *v4
	v6.InitialPacketSize = MaxPacketSizeIPv6
	c := *v4
	c.GetConfigForClient = func(info *quic.ClientInfo) (*quic.Config, error) {
		if PacketSize(info.RemoteAddr) == MaxPacketSizeIPv6 {
			return &v6, nil
		}
		return v4, nil
	}
	return &c
}

// pending are the request streams of one QUIC connection that have no
// complete header yet, and when each was taken. A stream with its header
// is a request: the handler has it, and a password, a token or the site's
// answer bounds it. One without is nobody's, and costs a goroutine and the
// buffer of its header: a peer that opened every stream a connection may
// have and sent three bytes on each held megabytes of the process for as
// long as it liked, without a password. So only Options.PendingStreams are
// taken at a time, each has HeaderWait for its header, and a connection
// that is full of them when one runs out of time is closed.
type pending struct {
	limit   int
	mu      sync.Mutex
	streams map[quic.StreamID]time.Time
	freed   chan struct{} // one place: a stream got its header, or ended
}

type pendingKey struct{}

func newPending(limit int) *pending {
	return &pending{limit: limit, streams: map[quic.StreamID]time.Time{}, freed: make(chan struct{}, 1)}
}

// take waits for room among the streams without a header and takes it for
// id; false when the connection ended first.
func (p *pending) take(conn context.Context, id quic.StreamID) bool {
	for {
		p.mu.Lock()
		if len(p.streams) < p.limit {
			p.streams[id] = time.Now()
			p.mu.Unlock()
			return true
		}
		p.mu.Unlock()
		select {
		case <-p.freed:
		case <-conn.Done():
			return false
		}
	}
}

// done takes id from the streams without a header, if it is one still:
// its header is complete, or it ended. It reports true when it had been one
// for wait or longer while the connection was full of them: its peer does
// not send headers, it holds streams.
func (p *pending) done(id quic.StreamID, wait time.Duration) (holding bool) {
	p.mu.Lock()
	since, ok := p.streams[id]
	if ok {
		holding = len(p.streams) >= p.limit && time.Since(since) >= wait
		delete(p.streams, id)
	}
	p.mu.Unlock()
	if ok {
		select {
		case p.freed <- struct{}{}:
		default:
		}
	}
	return holding
}

// headerRead is h for a request whose header is complete: its stream is
// no longer one without a header, and the time it had for the header no
// longer bounds its reads.
func headerRead(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, _ := r.Context().Value(pendingKey{}).(*pending); p != nil {
			// quic-go's request body knows its stream.
			if b, ok := r.Body.(interface{ StreamID() quic.StreamID }); ok {
				p.done(b.StreamID(), time.Hour) // in time, whatever it took
			}
		}
		_ = http.NewResponseController(w).SetReadDeadline(time.Time{})
		h.ServeHTTP(w, r)
	})
}

// Serve serves h on QUIC over pc until ctx ends: TLS 1.3 with
// X25519MLKEM768 only, ALPN h3, the certificate cert gives at each
// handshake (certfile.Holder).
func Serve(ctx context.Context, pc net.PacketConn, cert func(*tls.ClientHelloInfo) (*tls.Certificate, error), h http.Handler, o Options) error {
	tlsConf := http3.ConfigureTLSConfig(&tls.Config{MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, GetCertificate: cert})
	tr := &quic.Transport{Conn: pc, StatelessResetKey: o.ResetKey, ConnectionIDLength: ConnIDLen,
		// Each connection's streams without a header, where its requests
		// find them too: their contexts come from the connection's.
		ConnContext: func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
			return context.WithValue(ctx, pendingKey{}, newPending(o.PendingStreams)), nil
		}}
	ln, err := tr.ListenEarly(tlsConf, Config(o))
	if err != nil {
		return err
	}
	// A connection without a request goes after the same time as a silent
	// one.
	srv := &http3.Server{Handler: headerRead(h), IdleTimeout: o.Idle, MaxHeaderBytes: o.MaxHeaderBytes, EnableDatagrams: o.Datagrams}
	wait := o.HeaderWait
	if wait == 0 {
		wait = HeaderTimeout
	}
	// The connections are taken here, not by http3.Server's own loop,
	// which takes every stream a peer opens and waits for its header
	// without an end.
	var conns sync.WaitGroup
	for {
		qc, aerr := ln.Accept(ctx)
		if aerr != nil {
			err = aerr
			break
		}
		conns.Go(func() { serveConn(ctx, srv, qc, wait, o.PendingStreams) })
	}
	_ = ln.Close()
	conns.Wait() // each is closed with ctx, with a word to its client
	// The socket first: the transport waits for its reader, and a deadline
	// does not wake one that waits on the front's datagrams
	// (nikoipc.PacketConn).
	_ = pc.Close()
	_ = tr.Close()
	if ctx.Err() == nil && !errors.Is(err, quic.ErrServerClosed) {
		return err
	}
	return nil
}

// serveConn serves the requests of one connection until it ends, or ctx
// does: then the client is told (H3_NO_ERROR), as http3.Server.Close tells
// it.
func serveConn(ctx context.Context, srv *http3.Server, qc *quic.Conn, wait time.Duration, limit int) {
	hc, err := srv.NewRawServerConn(qc)
	if err != nil {
		_ = qc.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeInternalError), "")
		return
	}
	stop := context.AfterFunc(ctx, func() { _ = hc.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "") })
	defer stop()
	waiting, _ := qc.Context().Value(pendingKey{}).(*pending)
	if waiting == nil {
		waiting = newPending(limit)
	}
	var streams sync.WaitGroup
	defer streams.Wait()
	// The control and QPACK streams.
	streams.Go(func() {
		for {
			str, err := qc.AcceptUniStream(context.Background())
			if err != nil {
				return
			}
			go hc.HandleUnidirectionalStream(str)
		}
	})
	for {
		str, err := qc.AcceptStream(context.Background())
		if err != nil {
			return // the connection ended
		}
		id := str.StreamID()
		if !waiting.take(qc.Context(), id) {
			return
		}
		_ = str.SetReadDeadline(time.Now().Add(wait))
		streams.Go(func() {
			// Until the request is handled, or the connection ended.
			hc.HandleRequestStream(str)
			if waiting.done(id, wait) {
				// Not who: no address in the log, and nothing is logged.
				_ = hc.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeExcessiveLoad), "")
			}
		})
	}
}

// SettingsWait bounds how long a request waits for its client's SETTINGS
// (Datagrams): a client sends them first thing, before any request.
const SettingsWait = HeaderTimeout

// Datagrams gives a request's HTTP/3 stream with its datagrams (RFC 9297):
// ok false when w is no HTTP/3 server's of this package, when the server
// does not announce datagrams (Options.Datagrams), or when the client's
// SETTINGS, waited for while ctx lasts and SettingsWait at most, do not
// have SETTINGS_H3_DATAGRAM. take writes the answer's header (200 unless
// the handler wrote another status) and gives the stream over: the
// handler ends it, with Stream.Close or Stream.Reset.
func Datagrams(ctx context.Context, w http.ResponseWriter) (take func() *Stream, ok bool) {
	srv, _ := ctx.Value(http3.ServerContextKey).(*http3.Server)
	hw, isH3 := w.(interface {
		http3.HTTPStreamer
		http3.Settingser
	})
	if srv == nil || !srv.EnableDatagrams || !isH3 {
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
	if st := hw.Settings(); st == nil || !st.EnableDatagrams {
		return nil, false
	}
	return func() *Stream { return &Stream{s: hw.HTTPStream()} }, true
}

// Stream is a request's HTTP/3 stream, taken over for its datagrams: its
// content (inside DATA frames, which carry capsules) and its HTTP
// datagrams, the payload after the quarter stream ID.
type Stream struct{ s *http3.Stream }

func (d *Stream) Read(b []byte) (int, error)         { return d.s.Read(b) }
func (d *Stream) Write(b []byte) (int, error)        { return d.s.Write(b) }
func (d *Stream) SetReadDeadline(t time.Time) error  { return d.s.SetReadDeadline(t) }
func (d *Stream) SetWriteDeadline(t time.Time) error { return d.s.SetWriteDeadline(t) }

// SendDatagram queues b as one QUIC datagram, waiting while the
// connection's queue is full; tooLarge, with nothing sent, when it does not
// fit a QUIC packet of the connection.
func (d *Stream) SendDatagram(b []byte) (tooLarge bool, err error) {
	err = d.s.SendDatagram(b)
	if _, ok := errors.AsType[*quic.DatagramTooLargeError](err); ok {
		return true, nil
	}
	return false, err
}

// ReceiveDatagram waits for the next datagram of the stream; an error once
// ctx ends or the stream's receiving side does.
func (d *Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return d.s.ReceiveDatagram(ctx)
}

// Close ends the stream cleanly: FIN, and nothing more read, as http3 ends
// a request whose handler returned.
func (d *Stream) Close() error {
	d.s.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	return d.s.Close()
}

// Reset resets the stream both ways, as http3 resets a request whose
// handler aborted (http.ErrAbortHandler).
func (d *Stream) Reset() {
	d.s.CancelRead(quic.StreamErrorCode(http3.ErrCodeInternalError))
	d.s.CancelWrite(quic.StreamErrorCode(http3.ErrCodeInternalError))
}
