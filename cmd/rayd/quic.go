package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/arngory/raycontrol/internal/naive"
	"github.com/arngory/raycontrol/internal/render"
)

// rayd's QUIC servers behind the front, naive-quic and DoH3, are one
// server to whoever has no password and no token: the same transport
// parameters, the same HTTP/3 settings, connection IDs of the same length
// and a stateless reset from both. What differs is what each one's key and
// handler make of a request.
const (
	// quicConnIDLen is the length of the server's connection IDs. The
	// token of a stateless reset is a function of the connection ID and
	// the service's key, which never changes, and the server tells the
	// token of any ID that is not live to whoever sends a packet with it:
	// with quic-go's default of 4 bytes the tokens are a table of 2^32
	// entries that an admitted address can read out, and with it end any
	// connection whose packets it sees. 8 bytes, what large public
	// deployments use, is 2^64.
	quicConnIDLen = 8

	// h3HeaderTimeout is how long a request stream has for its header, as
	// ReadHeaderTimeout gives an HTTP/2 connection.
	h3HeaderTimeout = 10 * time.Second
)

// quicOptions are what one of rayd's QUIC servers has of its own.
type quicOptions struct {
	// resetKey makes the tokens of stateless resets (RFC 9000 §10.3); nil:
	// none are sent. With the same key at every start, a client whose
	// connection the process does not know (it started anew) gets a reset
	// it believes at its next packet, not silence until its idle time.
	resetKey *quic.StatelessResetKey
	// headerWait is h3HeaderTimeout when 0 (tests make it short).
	headerWait time.Duration
}

// parseResetKey reads a key of stateless resets from its text: 32 bytes,
// hex. Its error says what is wrong, and nothing of the text.
func parseResetKey(text []byte) (*quic.StatelessResetKey, error) {
	var key quic.StatelessResetKey
	text = bytes.TrimSpace(text)
	if hex.DecodedLen(len(text)) != len(key) {
		return nil, fmt.Errorf("not %d bytes in hex", len(key))
	}
	if _, err := hex.Decode(key[:], text); err != nil {
		return nil, errors.New("not hex")
	}
	return &key, nil
}

// readResetKey reads the key of stateless resets from its file
// (render.NaiveQUICReset). Its errors say what is wrong with the file, and
// nothing of what is in it.
func readResetKey(file string) (*quic.StatelessResetKey, error) {
	b, err := os.ReadFile(file) //nolint:gosec // G304: the unit's own file
	if err != nil {
		return nil, err
	}
	key, err := parseResetKey(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return key, nil
}

// quicConfig is the QUIC side of both servers: no keepalive of the
// server's, an idle time the front outlasts (render.QUICIdle,
// render.FrontUDPIdle), and room for all the requests a naive user may
// have at once (naive.MaxStreams).
func quicConfig() *quic.Config {
	return &quic.Config{MaxIdleTimeout: render.QUICIdle, KeepAlivePeriod: 0, MaxIncomingStreams: naive.MaxStreams}
}

// h3Pending are the request streams of one QUIC connection that have no
// complete header yet, and when each was taken. A stream with its header
// is a request: the handler has it, and a password, a token or the site's
// answer bounds it. One without is nobody's, and costs a goroutine and the
// buffer of its header: a peer that opened every stream a connection may
// have and sent three bytes on each held megabytes of the process for as
// long as it liked, without a password. So only naive.PendingStreams are
// taken at a time, each has headerWait for its header, and a connection
// that is full of them when one runs out of time is closed.
type h3Pending struct {
	mu      sync.Mutex
	streams map[quic.StreamID]time.Time
	freed   chan struct{} // one place: a stream got its header, or ended
}

type h3PendingKey struct{}

func newH3Pending() *h3Pending {
	return &h3Pending{streams: map[quic.StreamID]time.Time{}, freed: make(chan struct{}, 1)}
}

// take waits for room among the streams without a header and takes it for
// id; false when the connection ended first.
func (p *h3Pending) take(conn context.Context, id quic.StreamID) bool {
	for {
		p.mu.Lock()
		if len(p.streams) < naive.PendingStreams {
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
func (p *h3Pending) done(id quic.StreamID, wait time.Duration) (holding bool) {
	p.mu.Lock()
	since, ok := p.streams[id]
	if ok {
		holding = len(p.streams) >= naive.PendingStreams && time.Since(since) >= wait
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
		if p, _ := r.Context().Value(h3PendingKey{}).(*h3Pending); p != nil {
			// quic-go's request body knows its stream.
			if b, ok := r.Body.(interface{ StreamID() quic.StreamID }); ok {
				p.done(b.StreamID(), time.Hour) // in time, whatever it took
			}
		}
		_ = http.NewResponseController(w).SetReadDeadline(time.Time{})
		h.ServeHTTP(w, r)
	})
}

// serveHTTP3 serves h on QUIC over the front's datagrams until ctx ends:
// TLS 1.3 with X25519MLKEM768 only, ALPN h3, the certificate cert gives at
// each handshake (certfile.Holder).
func serveHTTP3(ctx context.Context, pc net.PacketConn, cert func(*tls.ClientHelloInfo) (*tls.Certificate, error), h http.Handler, o quicOptions) error {
	tlsConf := http3.ConfigureTLSConfig(&tls.Config{MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, GetCertificate: cert})
	tr := &quic.Transport{Conn: pc, StatelessResetKey: o.resetKey, ConnectionIDLength: quicConnIDLen,
		// Each connection's streams without a header, where its requests
		// find them too: their contexts come from the connection's.
		ConnContext: func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
			return context.WithValue(ctx, h3PendingKey{}, newH3Pending()), nil
		}}
	ln, err := tr.ListenEarly(tlsConf, quicConfig())
	if err != nil {
		return err
	}
	// A connection without a request goes after the same time as a silent
	// one.
	srv := &http3.Server{Handler: headerRead(h), IdleTimeout: render.QUICIdle, MaxHeaderBytes: naive.MaxHeaderBytes}
	wait := o.headerWait
	if wait == 0 {
		wait = h3HeaderTimeout
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
		conns.Go(func() { serveQUICConn(ctx, srv, qc, wait) })
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

// serveQUICConn serves the requests of one connection until it ends, or
// ctx does: then the client is told (H3_NO_ERROR), as http3.Server.Close
// tells it.
func serveQUICConn(ctx context.Context, srv *http3.Server, qc *quic.Conn, wait time.Duration) {
	hc, err := srv.NewRawServerConn(qc)
	if err != nil {
		_ = qc.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeInternalError), "")
		return
	}
	stop := context.AfterFunc(ctx, func() { _ = hc.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "") })
	defer stop()
	pending, _ := qc.Context().Value(h3PendingKey{}).(*h3Pending)
	if pending == nil {
		pending = newH3Pending()
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
		if !pending.take(qc.Context(), id) {
			return
		}
		_ = str.SetReadDeadline(time.Now().Add(wait))
		streams.Go(func() {
			// Until the request is handled, or the connection ended.
			hc.HandleRequestStream(str)
			if pending.done(id, wait) {
				// Not who: no address in the log, and nothing is logged.
				_ = hc.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeExcessiveLoad), "")
			}
		})
	}
}
