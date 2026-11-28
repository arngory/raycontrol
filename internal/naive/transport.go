package naive

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/arngory/raycontrol/internal/site"
)

// What one QUIC connection may carry (HTTP/3). The server says both
// numbers to whoever completes a handshake, before any password; rayd's
// other QUIC server on the address (DoH3) says the same ones, so that
// neither name is told from the other by them.
//
// HTTP/2 has neither: there a naive connection is Go's stock server, as the
// site's and DoH's are (site.HTTPServer), with 250 streams and 1 MiB of
// header. A limit of naive's own would tell its name from the site's at the
// first frame, for nothing: Chromium, which naive's clients are, never
// opens more than 256 streams on a connection whatever the server allows
// (kMaxConcurrentStreamLimit). Past 250 a client's new tunnels wait for a
// stream there, or go to another connection.
const (
	// MaxStreams is how many requests a QUIC connection holds at once.
	// The per-user limits must be what a client meets first
	// (spec/conn-limit-v1.md §5): past them it gets a 429 or a reset and
	// knows why, past the transport's own cap its new tunnels only wait. So
	// a connection takes all a user may hold, and streamSlack requests more
	// on their way to a refusal (a 429 after tcpWait at most, a reset) or
	// to the site's answer, which take no place of the user's.
	MaxStreams  = tcpPerUser + uotPerUser + icmpPerUser + streamSlack
	streamSlack = 64

	// PendingStreams is how many request streams of a QUIC connection may
	// be without their complete header at once: the next ones wait to be
	// taken. A stream with its header is a request, which a password or
	// the site's answer bounds; one without is nobody's yet, and each costs
	// a goroutine and its header's buffer.
	PendingStreams = streamSlack

	// MaxHeaderBytes bounds a request's header over HTTP/3, which is read
	// before the password is: a CONNECT with its target,
	// Proxy-Authorization, Padding (naive's is under a hundred bytes) and
	// what a browser's stack adds stays under a kilobyte. A longer header
	// never comes to the handler: the server answers 431 itself.
	MaxHeaderBytes = 16 << 10
)

// HTTPServer is the HTTP/2 server of a naive service: the one every name
// of the node's address has (site.HTTPServer), with its idle time
// (site.IdleTimeout: a connection without a stream; a tunnel has no idle
// time of its own, it lasts as long as its destination and its client
// keep it), and each connection's socket known to its streams
// (datagramStream, the tunnels' charge). TLS and the error log are the
// caller's.
//
// A client that is gone and leaves its data unacknowledged ends its
// connection after clientTimeout (TCP_USER_TIMEOUT, Linux): its tunnels'
// memory goes with it, with no timer on the tunnels themselves. It says
// nothing on the wire.
func (s *Server) HTTPServer() *http.Server {
	srv := site.HTTPServer(s, site.IdleTimeout)
	srv.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		ctx = connContext(ctx, c)
		if cs, _ := ctx.Value(connSocketKey{}).(*connSocket); cs != nil {
			var err error
			if cerr := cs.rc.Control(func(fd uintptr) { err = setUserTimeout(fd, clientTimeout) }); cerr != nil {
				err = cerr
			}
			if err != nil && s.Log != nil {
				s.Log.Debug("naive: TCP_USER_TIMEOUT not set", "err", err)
			}
		}
		return ctx
	}
	return srv
}

// clientTimeout is how long a client's connection may leave the server's
// data unacknowledged: as long as an HTTP/3 connection may be silent
// (render.QUICIdle).
const clientTimeout = 2 * time.Minute
