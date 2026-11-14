package naive

import (
	"net/http"
	"time"
)

// What one connection may carry, HTTP/2 and HTTP/3 alike. The numbers
// differ from a stock Go server's SETTINGS, which shows to whoever
// completes a handshake: acceptable, the port is hidden behind SPA from
// addresses that are no client's.
const (
	// MaxStreams is how many requests a connection holds at once. The
	// per-user limits must be what a client meets first (spec/conn-limit-
	// v1.md §5): past them it gets a 429 or a reset and knows why, past
	// the transport's own cap its new tunnels only wait. So a connection
	// takes all a user may hold, and streamSlack requests more on their way
	// to a refusal (a 429 after tcpWait at most, a reset) or to the site's
	// answer, which take no place of the user's.
	MaxStreams  = tcpPerUser + uotPerUser + icmpPerUser + streamSlack
	streamSlack = 64

	// MaxHeaderBytes bounds a request's header, which is read before the
	// password is: a CONNECT with its target, Proxy-Authorization, Padding
	// (naive's is under a hundred bytes) and what a browser's stack adds
	// stays under a kilobyte. Go's default is 1 MiB a request. A longer
	// header never comes to the handler, so it gets no answer of the
	// site's: the HTTP/2 and HTTP/3 servers answer 431 themselves, and
	// HTTP/2 ends the connection when one field alone is longer.
	MaxHeaderBytes = 16 << 10

	// h2Idle closes a connection that has had no stream for this long.
	// A tunnel has no idle time of its own: it lasts as long as its
	// destination and its client keep it.
	h2Idle = 5 * time.Minute
)

// HTTPServer is the HTTP/2 server of a naive service, with the limits of
// one connection set. TLS and the error log are the caller's.
func (s *Server) HTTPServer() *http.Server {
	return &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       h2Idle,
		MaxHeaderBytes:    MaxHeaderBytes,
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: MaxStreams},
	}
}
