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

	// The HTTP/2 flow-control windows for what a client sends (uploads).
	// A window is what the client may send before the handler has read it,
	// so a round trip carries one window at most: Go's default of 1 MiB,
	// for a stream and for a connection alike, is 28 Mbit/s at 300 ms for
	// all the tunnels of a connection together. 2 MiB a stream is 56 Mbit/s
	// there, 8 MiB a connection 224 Mbit/s. QUIC's windows grow by
	// themselves (quic-go: to 6 MiB a stream, 15 MiB a connection).
	//
	// The windows are the memory bound too. The server gives a window back
	// as the handler reads the request body (io.Copy to the destination),
	// not before: a destination that stalls leaves at most h2StreamWindow
	// of its tunnel unread in the process, and all the stalled
	// destinations of a connection together h2ConnWindow (and a copy
	// buffer each). Four stalled uploads can so hold the other uploads of
	// their connection; with the default windows one could.
	//
	// http.HTTP2Config documents windows under 4 MiB; go1.26 takes any up
	// to 2^31-1 and falls back to 1 MiB past what it takes, in silence:
	// TestUploadWindows reads what the server really advertises.
	h2StreamWindow = 2 << 20
	h2ConnWindow   = 8 << 20

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
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams:          MaxStreams,
			MaxReceiveBufferPerStream:     h2StreamWindow,
			MaxReceiveBufferPerConnection: h2ConnWindow,
		},
	}
}
