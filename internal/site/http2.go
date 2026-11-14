package site

import (
	"net/http"
	"time"
)

// The HTTP/2 flow-control windows for what a client sends (uploads), the
// same for every name the node answers on its address: the site, DoH and
// naive. A server says its windows to whoever completes a handshake
// (SETTINGS and a WINDOW_UPDATE, before any request and any password), so
// a name with windows of its own would be told from the others by them;
// naive is the one that needs them larger than Go's.
//
// A window is what the client may send before the handler has read it, so
// a round trip carries one window at most: Go's default of 1 MiB, for a
// stream and for a connection alike, is 28 Mbit/s at 300 ms for all the
// tunnels of a naive connection together. 2 MiB a stream is 56 Mbit/s
// there, 8 MiB a connection 224 Mbit/s. QUIC's windows grow by themselves
// (quic-go: to 6 MiB a stream, 15 MiB a connection).
//
// The windows are the memory bound too. The server gives a window back as
// the handler reads the request body, not before: a naive destination that
// stalls leaves at most StreamWindow of its tunnel unread in the process,
// and all the stalled destinations of a connection together ConnWindow
// (and a copy buffer each). A handler that will not read a body must not
// hold the request either: an answer returns at once, and the one that
// holds its requests (AnswerSilent) gives their bodies up first.
//
// http.HTTP2Config documents windows under 4 MiB; go1.26 takes any up to
// 2^31-1 and falls back to 1 MiB past what it takes, in silence: naive's
// TestUploadWindows reads what a server really advertises.
const (
	StreamWindow = 2 << 20
	ConnWindow   = 8 << 20

	// IdleTimeout closes a connection of the site's, and of DoH's, that
	// has had no request for this long. naive keeps its own longer: a
	// client's connection waits there for the next tunnel.
	IdleTimeout = 2 * time.Minute
)

// HTTPServer is the HTTP server of a name on the node's address, for h:
// what it tells a client before any request is the same whichever name it
// serves. Everything else of HTTP/2 is Go's default: the limit of streams
// (250) and of a request's header (1 MiB) are what any Go server says, and
// a number of the node's own there would be its signature. idle closes a
// connection that has had no request for that long. TLS and the error log
// are the caller's.
func HTTPServer(h http.Handler, idle time.Duration) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       idle,
		HTTP2: &http.HTTP2Config{
			MaxReceiveBufferPerStream:     StreamWindow,
			MaxReceiveBufferPerConnection: ConnWindow,
		},
	}
}
