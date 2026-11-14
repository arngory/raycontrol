package naive

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
)

// The honest connect (spec/naive-uot-v1.md §4). naive answers a CONNECT
// with 200 before it dials: the client's first bytes need not wait a round
// trip, but the client learns nothing of the dial, and an application
// behind it takes a destination that is not there for one that is until
// the stream is reset. A client that asks for it, with the request header
// niko-ack: 1 (the links say niko-ack=1 where the node knows it), gets the
// answer after the dial instead: 200 once the destination took the
// connection, or the dial's outcome. What the client sent meanwhile waits,
// a flow-control window of it at most, and goes to the destination first.
//
// Only a TCP CONNECT: a UoT or an ICMP stream has no dial to wait for and
// gets its 200 at once, with the header or without (a client sends it with
// every request of a connection).
const (
	AckHeader = "Niko-Ack"

	// The reasons of a 502, in the answer's niko-ack header: a fixed few,
	// which a client shows as they are. None says where to.
	ackRefused     = "refused"     // the destination refused the connection
	ackUnreachable = "unreachable" // no route to it, no such name, any other failure
	ackDenied      = "denied"      // the node's policy forbids the destination

	// dialTimeout is how long a destination has to take the connection. A
	// client with niko-ack waits for the answer that long (Niko's own
	// limit is 15 s).
	dialTimeout = 10 * time.Second
)

// errNotPublic refuses a destination that is not a public address.
var errNotPublic = errors.New("naive: destination not public")

// ackRefusal is the answer to a CONNECT with niko-ack whose dial failed:
// the status, and for a 502 the reason. The whole mapping is here.
//
// Never 401, 403, 404 or 407: from naive a client reads those as "the
// server did not take the name or the password", and 404 is the site's
// answer to strangers. So a destination the node's policy forbids is a 502
// too, with its own reason.
func ackRefusal(err error) (status int, reason string) {
	var dns *net.DNSError
	switch {
	// Not public, or stopped by the unit's and the perimeter's rules (the
	// kernel refuses the packet: EPERM).
	case errors.Is(err, errNotPublic), errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EACCES):
		return http.StatusBadGateway, ackDenied
	case errors.Is(err, syscall.ECONNREFUSED):
		return http.StatusBadGateway, ackRefused
	// A name that was not resolved is no destination, however the lookup
	// ended.
	case errors.As(err, &dns):
		return http.StatusBadGateway, ackUnreachable
	case timedOut(err):
		return http.StatusGatewayTimeout, ""
	}
	return http.StatusBadGateway, ackUnreachable
}

// timedOut reports whether a dial ended because its time ran out.
func timedOut(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (s *Server) dialTimeout() time.Duration {
	if s.dialWait > 0 {
		return s.dialWait
	}
	return dialTimeout
}
