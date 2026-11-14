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

// lookupError is a name that was not resolved, however its lookup ended: no
// such name, resolvers that failed or stayed silent, no token for it, the
// dial's time over before an answer.
type lookupError struct{ err error }

func (e lookupError) Error() string { return e.err.Error() }
func (e lookupError) Unwrap() error { return e.err }

// attemptErrors are how the attempts of a dial ended, one for each address
// tried, in no order (two families race).
type attemptErrors []error

func (e attemptErrors) Error() string   { return errors.Join(e...).Error() }
func (e attemptErrors) Unwrap() []error { return e }

// ackRefusal is the answer to a CONNECT with niko-ack whose dial failed:
// the status, and for a 502 the reason. The whole mapping is here.
//
// A dial may try several addresses, and the answer is of all its attempts,
// whichever came first, by rank:
//
//   - one of them was refused: 502 refused. Something is there and says
//     no; that another address stayed silent says less;
//   - the dial's whole time ran out (expired) while an attempt waited: 504.
//     Only then: an attempt that ran out of its share of the time, or that
//     the kernel gave up on, before the dial's time was over is a
//     destination that cannot be reached, not one that was given its time;
//   - every attempt was stopped by the node's policy: 502 denied;
//   - anything else: 502 unreachable. A name that was not resolved is
//     this, however the lookup ended (a lookup still under way at the
//     dial's time too: no address was ever silent).
//
// An address not tried for want of an attempt token is no attempt: the
// answer is of those made.
//
// Never 401, 403, 404 or 407: from naive a client reads those as "the
// server did not take the name or the password", and 404 is the site's
// answer to strangers. So a destination the node's policy forbids is a 502
// too, with its own reason.
func ackRefusal(err error, expired bool) (status int, reason string) {
	attempts := []error{err}
	var all attemptErrors
	if errors.As(err, &all) && len(all) > 0 {
		attempts = all
	}
	silent, denied := false, 0
	for _, err := range attempts {
		var lookup lookupError
		var dns *net.DNSError
		switch {
		case errors.Is(err, syscall.ECONNREFUSED):
			return http.StatusBadGateway, ackRefused
		// Not public, or stopped by the unit's and the perimeter's rules
		// (the kernel refuses the packet: EPERM).
		case errors.Is(err, errNotPublic), errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EACCES):
			denied++
		case errors.As(err, &lookup), errors.As(err, &dns):
		case timedOut(err):
			silent = true
		}
	}
	switch {
	case silent && expired:
		return http.StatusGatewayTimeout, ""
	case denied == len(attempts):
		return http.StatusBadGateway, ackDenied
	}
	return http.StatusBadGateway, ackUnreachable
}

// refuse answers an authenticated CONNECT that gets no tunnel: the status
// and, for the honest connect's 502, the reason. With naive's Padding
// header, as a 200 has it: a naive client keeps one padding type for a
// proxy, sets it anew from each answer (one without the header: a server
// that does not pad), and a tunnel takes it once its own CONNECT is done.
// An answer without the header that came in between left a tunnel beside
// it unpadded, to a server that strips padding.
func refuse(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Padding", paddingHeader())
	if reason != "" {
		w.Header().Set(AckHeader, reason)
	}
	w.WriteHeader(status)
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
