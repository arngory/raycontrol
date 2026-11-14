package naive

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/arngory/raycontrol/internal/probe"
)

// TCP's dial for a user (spec/conn-limit-v1.md §2, §3.1): a name's
// addresses come from the process's cache; each address tried is an
// attempt, the first paid before the 200 and each next one a token of its
// own; an attempt that sent a SYN and got no connection charges the
// failed dials. IPv4 and IPv6 race as Go's dialer has them (a fallback
// after 300 ms).
const (
	fallbackDelay = 300 * time.Millisecond
	// minAttempt is the least time one address of several gets, as Go's.
	minAttempt = 2 * time.Second
)

// dialUser reaches target for the user: the probe name's endpoint, or a
// public address; paid says the name's lookup token was taken already.
func (s *Server) dialUser(ctx context.Context, user, target string, paid bool) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	if s.Probe != "" && host == probe.Name {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", s.Probe)
		s.lim.failedDial(user, err)
		return c, err
	}
	if s.Dial != nil {
		// Tests: the dial is theirs, names included; one attempt.
		c, err := s.Dial(ctx, "tcp", target)
		s.lim.failedDial(user, err)
		return c, err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		if addrs, err = s.lookupName(ctx, user, host, paid); err != nil {
			return nil, lookupError{err}
		}
	}
	var public []netip.AddrPort
	for _, a := range addrs {
		if a = a.Unmap(); s.allowed(a) {
			public = append(public, netip.AddrPortFrom(a, uint16(p)))
		}
	}
	if len(public) == 0 {
		return nil, errNotPublic
	}
	return s.dialRace(ctx, user, public)
}

// errAttempts is a dial that tried no address: it had no token for one.
var errAttempts = errors.New("naive: too many attempts")

// errNoTime is a dial that tried no address: its time was over when the
// addresses came (a lookup that answered at the deadline). Not a timeout:
// no attempt waited, so it is no 504 (ackRefusal).
var errNoTime = errors.New("naive: no time left for an attempt")

// dialRace dials the addresses of the first one's family in turn, and
// those of the other family from fallbackDelay on (or once the first
// family failed), as Go's dialer does: the first connection wins. A dial
// that failed returns how each of its attempts ended (attemptErrors): what
// it means is ackRefusal's to say, over all of them.
func (s *Server) dialRace(ctx context.Context, user string, addrs []netip.AddrPort) (net.Conn, error) {
	var primary, fallback []netip.AddrPort
	for _, a := range addrs {
		if a.Addr().Is4() == addrs[0].Addr().Is4() {
			primary = append(primary, a)
		} else {
			fallback = append(fallback, a)
		}
	}
	var first atomic.Bool // the first attempt was paid before the 200
	dctx := ctx           // the dial's own, not the race's
	failed := func(errs []error) error {
		switch {
		case len(errs) > 0:
			return attemptErrors(errs)
		case dctx.Err() != nil || expired(dctx):
			return errNoTime
		}
		return errAttempts
	}
	if len(fallback) == 0 {
		c, errs := s.dialSerial(ctx, user, primary, &first)
		if c != nil {
			return c, nil
		}
		return nil, failed(errs)
	}
	type result struct {
		c    net.Conn
		errs []error
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result, 2)
	start := func(list []netip.AddrPort) {
		go func() {
			c, errs := s.dialSerial(ctx, user, list, &first)
			results <- result{c, errs}
		}()
	}
	start(primary)
	timer := time.NewTimer(fallbackDelay)
	defer timer.Stop()
	var errs []error
	started, done := 1, 0
	for {
		select {
		case <-timer.C:
			if started == 1 {
				start(fallback)
				started++
			}
		case r := <-results:
			done++
			if r.c != nil {
				// The other one, if it comes, is closed.
				go func(left int) {
					for range left {
						if r := <-results; r.c != nil {
							_ = r.c.Close()
						}
					}
				}(started - done)
				return r.c, nil
			}
			errs = append(errs, r.errs...)
			if started == 1 {
				timer.Stop()
				start(fallback)
				started++
			} else if done == started {
				return nil, failed(errs)
			}
		}
	}
}

// dialSerial tries the addresses in turn, each within its share of the
// time left: the first attempt of the dial is paid, every other takes a
// token now or ends the dial. It returns the connection, or how each
// attempt it made ended: none for an address it did not try.
func (s *Server) dialSerial(ctx context.Context, user string, addrs []netip.AddrPort, first *atomic.Bool) (net.Conn, []error) {
	dial := s.dialAddr
	if dial == nil {
		dial = func(ctx context.Context, a netip.AddrPort) (net.Conn, error) {
			return PublicDialer().DialContext(ctx, "tcp", a.String())
		}
	}
	least := s.minAttempt
	if least == 0 {
		least = minAttempt
	}
	var errs []error
	for i, a := range addrs {
		if ctx.Err() != nil {
			break
		}
		if !first.CompareAndSwap(false, true) && !s.lim.attempt(user) {
			break
		}
		actx := ctx
		if d, ok := ctx.Deadline(); ok {
			share := time.Until(d) / time.Duration(len(addrs)-i)
			if share < least {
				share = min(least, time.Until(d))
			}
			var cancel context.CancelFunc
			actx, cancel = context.WithTimeout(ctx, share)
			defer cancel()
		}
		c, err := dial(actx, a)
		if err == nil {
			return c, nil
		}
		// A race lost, or a client gone, sent its SYN for nothing of its
		// own doing: not charged.
		if !errors.Is(ctx.Err(), context.Canceled) {
			s.lim.failedDial(user, err)
		}
		errs = append(errs, err)
	}
	return nil, errs
}
