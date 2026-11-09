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
			return nil, err
		}
	}
	var public []netip.AddrPort
	for _, a := range addrs {
		if a = a.Unmap(); s.allowed(a) {
			public = append(public, netip.AddrPortFrom(a, uint16(p)))
		}
	}
	if len(public) == 0 {
		return nil, errors.New("naive: destination not public")
	}
	return s.dialRace(ctx, user, public)
}

// dialRace dials the addresses of the first one's family in turn, and
// those of the other family from fallbackDelay on (or once the first
// family failed), as Go's dialer does: the first connection wins.
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
	if len(fallback) == 0 {
		return s.dialSerial(ctx, user, primary, &first)
	}
	type result struct {
		c       net.Conn
		err     error
		primary bool
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result, 2)
	start := func(list []netip.AddrPort, primary bool) {
		go func() {
			c, err := s.dialSerial(ctx, user, list, &first)
			results <- result{c, err, primary}
		}()
	}
	start(primary, true)
	timer := time.NewTimer(fallbackDelay)
	defer timer.Stop()
	var firstErr error
	started, done := 1, 0
	for {
		select {
		case <-timer.C:
			if started == 1 {
				start(fallback, false)
				started++
			}
		case r := <-results:
			done++
			if r.err == nil {
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
			if firstErr == nil || r.primary {
				firstErr = r.err
			}
			if started == 1 {
				timer.Stop()
				start(fallback, false)
				started++
			} else if done == started {
				return nil, firstErr
			}
		}
	}
}

// dialSerial tries the addresses in turn, each within its share of the
// time left: the first attempt of the dial is paid, every other takes a
// token now or ends the dial.
func (s *Server) dialSerial(ctx context.Context, user string, addrs []netip.AddrPort, first *atomic.Bool) (net.Conn, error) {
	var firstErr error
	for i, a := range addrs {
		if ctx.Err() != nil {
			break
		}
		if !first.CompareAndSwap(false, true) && !s.lim.attempt(user) {
			if firstErr == nil {
				firstErr = errors.New("naive: too many attempts")
			}
			break
		}
		actx := ctx
		if d, ok := ctx.Deadline(); ok {
			share := time.Until(d) / time.Duration(len(addrs)-i)
			if share < minAttempt {
				share = min(minAttempt, time.Until(d))
			}
			var cancel context.CancelFunc
			actx, cancel = context.WithTimeout(ctx, share)
			defer cancel()
		}
		c, err := PublicDialer().DialContext(actx, "tcp", a.String())
		if err == nil {
			return c, nil
		}
		// A race lost, or a client gone, sent its SYN for nothing of its
		// own doing: not charged.
		if !errors.Is(ctx.Err(), context.Canceled) {
			s.lim.failedDial(user, err)
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = ctx.Err()
	}
	return nil, firstErr
}
