package dnscheck

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// Exchanger sends one query to a server and returns its answer, over
// "udp" or "tcp". An answer whose ID or question is not the query's is not
// the answer: the exchanger waits on for the right one until ctx ends.
type Exchanger interface {
	Exchange(ctx context.Context, network string, srv netip.AddrPort, q []byte) ([]byte, error)
}

// Net is the host's network: a socket of its own for every query, so a
// random source port each time; TCP with the length prefix (RFC 7766).
type Net struct{}

// Exchange implements Exchanger.
func (Net) Exchange(ctx context.Context, network string, srv netip.AddrPort, q []byte) ([]byte, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, network, srv.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	// The socket's reads end when ctx does, deadline or not.
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
	defer stop()
	if network == "tcp" {
		if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...)); err != nil {
			return nil, ctxErr(ctx, err)
		}
		var n [2]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return nil, ctxErr(ctx, err)
		}
		r := make([]byte, binary.BigEndian.Uint16(n[:]))
		if _, err := io.ReadFull(c, r); err != nil {
			return nil, ctxErr(ctx, err)
		}
		if !isReplyTo(q, r) {
			return nil, errNotReply
		}
		return r, nil
	}
	if _, err := c.Write(q); err != nil {
		return nil, ctxErr(ctx, err)
	}
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, ctxErr(ctx, err)
		}
		// Anything else on the socket is not the answer, which may still come.
		if isReplyTo(q, buf[:n]) {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var ne net.Error
	if dl, ok := ctx.Deadline(); ok && errors.As(err, &ne) && ne.Timeout() && !time.Now().Before(dl) {
		return context.DeadlineExceeded
	}
	return err
}

var (
	// errBudget: the server's queries of this round are spent.
	errBudget = errors.New("its queries of this round are spent")
	// errRoundOver: the round's time ran out before the answer.
	errRoundOver = errors.New("the round's time ran out")
)

// noAnswer is a query that got no answer in time.
type noAnswer struct{ after time.Duration }

func (e noAnswer) Error() string {
	return fmt.Sprintf("no answer in %v", e.after.Round(10*time.Millisecond))
}

// unreachable reports an error of a network the node has no route on
// (IPv4 resolvers from a node with IPv6 only): nothing to say of the zone.
func unreachable(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.EADDRNOTAVAIL)
}

// asker sends the queries of one server, one at a time and at most budget
// of them in a round: the second copy of a UDP query and the same query
// over TCP after a truncated answer count too.
type asker struct {
	c      *Checker
	net    string
	addr   netip.AddrPort
	budget int
}

// exchange is a query's answer.
type exchange struct {
	r   *reply
	rtt time.Duration
	tcp bool // over TCP, after a truncated answer over UDP
}

// ask sends a query and waits for its answer: a second copy after
// c.Retry without one, none after c.GiveUp. A truncated answer over UDP is
// asked again over TCP while the budget allows; otherwise it is returned
// as it came.
func (a *asker) ask(ctx context.Context, q []byte) (exchange, error) {
	x, err := a.once(ctx, a.net, q)
	if err != nil || a.net != "udp" || !x.r.Truncated || a.budget == 0 {
		return x, err
	}
	t, err := a.once(ctx, "tcp", q)
	if err != nil {
		return x, nil // the truncated one says enough
	}
	t.tcp = true
	return t, nil
}

func (a *asker) once(parent context.Context, network string, q []byte) (exchange, error) {
	if a.budget <= 0 {
		return exchange{}, errBudget
	}
	giveUp := a.c.giveUp()
	ctx, cancel := context.WithTimeout(parent, giveUp)
	type got struct {
		raw []byte
		err error
	}
	answers := make(chan got, 2)
	pending := 0
	// The copy still out ends with the query: the server never has two
	// of the node's queries at once.
	defer func() {
		cancel()
		for ; pending > 0; pending-- {
			<-answers
		}
	}()
	send := func() {
		a.budget--
		go func() {
			raw, err := a.c.net().Exchange(ctx, network, a.addr, q)
			answers <- got{raw, err}
		}()
	}
	start := time.Now()
	send()
	pending++
	var retry <-chan time.Time
	if network == "udp" {
		t := time.NewTimer(a.c.retry())
		defer t.Stop()
		retry = t.C
	}
	var last error
	for pending > 0 {
		select {
		case <-retry:
			retry = nil
			if a.budget > 0 {
				send()
				pending++
			}
		case g := <-answers:
			pending--
			if g.err != nil {
				last = g.err
				continue
			}
			r, err := parseReply(q, g.raw)
			if err != nil {
				last = err
				continue
			}
			return exchange{r: r, rtt: time.Since(start)}, nil
		}
	}
	switch {
	case parent.Err() != nil:
		return exchange{}, errRoundOver
	case ctx.Err() != nil || errors.Is(last, context.DeadlineExceeded):
		return exchange{}, noAnswer{giveUp}
	}
	return exchange{}, last
}
