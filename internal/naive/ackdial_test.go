package naive

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/site"
)

// A name whose lookup is still under way when the dial's time ends is a
// name that was not resolved: 502 unreachable, as for any other end of a
// lookup, not the 504 of a destination that stayed silent. Through the
// server's own lookup (the Dial hook of TestAckConnect has none).
func TestAckSlowLookup(t *testing.T) {
	const dialWait = 300 * time.Millisecond
	_, connect := ackServer(t, func(h *Server) {
		h.dialWait = dialWait
		h.Resolve = func(ctx context.Context, _ string) ([]netip.Addr, error) {
			<-ctx.Done() // resolvers that do not answer
			return nil, &net.DNSError{Err: "i/o timeout", IsTimeout: true}
		}
	})
	start := time.Now()
	resp, _ := connect("slow-resolvers.example:443", true, nil)
	refused(t, "a lookup that outlasts the dial", resp, http.StatusBadGateway, ackUnreachable)
	if took := time.Since(start); took < dialWait {
		t.Errorf("answered after %v, the dial's time is %v", took, dialWait)
	}
}

// Addresses that come exactly at the dial's deadline (a lookup that
// answered then) leave no time for an attempt: none was tried, none was
// silent, so 502 unreachable, not the 504 of a destination given its
// time. The dial returned the context's DeadlineExceeded, ranked silent.
// Both ways the addresses are tried: one family, and two.
func TestAckNoTimeForAttempt(t *testing.T) {
	h := &Server{dialAddr: func(context.Context, netip.AddrPort) (net.Conn, error) {
		t.Error("an address was dialed after the dial's time")
		return nil, os.ErrDeadlineExceeded
	}}
	for what, addrs := range map[string][]netip.AddrPort{
		"one family":   {netip.MustParseAddrPort("198.51.100.1:443")},
		"two families": {netip.MustParseAddrPort("198.51.100.1:443"), netip.MustParseAddrPort("[2001:db8::1]:443")},
	} {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now())
		_, err := h.dialRace(ctx, "u5", addrs)
		cancel()
		if status, reason := ackRefusal(err, true); status != http.StatusBadGateway || reason != ackUnreachable {
			t.Errorf("%s, no time left: %v, answered %d %q", what, err, status, reason)
		}
	}
}

// A client whose password was taken and who asked for the dial's outcome
// does not get the site's 404 for a target the node will not dial (a naive
// client reads 404 from its proxy as its password refused): 502 denied,
// and nothing is looked up or dialed. Without niko-ack the answer is the
// site's, as it was.
func TestAckBadTarget(t *testing.T) {
	_, connect := ackServer(t, func(h *Server) {
		h.Resolve = func(context.Context, string) ([]netip.Addr, error) {
			t.Error("a bad target was looked up")
			return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
		}
		h.dialAddr = func(context.Context, netip.AddrPort) (net.Conn, error) {
			t.Error("a bad target was dialed")
			return nil, syscall.ECONNREFUSED
		}
	})
	for _, target := range []string{"12345:443", "-host.example:443", strings.Repeat("a", 64) + ".example:443", "a..b:443"} {
		resp, _ := connect(target, true, nil)
		refused(t, "niko-ack and the target "+target[:8], resp, http.StatusBadGateway, ackDenied)
		resp, _ = connect(target, false, nil)
		if resp.StatusCode != http.StatusNotFound || resp.Header.Get("Padding") != "" || resp.Header.Get(AckHeader) != "" {
			t.Errorf("the target %.8s without niko-ack: %s %v, want the site's answer", target, resp.Status, resp.Header)
		}
	}
}

// The answer of a dial that tried several addresses is of all its attempts,
// not of the first to fail: through the server's own lookup, its choice of
// addresses and both ways it tries them (dialSerial for one family,
// dialRace for two), with only the connect of one address the test's.
func TestAckDialRank(t *testing.T) {
	const dialWait = 2 * time.Second // an attempt of two gets half
	op := func(err error) error { return &net.OpError{Op: "dial", Net: "tcp", Err: err} }
	sys := func(errno syscall.Errno) error { return op(os.NewSyscallError("connect", errno)) }
	const (
		silent4, refused4, noRoute4, denied4 = "198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"
		refused6, denied6                    = "2001:db8::2", "2001:db8::4"
		// Silent too, as the real dialer has it: the connect ends on the
		// socket's deadline, and returns without waiting for ctx.Done().
		timeout4 = "198.51.100.5"
	)
	names := map[string][]string{
		"silent-refused.test":   {silent4, refused4},
		"silent-noroute.test":   {silent4, noRoute4},
		"silent-silent.test":    {silent4, silent4},
		"noroute-refused6.test": {noRoute4, refused6},
		"silent-denied6.test":   {silent4, denied6},
		"denied-denied6.test":   {denied4, denied6},
		"denied-noroute.test":   {denied4, noRoute4},
		"one-token.test":        {silent4, refused4},
		"timeout.test":          {timeout4},
		"timeout-timeout.test":  {timeout4, timeout4},
	}
	var mu sync.Mutex
	dialed := map[string]int{}
	setup := func(h *Server) {
		h.dialWait = dialWait
		h.minAttempt = 50 * time.Millisecond
		h.Allow = func(netip.Addr) bool { return true }
		h.Resolve = func(_ context.Context, name string) ([]netip.Addr, error) {
			var addrs []netip.Addr
			for _, a := range names[name] {
				addrs = append(addrs, netip.MustParseAddr(a))
			}
			return addrs, nil
		}
		h.dialAddr = func(ctx context.Context, a netip.AddrPort) (net.Conn, error) {
			mu.Lock()
			dialed[a.Addr().String()]++
			mu.Unlock()
			switch a.Addr().String() {
			case silent4:
				<-ctx.Done()
				if ctx.Err() == context.DeadlineExceeded {
					return nil, op(os.ErrDeadlineExceeded) // "i/o timeout", as the dialer says it
				}
				return nil, op(ctx.Err())
			case timeout4:
				if d, ok := ctx.Deadline(); ok {
					time.Sleep(time.Until(d))
				}
				return nil, op(os.ErrDeadlineExceeded)
			case refused4, refused6:
				return nil, sys(syscall.ECONNREFUSED)
			case noRoute4:
				return nil, sys(syscall.EHOSTUNREACH)
			}
			return nil, sys(syscall.EPERM)
		}
	}
	_, connect := ackServer(t, setup)
	var wg sync.WaitGroup
	for _, c := range []struct {
		what, name string
		status     int
		reason     string
		whole      bool // not before the dial's time
	}{
		// One family, in turn. The first address is silent for its share of
		// the time, which was the dial's answer (504, before the dial's
		// time) whatever the second said.
		{"silent, then refused", "silent-refused.test", http.StatusBadGateway, ackRefused, false},
		{"silent, then no route", "silent-noroute.test", http.StatusBadGateway, ackUnreachable, false},
		{"silent twice", "silent-silent.test", http.StatusGatewayTimeout, "", true},
		{"silent to the socket's deadline", "timeout.test", http.StatusGatewayTimeout, "", true},
		{"silent to the socket's deadline twice", "timeout-timeout.test", http.StatusGatewayTimeout, "", true},
		{"stopped by the rules, then no route", "denied-noroute.test", http.StatusBadGateway, ackUnreachable, false},
		// Two families: the first family's error was the dial's answer.
		{"no route, the other family refused", "noroute-refused6.test", http.StatusBadGateway, ackRefused, false},
		{"silent, the other family stopped by the rules", "silent-denied6.test", http.StatusGatewayTimeout, "", true},
		{"both families stopped by the rules", "denied-denied6.test", http.StatusBadGateway, ackDenied, false},
	} {
		wg.Go(func() {
			start := time.Now()
			resp, _ := connect(c.name+":443", true, nil)
			refused(t, c.what, resp, c.status, c.reason)
			if took := time.Since(start); c.whole && took < dialWait {
				t.Errorf("%s: 504 after %v, the dial's time is %v", c.what, took, dialWait)
			}
		})
	}
	wg.Wait()

	// An address not tried for want of a token is no attempt: the answer is
	// of those made. Here one, silent for its share of the time: not 504,
	// the dial's time was not over.
	now := time.Now()
	h, connect := ackServer(t, func(h *Server) {
		setup(h)
		h.lim.now = func() time.Time { return now } // no token comes back
	})
	h.lim.mu.Lock()
	h.lim.userLocked("u5", now).attempts = bucket{1, now}
	h.lim.mu.Unlock()
	mu.Lock()
	before := dialed[refused4]
	mu.Unlock()
	resp, _ := connect("one-token.test:443", true, nil)
	refused(t, "silent, then no token for the next address", resp, http.StatusBadGateway, ackUnreachable)
	mu.Lock()
	if dialed[refused4] != before {
		t.Error("an address was tried without a token")
	}
	mu.Unlock()
}

// What clients send before the answer of an honest connect is bounded by
// the connection's window however many dials wait, and none of it is read
// (no window given back) before its dial ends.
func TestAckEarlyDataBound(t *testing.T) {
	users := filepath.Join(t.TempDir(), "users.json")
	writeUsersNamed(t, users, map[string]string{"pw": "u5-ab12"})
	answer, _ := site.Responder(site.Answer404, "")
	h := &Server{Users: &Users{Path: users}, Answer: answer, Log: slog.New(slog.DiscardHandler), dialWait: 3 * time.Second,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}}
	p := newH2Peer(t, serveNaive(t, h))
	eventually(t, "no window", func() bool { return p.window(0) > 0 })
	sent := 0
	chunk := make([]byte, 16<<10)
	room := site.ConnWindow
	for i := range 16 {
		stream := uint32(1 + 2*i)
		p.headers(t, stream, false, [2]string{":method", "CONNECT"}, [2]string{":authority", "192.0.2.1:443"},
			[2]string{"padding", paddingHeader()}, [2]string{"proxy-authorization", "Basic bmlrbzpwdw=="}, [2]string{"niko-ack", "1"})
		d := &h2Data{p: p, stream: stream, room: min(site.StreamWindow, room)}
		for d.room > 0 {
			n, err := d.Write(chunk)
			sent += n
			room -= n
			if err != nil {
				break
			}
		}
	}
	if sent != site.ConnWindow {
		t.Fatalf("sent %d bytes, want the connection's window", sent)
	}
	time.Sleep(500 * time.Millisecond) // the dials wait 3 s
	p.mu.Lock()
	back, ended := p.windows[0]+65535-site.ConnWindow, p.ended
	p.mu.Unlock()
	if back != 0 || ended != "" {
		t.Errorf("16 dials under way: %d bytes of the window given back, the connection ended %q", back, ended)
	}
}

// deadlineCtx is a dial's context whose time is over while its Err() is
// still nil: the context's timer has not run yet.
type deadlineCtx struct {
	context.Context
	deadline time.Time
	err      error
}

func (c deadlineCtx) Deadline() (time.Time, bool) { return c.deadline, true }
func (c deadlineCtx) Err() error                  { return c.err }

// The dial expired by its deadline, not by ctx.Err(): the real dialer's
// "i/o timeout" comes on the socket's deadline, the same instant, and can
// come before the context's timer has run. A destination silent for the
// whole time got 502 unreachable then, one or two dials in a hundred. A
// client gone before the time is over is not expired.
func TestDialExpired(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		what string
		ctx  context.Context
		want bool
	}{
		{"over, the timer not run yet", deadlineCtx{context.Background(), now.Add(-time.Millisecond), nil}, true},
		{"over at this instant", deadlineCtx{context.Background(), now, nil}, true},
		{"over", deadlineCtx{context.Background(), now.Add(-time.Second), context.DeadlineExceeded}, true},
		{"the client went away", deadlineCtx{context.Background(), now.Add(time.Hour), context.Canceled}, false},
		{"no deadline", context.Background(), false},
	} {
		if got := expired(c.ctx); got != c.want {
			t.Errorf("%s: expired %v", c.what, got)
		}
	}
}
