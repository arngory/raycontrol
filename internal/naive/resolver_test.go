package naive

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeDNS answers every A question with 203.0.113.9.
func fakeDNS(t *testing.T) string { return answeringDNS(t, dnsmessage.RCodeSuccess) }

// answeringDNS answers every question: with 203.0.113.9 to A when rcode is
// success, with rcode alone otherwise.
func answeringDNS(t *testing.T, rcode dnsmessage.RCode) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var m dnsmessage.Message
			if m.Unpack(buf[:n]) != nil || len(m.Questions) == 0 {
				continue
			}
			q := m.Questions[0]
			m.Response, m.RecursionAvailable, m.RCode = true, true, rcode
			if q.Type == dnsmessage.TypeA && rcode == dnsmessage.RCodeSuccess {
				m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
					Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 9}}}}
			}
			out, _ := m.Pack()
			_, _ = pc.WriteTo(out, from)
		}
	}()
	return pc.LocalAddr().String()
}

// silentDNS takes queries and never answers.
func silentDNS(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc.LocalAddr().String()
}

// naive looks names up with its own resolvers, not the host's (which the
// unit may not reach). One that does not answer, refuses or answers
// SERVFAIL is passed over (within the wait, much shorter than any
// resolv.conf timeout here) and the next one asked first from then on;
// only one that does not answer goes in the log.
func TestPublicResolver(t *testing.T) {
	const wait = 200 * time.Millisecond
	closed, _ := net.ListenPacket("udp", "127.0.0.1:0")
	refused := closed.LocalAddr().String()
	closed.Close()
	for name, c := range map[string]struct {
		first string
		warns int
	}{
		"silent":   {silentDNS(t), 1},
		"refused":  {refused, 1},
		"servfail": {answeringDNS(t, dnsmessage.RCodeServerFailure), 0},
		"refuses":  {answeringDNS(t, dnsmessage.RCodeRefused), 0},
		// Not dialed at all: no IPv6 here (passed over quietly) or a
		// link-local address without a zone (warned about).
		"no route": {"[fe80::1]:53", -1},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &records{}
			p := newPublicDNS([]string{c.first, fakeDNS(t)}, wait)
			p.log.Store(slog.New(rec))
			lookup := func() error {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				ips, err := p.r.LookupNetIP(ctx, "ip4", "example.test")
				if err == nil && (len(ips) != 1 || ips[0] != netip.MustParseAddr("203.0.113.9")) {
					return fmt.Errorf("answer %v", ips)
				}
				return err
			}
			// However few attempts the host's resolv.conf allows, the
			// lookups get to the one that answers, and quickly.
			start := time.Now()
			var err error
			for range 3 {
				if err = lookup(); err == nil {
					break
				}
			}
			if err != nil {
				t.Fatalf("never answered: %v", err)
			}
			if d := time.Since(start); d > 900*time.Millisecond {
				t.Errorf("took %s: the first resolver held the lookups", d)
			}
			if got := p.cur.Load(); got != 1 {
				t.Errorf("asked first now: %d, want the one that answered", got)
			}
			start = time.Now()
			if err := lookup(); err != nil || time.Since(start) > 300*time.Millisecond {
				t.Errorf("next lookup: %v in %s", err, time.Since(start))
			}
			if c.warns >= 0 && len(rec.msgs) != c.warns {
				t.Errorf("warnings: %v, want %d", rec.msgs, c.warns)
			}
		})
	}
}

type records struct {
	mu   sync.Mutex
	msgs []string
}

func (r *records) Enabled(context.Context, slog.Level) bool { return true }
func (r *records) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec.Level >= slog.LevelWarn {
		r.msgs = append(r.msgs, rec.Message)
	}
	return nil
}
func (r *records) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *records) WithGroup(string) slog.Handler      { return r }

// A resolver that does not answer is warned about once a minute at most.
func TestResolverWarn(t *testing.T) {
	rec := &records{}
	log := slog.New(rec)
	var w resolverWarn
	for range 5 {
		w.note(log, "1.1.1.1:53", errors.New("i/o timeout"))
	}
	if len(rec.msgs) != 1 || w.missed != 4 {
		t.Fatalf("warned %v, missed %d", rec.msgs, w.missed)
	}
	w.last = time.Now().Add(-2 * time.Minute)
	w.note(log, "1.1.1.1:53", errors.New("i/o timeout"))
	if len(rec.msgs) != 2 || w.missed != 0 {
		t.Fatalf("a minute later: %v, missed %d", rec.msgs, w.missed)
	}
}

// A lookup its caller gave up on dials with a dead context: that fails no
// resolver and is not warned about.
func TestResolverCancel(t *testing.T) {
	rec := &records{}
	p := newPublicDNS([]string{fakeDNS(t), fakeDNS(t)}, resolverWait)
	p.log.Store(slog.New(rec))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c, err := p.dial(ctx, "udp", ""); err == nil {
		c.Close()
		t.Fatal("dialed with a dead context")
	}
	if p.cur.Load() != 0 || len(rec.msgs) != 0 {
		t.Fatalf("a cancelled lookup failed resolvers: now %d, warned %v", p.cur.Load(), rec.msgs)
	}
}

// Many lookups at once with the first resolver silent: it is passed over
// once, and said once.
func TestPublicResolverConcurrent(t *testing.T) {
	rec := &records{}
	p := newPublicDNS([]string{silentDNS(t), fakeDNS(t)}, 200*time.Millisecond)
	p.log.Store(slog.New(rec))
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, _ = p.r.LookupNetIP(ctx, "ip", "example.test.")
		})
	}
	wg.Wait()
	if got := p.cur.Load(); got != 1 || len(rec.msgs) != 1 {
		t.Fatalf("asked first %d (want 1), warnings %v (want one)", got, rec.msgs)
	}
}

// fakeConn is a resolver's connection that says what it is told.
type fakeConn struct {
	net.Conn
	read              []byte
	readErr, writeErr error
}

func (f *fakeConn) Read(b []byte) (int, error)  { return copy(b, f.read), f.readErr }
func (f *fakeConn) Write(b []byte) (int, error) { return len(b), f.writeErr }

// What fails a resolver, and what does not.
func TestResolverConnFailures(t *testing.T) {
	query := []byte{0xab, 0xcd, 0x01, 0x00}
	answer := func(id uint16, qr bool, rcode byte) []byte {
		b := []byte{byte(id >> 8), byte(id), 0, rcode}
		if qr {
			b[2] = 0x80
		}
		return b
	}
	for name, c := range map[string]struct {
		conn  *fakeConn
		good  bool // the resolver answered another query well meanwhile
		moved bool
		warns int
	}{
		"cannot send":          {conn: &fakeConn{writeErr: syscall.EPERM}, moved: true, warns: 1},
		"servfail":             {conn: &fakeConn{read: answer(0xabcd, true, 2)}, moved: true},
		"refused":              {conn: &fakeConn{read: answer(0xabcd, true, 5)}, moved: true},
		"servfail, another id": {conn: &fakeConn{read: answer(0x1234, true, 2)}},
		"servfail, not answer": {conn: &fakeConn{read: answer(0xabcd, false, 2)}},
		"servfail, good since": {conn: &fakeConn{read: answer(0xabcd, true, 2)}, good: true},
		"no such name":         {conn: &fakeConn{read: answer(0xabcd, true, 3)}},
		"timeout":              {conn: &fakeConn{readErr: os.ErrDeadlineExceeded}, moved: true, warns: 1},
		"timeout, good since":  {conn: &fakeConn{readErr: os.ErrDeadlineExceeded}, good: true},
		"closed by the caller": {conn: &fakeConn{readErr: net.ErrClosed}},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &records{}
			p := newPublicDNS([]string{"a", "b"}, time.Second)
			p.log.Store(slog.New(rec))
			rc := &resolverConn{Conn: c.conn, p: p, packet: true}
			_, _ = rc.Write(query)
			if c.good {
				p.good[0].Store(time.Now().Add(time.Millisecond).UnixNano())
			}
			if c.conn.writeErr == nil {
				_, _ = rc.Read(make([]byte, 512))
			}
			if moved := p.cur.Load() == 1; moved != c.moved || len(rec.msgs) != c.warns {
				t.Fatalf("moved %v (want %v), warnings %v (want %d)", moved, c.moved, rec.msgs, c.warns)
			}
		})
	}
}

// Over TCP a query stays a stream: Go frames it with its length.
func TestResolverTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	p := newPublicDNS([]string{ln.Addr().String()}, time.Second)
	c, err := p.dial(context.Background(), "tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, ok := c.(net.PacketConn); ok {
		t.Fatal("a TCP query as a PacketConn")
	}
	if c.(*resolverConn).packet {
		t.Fatal("a TCP query read as datagrams")
	}
}

// Names go out fully qualified: the host's search domains stay home.
func TestFQDN(t *testing.T) {
	for in, want := range map[string]string{"example.com": "example.com.", "example.com.": "example.com.", "localhost": "localhost.",
		"192.0.2.1": "192.0.2.1", "2001:db8::1": "2001:db8::1", "": ""} {
		if got := fqdn(in); got != want {
			t.Errorf("fqdn(%q) = %q", in, got)
		}
	}
}

// Several queries to the same resolver fail: it is passed over once, to
// the next, and said once.
func TestResolverFailsOnce(t *testing.T) {
	rec := &records{}
	p := newPublicDNS([]string{"a", "b", "c"}, time.Second)
	p.log.Store(slog.New(rec))
	for range 3 {
		rc := &resolverConn{Conn: &fakeConn{readErr: os.ErrDeadlineExceeded}, p: p, packet: true}
		_, _ = rc.Write([]byte{1, 2, 1, 0})
		_, _ = rc.Read(make([]byte, 512))
	}
	if got := p.cur.Load(); got != 1 || len(rec.msgs) != 1 {
		t.Fatalf("asked first %d (want 1), warnings %v (want one)", got, rec.msgs)
	}
}
