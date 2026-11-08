package naive

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeDNS answers every A question with 203.0.113.9.
func fakeDNS(t *testing.T) string {
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
			m.Response, m.RecursionAvailable = true, true
			if q.Type == dnsmessage.TypeA {
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
// unit may not reach). One that does not answer is passed over within
// resolverWait and said in the log; the one that answered is asked first
// from then on.
func TestPublicResolver(t *testing.T) {
	// Shorter than any resolv.conf timeout (1 s at least): a lookup that
	// waits for that did not cut the silent one short.
	saved := resolverWait
	resolverWait = 200 * time.Millisecond
	t.Cleanup(func() { resolverWait = saved })
	closed, _ := net.ListenPacket("udp", "127.0.0.1:0")
	refused := closed.LocalAddr().String()
	closed.Close()
	rec := &records{}
	p := newPublicDNS([]string{silentDNS(t), refused, fakeDNS(t)})
	p.log.Store(slog.New(rec))
	lookup := func() time.Duration {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		start := time.Now()
		ips, err := p.r.LookupNetIP(ctx, "ip4", "example.test")
		if err != nil || len(ips) != 1 || ips[0] != netip.MustParseAddr("203.0.113.9") {
			t.Fatalf("lookup: %v %v", ips, err)
		}
		return time.Since(start)
	}
	if d := lookup(); d > 900*time.Millisecond {
		t.Errorf("first lookup took %s: the silent resolver held it", d)
	}
	if got := p.cur.Load(); got != 2 {
		t.Errorf("asked first now: %d, want the one that answered", got)
	}
	if d := lookup(); d > time.Second {
		t.Errorf("second lookup took %s: the one that answered was not asked first", d)
	}
	if len(rec.msgs) != 1 {
		t.Errorf("warnings: %v", rec.msgs)
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

// A lookup its caller gives up on does not fail the resolver.
func TestResolverCancel(t *testing.T) {
	rec := &records{}
	p := newPublicDNS([]string{silentDNS(t)})
	p.log.Store(slog.New(rec))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _ = p.r.LookupNetIP(ctx, "ip4", "example.test")
	time.Sleep(100 * time.Millisecond)
	if len(rec.msgs) != 0 {
		t.Fatalf("warned: %v", rec.msgs)
	}
}
