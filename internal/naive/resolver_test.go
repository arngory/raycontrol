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

// naive looks names up with its own resolvers, not the host's (which the
// unit may not reach); a resolver that does not answer is passed over.
func TestPublicResolver(t *testing.T) {
	saved := resolvers
	t.Cleanup(func() { resolvers = saved })
	// A closed port first: the next attempt goes to the one that answers.
	closed, _ := net.ListenPacket("udp", "127.0.0.1:0")
	dead := closed.LocalAddr().String()
	closed.Close()
	resolvers = []string{dead, fakeDNS(t)}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ips, err := PublicResolver().LookupNetIP(ctx, "ip4", "example.test")
	if err != nil || len(ips) != 1 || ips[0] != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("lookup: %v %v", ips, err)
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

// Names that cannot be looked up are warned about, once a minute at most;
// a name that does not exist, or a destination that does not answer, is
// the client's business.
func TestResolverWarn(t *testing.T) {
	rec := &records{}
	log := slog.New(rec)
	var w resolverWarn
	w.note(log, &net.DNSError{Err: "no such host", Name: "x.test", IsNotFound: true})
	w.note(log, errors.New("connection refused"))
	if len(rec.msgs) != 0 {
		t.Fatalf("warned: %v", rec.msgs)
	}
	blocked := &net.DNSError{Err: "dial udp 127.0.0.53:53: connect: operation not permitted", Name: "x.test", Server: "127.0.0.53:53"}
	for range 5 {
		w.note(log, blocked)
	}
	if len(rec.msgs) != 1 || w.missed != 4 {
		t.Fatalf("warned %v, missed %d", rec.msgs, w.missed)
	}
	w.last = time.Now().Add(-2 * time.Minute)
	w.note(log, blocked)
	if len(rec.msgs) != 2 || w.missed != 0 {
		t.Fatalf("a minute later: %v, missed %d", rec.msgs, w.missed)
	}
}
