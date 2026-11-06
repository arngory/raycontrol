package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/arngory/raycontrol/internal/dnscheck"
	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
)

// fakeDNS is the host's resolver (192.0.2.53) and the one server of
// example.com (192.0.2.1), which delegates the tunnel zones to the node
// once told to; every other server is out of the node's reach.
type fakeDNS struct {
	ns string // the name the zones are delegated to

	mu        sync.Mutex
	delegate  bool
	parentNS  int // NS queries to the parent
	resolvers int // queries to public resolvers
}

func (f *fakeDNS) set(delegate bool) {
	f.mu.Lock()
	f.delegate = delegate
	f.mu.Unlock()
}

func (f *fakeDNS) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.parentNS, f.resolvers
}

func name(s string) dnsmessage.Name { return dnsmessage.MustNewName(s + ".") }

func (f *fakeDNS) Exchange(_ context.Context, network string, srv netip.AddrPort, q []byte) ([]byte, error) {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil {
		return nil, err
	}
	question, err := p.Question()
	if err != nil {
		return nil, err
	}
	qname := strings.TrimSuffix(strings.ToLower(question.Name.String()), ".")
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired},
		Questions: []dnsmessage.Question{question}}
	soa := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: name("example.com"), Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: 300},
		Body: &dnsmessage.SOAResource{NS: name("ns1.example.net"), MBox: name("hostmaster.example.com"), MinTTL: 60}}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch srv.Addr().String() {
	case "192.0.2.53":
		switch question.Type {
		case dnsmessage.TypeSOA:
			m.Answers = []dnsmessage.Resource{soa}
		case dnsmessage.TypeNS:
			m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name("example.com"), Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, TTL: 300},
				Body: &dnsmessage.NSResource{NS: name("ns1.example.net")}}}
			m.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name("ns1.example.net"), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
				Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}}}
		}
	case "192.0.2.1":
		if question.Type == dnsmessage.TypeNS {
			f.parentNS++
		}
		if question.Type == dnsmessage.TypeNS && f.delegate {
			m.Authorities = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name(qname), Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, TTL: 300},
				Body: &dnsmessage.NSResource{NS: name(f.ns)}}}
			m.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name(f.ns), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
				Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 7}}}}
		} else {
			m.Authoritative, m.Authorities = true, []dnsmessage.Resource{soa}
		}
	default:
		if srv.Addr().String() != "127.0.0.1" {
			f.resolvers++
		}
		return nil, &net.OpError{Op: "dial", Net: network, Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}
	}
	return m.Pack()
}

// The loop asks only the parent after a change, every dnsParentEvery,
// until it delegates the zones; then the whole check once, and again
// after the period; a zone that goes takes its loop with it.
func TestCheckDNSZones(t *testing.T) {
	defer func(every, during time.Duration) { dnsParentEvery, dnsParentFor = every, during }(dnsParentEvery, dnsParentFor)
	dnsParentEvery, dnsParentFor = 20*time.Millisecond, 5*time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	ns, err := provision.NSName(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeDNS{ns: ns}
	hb := &health.Board{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	resolvers, _ := dnscheck.ParseResolvers(dnscheck.DefaultResolvers)
	mon := dnsMonitor(ctx, st, resolvers, hb, log)
	mon.Checker = &dnscheck.Checker{Net: fake, System: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")},
		Local: func(netip.Addr) bool { return false }, Retry: 5 * time.Millisecond, GiveUp: 20 * time.Millisecond}
	var mu sync.Mutex
	wake := make(chan struct{})
	changes := func() <-chan struct{} {
		mu.Lock()
		defer mu.Unlock()
		return wake
	}
	notify := func() {
		mu.Lock()
		close(wake)
		wake = make(chan struct{})
		mu.Unlock()
	}
	done := make(chan struct{})
	go func() { checkDNSZones(ctx, mon, st, changes, 300*time.Millisecond, hb, log); close(done) }()

	until := func(what string, ok func() bool) {
		t.Helper()
		for range 400 {
			if ok() {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("no %s", what)
	}
	zoneLoop := func() (health.Loop, bool) {
		for _, l := range hb.Loops() {
			if l.Name == "dns-zone dns" {
				return l, true
			}
		}
		return health.Loop{}, false
	}
	// Not delegated yet: the parent again and again, no resolver.
	until("parent polls", func() bool { n, _ := fake.counts(); return n >= 3 })
	if _, r := fake.counts(); r != 0 {
		t.Fatalf("%d queries to resolvers before the delegation", r)
	}
	if _, ok := zoneLoop(); ok {
		t.Fatal("a zone's loop before its check")
	}
	// Delegated: the whole check, resolvers asked, the loop on the board.
	fake.set(true)
	until("the zone's loop", func() bool { _, ok := zoneLoop(); return ok })
	if l, _ := zoneLoop(); l.Runs != 1 || l.Failing() || !strings.HasPrefix(l.Detail, "delegated") {
		t.Fatalf("loop %+v", l)
	}
	if _, r := fake.counts(); r == 0 {
		t.Fatal("no resolver asked")
	}
	if next := mon.Next(); next.IsZero() || time.Until(next) > 330*time.Millisecond {
		t.Fatalf("next check at %v", next)
	}
	// The period: once more.
	until("the second round", func() bool { l, _ := zoneLoop(); return l.Runs == 2 })
	// The zone goes: its loop too.
	if err := st.DeleteService(ctx, "dns"); err != nil {
		t.Fatal(err)
	}
	notify()
	until("the loop gone", func() bool { _, ok := zoneLoop(); return !ok })
	cancel()
	<-done
	if !mon.Next().IsZero() {
		t.Fatal("a next check after the loop ended")
	}
}
