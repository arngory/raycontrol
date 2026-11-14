package naive

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDomainName(t *testing.T) {
	label := strings.Repeat("a", 63)
	long := strings.Join([]string{label, label, label, strings.Repeat("b", 61)}, ".") // 253 bytes
	for host, want := range map[string]bool{
		"example.com": true, "example.com.": true, "_dmarc.example.com": true, "a-b.c": true, "xn--d1acufc.xn--p1ai": true,
		long: true, long + ".": true, long + "b": false, strings.Repeat("a", 1<<20): false,
		label + "a.com": false, "": false, ".": false, "a..b": false, "-a.com": false, "a-.com": false, "a.com-": false,
		"123": false, "1.2.3": false, "a b.com": false, "a/b": false, "a\x00b": false, "exämple.com": false,
	} {
		if got := domainName(host); got != want {
			t.Errorf("%.40q (%d bytes): %v, want %v", host, len(host), got, want)
		}
	}
}

// A host that is no domain name (too long, not a name) is refused before
// the cache, the user's token and the resolvers: one user's megabyte names
// must not fill the process's memory.
func TestNameCacheBadNames(t *testing.T) {
	var asked atomic.Int32
	s := &Server{Resolve: func(context.Context, string) ([]netip.Addr, error) {
		asked.Add(1)
		return []netip.Addr{netip.MustParseAddr("192.0.2.7")}, nil
	}}
	c := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s.lim.now = c.now
	s.lim.lookupBurst = 1
	for _, n := range []string{strings.Repeat("a", 1<<20) + ".com", strings.Repeat("a.", 127) + "com", "a..b", "-x.test"} {
		if _, err := s.lookupName(context.Background(), "u5", n, false); !errors.Is(err, errBadName) {
			t.Errorf("%.20q: %v", n, err)
		}
	}
	if asked.Load() != 0 || len(s.names.m) != 0 {
		t.Fatalf("bad names looked up %d times, %d kept", asked.Load(), len(s.names.m))
	}
	// No token went: the one there is still looks a good name up.
	if _, err := s.lookupName(context.Background(), "u5", "ok.test", false); err != nil || asked.Load() != 1 {
		t.Fatalf("a good name after bad ones: %v, asked %d", err, asked.Load())
	}
}

// Over HTTP/2: a CONNECT to a host that is no name gets the site's answer,
// as any bad target; nothing is looked up, kept or charged.
func TestNaiveBadName(t *testing.T) {
	var asked atomic.Int32
	h, connect := limitServer(t, nil)
	h.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		asked.Add(1)
		return nil, nil
	}
	for _, host := range []string{strings.Repeat("a", 64<<10) + ".test", "a..b", "a-.test"} {
		resp, err := connect("pw", host+":443")
		if err != nil {
			t.Fatalf("%.20q: %v", host, err)
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%.20q: %s", host, resp.Status)
		}
	}
	h.names.mu.Lock()
	kept := len(h.names.m)
	h.names.mu.Unlock()
	h.lim.mu.Lock()
	u := h.lim.users["u5"]
	tokens := -1.0
	if u != nil {
		tokens = u.lookups.level(time.Now(), lookupRate, lookupBurst)
	}
	h.lim.mu.Unlock()
	if asked.Load() != 0 || kept != 0 || (u != nil && tokens < lookupBurst) {
		t.Fatalf("asked %d, kept %d, tokens %v", asked.Load(), kept, tokens)
	}
}

// An answer keeps 16 addresses at most.
func TestNameCacheAddrs(t *testing.T) {
	var many []netip.Addr
	for i := range 200 {
		many = append(many, netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}))
	}
	s := &Server{Resolve: func(context.Context, string) ([]netip.Addr, error) { return many, nil }}
	got, err := s.lookupName(context.Background(), "u5", "many.test", false)
	if err != nil || len(got) != nameAddrs {
		t.Fatalf("%d addresses, %v", len(got), err)
	}
	s.names.mu.Lock()
	kept := s.names.m["many.test"].addrs
	s.names.mu.Unlock()
	if len(kept) != nameAddrs || cap(kept) != nameAddrs {
		t.Fatalf("kept %d (cap %d)", len(kept), cap(kept))
	}
}

// What expired leaves the cache at the next answer kept, full or not; a
// full cache drops what expires first, not any name.
func TestNameCacheExpiry(t *testing.T) {
	var c names
	t0 := time.Unix(1_700_000_000, 0)
	a := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	c.put("nx.test", nil, nil, t0)
	c.put("ok.test", a, nil, t0)
	c.put("new.test", a, nil, t0.Add(nameMiss))
	if _, ok := c.m["nx.test"]; ok || len(c.m) != 2 {
		t.Fatalf("an expired miss kept: %d names", len(c.m))
	}
	// Full: answers at one time each, misses later; the first answer, the
	// earliest to expire, goes for a new name.
	c = names{}
	for i := range nameCache - 1 {
		c.put(fmt.Sprintf("h%d.test", i), a, nil, t0.Add(time.Duration(i)*time.Millisecond))
	}
	c.put("m.test", nil, nil, t0.Add(time.Duration(nameCache)*time.Millisecond)) // expires before every answer
	now := t0.Add(time.Duration(nameCache+1) * time.Millisecond)
	c.put("next.test", a, nil, now)
	if _, ok := c.m["m.test"]; ok || len(c.m) != nameCache {
		t.Fatalf("full: the miss expiring first kept, %d names", len(c.m))
	}
	c.put("next2.test", a, nil, now)
	if _, ok := c.m["h0.test"]; ok || len(c.m) != nameCache {
		t.Fatalf("full: the first answer kept, %d names", len(c.m))
	}
	if _, ok := c.m["h1.test"]; !ok {
		t.Fatal("full: more than one went")
	}
	// A name replaced keeps its place by its new time.
	c.put("h1.test", a, nil, now)
	c.put("next3.test", a, nil, now)
	if _, ok := c.m["h1.test"]; !ok {
		t.Fatal("a replaced name went by its old time")
	}
	if _, ok := c.m["h2.test"]; ok {
		t.Fatal("full: h2 should have gone")
	}
}

// Misses of one name at once share one lookup: only the first pays a token
// (none left for the others, they are not refused), and the first one's
// client leaving does not end the others' wait. A name under way needs no
// token before the 200.
func TestNameCacheInFlight(t *testing.T) {
	var asked atomic.Int32
	release := make(chan struct{})
	h, connect := limitServer(t, nil)
	h.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		asked.Add(1)
		<-release
		return []netip.Addr{netip.MustParseAddr("192.0.2.7")}, nil
	}
	h.Allow = func(netip.Addr) bool { return false } // no dial
	h.lim.lookupBurst = 1
	lctx, leave := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() {
		_, err := h.lookupName(lctx, "u5", "slow.test", false)
		first <- err
	}()
	eventually(t, "not looked up", func() bool { return asked.Load() == 1 })
	errs := make(chan error, 9)
	for range cap(errs) {
		go func() {
			_, err := h.lookupName(context.Background(), "u5", "slow.test", false)
			errs <- err
		}()
	}
	// u5 has no token left: under way, the name needs none before the 200.
	resp, err := connect("pw", "slow.test:443")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("a name under way: %v %v", resp, err)
	}
	time.Sleep(50 * time.Millisecond) // the others wait
	leave()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("the first one, gone: %v", err)
	}
	close(release)
	for range cap(errs) {
		if err := <-errs; err != nil {
			t.Fatalf("a miss under way: %v", err)
		}
	}
	if asked.Load() != 1 {
		t.Fatalf("looked up %d times", asked.Load())
	}
	if got := h.Refused()["u5"][refusedLookup]; got != 0 {
		t.Fatalf("refused %d lookups", got)
	}
}

// A UoT stream's packets to a name it resolved neither allocate nor take
// the process's cache's lock until the shared answer expires; then the
// name is looked up again.
func TestUoTNameKept(t *testing.T) {
	var asked atomic.Int32
	s := &Server{Allow: func(netip.Addr) bool { return true }, Resolve: func(context.Context, string) ([]netip.Addr, error) {
		asked.Add(1)
		return []netip.Addr{netip.MustParseAddr("192.0.2.7")}, nil
	}}
	c := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s.lim.now = c.now
	_, u := slotWith(t, s, "u5")
	a := uotAddr{name: "ok.test", port: 53}
	if to, ok := u.resolve(a); !ok || to.Addr() != netip.MustParseAddr("192.0.2.7") {
		t.Fatalf("resolved %v %v", to, ok)
	}
	// The cache's lock held: a packet that takes it waits, one that does
	// not passes.
	s.names.mu.Lock()
	done := make(chan bool, 1)
	go func() { _, ok := u.resolve(a); done <- ok }()
	select {
	case ok := <-done:
		if !ok {
			t.Error("refused")
		}
	case <-time.After(time.Second):
		s.names.mu.Unlock()
		t.Fatal("a packet to a kept name took the cache's lock")
	}
	s.names.mu.Unlock()
	if n := testing.AllocsPerRun(100, func() { u.resolve(a) }); n != 0 {
		t.Fatalf("%v allocations a packet", n)
	}
	c.t = c.t.Add(nameHit)
	if _, ok := u.resolve(a); !ok || asked.Load() != 2 {
		t.Fatalf("after the shared answer expired: %v, asked %d", ok, asked.Load())
	}
}

// A stream remembers for itself only a lookup that timed out or got
// SERVFAIL, which the shared cache does not keep: no token, no such name or
// no allowed address are the shared cache's to know (or no one's). Kept
// names past their time make room for new ones.
func TestUoTNameFailures(t *testing.T) {
	var asked atomic.Int32
	answer := map[string]error{
		"slow.test":     &net.DNSError{Err: "i/o timeout", IsTimeout: true, IsTemporary: true},
		"servfail.test": &net.DNSError{Err: "server misbehaving", IsTemporary: true},
		"nx.test":       &net.DNSError{Err: "no such host", IsNotFound: true},
	}
	s := &Server{Allow: func(a netip.Addr) bool { return a.Is4() }, Resolve: func(_ context.Context, name string) ([]netip.Addr, error) {
		asked.Add(1)
		if err := answer[name]; err != nil {
			return nil, err
		}
		if name == "v6.test" {
			return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.7")}, nil
	}}
	c := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s.lim.now = c.now
	_, u := slotWith(t, s, "u5")
	for _, n := range []string{"slow.test", "servfail.test"} {
		u.resolve(uotAddr{name: n, port: 53})
		u.resolve(uotAddr{name: n, port: 53})
	}
	if asked.Load() != 2 {
		t.Fatalf("a timeout or SERVFAIL looked up again within 30 s: %d", asked.Load())
	}
	for _, n := range []string{"nx.test", "v6.test"} {
		u.resolve(uotAddr{name: n, port: 53})
		if r, ok := u.names[n]; ok && !r.ip.IsValid() {
			t.Errorf("%s remembered as a failure of the stream's", n)
		}
	}
	// No token: not remembered; with one again, looked up at once.
	s.lim.mu.Lock()
	s.lim.users["u5"].lookups = bucket{0, c.t}
	s.lim.mu.Unlock()
	before := asked.Load()
	if _, ok := u.resolve(uotAddr{name: "later.test", port: 53}); ok || asked.Load() != before {
		t.Fatal("looked up without a token")
	}
	s.lim.mu.Lock()
	s.lim.users["u5"].lookups = bucket{1, c.t}
	s.lim.mu.Unlock()
	if _, ok := u.resolve(uotAddr{name: "later.test", port: 53}); !ok {
		t.Fatal("a refused token remembered by the stream")
	}
	// Full of failures; 30 s on, they make room.
	clear(u.names)
	for i := range uotNames {
		u.names[fmt.Sprintf("f%d.test", i)] = uotResolved{until: c.t.Add(uotNameMiss)}
	}
	c.t = c.t.Add(uotNameMiss)
	s.lim.mu.Lock()
	s.lim.users["u5"].lookups = bucket{lookupBurst, c.t}
	s.lim.mu.Unlock()
	u.resolve(uotAddr{name: "slow.test", port: 53})
	if r, ok := u.names["slow.test"]; !ok || r.ip.IsValid() || len(u.names) != 1 {
		t.Fatalf("expired names not pruned: %d kept", len(u.names))
	}
}
