package naive

import (
	"context"
	"errors"
	"fmt"
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
