package naive

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// fakeClock is a clock that moves only when told, and a sleep that moves it.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }
func (c *fakeClock) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.t = c.t.Add(d)
	return nil
}

func fakeLimits() (*limits, *fakeClock) {
	c := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	return &limits{now: c.now, sleep: c.sleep}, c
}

// TCP at once: 1024 a user, the next refused at once; places come back;
// another user is not touched.
func TestLimitsTCPConcurrent(t *testing.T) {
	l, c := fakeLimits()
	var dones []func()
	for i := range tcpPerUser {
		done, kind := l.tcpStart(context.Background(), "u5")
		if kind != "" {
			t.Fatalf("%d: %s", i, kind)
		}
		dones = append(dones, done)
		c.t = c.t.Add(time.Second / tcpRate) // tokens enough
	}
	if _, kind := l.tcpStart(context.Background(), "u5"); kind != refusedTCP {
		t.Fatalf("the 1025th: %q", kind)
	}
	if _, kind := l.tcpStart(context.Background(), "u6"); kind != "" {
		t.Fatalf("another user: %q", kind)
	}
	dones[0]()
	dones[0]() // twice changes nothing
	if done, kind := l.tcpStart(context.Background(), "u5"); kind != "" {
		t.Fatalf("after one ended: %q", kind)
	} else {
		done()
	}
	if got := l.Refused()["u5"][refusedTCP]; got != 1 {
		t.Fatalf("refused tcp: %d", got)
	}
	for _, d := range dones {
		d()
	}
	if l.users["u5"].tcp != 0 {
		t.Fatalf("places left: %d", l.users["u5"].tcp)
	}
}

// Attempts: the burst, then a wait for the next token (0.5 s at most),
// which a client gone ends at once, giving its place back.
func TestLimitsTCPAttempts(t *testing.T) {
	l, c := fakeLimits()
	start := c.t
	for i := range tcpBurst {
		done, kind := l.tcpStart(context.Background(), "u5")
		if kind != "" {
			t.Fatalf("%d of the burst: %s", i, kind)
		}
		done()
	}
	if c.t != start {
		t.Fatal("the burst waited")
	}
	// The next waits for its token: 1/30 s.
	done, kind := l.tcpStart(context.Background(), "u5")
	if kind != "" || c.t.Sub(start) < time.Second/tcpRate-time.Millisecond || c.t.Sub(start) > time.Second/tcpRate+time.Millisecond {
		t.Fatalf("after the burst: %q, waited %v", kind, c.t.Sub(start))
	}
	done()
	// A token further than 0.5 s away: refused without waiting.
	l.users["u5"].attempts = bucket{-20, c.t} // 0.7 s to the next
	before := c.t
	if _, kind := l.tcpStart(context.Background(), "u5"); kind != refusedRate || c.t != before {
		t.Fatalf("0.7 s away: %q, waited %v", kind, c.t.Sub(before))
	}
	// 0.4 s away: waited.
	l.users["u5"].attempts = bucket{-11, c.t}
	if done, kind := l.tcpStart(context.Background(), "u5"); kind != "" || c.t.Sub(before) < 390*time.Millisecond {
		t.Fatalf("0.4 s away: %q, waited %v", kind, c.t.Sub(before))
	} else {
		done()
	}
	// A client gone while it waits: refused, its place back.
	l.users["u5"].attempts = bucket{0, c.t}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, kind := l.tcpStart(ctx, "u5"); kind != refusedRate {
		t.Fatalf("a client gone: %q", kind)
	}
	if l.users["u5"].tcp != 0 {
		t.Fatalf("a client gone kept its place: %d", l.users["u5"].tcp)
	}
	// Another dial attempt (the next address) takes a token now or none.
	l.users["u5"].attempts = bucket{1, c.t}
	if !l.attempt("u5") || l.attempt("u5") {
		t.Fatal("next attempts")
	}
}

// Real waiting: concurrent attempts past the burst wait their tokens, and
// those that would wait more than 0.5 s are refused.
func TestLimitsTCPAttemptsWait(t *testing.T) {
	var l limits
	for range tcpBurst {
		done, _ := l.tcpStart(context.Background(), "u5")
		done()
	}
	type res struct {
		kind string
		took time.Duration
	}
	out := make(chan res, 40)
	for range 40 {
		go func() {
			start := time.Now()
			done, kind := l.tcpStart(context.Background(), "u5")
			if done != nil {
				done()
			}
			out <- res{kind, time.Since(start)}
		}()
	}
	ok, refused := 0, 0
	for range 40 {
		r := <-out
		switch r.kind {
		case "":
			ok++
			if r.took > tcpWait+200*time.Millisecond {
				t.Errorf("admitted after %v", r.took)
			}
		case refusedRate:
			refused++
		}
	}
	// 30 a second: about 15 in half a second.
	if ok < 10 || ok > 20 || refused != 40-ok {
		t.Fatalf("admitted %d, refused %d", ok, refused)
	}
}

// Failed dials: a timeout, ECONNREFUSED and EHOSTUNREACH charge, in debt;
// ENETUNREACH, EPERM and a dial given up do not. In debt new ones are
// refused until it is paid off at 5 a second.
func TestLimitsFailedDials(t *testing.T) {
	for _, c := range []struct {
		err    error
		charge bool
	}{
		{syscall.ECONNREFUSED, true},
		{syscall.EHOSTUNREACH, true},
		{&net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}, true},
		{context.DeadlineExceeded, true},
		{syscall.ENETUNREACH, false},
		{syscall.EPERM, false},
		{&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.EPERM)}, false},
		{context.Canceled, false},
		{errors.New("naive: destination not public"), false},
	} {
		if got := chargeable(c.err); got != c.charge {
			t.Errorf("%v: charged %v", c.err, got)
		}
	}
	l, c := fakeLimits()
	for range failBurst {
		l.failedDial("u5", syscall.ECONNREFUSED)
	}
	l.failedDial("u5", syscall.ENETUNREACH) // not charged
	if done, kind := l.tcpStart(context.Background(), "u5"); kind != "" {
		t.Fatalf("at zero, not in debt: %q", kind)
	} else {
		done()
	}
	l.failedDial("u5", syscall.EHOSTUNREACH) // one in debt
	if _, kind := l.tcpStart(context.Background(), "u5"); kind != refusedFailed {
		t.Fatalf("in debt: %q", kind)
	}
	c.t = c.t.Add(time.Second) // 5 back: out of debt
	if done, kind := l.tcpStart(context.Background(), "u5"); kind != "" {
		t.Fatalf("debt paid: %q", kind)
	} else {
		done()
	}
	// The debt is bounded.
	for range 10 * failDebt {
		l.failedDial("u6", syscall.ECONNREFUSED)
	}
	if v := l.users["u6"].failed.tokens; v != -failDebt {
		t.Fatalf("debt %v", v)
	}
	// Off: nothing charged, nothing refused.
	l.off.Store(true)
	l.failedDial("u7", syscall.ECONNREFUSED)
	if l.users["u7"] != nil {
		t.Fatal("charged while off")
	}
	if done, kind := l.tcpStart(context.Background(), "u6"); kind != "" {
		t.Fatalf("off: %q", kind)
	} else {
		done()
	}
}

// slotWith gives a user a stream with pairs at times relative to now.
func slotWith(t *testing.T, s *Server, user string) (*uotSlot, *uotStream) {
	t.Helper()
	slot, kind := s.lim.uotTake(user, func(error) {})
	if slot == nil {
		t.Fatalf("no slot: %s", kind)
	}
	u := &uotStream{s: s, ctx: context.Background(), slot: slot, names: map[string]uotResolved{}, peers: map[netip.AddrPort]pairTimes{}}
	s.lim.uotRun(slot, u)
	return slot, u
}

func dest(i int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), 443) //nolint:gosec // test
}

// refillDest gives the user new-destination tokens enough.
func refillDest(s *Server, user string) {
	s.lim.mu.Lock()
	defer s.lim.mu.Unlock()
	if u := s.lim.users[user]; u != nil {
		u.peers = bucket{uotPeerBurst, s.lim.clock()}
	}
}

// The journal of pairs: a pair without an answer counts 30 s after the
// last packet sent, one with an answer 120 s after the last packet either
// way; in a live stream and after its end. A long-lived stream whose old
// destinations went quiet takes new ones again.
func TestLimitsPairJournal(t *testing.T) {
	s := &Server{}
	c := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s.lim.now, s.lim.sleep = c.now, c.sleep
	s.lim.ctMax = func() (uint64, error) { return 1 << 20, nil }
	slot, u := slotWith(t, s, "u5")
	for i := range pairsPerUser {
		refillDest(s, "u5")
		if !u.mayReach(dest(i)) {
			t.Fatalf("pair %d refused", i)
		}
	}
	refillDest(s, "u5")
	if u.mayReach(dest(5000)) {
		t.Fatal("pair 1025 admitted")
	}
	if got := s.lim.Refused()["u5"][refusedLive]; got != 1 {
		t.Fatalf("refused live: %d", got)
	}
	// Half of them answered.
	for i := 0; i < pairsPerUser; i += 2 {
		u.heard(dest(i))
	}
	// 31 s on: the unanswered ones are gone, in the live stream too.
	c.t = c.t.Add(31 * time.Second)
	refillDest(s, "u5")
	if !u.mayReach(dest(5000)) {
		t.Fatal("unanswered pairs still held after 30 s")
	}
	s.lim.mu.Lock()
	pairs := s.lim.users["u5"].pairs
	s.lim.mu.Unlock()
	if pairs != pairsPerUser/2+1 {
		t.Fatalf("pairs %d, want %d", pairs, pairsPerUser/2+1)
	}
	// A packet either way keeps an answered pair: one sent at 100 s.
	c.t = c.t.Add(69 * time.Second)
	u.mayReach(dest(0))
	// The stream ends: its pairs live out their time in the journal.
	s.lim.uotPut(slot)
	slot2, v := slotWith(t, s, "u5")
	c.t = c.t.Add(30 * time.Second) // 130 s: the answered ones of 0 s are gone (120 s), 5000 too (unanswered, sent at 31 s), dest(0) not (100 s)
	refillDest(s, "u5")
	if !v.mayReach(dest(7000)) {
		t.Fatal("refused with the old pairs gone")
	}
	s.lim.mu.Lock()
	pairs, journal := s.lim.users["u5"].pairs, len(s.lim.users["u5"].journal)
	s.lim.mu.Unlock()
	if journal != 1 || pairs != 2 {
		t.Fatalf("journal %d, pairs %d; want 1 and 2", journal, pairs)
	}
	c.t = c.t.Add(121 * time.Second)
	s.lim.uotPut(slot2)
	s.lim.mu.Lock()
	s.lim.sweepLocked(c.t.Add(time.Minute))
	left := s.lim.pairs
	s.lim.mu.Unlock()
	if left != 0 {
		t.Fatalf("pairs left in the process: %d", left)
	}
}

// The process's ceiling, a quarter of nf_conntrack_max: at it, a new pair
// is refused only to those above the fair share; the others get theirs.
func TestLimitsCeiling(t *testing.T) {
	s := &Server{}
	c := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s.lim.now, s.lim.sleep = c.now, c.sleep
	max := uint64(400) // a ceiling of 100
	s.lim.ctMax = func() (uint64, error) { return max, nil }
	_, a := slotWith(t, s, "u1")
	_, b := slotWith(t, s, "u2")
	for i := range 90 {
		refillDest(s, "u1")
		if !a.mayReach(dest(i)) {
			t.Fatalf("u1 pair %d", i)
		}
	}
	for i := range 10 {
		refillDest(s, "u2")
		if !b.mayReach(dest(100 + i)) {
			t.Fatalf("u2 pair %d", i)
		}
	}
	// 100 pairs: the ceiling. The share is 50.
	refillDest(s, "u1")
	if a.mayReach(dest(1000)) {
		t.Fatal("u1, above the share, got a pair at the ceiling")
	}
	refillDest(s, "u2")
	if !b.mayReach(dest(1001)) {
		t.Fatal("u2, below the share, was refused at the ceiling")
	}
	// The ceiling follows nf_conntrack_max, read again each minute.
	max = 4000
	c.t = c.t.Add(time.Minute)
	refillDest(s, "u1")
	if !a.mayReach(dest(1002)) {
		t.Fatal("refused under a bigger ceiling")
	}
	// Unreadable: a quarter of 65 536.
	s.lim.ctMax = func() (uint64, error) { return 0, errors.New("no file") }
	c.t = c.t.Add(time.Minute)
	s.lim.mu.Lock()
	got := s.lim.ceilingLocked(c.t)
	s.lim.mu.Unlock()
	if got != defaultCeiling {
		t.Fatalf("ceiling without the file: %d", got)
	}
}

// A new stream past a user's 256 takes the place of the quietest one, silent
// 10 s both ways; with none quiet, or the limits off, it is refused.
func TestLimitsEvictQuiet(t *testing.T) {
	var l limits
	var slots []*uotSlot
	ended := map[*uotSlot]error{}
	for range uotPerUser {
		var s *uotSlot
		s, _ = l.uotTake("u5", func(err error) { ended[s] = err })
		slots = append(slots, s)
	}
	if s, kind := l.uotTake("u5", func(error) {}); s != nil || kind != refusedUDP {
		t.Fatal("none quiet: not refused")
	}
	slots[7].last.Store(mono() - int64(11*time.Second))
	slots[9].last.Store(mono() - int64(30*time.Second)) // the quietest
	s, kind := l.uotTake("u5", func(error) {})
	if s == nil || kind != "" {
		t.Fatalf("a quiet one did not give way: %q", kind)
	}
	if !errors.Is(ended[slots[9]], errEvicted) || ended[slots[7]] != nil {
		t.Fatalf("ended: %v", ended)
	}
	if l.total != uotPerUser || l.users["u5"].streams != uotPerUser {
		t.Fatalf("streams %d", l.total)
	}
	l.uotPut(slots[9]) // it ends later: its place is given already
	if l.total != uotPerUser {
		t.Fatalf("an evicted stream gave its place twice: %d", l.total)
	}
	if got := l.Refused()["u5"]; got[refusedEvicted] != 1 || got[refusedUDP] != 1 {
		t.Fatalf("refused %v", got)
	}
	l.off.Store(true)
	if s, _ := l.uotTake("u5", func(error) {}); s != nil {
		t.Fatal("off: a quiet stream gave way")
	}
}

// The process's cache of names keeps answers and NXDOMAIN or NODATA, never
// a timeout, SERVFAIL or a refusal; a miss pays a lookup token.
func TestNameCache(t *testing.T) {
	asked := map[string]int{}
	answer := map[string]error{
		"nx.test":       &net.DNSError{Err: "no such host", IsNotFound: true},
		"slow.test":     &net.DNSError{Err: "i/o timeout", IsTimeout: true},
		"servfail.test": &net.DNSError{Err: "server misbehaving", IsTemporary: true},
		"guard.test":    &net.OpError{Op: "write", Err: os.NewSyscallError("sendto", syscall.EPERM)},
	}
	s := &Server{Resolve: func(_ context.Context, name string) ([]netip.Addr, error) {
		asked[name]++
		if err := answer[name]; err != nil {
			return nil, err
		}
		if name == "nodata.test" {
			return nil, nil
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.7")}, nil
	}}
	c := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s.lim.now = c.now
	for range 3 {
		for _, n := range []string{"ok.test", "nx.test", "nodata.test", "slow.test", "servfail.test", "guard.test"} {
			_, _ = s.lookupName(context.Background(), "u5", n, false)
		}
	}
	for n, want := range map[string]int{"ok.test": 1, "nx.test": 1, "nodata.test": 1, "slow.test": 3, "servfail.test": 3, "guard.test": 3} {
		if asked[n] != want {
			t.Errorf("%s asked %d times, want %d", n, asked[n], want)
		}
	}
	if _, err := s.lookupName(context.Background(), "u5", "nx.test", false); !errors.Is(err, errNoName) {
		t.Errorf("a cached NXDOMAIN: %v", err)
	}
	// Answers for a minute, misses for 30 s.
	c.t = c.t.Add(31 * time.Second)
	_, _ = s.lookupName(context.Background(), "u5", "nx.test", false)
	_, _ = s.lookupName(context.Background(), "u5", "ok.test", false)
	if asked["nx.test"] != 2 || asked["ok.test"] != 1 {
		t.Errorf("after 31 s: nx %d, ok %d", asked["nx.test"], asked["ok.test"])
	}
	c.t = c.t.Add(30 * time.Second)
	_, _ = s.lookupName(context.Background(), "u5", "ok.test", false)
	if asked["ok.test"] != 2 {
		t.Errorf("after 61 s: ok %d", asked["ok.test"])
	}
	// Misses pay: the burst, then no lookup.
	s.lim.mu.Lock()
	s.lim.users["u6"] = &limUser{lookups: bucket{0, c.t}}
	s.lim.mu.Unlock()
	if _, err := s.lookupName(context.Background(), "u6", "other.test", false); err == nil || asked["other.test"] != 0 {
		t.Errorf("no token: looked up (%v)", err)
	}
	if _, err := s.lookupName(context.Background(), "u6", "ok.test", false); err != nil {
		t.Errorf("a cached name needs no token: %v", err)
	}
	if got := s.lim.Refused()["u6"][refusedLookup]; got != 1 {
		t.Errorf("refused lookups: %d", got)
	}
}

// Users apart; u5-n, u5-p and u5's credentials share u5's limits; only u<id>
// names are reported.
func TestLimitsByBaseName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(path, []byte(`{"`+HashPassword("a")+`":"u5-n","`+HashPassword("b")+`":"u5-p","`+
		HashPassword("c")+`":"u5-3f2a","`+HashPassword("d")+`":"u6"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	nu := &Users{Path: path}
	for pw, want := range map[string]string{"a": "u5", "b": "u5", "c": "u5", "d": "u6"} {
		a, ok := nu.admit(context.Background(), pw)
		if !ok || a.key != want {
			t.Errorf("%s: key %q, want %q", pw, a.key, want)
		}
		a.leave()
	}
	var l limits
	l.refuse("u5", refusedTCP)
	l.refuse("#0011223344556677", refusedTCP)
	l.refuse("u5x", refusedTCP)
	if got := l.Refused(); len(got) != 1 || got["u5"][refusedTCP] != 1 {
		t.Errorf("reported: %v", got)
	}
	s := &Server{}
	nu.Refused = s.Refused
	s.lim.refuse("u6", refusedRate)
	if snap := nu.Snapshot(); snap.Limit["u6"][refusedRate] != 1 {
		t.Errorf("stats snapshot: %v", snap.Limit)
	}
}

// The switch file: "off" turns the limits off, anything else or none on.
func TestWatchConnLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conn-limit")
	s := &Server{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := os.WriteFile(path, []byte("off\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	go s.WatchConnLimit(ctx, path)
	eventually(t, "not off", func() bool { return !s.ConnLimitOn() })
	if err := os.WriteFile(path, []byte("on\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(reloadEvery + time.Second)
	if !s.ConnLimitOn() {
		t.Fatal("not on again")
	}
	_ = os.Remove(path)
	s.SetConnLimit(false)
	time.Sleep(reloadEvery + time.Second)
	if !s.ConnLimitOn() {
		t.Fatal("no file: not on")
	}
}

func ExampleServer_Refused() {
	s := &Server{}
	s.lim.refuse("u5", refusedTCP)
	fmt.Println(s.Refused())
	// Output: map[u5:map[tcp:1]]
}
