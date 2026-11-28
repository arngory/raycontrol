package naive

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/memlimit"
	"github.com/arngory/raycontrol/internal/site"
)

func memLimits(maxBytes, high, total int64) memlimit.Limits {
	return memlimit.Limits{Max: maxBytes, High: high, MemTotal: total}
}

// fakeSignals are a scanner's readings that a test sets.
type fakeSignals struct {
	mu  sync.Mutex
	sig memSignals
}

func (f *fakeSignals) set(fn func(*memSignals)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(&f.sig)
}

func (f *fakeSignals) read() memSignals {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sig
}

// testTunnels is a registry of budget b whose readings the test sets.
func testTunnels(b int64) (*tunnels, *fakeSignals) {
	f := &fakeSignals{}
	return &tunnels{budget: b, read: f.read}, f
}

// cancelled records the tunnels a test's registry reset.
type cancelled struct {
	mu   sync.Mutex
	errs map[string]error
}

func (c *cancelled) fn(name string) context.CancelCauseFunc {
	return func(err error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.errs == nil {
			c.errs = map[string]error{}
		}
		if c.errs[name] == nil {
			c.errs[name] = err
		}
	}
}

func (c *cancelled) evicted(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return errors.Is(c.errs[name], errEvicted)
}

func (c *cancelled) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.errs)
}

// blocked makes a running tunnel's write to the destination (up) or to the
// client blocked for d.
func blocked(t *tunnels, tm *tunnelMem, up bool, d time.Duration) {
	t.run(tm, nil)
	since := mono() - int64(d)
	if up {
		tm.up.Store(since)
	} else {
		tm.down.Store(since)
	}
}

// The charge: F a tunnel, its window part while pending or blocked on its
// upload, all of a connection's within the connection's window; a
// download blocked, an idle tunnel and an evicted one charge no window.
func TestTunnelCharge(t *testing.T) {
	tn, _ := testTunnels(1 << 30)
	var c cancelled
	conn := new(int)
	var list []*tunnelMem
	for i := range 6 {
		list = append(list, tn.admit("u5", conn, false, c.fn(string(rune('a'+i)))))
	}
	if got, want := tn.stats().Charge, int64(6*tunnelCost+site.ConnWindow); got != want {
		t.Fatalf("6 pending on one connection: %d, want %d", got, want)
	}
	// On no connection known, each its own.
	alone := tn.admit("u5", nil, false, c.fn("alone"))
	if got, want := tn.stats().Charge, int64(7*tunnelCost+site.ConnWindow+site.StreamWindow); got != want {
		t.Fatalf("one more on its own: %d, want %d", got, want)
	}
	tn.leave(alone)
	for _, tm := range list {
		tn.run(tm, nil)
	}
	if got := tn.stats().Charge; got != 6*tunnelCost {
		t.Fatalf("running, idle: %d", got)
	}
	blocked(tn, list[0], true, time.Millisecond)
	blocked(tn, list[1], false, time.Hour)
	tn.snapshot()
	if got, want := tn.stats().Charge, int64(6*tunnelCost+site.StreamWindow); got != want {
		t.Fatalf("one upload blocked, one download: %d, want %d", got, want)
	}
	tn.evict([]*tunnelMem{list[0]})
	if got := tn.stats().Charge; got != 5*tunnelCost || !c.evicted("a") || tn.stats().Evicted != 1 {
		t.Fatalf("evicted: %d, %+v", got, tn.stats())
	}
	// Not counted again, and its end takes nothing more off.
	tn.snapshot()
	tn.evict([]*tunnelMem{list[0]})
	tn.leave(list[0])
	if got := tn.stats().Charge; got != 5*tunnelCost || tn.stats().Evicted != 1 {
		t.Fatalf("after its end: %d, %+v", got, tn.stats())
	}
	for _, tm := range list[1:] {
		tn.leave(tm)
	}
	if st := tn.stats(); st.Charge != 0 || len(tn.users) != 0 || len(tn.groups) != 0 || len(tn.all) != 0 {
		t.Fatalf("all ended: %+v, %d users, %d groups", st, len(tn.users), len(tn.groups))
	}
}

// HTTP/3: h3Packets times the stream's window within the connection's,
// all of a connection's within h3Packets times its window, the window as
// it grew by the hook; the hook stops at the budget and under pressure,
// and forgets a connection once it ends.
func TestTunnelChargeH3(t *testing.T) {
	tn, _ := testTunnels(64 << 20)
	conn := new(int)
	a := tn.admit("u5", conn, true, func(error) {})
	b := tn.admit("u5", conn, true, func(error) {})
	if got, want := tn.stats().Charge, int64(2*tunnelCost+h3Packets*h3ConnWindow); got != want {
		t.Fatalf("2 pending: %d, want %d", got, want)
	}
	done := make(chan struct{})
	if !tn.grow(conn, done, 1<<20) {
		t.Fatal("under the budget: the window did not grow")
	}
	tn.snapshot()
	win := int64(h3ConnWindow + 1<<20)
	if got, want := tn.stats().Charge, 2*tunnelCost+min(2*h3Packets*min(h3StreamWindowMax, win), h3Packets*win); got != want {
		t.Fatalf("grown: %d, want %d", got, want)
	}
	tn.pressure.Store(true)
	if tn.grow(conn, done, 1<<20) {
		t.Fatal("under pressure: the window grew")
	}
	tn.pressure.Store(false)
	tn.budget = tn.stats().Charge
	if tn.grow(conn, done, 1<<20) {
		t.Fatal("at the budget: the window grew")
	}
	close(done)
	eventually(t, "the ended connection's grant stays", func() bool {
		tn.mu.Lock()
		defer tn.mu.Unlock()
		return len(tn.grants) == 0
	})
	// Running and idle, their uploads not ended: the connection's window
	// (out of order data, unseen); ended, F alone.
	tn.run(a, nil)
	tn.run(b, nil)
	if got, want := tn.stats().Charge, 2*tunnelCost+int64(h3ConnWindow); got != want {
		t.Fatalf("idle: %d, want %d", got, want)
	}
	tn.uploaded(a)
	if got, want := tn.stats().Charge, 2*tunnelCost+int64(h3ConnWindow); got != want {
		t.Fatalf("one upload ended: %d, want %d", got, want)
	}
	tn.uploaded(b)
	if got := tn.stats().Charge; got != 2*tunnelCost {
		t.Fatalf("both ended: %d", got)
	}
	tn.leave(a)
	tn.leave(b)
}

// The budget's first mark: at B a user at its fair share is refused, one
// under it is not; under B nobody is.
func TestTunnelAdmit(t *testing.T) {
	const b = 16 << 20 // shares of 2 MiB
	tn, _ := testTunnels(b)
	n := 0
	for ; tn.admit("u5", nil, false, func(error) {}) != nil; n++ {
		if n > 100 {
			t.Fatal("never refused")
		}
	}
	// Admitted while the charge was under B: the last one took it over.
	if per := int64(tunnelCost + site.StreamWindow); int64(n) != (b+per-1)/per || tn.stats().Refused != 1 {
		t.Fatalf("%d admitted, %+v", n, tn.stats())
	}
	if tn.admit("u6", nil, false, func(error) {}) == nil {
		t.Fatal("a user under its share refused")
	}
	// Under pressure the same, below B too.
	tn2, _ := testTunnels(b)
	tn2.pressure.Store(true)
	tn2.admit("u5", nil, false, func(error) {})
	if tn2.admit("u5", nil, false, func(error) {}) != nil || tn2.admit("u6", nil, false, func(error) {}) == nil {
		t.Fatal("under pressure: the user at its share admitted, or one under it refused")
	}
}

// The budget of a unit as rayctl apply sizes it: half the less of
// memory.high and 15/16 of memory.max; without a limit an eighth of the
// host, 32 MiB to 2 GiB. The arithmetic for 512 MiB, 1 GiB and 4 GiB
// hosts is in TestMemoryBudgetUnits (naive_test, with internal/deploy).
func TestMemoryBudgetNoLimit(t *testing.T) {
	for _, c := range []struct{ total, want int64 }{
		{0, 32 << 20}, {128 << 20, 32 << 20}, {1 << 30, 128 << 20}, {64 << 30, 2 << 30},
	} {
		if got := MemoryBudget(memLimits(0, 0, c.total)); got != c.want {
			t.Errorf("host %d MiB: %d MiB, want %d MiB", c.total>>20, got>>20, c.want>>20)
		}
	}
	if got := MemoryBudget(memLimits(100<<20, 0, 64<<30)); got != 100<<20/16*15/2 {
		t.Errorf("a small limit on a large host: %d", got)
	}
}

// The marks of pressure: each trigger on at its first mark, off at its
// second; a round only while a signal is over its first mark, and as many
// resets as bring it under; after a round of the heap's the next waits for
// a GC cycle, the charge's does not.
func TestPressureMarks(t *testing.T) {
	const b = 64 << 20
	tn, f := testTunnels(b)
	var c cancelled
	for i := range 10 {
		tm := tn.admit("u5", nil, false, c.fn(string(rune('a'+i))))
		blocked(tn, tm, true, time.Duration(10-i)*time.Hour) // a the longest
	}
	const g = 1000 << 20
	f.set(func(s *memSignals) { s.limit, s.live, s.cycles = g, g*85/100-1, 1 })
	tn.tick()
	if tn.pressure.Load() || c.count() != 0 {
		t.Fatalf("under the mark: pressure %v, %d reset", tn.pressure.Load(), c.count())
	}
	// Over by a byte: one reset, the longest blocked.
	f.set(func(s *memSignals) { s.live = g * 85 / 100 })
	f.set(func(s *memSignals) { s.live++ })
	tn.tick()
	if !tn.pressure.Load() || c.count() != 1 || !c.evicted("a") {
		t.Fatalf("over the mark: pressure %v, %v", tn.pressure.Load(), c.errs)
	}
	// No GC since: none; one cycle from the look after the round is not
	// enough either (it may have marked before the tunnels went).
	tn.tick()
	f.set(func(s *memSignals) { s.cycles++ })
	tn.tick()
	if c.count() != 1 {
		t.Fatalf("before two GCs: %v", c.errs)
	}
	// Two, and the heap still over: one more.
	f.set(func(s *memSignals) { s.cycles++ })
	tn.tick()
	if c.count() != 2 || !c.evicted("b") {
		t.Fatalf("after two GCs: %v", c.errs)
	}
	// Between the marks: pressure stays, nothing reset.
	f.set(func(s *memSignals) { s.live, s.cycles = g*80/100, s.cycles+1 })
	tn.tick()
	if !tn.pressure.Load() || c.count() != 2 {
		t.Fatalf("between the marks: pressure %v, %v", tn.pressure.Load(), c.errs)
	}
	f.set(func(s *memSignals) { s.live = g * 70 / 100 })
	tn.tick()
	if tn.pressure.Load() {
		t.Fatal("at the second mark: still on")
	}
	// The goal against the throttle: the goal within the Go limit.
	f.set(func(s *memSignals) { s.goal, s.throttle, s.stacks, s.sock = 2*g, g+g/2, g/20, g/20 })
	tn.tick() // min(goal, limit) + stacks + sock = 1.1 g, of 1.5 g: 73 %
	if tn.pressure.Load() {
		t.Fatal("the goal under its mark")
	}
	f.set(func(s *memSignals) { s.throttle, s.cycles = g*11/10*100/95, s.cycles+2 })
	tn.tick() // 95 %, over by a little
	if !tn.pressure.Load() || c.count() != 3 {
		t.Fatalf("the goal over its mark: pressure %v, %v", tn.pressure.Load(), c.errs)
	}
	f.set(func(s *memSignals) { s.throttle = g * 130 / 100 })
	tn.tick() // 84.6 %
	if tn.pressure.Load() {
		t.Fatal("the goal at its second mark: still on")
	}
	// The charge: 7 blocked uploads left, 7 × (F + 2 MiB) ≈ 14.7 MiB.
	tn.budget = 9 << 20 // on at 13.5 MiB
	tn.tick()
	if !tn.pressure.Load() || c.count() != 4 {
		t.Fatalf("the charge over its mark: pressure %v, %v", tn.pressure.Load(), c.errs)
	}
	// Its rounds do not wait for a GC: 6 left, 12.6 MiB, under; a lower
	// budget brings it over again at once.
	tn.budget = 8 << 20 // on at 12 MiB, off at 10 MiB
	tn.tick()
	if c.count() != 5 {
		t.Fatalf("the charge's next round: %v", c.errs)
	}
	tn.tick() // 5 × 2.1 MiB = 10.5 MiB: between the marks
	if !tn.pressure.Load() || c.count() != 5 {
		t.Fatalf("the charge between its marks: pressure %v, %v", tn.pressure.Load(), c.errs)
	}
	tn.budget = 9 << 20 // off at 11.25 MiB
	tn.tick()
	if tn.pressure.Load() {
		t.Fatal("the charge under its second mark: still on")
	}
}

// The order of a round: the users over their share, the largest first;
// of each, its streams blocked past the grace, the longest first, then its
// pending and those blocked less only at twice its share; once no stream
// past the grace is left with a user over its share, theirs; the users
// under their share last, only their streams past the grace. An idle
// stream never.
func TestEvictOrder(t *testing.T) {
	const b = 64 << 20 // shares of 8 MiB
	tn, _ := testTunnels(b)
	names := map[*tunnelMem]string{}
	add := func(user, name string, state func(*tunnelMem)) {
		tm := tn.admit(user, nil, false, func(error) {})
		names[tm] = name
		state(tm)
	}
	stuck := func(d time.Duration) func(*tunnelMem) {
		return func(tm *tunnelMem) { blocked(tn, tm, true, d) }
	}
	stuckDown := func(d time.Duration) func(*tunnelMem) {
		return func(tm *tunnelMem) { blocked(tn, tm, false, d) }
	}
	pending := func(*tunnelMem) {}
	idle := func(tm *tunnelMem) { tn.run(tm, nil) }
	// u2: 8 streams, some 16.8 MiB, twice its share.
	add("u2", "u2-stuck", stuck(time.Minute))
	add("u2", "u2-slow", stuck(time.Millisecond))
	for range 6 {
		add("u2", "u2-pending", pending)
	}
	// u1: 5 streams, some 8.5 MiB: over its share, under twice.
	add("u1", "u1-stuck-short", stuck(time.Minute))
	add("u1", "u1-stuck-long", stuck(time.Hour))
	add("u1", "u1-slow", stuck(time.Millisecond))
	add("u1", "u1-pending", pending)
	add("u1", "u1-idle", idle)
	// u3: under its share.
	add("u3", "u3-stuck-down", stuckDown(time.Minute))
	add("u3", "u3-slow", stuck(time.Millisecond))
	add("u3", "u3-idle", idle)
	var got []string
	p, _ := pick(tn.snapshot(), 1<<40)
	for _, tm := range p {
		got = append(got, names[tm])
	}
	want := []string{"u2-stuck", "u2-pending", "u2-pending", "u2-pending", "u2-pending", "u2-pending", "u2-pending", "u2-slow",
		"u1-stuck-long", "u1-stuck-short", "u1-pending", "u1-slow", "u3-stuck-down"}
	if len(got) != len(want) {
		t.Fatalf("picked %v\nwant %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("picked %v\nwant %v", got, want)
		}
	}
	// What is wanted bounds the round: u2's stuck one frees F and its
	// window part.
	if p, freed := pick(tn.snapshot(), tunnelCost+site.StreamWindow); len(p) != 1 || names[p[0]] != "u2-stuck" || freed != tunnelCost+site.StreamWindow {
		t.Fatalf("one wanted: %d picked", len(p))
	}
	// At most evictRound a round.
	tn2, _ := testTunnels(b)
	for range evictRound + 10 {
		blocked(tn2, tn2.admit("u9", nil, false, func(error) {}), true, time.Hour)
	}
	if p, _ := pick(tn2.snapshot(), 1<<40); len(p) != evictRound {
		t.Fatalf("%d in a round", len(p))
	}
}

// memServer is a naive server for u5 (pw) and u6 (other) whose
// destinations are the test's (memDial), over the test's transport, its
// tunnels' budget b and readings the test's; connect opens a tunnel.
func memServer(t *testing.T, b int64, o ...clientOpts) (*Server, *fakeSignals, func(password, target string) (*http.Response, *io.PipeWriter)) {
	t.Helper()
	h, f, try := memServerTry(t, b, o...)
	return h, f, func(password, target string) (*http.Response, *io.PipeWriter) {
		t.Helper()
		resp, pw, err := try(password, target)
		if err != nil {
			t.Fatalf("CONNECT %s: %v", target, err)
		}
		return resp, pw
	}
}

// memServerTry is memServer whose connect gives the request's error.
func memServerTry(t *testing.T, b int64, o ...clientOpts) (*Server, *fakeSignals, func(password, target string) (*http.Response, *io.PipeWriter, error)) {
	t.Helper()
	users := filepath.Join(t.TempDir(), "users.json")
	writeUsersNamed(t, users, map[string]string{"pw": "u5-ab12", "other": "u6"})
	answer, _ := site.Responder(site.Answer404, "")
	f := &fakeSignals{}
	h := &Server{Users: &Users{Path: users}, Answer: answer, Dial: memDial(t), Log: slog.New(slog.DiscardHandler)}
	h.mem.budget, h.mem.read = b, f.read
	url, tr := serveOver(t, h, o...)
	return h, f, func(password, target string) (*http.Response, *io.PipeWriter, error) {
		pr, pw := io.Pipe()
		t.Cleanup(func() { pw.Close() })
		req, _ := http.NewRequest(http.MethodConnect, url, pr)
		req.Host = target
		req.Header.Set("Padding", paddingHeader())
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("niko:"+password)))
		resp, err := roundTrip(t, tr, req)
		if err == nil {
			t.Cleanup(func() { resp.Body.Close() })
		}
		return resp, pw, err
	}
}

// The destinations of memServer, by port: 1 takes nothing and sends
// nothing; 2 takes 8 KiB every 10 ms; 3 sends without an end; 4 echoes;
// 5 answers its dial only once memRelease is closed.
var memRelease = struct {
	sync.Mutex
	ch chan struct{}
}{ch: make(chan struct{})}

func memDial(t *testing.T) func(ctx context.Context, network, addr string) (net.Conn, error) {
	var held sync.Mutex
	var ends []net.Conn
	t.Cleanup(func() {
		held.Lock()
		defer held.Unlock()
		for _, c := range ends {
			c.Close()
		}
	})
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(addr)
		if port == "5" {
			memRelease.Lock()
			ch := memRelease.ch
			memRelease.Unlock()
			select {
			case <-ch:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		c, s := net.Pipe()
		held.Lock()
		ends = append(ends, s)
		held.Unlock()
		switch port {
		case "2":
			go func() {
				buf := make([]byte, 8<<10)
				for {
					if _, err := io.ReadFull(s, buf); err != nil {
						return
					}
					time.Sleep(10 * time.Millisecond)
				}
			}()
		case "3":
			go func() {
				buf := make([]byte, 32<<10)
				for {
					if _, err := s.Write(buf); err != nil {
						return
					}
				}
			}()
		case "4":
			go func() { _, _ = io.Copy(s, s) }()
		}
		return c, nil
	}
}

// pump writes to the tunnel's upload until it fails.
func pump(w io.Writer) {
	go func() {
		ps := ClientStream(nil, w)
		buf := make([]byte, 16<<10)
		for {
			if _, err := ps.Write(buf); err != nil {
				return
			}
		}
	}()
}

// ended reads the tunnel's download until it ends, within d: its error,
// or errStillOpen.
func ended(body io.Reader, d time.Duration) error {
	got := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, body)
		got <- err
	}()
	select {
	case err := <-got:
		return err
	case <-time.After(d):
		return errStillOpen
	}
}

var errStillOpen = errors.New("still open")

// Over HTTP/2 and HTTP/3: tunnels waiting for their dial are charged their
// window part, a connection's within its window; once the copy runs, an
// idle tunnel is charged F alone.
func TestTunnelChargePendingOver(t *testing.T) {
	overProtos(t, func(t *testing.T) {
		memRelease.Lock()
		memRelease.ch = make(chan struct{})
		release := memRelease.ch
		memRelease.Unlock()
		h, _, connect := memServer(t, 1<<30)
		var resps []*http.Response
		for range 6 {
			resp, _ := connect("pw", "192.0.2.1:5")
			resps = append(resps, resp)
		}
		w, limit := int64(site.StreamWindow), int64(site.ConnWindow)
		if protoOf(t) == "h3" {
			w, limit = h3Packets*h3ConnWindow, h3Packets*h3ConnWindow
		}
		want := 6*tunnelCost + min(6*w, limit)
		eventually(t, "pending tunnels not charged", func() bool { return h.MemoryStats().Charge == want })
		close(release)
		idle := int64(6 * tunnelCost)
		if protoOf(t) == "h3" {
			idle += h3ConnWindow // the connection's, while uploads are open
		}
		eventually(t, "running tunnels charged more than F", func() bool { return h.MemoryStats().Charge == idle })
		for _, r := range resps {
			r.Body.Close()
		}
		eventually(t, "ended tunnels still charged", func() bool { return h.MemoryStats().Charge == 0 })
	})
}

// At the budget a user at its share gets 429 before any 200, counted as
// the limits' "memory", with naive's padding; another user under its
// share connects. A burst of 600 CONNECTs does not slip past the check:
// each is weighed after the one before is charged.
func TestTunnelBudgetOver(t *testing.T) {
	overProtos(t, func(t *testing.T) {
		memRelease.Lock()
		memRelease.ch = make(chan struct{})
		release := memRelease.ch
		memRelease.Unlock()
		defer close(release)
		const b = 16 << 20
		h, _, connect := memServer(t, b)
		var wg sync.WaitGroup
		var admitted, refused atomic.Int32
		for range 600 {
			wg.Go(func() {
				resp, _ := connect("pw", "192.0.2.1:5")
				switch resp.StatusCode {
				case http.StatusOK:
					admitted.Add(1)
				case http.StatusTooManyRequests:
					if resp.Header.Get("Padding") == "" {
						t.Error("a 429 without the Padding header")
					}
					refused.Add(1)
				default:
					t.Errorf("CONNECT: %s", resp.Status)
				}
			})
		}
		wg.Wait()
		st := h.MemoryStats()
		w := int64(site.StreamWindow)
		if protoOf(t) == "h3" {
			w = h3Packets * h3ConnWindow
		}
		// Each admitted while the charge was under B: past it by one
		// tunnel's at most.
		if admitted.Load() == 0 || refused.Load() == 0 || st.Charge >= b+tunnelCost+w || st.Refused != int64(refused.Load()) {
			t.Fatalf("%d admitted, %d refused, %+v", admitted.Load(), refused.Load(), st)
		}
		if got := h.Refused()["u5"][refusedMemory]; got != int64(refused.Load()) {
			t.Fatalf("counted %d", got)
		}
		if resp, _ := connect("other", "192.0.2.1:4"); resp.StatusCode != http.StatusOK {
			t.Fatalf("a user under its share: %s", resp.Status)
		}
	})
}

// Under pressure, an idle tunnel is charged F (and over HTTP/3 the
// connection's window) and never reset, however long it has been idle:
// over HTTP/2 whatever the user's share, over HTTP/3 within it.
func TestIdleTunnelsStay(t *testing.T) {
	g := evictGrace
	evictGrace = 50 * time.Millisecond
	t.Cleanup(func() { evictGrace = g })
	overProtos(t, func(t *testing.T) {
		h, f, connect := memServer(t, 1<<30)
		var tunnels []*paddedStream
		for range 3 {
			resp, pw := connect("pw", "192.0.2.1:4")
			tunnels = append(tunnels, &paddedStream{r: resp.Body, w: pw})
		}
		want := int64(3 * tunnelCost)
		if protoOf(t) == "h3" {
			want += h3ConnWindow // the connection's, while uploads are open
		} else {
			// HTTP/2's idle tunnels stay over the user's share too, the
			// charge past 1.5 B.
			h.mem.mu.Lock()
			h.mem.budget = 64 << 10
			h.mem.mu.Unlock()
		}
		eventually(t, "not F each", func() bool { return h.MemoryStats().Charge == want })
		time.Sleep(3 * evictGrace)
		f.set(func(s *memSignals) { s.limit, s.live, s.cycles = 100<<20, 100<<20, 1 })
		for range 3 {
			h.tunnels().tick()
			f.set(func(s *memSignals) { s.cycles++ })
		}
		if st := h.MemoryStats(); !st.Pressure || st.Evicted != 0 {
			t.Fatalf("idle tunnels under pressure: %+v", st)
		}
		for _, p := range tunnels {
			if _, err := p.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4)
			if _, err := io.ReadFull(p, buf); err != nil || string(buf) != "ping" {
				t.Fatalf("an idle tunnel after the rounds: %q %v", buf, err)
			}
		}
	})
}

// Under pressure the stream that has been blocked longest of the user over
// its share is reset (the client sees a reset, not an end); a slow stream
// of the same user that moves stays, and so does the paused download of a
// user under its share while the one over it has streams to give. A
// reader that takes a trickle is reset at the next round. Without
// pressure a stream blocked far past the grace stays.
func TestPressureEvicts(t *testing.T) {
	g := evictGrace
	evictGrace = 300 * time.Millisecond
	t.Cleanup(func() { evictGrace = g })
	overProtos(t, func(t *testing.T) {
		h, f, connect := memServer(t, 16<<20, clientOpts{window: 64 << 10, connWindow: 1 << 20})
		// u5: an upload its destination does not take, one it takes
		// slowly, a download read a byte at a time.
		stuck, stuckUp := connect("pw", "192.0.2.1:1")
		pump(stuckUp)
		slow, slowUp := connect("pw", "192.0.2.1:2")
		pump(slowUp)
		trickle, _ := connect("pw", "192.0.2.1:3")
		trickleEnd := make(chan error, 1)
		var drain atomic.Bool // what the client holds read at once: the reset comes after it
		go func() {
			b := make([]byte, 1)
			for {
				if _, err := trickle.Body.Read(b); err != nil {
					trickleEnd <- err
					return
				}
				if !drain.Load() {
					time.Sleep(20 * time.Millisecond)
				}
			}
		}()
		// u6: a download it does not read.
		paused, _ := connect("other", "192.0.2.1:3")
		time.Sleep(4 * evictGrace)
		// No pressure: all stay, however long blocked.
		h.tunnels().tick()
		if st := h.MemoryStats(); st.Pressure || st.Evicted != 0 {
			t.Fatalf("without pressure: %+v", st)
		}
		const gl = 1000 << 20
		f.set(func(s *memSignals) { s.limit, s.live, s.cycles = gl, gl*85/100+1, 1 })
		h.tunnels().tick()
		if st := h.MemoryStats(); !st.Pressure || st.Evicted != 1 {
			t.Fatalf("under pressure: %+v", st)
		}
		if err := ended(stuck.Body, 5*time.Second); !serverReset(t, err) {
			t.Fatalf("the stuck upload: %v, want a reset", err)
		}
		// No GC since: no round.
		h.tunnels().tick()
		if st := h.MemoryStats(); st.Evicted != 1 {
			t.Fatalf("before a GC: %+v", st)
		}
		f.set(func(s *memSignals) { s.cycles += 2 })
		h.tunnels().tick()
		if st := h.MemoryStats(); st.Evicted != 2 {
			t.Fatalf("after a GC: %+v", st)
		}
		drain.Store(true)
		select {
		case err := <-trickleEnd:
			if !serverReset(t, err) {
				t.Fatalf("the trickle: %v, want a reset", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the trickle reader was not reset")
		}
		if err := ended(paused.Body, 100*time.Millisecond); !errors.Is(err, errStillOpen) {
			t.Fatalf("the paused download of a user under its share: %v", err)
		}
		if err := ended(slow.Body, 100*time.Millisecond); !errors.Is(err, errStillOpen) {
			t.Fatalf("the slow upload: %v", err)
		}
		if got := h.MemoryStats().Evicted; got != 2 {
			t.Fatalf("%d reset", got)
		}
	})
}

// An HTTP/3 stream whose upload's read waits (what came out of order may
// sit in QUIC's packets) is reset under pressure only from a user over its
// share, after its pending and blocked streams and every other user's over
// its share, and before a user under its share; an idle HTTP/2 stream
// never, an idle HTTP/3 one of a user within its share never.
func TestEvictReading(t *testing.T) {
	const b = 64 << 20 // shares of 8 MiB
	tn, _ := testTunnels(b)
	names := map[*tunnelMem]string{}
	add := func(user, name string, conn any, h3 bool, state func(*tunnelMem)) {
		tm := tn.admit(user, conn, h3, func(error) {})
		names[tm] = name
		state(tm)
	}
	reading := func(d time.Duration) func(*tunnelMem) {
		return func(tm *tunnelMem) { tn.run(tm, nil); tm.rd.Store(mono() - int64(d)) }
	}
	c1, c2 := new(int), new(int)
	// u1, over HTTP/3: 8.25 MiB of the connection's window and 4 F.
	add("u1", "u1-stuck", c1, true, func(tm *tunnelMem) { blocked(tn, tm, true, time.Minute) })
	add("u1", "u1-read-short", c1, true, reading(time.Minute))
	add("u1", "u1-read-long", c1, true, reading(time.Hour))
	add("u1", "u1-read-young", c1, true, reading(time.Millisecond))
	// u4, over HTTP/2: 4 stuck uploads and an idle one reading.
	for range 4 {
		add("u4", "u4-stuck", nil, false, func(tm *tunnelMem) { blocked(tn, tm, true, time.Minute) })
	}
	add("u4", "u4-idle", nil, false, reading(time.Hour))
	// u2 within its share, over HTTP/3; u3 within it, over HTTP/2.
	add("u2", "u2-read", c2, true, reading(time.Hour))
	add("u2", "u2-stuck-down", c2, true, func(tm *tunnelMem) { blocked(tn, tm, false, time.Minute) })
	add("u3", "u3-idle", nil, false, reading(time.Hour))
	p, _ := pick(tn.snapshot(), 1<<40)
	var got []string
	for _, tm := range p {
		got = append(got, names[tm])
	}
	want := []string{"u1-stuck", "u4-stuck", "u4-stuck", "u4-stuck", "u4-stuck", "u1-read-long", "u1-read-short", "u2-stuck-down"}
	if len(got) != len(want) {
		t.Fatalf("picked %v\nwant %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("picked %v\nwant %v", got, want)
		}
	}
}

// The wait for a GC after a round of the heap's, both ways: two cycles
// from the look after the round, unless the sockets alone grew past what
// the round reckoned to free.
func TestPressureGCWait(t *testing.T) {
	tn, f := testTunnels(1 << 30)
	var c cancelled
	for i := range 10 {
		blocked(tn, tn.admit("u5", nil, false, c.fn(string(rune('a'+i)))), true, time.Duration(10-i)*time.Hour)
	}
	const g = 1000 << 20
	f.set(func(s *memSignals) { s.limit, s.live, s.cycles = g, g*85/100+1, 1 })
	tn.tick()
	if c.count() != 1 {
		t.Fatalf("the round: %v", c.errs)
	}
	tn.tick() // the look after it: no GC, the sockets as they were
	if c.count() != 1 {
		t.Fatalf("before a GC: %v", c.errs)
	}
	// The sockets grew by more than the round freed: a round now.
	f.set(func(s *memSignals) { s.sock = 4 << 20 })
	tn.tick()
	if c.count() != 2 {
		t.Fatalf("the sockets past it: %v", c.errs)
	}
	// What both rounds freed covers it: none, until two cycles from the
	// look after.
	tn.tick()
	f.set(func(s *memSignals) { s.cycles++ })
	tn.tick()
	if c.count() != 2 {
		t.Fatalf("one cycle: %v", c.errs)
	}
	f.set(func(s *memSignals) { s.cycles++ })
	tn.tick()
	if c.count() != 4 { // fresh: 4 MiB over, two of 2.1 MiB
		t.Fatalf("two cycles: %v", c.errs)
	}
}

// A pending stream reset under pressure, while it waits for its dial or
// for its attempt's token, is a reset at the client, never an answer; one
// whose wait ends as its user is revoked too. Neither counts as a refusal
// of the rate.
func TestEvictPending(t *testing.T) {
	overProtos(t, func(t *testing.T) {
		memRelease.Lock()
		memRelease.ch = make(chan struct{})
		release := memRelease.ch
		memRelease.Unlock()
		defer close(release)
		h, _, try := memServerTry(t, 1<<30)
		evictAll := func() {
			h.mem.mu.Lock()
			var list []*tunnelMem
			for tm := range h.mem.all {
				list = append(list, tm)
			}
			h.mem.mu.Unlock()
			h.mem.evict(list)
		}
		// During the dial: after the 200 (no niko-ack).
		resp, _, err := try("pw", "192.0.2.1:5")
		if err != nil {
			t.Fatal(err)
		}
		eventually(t, "not registered", func() bool { return h.MemoryStats().Charge > 0 })
		evictAll()
		if err := ended(resp.Body, 5*time.Second); !serverReset(t, err) {
			t.Fatalf("during the dial: %v, want a reset", err)
		}
		// During the token's wait: before any answer.
		waiting := make(chan struct{}, 1)
		h.lim.mu.Lock()
		h.lim.userLocked("u5", time.Now()).attempts = bucket{0.5, time.Now()}
		h.lim.sleep = func(ctx context.Context, _ time.Duration) error {
			waiting <- struct{}{}
			<-ctx.Done()
			return ctx.Err()
		}
		h.lim.mu.Unlock()
		for _, end := range []string{"evicted", "revoked"} {
			got := make(chan error, 1)
			go func() {
				_, _, err := try("pw", "192.0.2.1:4")
				got <- err
			}()
			<-waiting
			if end == "evicted" {
				evictAll()
			} else {
				writeUsersNamed(t, h.Users.Path, map[string]string{"other": "u6", "more": "u7-ab"})
				h.Users.mu.Lock()
				h.Users.reload()
				h.Users.mu.Unlock()
			}
			if err := <-got; !serverReset(t, err) {
				t.Fatalf("%s while it waits for its token: %v, want a reset", end, err)
			}
		}
		if st, rate := h.MemoryStats(), h.Refused()["u5"][refusedRate]; st.Evicted != 2 || rate != 0 {
			t.Fatalf("%+v, %d refusals of the rate", st, rate)
		}
	})
}
