package doh

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHandler(t *testing.T) {
	query := bytes.Repeat([]byte{1}, 20)
	answer := bytes.Repeat([]byte{2}, 30)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" || !bytes.Equal(b, query) {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		w.Header().Set("Cache-Control", "max-age=60")
		w.Write(answer)
	}))
	defer upstream.Close()
	down := httptest.NewServer(http.NotFoundHandler())
	down.Close() // the first upstream is gone: the next one answers
	good := tok(1)
	h := &Handler{Upstreams: []string{down.URL, upstream.URL},
		Tokens: func(context.Context) (map[string]bool, error) { return map[string]bool{good: true, "tok": true}, nil }}
	srv := httptest.NewServer(h)
	defer srv.Close()

	get := func(path string) (*http.Response, []byte) {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	resp, b := get("/dns-query/" + good + "?dns=" + base64.RawURLEncoding.EncodeToString(query))
	if resp.StatusCode != 200 || !bytes.Equal(b, answer) || resp.Header.Get("Content-Type") != "application/dns-message" ||
		resp.Header.Get("Cache-Control") != "max-age=60" {
		t.Fatalf("GET: %s %v", resp.Status, resp.Header)
	}
	r, _ := http.Post(srv.URL+"/dns-query/"+good, "application/dns-message", bytes.NewReader(query))
	b, _ = io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || !bytes.Equal(b, answer) {
		t.Fatalf("POST: %s", r.Status)
	}
	// "tok" is in the tokens, but of no token's shape: never one.
	for _, path := range []string{"/dns-query/other?dns=AAAA", "/dns-query/", "/", "/dns-query/" + good + "/x", "/dns-query/tok"} {
		if resp, b := get(path); resp.StatusCode != 404 || len(b) != 0 {
			t.Errorf("%s: %s %q", path, resp.Status, b)
		}
	}
	if resp, _ := get("/dns-query/" + good + "?dns=" + base64.RawURLEncoding.EncodeToString([]byte("short"))); resp.StatusCode != 400 {
		t.Errorf("short message: %s", resp.Status)
	}
	r, _ = http.Post(srv.URL+"/dns-query/"+good, "text/plain", strings.NewReader("x"))
	r.Body.Close()
	if r.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("wrong type: %s", r.Status)
	}
}

// tok is a token of the node's shape (a UUID's), numbered.
func tok(n int) string { return fmt.Sprintf("%08x-0000-4000-8000-000000000000", n) }

// source is a Tokens that tests change as they go, safe to race with the
// handler's background loads.
type source struct {
	mu     sync.Mutex
	tokens map[string]bool
	err    error
	calls  atomic.Int32
	gate   chan struct{} // when set, each call waits for a receive on it, or its context
}

func newSource(tokens ...string) *source {
	s := &source{}
	s.set(tokens...)
	return s
}

func (s *source) set(tokens ...string) {
	m := map[string]bool{}
	for _, t := range tokens {
		m[t] = true
	}
	s.mu.Lock()
	s.tokens, s.err = m, nil
	s.mu.Unlock()
}

func (s *source) fail(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

func (s *source) hold(gate chan struct{}) {
	s.mu.Lock()
	s.gate = gate
	s.mu.Unlock()
}

func (s *source) Tokens(ctx context.Context) (map[string]bool, error) {
	s.calls.Add(1)
	s.mu.Lock()
	gate := s.gate
	s.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens, s.err
}

// A token taken away is refused once the handler forgets, not a cache
// later (a revoked device's, R4-37).
func TestForget(t *testing.T) {
	src := newSource(tok(1))
	h := &Handler{CacheFor: time.Hour, Tokens: src.Tokens}
	ctx := context.Background()
	if h.check(ctx, tok(1), true) != accepted {
		t.Fatal("the token is refused")
	}
	src.set(tok(2))
	if h.check(ctx, tok(1), true) != accepted {
		t.Fatal("cached: still taken until forgotten")
	}
	h.Forget()
	if h.check(ctx, tok(1), true) == accepted || h.check(ctx, tok(2), true) != accepted {
		t.Fatal("after Forget the old token passes or the new one does not")
	}
}

// After Forget a request with a token waits for the load Forget began, and
// is never answered from the tokens before it, however slow the load; a
// request with none does not wait. Past ReloadTimeout the load counts as
// failed and the token gets the quick refusal; no second call of Tokens
// starts while the first is out.
func TestForgetWaits(t *testing.T) {
	src := newSource(tok(1))
	h := &Handler{CacheFor: time.Hour, ReloadTimeout: 300 * time.Millisecond, Tokens: src.Tokens}
	ctx := context.Background()
	if h.check(ctx, tok(1), true) != accepted {
		t.Fatal("before")
	}
	gate := make(chan struct{})
	src.hold(gate)
	src.set(tok(2)) // tok(1)'s device revoked
	h.Forget()
	verdict := make(chan verdict)
	go func() { verdict <- h.check(ctx, tok(1), true) }()
	if h.check(ctx, "", false) != stranger {
		t.Fatal("a request without a token")
	}
	select {
	case v := <-verdict:
		t.Fatalf("answered before the load: %v", v)
	case <-time.After(50 * time.Millisecond):
	}
	gate <- struct{}{}
	if v := <-verdict; v != refused {
		t.Fatalf("the revoked token after the load: %v", v)
	}
	if h.check(ctx, tok(2), true) != accepted {
		t.Fatal("the new token")
	}

	// A load that hangs: closed, at its timeout.
	calls := src.calls.Load()
	h.Forget()
	start := time.Now()
	if v := h.check(ctx, tok(2), true); v != refused {
		t.Fatalf("a hung load: %v", v)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("waited %v", d)
	}
	for range 5 {
		h.Forget()
		h.check(ctx, tok(2), true)
	}
	if n := src.calls.Load() - calls; n > 2 {
		t.Fatalf("%d calls of Tokens with one hung", n)
	}
	src.hold(nil)
	close(gate)
}

// Past CacheFor with no Forget, the requests go on with the tokens they
// have, not waiting for the load that runs.
func TestStaleDoesNotWait(t *testing.T) {
	src := newSource(tok(1))
	h := &Handler{CacheFor: time.Millisecond, Tokens: src.Tokens}
	ctx := context.Background()
	if h.check(ctx, tok(1), true) != accepted {
		t.Fatal("before")
	}
	gate := make(chan struct{})
	src.hold(gate)
	time.Sleep(5 * time.Millisecond)
	start := time.Now()
	for range 100 {
		if h.check(ctx, tok(1), true) != accepted {
			t.Fatal("refused while a load runs")
		}
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("waited %v", d)
	}
	for deadline := time.Now().Add(time.Second); src.calls.Load() < 2 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	if n := src.calls.Load(); n != 2 {
		t.Fatalf("%d calls of Tokens, want 2: one load at a time", n)
	}
	src.hold(nil)
	close(gate)
}

// A burst of Forgets during a load makes one more load, not one each.
func TestForgetCoalesces(t *testing.T) {
	src := newSource(tok(1))
	h := &Handler{CacheFor: time.Hour, Tokens: src.Tokens}
	ctx := context.Background()
	h.check(ctx, tok(1), true)
	gate := make(chan struct{})
	src.hold(gate)
	h.Forget()
	for range 100 {
		h.Forget()
	}
	src.hold(nil)
	close(gate)
	if h.check(ctx, tok(1), true) != accepted {
		t.Fatal("after")
	}
	if n := src.calls.Load(); n < 2 || n > 3 { // the burst may come before the load reads the count
		t.Fatalf("%d calls of Tokens, want 2 or 3", n)
	}
}

// After Forget, while the load is out, only a request whose segment after
// /dns-query/ has a token's shape waits for it: any other is answered at
// once, as before the change, so that its time tells nothing of one.
func TestUnshapedDoesNotWait(t *testing.T) {
	src := newSource(tok(1))
	h := &Handler{CacheFor: time.Hour, Tokens: src.Tokens,
		Answer: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })}
	status := func(path string) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPut, path, nil))
		return w.Code
	}
	if status("/dns-query/"+tok(1)) != http.StatusMethodNotAllowed {
		t.Fatal("before")
	}
	gate := make(chan struct{})
	src.hold(gate)
	h.Forget()
	start := time.Now()
	for _, path := range []string{"/dns-query/abc", "/dns-query/" + tok(1) + "x", "/dns-query/", "/dns-query/" + tok(1) + "/x", "/", "/x/" + tok(1)} {
		if got := status(path); got != http.StatusTeapot {
			t.Errorf("%s: %d", path, got)
		}
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("waited %v", d)
	}
	shaped := make(chan int)
	go func() { shaped <- status("/dns-query/" + tok(9)) }()
	select {
	case c := <-shaped:
		t.Fatalf("a token-shaped request answered before the load: %d", c)
	case <-time.After(50 * time.Millisecond):
	}
	src.hold(nil)
	close(gate)
	if c := <-shaped; c != http.StatusTeapot {
		t.Fatalf("a stranger's token after the load: %d", c)
	}
}

// Forgets with no request (a burst of changes, no DoH traffic) load the
// tokens at once for the first, then once each ForgetDelay after the last
// load at most, not back to back; an isolated one later loads at once. A
// request with a token never waits for the delay: it starts the load
// itself, and gets no token of before the Forget.
func TestForgetIdle(t *testing.T) {
	src := newSource(tok(1))
	h := &Handler{CacheFor: time.Hour, Tokens: src.Tokens, delay: 50 * time.Millisecond}
	ctx := context.Background()
	if h.check(ctx, tok(1), true) != accepted {
		t.Fatal("before")
	}
	time.Sleep(60 * time.Millisecond)
	calls := src.calls.Load()
	h.Forget()
	for deadline := time.Now().Add(time.Second); src.calls.Load() == calls; {
		if time.Now().After(deadline) {
			t.Fatal("no load after a Forget")
		}
		time.Sleep(time.Millisecond)
	}
	calls = src.calls.Load()
	for t0 := time.Now(); time.Since(t0) < 500*time.Millisecond; {
		h.Forget()
		time.Sleep(time.Millisecond)
	}
	time.Sleep(60 * time.Millisecond)
	if n := src.calls.Load() - calls; n < 2 || n > 12 {
		t.Fatalf("%d loads in 500 ms of Forgets, want one each 50 ms at most", n)
	}

	h.mu.Lock()
	h.delay = time.Hour // only a request starts the load now
	h.mu.Unlock()
	if h.check(ctx, tok(1), true) != accepted {
		t.Fatal("caught up")
	}
	src.set(tok(2))
	h.Forget()
	start := time.Now()
	if h.check(ctx, tok(1), true) != refused || h.check(ctx, tok(2), true) != accepted {
		t.Fatal("a token of before the Forget, or not the new one")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("the request waited %v", d)
	}
}

// A load that ends behind the Forgets starts the next at once when a
// request waits for it, whatever the delay.
func TestForgetWaiterStartsAtOnce(t *testing.T) {
	src := newSource(tok(1))
	h := &Handler{CacheFor: time.Hour, Tokens: src.Tokens, delay: time.Hour}
	ctx := context.Background()
	if h.check(ctx, tok(1), true) != accepted {
		t.Fatal("before")
	}
	gate := make(chan struct{})
	src.hold(gate)
	h.Forget()
	verdict := make(chan verdict)
	go func() { verdict <- h.check(ctx, tok(1), true) }() // starts the load, held
	for deadline := time.Now().Add(time.Second); src.calls.Load() < 2; {
		if time.Now().After(deadline) {
			t.Fatal("no load")
		}
		time.Sleep(time.Millisecond)
	}
	src.set(tok(2))
	h.Forget() // during it: the waiter needs one more
	go func() { verdict <- h.check(ctx, tok(2), true) }()
	time.Sleep(20 * time.Millisecond)
	src.hold(nil)
	close(gate)
	start := time.Now()
	for range 2 {
		select {
		case <-verdict:
		case <-time.After(2 * time.Second):
			t.Fatal("the next load waited for the delay")
		}
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("%v", d)
	}
	if h.check(ctx, tok(2), true) != accepted || h.check(ctx, tok(1), true) == accepted {
		t.Fatal("after")
	}
}

// The answers as a client sees them: a token retired lately gets an empty
// 404 at once, never the site's answer (which may hold it a minute) and
// never an answer to its query; a stranger, and a token retired longer
// ago than RetiredFor, the site's answer; one accepted again is answered.
func TestRetired(t *testing.T) {
	a, b, x := tok(0xa), tok(0xb), tok(0xc)
	src := newSource(a, b)
	h := &Handler{CacheFor: time.Hour, Tokens: src.Tokens,
		Answer: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })}
	status := func(path string) int {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPut, path, nil))
		if w.Code == http.StatusNotFound && (w.Body.Len() != 0 || w.Header().Get("Content-Length") != "0") {
			t.Fatalf("%s: a 404 with %q", path, w.Body)
		}
		return w.Code
	}
	// PUT: an accepted token gets 405 without an upstream to ask.
	if status("/dns-query/"+a) != http.StatusMethodNotAllowed || status("/dns-query/"+x) != http.StatusTeapot {
		t.Fatal("before")
	}
	src.set(b)
	h.Forget()
	for path, want := range map[string]int{"/dns-query/" + a: 404, "/dns-query/" + b: 405, "/dns-query/" + x: 418, "/": 418,
		"/dns-query/" + a + "/x": 418, "/dns-query/": 418} {
		if got := status(path); got != want {
			t.Errorf("%s: %d, want %d", path, got, want)
		}
	}
	// Past RetiredFor: a stranger again.
	h.rmu.Lock()
	past := time.Now().UnixNano()
	for i, e := range h.retired.ring {
		if e.until != 0 {
			h.retired.ring[i].until, h.retired.until[e.key] = past, past
		}
	}
	h.rmu.Unlock()
	if got := status("/dns-query/" + a); got != http.StatusTeapot {
		t.Errorf("retired long ago: %d", got)
	}
	// Back (a user enabled again): accepted.
	src.set(a, b)
	h.Forget()
	if got := status("/dns-query/" + a); got != http.StatusMethodNotAllowed {
		t.Errorf("accepted again: %d", got)
	}
	// What is kept is no token.
	h.rmu.Lock()
	defer h.rmu.Unlock()
	h.retired.prune(time.Now().UnixNano())
	if len(h.retired.until) != 0 {
		t.Errorf("pruned: %d left", len(h.retired.until))
	}
}

// retired holds MaxRetired tokens at most, the latest.
func TestRetiredBound(t *testing.T) {
	var r retired
	until := time.Now().Add(time.Hour).UnixNano()
	for i := range MaxRetired + 10 {
		r.add(strconv.Itoa(i), until)
	}
	now := time.Now().UnixNano()
	if len(r.until) != MaxRetired || r.has("0", now) || r.has("9", now) || !r.has("10", now) || !r.has(strconv.Itoa(MaxRetired+9), now) {
		t.Fatalf("%d kept", len(r.until))
	}
	// The same token twice is one entry, and the later time.
	r.add("10", until+1)
	r.add("11", until)
	if !r.has("10", now) {
		t.Fatal("a token retired twice was dropped")
	}
	if r.has(strings.Repeat("x", 65), now) || r.has("", now) {
		t.Fatal("no key for those")
	}
}

// While Tokens fails a request whose path has a token-shaped segment gets
// the quick 404, the good token's and a stranger's alike: nobody waits out
// a silent site's hold, and nothing is answered. Any other request gets the
// site's answer, as when the tokens are read. One line says so, one more
// when it is over, and the retry is spaced.
func TestTokensFail(t *testing.T) {
	a := tok(0xa)
	src := newSource(a)
	h := &Handler{CacheFor: time.Hour, Tokens: src.Tokens, retry: 50 * time.Millisecond,
		Answer: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })}
	var log bytes.Buffer
	var logMu sync.Mutex
	h.Log = slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return log.Write(p)
	}), nil))
	logged := func() string {
		logMu.Lock()
		defer logMu.Unlock()
		return log.String()
	}
	ctx := context.Background()
	if h.check(ctx, a, true) != accepted {
		t.Fatal("before")
	}
	src.fail(errors.New("database is locked"))
	h.Forget()
	status := func(path string) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPut, path, nil))
		return w.Code
	}
	status("/dns-query/" + a) // waits for the load the Forget began
	for range 3 {
		for path, want := range map[string]int{"/dns-query/" + a: 404, "/dns-query/" + tok(7): 404, "/x/" + tok(7) + "/y": 404,
			"/": 418, "/anything": 418, "/dns-query/abc": 418} {
			if got := status(path); got != want {
				t.Fatalf("%s while failing: %d, want %d", path, got, want)
			}
		}
	}
	calls := src.calls.Load()
	for range 20 {
		h.Forget()
		status("/dns-query/" + a)
	}
	if n := src.calls.Load() - calls; n > 2 {
		t.Fatalf("%d calls of Tokens in a moment while failing", n)
	}
	if c := strings.Count(logged(), "level=ERROR"); c != 1 {
		t.Fatalf("%d error lines:\n%s", c, logged())
	}
	src.set(a)
	time.Sleep(60 * time.Millisecond) // the retry
	deadline := time.Now().Add(2 * time.Second)
	for h.check(ctx, a, true) != accepted {
		if time.Now().After(deadline) {
			t.Fatal("after")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if h.check(ctx, tok(9), true) != stranger {
		t.Fatal("a stranger after")
	}
	if !strings.Contains(logged(), "read again") || strings.Contains(logged(), a) {
		t.Fatalf("log:\n%s", logged())
	}
	// A request whose client is gone does not fail the others.
	h.Forget()
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	h.check(cctx, a, true)
	if h.check(ctx, a, true) != accepted {
		t.Fatal("a cancelled request failed the tokens")
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestTokenShaped(t *testing.T) {
	for s, want := range map[string]bool{tok(1): true, strings.ToUpper(tok(1)): true, "": false, "abc": false,
		strings.Replace(tok(1), "-", "x", 1): false, tok(1) + "0": false, strings.Replace(tok(1), "0", "g", 1): false} {
		if tokenShaped(s) != want {
			t.Errorf("%q: %v", s, !want)
		}
	}
}

// The verdict on a query costs a map lookup and no allocation, with
// 30,000 tokens (10,000 devices, current, next and previous).
func BenchmarkCheck(b *testing.B) {
	tokens := map[string]bool{}
	for i := range 30000 {
		tokens[tok(i)] = true
	}
	h := &Handler{Tokens: func(context.Context) (map[string]bool, error) { return tokens, nil }}
	ctx := context.Background()
	h.check(ctx, tok(0), true)
	h.rmu.Lock()
	for i := range MaxRetired {
		h.retired.add(fmt.Sprintf("%08x-0000-4000-8000-00000000000f", i), time.Now().Add(time.Hour).UnixNano())
	}
	h.rmu.Unlock()
	for _, c := range []struct{ name, tok string }{{"valid", tok(0x1234)},
		{"retired", "00001234-0000-4000-8000-00000000000f"}, {"stranger", "ffffffff-0000-4000-8000-000000000000"}} {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				h.check(ctx, c.tok, true)
			}
		})
	}
}
