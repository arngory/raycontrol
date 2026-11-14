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
	h := &Handler{Upstreams: []string{down.URL, upstream.URL},
		Tokens: func(context.Context) (map[string]bool, error) { return map[string]bool{"tok": true}, nil }}
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
	resp, b := get("/dns-query/tok?dns=" + base64.RawURLEncoding.EncodeToString(query))
	if resp.StatusCode != 200 || !bytes.Equal(b, answer) || resp.Header.Get("Content-Type") != "application/dns-message" ||
		resp.Header.Get("Cache-Control") != "max-age=60" {
		t.Fatalf("GET: %s %v", resp.Status, resp.Header)
	}
	r, _ := http.Post(srv.URL+"/dns-query/tok", "application/dns-message", bytes.NewReader(query))
	b, _ = io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || !bytes.Equal(b, answer) {
		t.Fatalf("POST: %s", r.Status)
	}
	for _, path := range []string{"/dns-query/other?dns=AAAA", "/dns-query/", "/", "/dns-query/tok/x"} {
		if resp, b := get(path); resp.StatusCode != 404 || len(b) != 0 {
			t.Errorf("%s: %s %q", path, resp.Status, b)
		}
	}
	if resp, _ := get("/dns-query/tok?dns=" + base64.RawURLEncoding.EncodeToString([]byte("short"))); resp.StatusCode != 400 {
		t.Errorf("short message: %s", resp.Status)
	}
	r, _ = http.Post(srv.URL+"/dns-query/tok", "text/plain", strings.NewReader("x"))
	r.Body.Close()
	if r.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("wrong type: %s", r.Status)
	}
}

// A token taken away is refused once the handler forgets, not a cache
// later (a revoked device's, R4-37).
func TestForget(t *testing.T) {
	tokens := map[string]bool{"old": true}
	h := &Handler{CacheFor: time.Hour, Tokens: func(context.Context) (map[string]bool, error) { return tokens, nil }}
	ctx := context.Background()
	if h.check(ctx, "old") != accepted {
		t.Fatal("the token is refused")
	}
	tokens = map[string]bool{"new": true}
	if h.check(ctx, "old") != accepted {
		t.Fatal("cached: still taken until forgotten")
	}
	h.Forget()
	if h.check(ctx, "old") == accepted || h.check(ctx, "new") != accepted {
		t.Fatal("after Forget the old token passes or the new one does not")
	}
}

// The answers as a client sees them: a token retired lately gets an empty
// 404 at once, never the site's answer (which may hold it a minute) and
// never an answer to its query; a stranger, and a token retired longer
// ago than RetiredFor, the site's answer; one accepted again is answered.
func TestRetired(t *testing.T) {
	tokens := map[string]bool{"a": true, "b": true}
	h := &Handler{CacheFor: time.Hour, Tokens: func(context.Context) (map[string]bool, error) { return tokens, nil },
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
	if status("/dns-query/a") != http.StatusMethodNotAllowed || status("/dns-query/x") != http.StatusTeapot {
		t.Fatal("before")
	}
	tokens = map[string]bool{"b": true}
	h.Forget()
	for path, want := range map[string]int{"/dns-query/a": 404, "/dns-query/b": 405, "/dns-query/x": 418, "/": 418,
		"/dns-query/a/x": 418, "/dns-query/": 418} {
		if got := status(path); got != want {
			t.Errorf("%s: %d, want %d", path, got, want)
		}
	}
	// Past RetiredFor: a stranger again.
	h.mu.Lock()
	past := time.Now().UnixNano()
	for i, e := range h.retired.ring {
		if e.until != 0 {
			h.retired.ring[i].until, h.retired.until[e.key] = past, past
		}
	}
	h.mu.Unlock()
	if got := status("/dns-query/a"); got != http.StatusTeapot {
		t.Errorf("retired long ago: %d", got)
	}
	// Back (a user enabled again): accepted.
	tokens = map[string]bool{"a": true, "b": true}
	h.Forget()
	if got := status("/dns-query/a"); got != http.StatusMethodNotAllowed {
		t.Errorf("accepted again: %d", got)
	}
	// What is kept is no token.
	h.mu.Lock()
	defer h.mu.Unlock()
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

// While Tokens fails every request gets the quick 404, the good token's
// and the stranger's alike: nobody waits out a silent site's hold, and
// nothing is answered. One line says so, one more when it is over.
func TestTokensFail(t *testing.T) {
	var fail bool
	h := &Handler{CacheFor: time.Hour, Tokens: func(context.Context) (map[string]bool, error) {
		if fail {
			return nil, errors.New("database is locked")
		}
		return map[string]bool{"a": true}, nil
	}, Answer: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })}
	var log bytes.Buffer
	h.Log = slog.New(slog.NewTextHandler(&log, nil))
	ctx := context.Background()
	if h.check(ctx, "a") != accepted {
		t.Fatal("before")
	}
	fail = true
	h.Forget()
	for range 3 {
		for _, tok := range []string{"a", "x", ""} {
			if v := h.check(ctx, tok); v != refused {
				t.Fatalf("%q while failing: %v", tok, v)
			}
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/anything", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("a stranger while failing: %d", w.Code)
	}
	if c := strings.Count(log.String(), "level=ERROR"); c != 1 {
		t.Fatalf("%d error lines:\n%s", c, log.String())
	}
	fail = false
	h.Forget()
	if h.check(ctx, "a") != accepted || h.check(ctx, "x") != stranger {
		t.Fatal("after")
	}
	if !strings.Contains(log.String(), "read again") || strings.Contains(log.String(), `"a"`) {
		t.Fatalf("log:\n%s", log.String())
	}
	// A request whose client is gone does not fail the others.
	h.Forget()
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	h.Tokens = func(ctx context.Context) (map[string]bool, error) { return map[string]bool{"a": true}, ctx.Err() }
	if h.check(cctx, "a") != accepted {
		t.Fatal("a cancelled request failed the tokens")
	}
}

// The verdict on a query costs a map lookup and no allocation, with
// 30,000 tokens (10,000 devices, current, next and previous).
func BenchmarkCheck(b *testing.B) {
	tokens := map[string]bool{}
	for i := range 30000 {
		tokens[fmt.Sprintf("%08x-0000-4000-8000-000000000000", i)] = true
	}
	h := &Handler{Tokens: func(context.Context) (map[string]bool, error) { return tokens, nil }}
	ctx := context.Background()
	h.check(ctx, "")
	h.mu.Lock()
	for i := range MaxRetired {
		h.retired.add(fmt.Sprintf("%08x-0000-4000-8000-00000000000f", i), time.Now().Add(time.Hour).UnixNano())
	}
	h.mu.Unlock()
	for _, c := range []struct{ name, tok string }{{"valid", "00001234-0000-4000-8000-000000000000"},
		{"retired", "00001234-0000-4000-8000-00000000000f"}, {"stranger", "ffffffff-0000-4000-8000-000000000000"}} {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				h.check(ctx, c.tok)
			}
		})
	}
}
