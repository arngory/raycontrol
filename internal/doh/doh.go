// Package doh answers DNS over HTTPS for the node's clients (docs/08-
// decisions.md, R3-2): https://<name>/dns-query/<token>, RFC 8484 GET and
// POST, the token being the device's (R4-37), from its user's credential
// for the service (with rotation). Queries go on to upstream DoH
// resolvers; nothing is logged. Anything else gets the site's answer
// (Handler.Answer), as naive does; a token that was accepted a moment ago
// gets an empty 404 at once instead (retired).
package doh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultUpstreams are asked in order.
var DefaultUpstreams = []string{"https://1.1.1.1/dns-query", "https://9.9.9.9/dns-query"}

// Handler serves the DoH endpoint.
//
// Requests read the tokens through an atomic pointer and never wait for
// a load of them, but in one case: after Forget, a request with a token
// (a path segment of a token's shape after /dns-query/: no other can be
// one) is not answered from tokens read before that Forget. It waits for
// a load begun after it (ReloadTimeout at most, twice if one was already
// on its way), then fails closed. Any other request is answered at once.
// One load at a time, in the background. Forgets that come while one runs
// make one more, not one each, and it starts at once only if a request
// waits for it: else ForgetDelay after the last load ended, so that a
// burst of changes with no query costs a load each ForgetDelay at most.
type Handler struct {
	// Tokens returns the tokens accepted now.
	Tokens    func(ctx context.Context) (map[string]bool, error)
	Upstreams []string     // DefaultUpstreams when empty
	HTTP      *http.Client // with a timeout when nil
	// CacheFor bounds how long Tokens is trusted (30 s when zero); past it
	// the requests go on with the tokens they have while a load runs.
	CacheFor time.Duration
	// ReloadTimeout bounds a call of Tokens (5 s when zero): past it the
	// load counts as failed, and no other starts before that call returns.
	ReloadTimeout time.Duration
	// Answer serves whatever is not a query with a token: the site's
	// answer, as naive gives it (an empty 404 when nil).
	Answer http.Handler
	// Log takes one line when Tokens fails and one when it answers again;
	// never a query, a token or an address.
	Log *slog.Logger

	cur  atomic.Pointer[snapshot]
	want atomic.Uint64 // Forgets so far

	mu      sync.Mutex
	running bool          // a load is on its way
	waiting int           // requests in await
	due     bool          // a load is set to start after delay
	lastEnd time.Time     // when the last load ended
	changed chan struct{} // closed and replaced at each new snapshot
	retry   time.Duration // retryFailed when zero
	delay   time.Duration // ForgetDelay when zero

	rmu     sync.Mutex
	retired retired
	last    map[string]bool // the tokens of the last load that worked
}

// snapshot is one load of the tokens.
type snapshot struct {
	tokens map[string]bool
	gen    uint64    // the Forgets before the load began
	until  time.Time // trusted until; for a failure, when to try again
	// failing: Tokens failed; requests with a token-shaped path get the
	// quick refusal, the others the site's answer.
	failing bool
}

const maxMessage = 65535

// RetiredFor is how long a token the handler accepted, and no longer
// does, gets the quick refusal rather than the site's answer; MaxRetired
// bounds how many it remembers (the oldest go first, and get the site's
// answer as strangers do).
const (
	RetiredFor = 10 * time.Minute
	MaxRetired = 8192
)

// retryFailed is how soon Tokens is asked again after it failed;
// defaultReloadTimeout bounds a call of it. ForgetDelay is how long after
// the last load a load for Forgets waits when no request waits for it.
const (
	retryFailed          = time.Second
	defaultReloadTimeout = 5 * time.Second
	ForgetDelay          = 200 * time.Millisecond
)

// retired remembers the tokens the handler stopped accepting, for
// RetiredFor: a device holding one (a rotation's previous token past its
// grace, a revoked device's, the user's shared one past its window) is
// told at once, not held by a silent site's answer for a minute. Only the
// first 16 bytes of each token's SHA-256 are kept, in a ring of
// MaxRetired.
type retired struct {
	until map[[16]byte]int64 // unix nanoseconds
	ring  []retiredEntry
	next  int
}

type retiredEntry struct {
	key   [16]byte
	until int64
}

// tokenKey is what retired keeps of a token. The node's tokens are 36
// characters (a UUID's shape); one past 64 is no key and costs no hash.
// The copy keeps the hash off the heap.
func tokenKey(token string) ([16]byte, bool) {
	var buf [64]byte
	if token == "" || len(token) > len(buf) {
		return [16]byte{}, false
	}
	n := copy(buf[:], token)
	sum := sha256.Sum256(buf[:n])
	return [16]byte(sum[:16]), true
}

func (r *retired) add(token string, until int64) {
	key, ok := tokenKey(token)
	if !ok {
		return
	}
	if r.ring == nil {
		r.ring, r.until = make([]retiredEntry, MaxRetired), map[[16]byte]int64{}
	}
	if old := r.ring[r.next]; old.until != 0 && r.until[old.key] == old.until {
		delete(r.until, old.key)
	}
	r.ring[r.next] = retiredEntry{key, until}
	r.until[key] = until
	r.next = (r.next + 1) % len(r.ring)
}

func (r *retired) has(token string, now int64) bool {
	if len(r.until) == 0 {
		return false
	}
	key, ok := tokenKey(token)
	if !ok {
		return false
	}
	u, ok := r.until[key]
	return ok && now < u
}

// prune drops what is past its time.
func (r *retired) prune(now int64) {
	for i, e := range r.ring {
		if e.until != 0 && e.until <= now {
			if r.until[e.key] == e.until {
				delete(r.until, e.key)
			}
			r.ring[i] = retiredEntry{}
		}
	}
}

// verdict is what the handler makes of a request's token.
type verdict int

const (
	stranger verdict = iota // the site's answer
	accepted                // the query is answered
	refused                 // an empty 404 at once
)

func notFound(w http.ResponseWriter) {
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusNotFound)
}

// check is the verdict on a request's token ("" for a request with none,
// or with none of a token's shape; shaped: its path has a segment of a
// token's shape): accepted while the tokens have it; refused for a token
// retired lately; while Tokens fails, refused if shaped, else a stranger.
// The tokens are loaded at most every CacheFor, and after Forget.
func (h *Handler) check(ctx context.Context, token string, shaped bool) verdict {
	need := h.want.Load()
	s := h.cur.Load()
	now := time.Now()
	switch {
	case s == nil && token == "":
		h.kick(now) // for the next request with a token
		return stranger
	case token != "" && (s == nil || (!s.failing && s.gen < need)):
		// Never loaded, or forgotten since: a token gets none older than
		// the Forget. A request without one needs no tokens, and does not
		// wait (nor tell by its time that the node's state changed).
		if s = h.await(ctx, need); s == nil || s.gen < need {
			return closed(shaped)
		}
	case !now.Before(s.until):
		h.kick(now) // stale: answered from these while the load runs
	}
	switch {
	case s.failing:
		return closed(shaped)
	case token != "" && s.tokens[token]:
		return accepted
	case token != "" && h.isRetired(token, now.UnixNano()):
		return refused
	}
	return stranger
}

// closed is the verdict while the tokens cannot be had: a device whose
// token is good must not wait out a silent site's hold, one whose token is
// gone must get no answer, and a request with no token gets the site's
// answer as ever.
func closed(shaped bool) verdict {
	if shaped {
		return refused
	}
	return stranger
}

func (h *Handler) isRetired(token string, now int64) bool {
	h.rmu.Lock()
	defer h.rmu.Unlock()
	return h.retired.has(token, now)
}

func (h *Handler) reloadTimeout() time.Duration {
	if h.ReloadTimeout > 0 {
		return h.ReloadTimeout
	}
	return defaultReloadTimeout
}

// await waits for a snapshot of a load begun after the need-th Forget,
// starting one if none is on its way, for two ReloadTimeouts at most (one
// begun before may be running) or until the request is gone; it returns
// the snapshot there is then. While it waits, a load that ends behind the
// Forgets starts the next at once.
func (h *Handler) await(ctx context.Context, need uint64) *snapshot {
	timer := time.NewTimer(2 * h.reloadTimeout())
	defer timer.Stop()
	h.mu.Lock()
	h.waiting++
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		h.waiting--
		h.mu.Unlock()
	}()
	for {
		h.mu.Lock()
		if s := h.cur.Load(); s != nil && s.gen >= need {
			h.mu.Unlock()
			return s
		}
		if !h.running {
			h.start()
		}
		ch := h.changedLocked()
		h.mu.Unlock()
		select {
		case <-ch:
		case <-timer.C:
			return h.cur.Load()
		case <-ctx.Done():
			return h.cur.Load()
		}
	}
}

// kick starts a load if none runs and the tokens are never loaded or
// stale; after a failure not before its retry. One for Forgets is
// forgotten's to start.
func (h *Handler) kick(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.running {
		return
	}
	if s := h.cur.Load(); s == nil || !now.Before(s.until) {
		h.start()
	}
}

// forgotten starts the load the Forgets so far need, if they need one: at
// once when a request waits for it or the last load ended ForgetDelay ago,
// else when it is that long ago. None while one runs (its end sees to it),
// none while one is set to start, none while Tokens fails (nothing is
// accepted then, and the retry comes as it would). h.mu is held.
func (h *Handler) forgotten(now time.Time) {
	if h.running || h.due {
		return
	}
	if s := h.cur.Load(); s != nil && (s.failing || s.gen >= h.want.Load()) {
		return
	}
	delay := h.delay
	if delay == 0 {
		delay = ForgetDelay
	}
	wait := h.lastEnd.Add(delay).Sub(now)
	if h.waiting > 0 || wait <= 0 {
		h.start()
		return
	}
	h.due = true
	time.AfterFunc(wait, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.due = false
		h.forgotten(time.Now())
	})
}

func (h *Handler) changedLocked() chan struct{} {
	if h.changed == nil {
		h.changed = make(chan struct{})
	}
	return h.changed
}

// start runs a load in the background; h.mu is held.
func (h *Handler) start() {
	h.running = true
	go h.load()
}

// load asks Tokens anew, with its own deadline (not a request's: a client
// gone must not fail them all), and publishes what it got; what the tokens
// no longer have is retired. A failure, or a call past ReloadTimeout,
// publishes a failing snapshot until the retry. A call past its time is
// waited for before the next one starts: one at a time, even wedged. When
// a Forget came during the load, another follows (forgotten).
func (h *Handler) load() {
	gen := h.want.Load()
	ctx, cancel := context.WithTimeout(context.Background(), h.reloadTimeout())
	defer cancel()
	type result struct {
		tokens map[string]bool
		err    error
	}
	ch := make(chan result, 1)
	go func() {
		t, err := h.Tokens(ctx)
		ch <- result{t, err}
	}()
	select {
	case r := <-ch:
		h.publish(gen, r.tokens, r.err)
	case <-ctx.Done():
		h.publish(gen, nil, fmt.Errorf("no answer in %v", h.reloadTimeout()))
		<-ch
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.running = false
	h.lastEnd = time.Now()
	h.forgotten(h.lastEnd)
}

func (h *Handler) publish(gen uint64, t map[string]bool, err error) {
	now := time.Now()
	prev := h.cur.Load()
	wasFailing := prev != nil && prev.failing
	s := &snapshot{gen: gen}
	if err != nil {
		if !wasFailing && h.Log != nil {
			h.Log.Error("doh: the tokens cannot be read; queries with a token are refused until they can", "err", err)
		}
		retry := h.retry
		if retry == 0 {
			retry = retryFailed
		}
		s.failing, s.until = true, now.Add(retry)
	} else {
		if wasFailing && h.Log != nil {
			h.Log.Info("doh: the tokens are read again")
		}
		at := now.UnixNano()
		h.rmu.Lock()
		h.retired.prune(at)
		for tok := range h.last {
			if !t[tok] {
				h.retired.add(tok, now.Add(RetiredFor).UnixNano())
			}
		}
		h.last = t
		h.rmu.Unlock()
		every := h.CacheFor
		if every == 0 {
			every = 30 * time.Second
		}
		s.tokens, s.until = t, now.Add(every)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cur.Store(s)
	close(h.changedLocked())
	h.changed = make(chan struct{})
}

// Forget makes the tokens be loaded again: rayd calls it on every change
// of the node's state, in the call that made it, so a token gone with it
// (a revoked device's, R4-37) is refused from the next request, not up to
// CacheFor later. Once it returns, no request with a token is answered
// from tokens loaded before it. The load starts at once, or ForgetDelay
// after the last one when changes come faster (forgotten). The tokens it
// had stay, to tell which went (retired). While Tokens fails it does not
// hasten the retry: nothing is accepted then anyway.
func (h *Handler) Forget() {
	h.want.Add(1)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.forgotten(time.Now())
}

// tokenShaped reports whether a path segment has a token's shape: 36
// characters, hex digits and four dashes as a UUID's.
func tokenShaped(seg string) bool {
	if len(seg) != 36 {
		return false
	}
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case '0' <= c && c <= '9', 'a' <= c && c <= 'f', 'A' <= c && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// shapedPath reports whether a segment of path has a token's shape.
func shapedPath(path string) bool {
	for seg := range strings.SplitSeq(path, "/") {
		if tokenShaped(seg) {
			return true
		}
	}
	return false
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.URL.Path, "/dns-query/")
	if !ok || !tokenShaped(token) { // the node's tokens are all of that shape
		token = ""
	}
	switch h.check(r.Context(), token, shapedPath(r.URL.Path)) {
	case refused:
		// An empty 404, as a 404 site answers: at once, a status the
		// client reads as a refusal over h2 and h3 alike.
		notFound(w)
		return
	case stranger:
		if h.Answer != nil {
			h.Answer.ServeHTTP(w, r)
			return
		}
		notFound(w)
		return
	}
	var msg []byte
	switch r.Method {
	case http.MethodGet:
		b, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		if err != nil {
			http.Error(w, "bad dns parameter", http.StatusBadRequest)
			return
		}
		msg = b
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
			return
		}
		// A body cut short is no message, whatever came of it: one shorter
		// than its Content-Length, which HTTP/2 tells as an error at the
		// stream's end and HTTP/3 (quic-go) as its end, or broken off. It
		// gets the 400 of a bad message, not the empty 200 of a handler
		// that wrote nothing.
		b, err := io.ReadAll(io.LimitReader(r.Body, maxMessage+1))
		if err != nil || int64(len(b)) < r.ContentLength {
			http.Error(w, "bad dns message", http.StatusBadRequest)
			return
		}
		msg = b
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if len(msg) < 12 || len(msg) > maxMessage {
		http.Error(w, "bad dns message", http.StatusBadRequest)
		return
	}
	resp, cache, err := h.forward(r.Context(), msg)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	if cache != "" {
		w.Header().Set("Cache-Control", cache)
	}
	_, _ = w.Write(resp) //nolint:gosec // G705: a DNS message as application/dns-message, not a page
}

// forward asks the upstreams in turn.
func (h *Handler) forward(ctx context.Context, msg []byte) (resp []byte, cache string, err error) {
	hc := h.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	ups := h.Upstreams
	if len(ups) == 0 {
		ups = DefaultUpstreams
	}
	var errs []error
	for _, u := range ups {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(msg))
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		r, err := hc.Do(req) //nolint:gosec // G704: the node's own upstreams; only the body is the client's
		if err != nil {
			errs = append(errs, err)
			continue
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, maxMessage+1))
		_ = r.Body.Close()
		if err != nil || r.StatusCode != http.StatusOK || len(b) < 12 || len(b) > maxMessage {
			errs = append(errs, fmt.Errorf("%s: %s", u, r.Status))
			continue
		}
		return b, r.Header.Get("Cache-Control"), nil
	}
	return nil, "", errors.Join(errs...)
}
