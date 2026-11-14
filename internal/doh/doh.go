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
	"time"
)

// DefaultUpstreams are asked in order.
var DefaultUpstreams = []string{"https://1.1.1.1/dns-query", "https://9.9.9.9/dns-query"}

// Handler serves the DoH endpoint.
type Handler struct {
	// Tokens returns the tokens accepted now.
	Tokens    func(ctx context.Context) (map[string]bool, error)
	Upstreams []string     // DefaultUpstreams when empty
	HTTP      *http.Client // with a timeout when nil
	// CacheFor bounds how long Tokens is trusted (30 s when zero).
	CacheFor time.Duration
	// Answer serves whatever is not a query with a token: the site's
	// answer, as naive gives it (an empty 404 when nil).
	Answer http.Handler
	// Log takes one line when Tokens fails and one when it answers again;
	// never a query, a token or an address.
	Log *slog.Logger

	mu     sync.Mutex
	tokens map[string]bool
	until  time.Time
	// failing: Tokens failed at the last ask; every request is refused.
	failing bool
	retired retired
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

// retryFailed is how soon Tokens is asked again after it failed.
const retryFailed = time.Second

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

// check is the verdict on a request's token ("" for a request with none):
// accepted while Tokens has it; refused while Tokens fails, for everyone,
// and for a token retired lately; else a stranger. The tokens are asked
// for at most every CacheFor, and at once after Forget.
func (h *Handler) check(ctx context.Context, token string) verdict {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if now.After(h.until) {
		h.load(ctx, now)
	}
	switch {
	case h.failing:
		return refused
	case token != "" && h.tokens[token]:
		return accepted
	case token != "" && h.retired.has(token, now.UnixNano()):
		return refused
	}
	return stranger
}

// load asks Tokens anew; what it no longer has is retired. A failure
// refuses every request until Tokens answers, asked again every
// retryFailed: a device whose token is good must not wait out a silent
// site's hold while the store cannot be read, and one whose token is gone
// must get no answer.
func (h *Handler) load(ctx context.Context, now time.Time) {
	// Not the request's cancellation: a client gone must not fail them all.
	t, err := h.Tokens(context.WithoutCancel(ctx))
	if err != nil {
		if !h.failing && h.Log != nil {
			h.Log.Error("doh: the tokens cannot be read; every query is refused until they can", "err", err)
		}
		h.failing, h.until = true, now.Add(retryFailed)
		return
	}
	if h.failing && h.Log != nil {
		h.Log.Info("doh: the tokens are read again")
	}
	h.failing = false
	at := now.UnixNano()
	h.retired.prune(at)
	for tok := range h.tokens {
		if !t[tok] {
			h.retired.add(tok, now.Add(RetiredFor).UnixNano())
		}
	}
	every := h.CacheFor
	if every == 0 {
		every = 30 * time.Second
	}
	h.tokens, h.until = t, now.Add(every)
}

// Forget makes the next request ask Tokens again: rayd calls it on every
// change of the node's state, so a token gone with it (a revoked device's,
// R4-37) is refused at once, not up to CacheFor later. The tokens it had
// stay, to tell which went (retired).
func (h *Handler) Forget() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.until = time.Time{}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.URL.Path, "/dns-query/")
	if !ok || strings.Contains(token, "/") {
		token = ""
	}
	switch h.check(r.Context(), token) {
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
		b, err := io.ReadAll(io.LimitReader(r.Body, maxMessage+1))
		if err != nil {
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
	_, _ = w.Write(resp)
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
		r, err := hc.Do(req)
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
