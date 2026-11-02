// Package doh answers DNS over HTTPS for the node's clients (docs/08-
// decisions.md, R3-2): https://<name>/dns-query/<token>, RFC 8484 GET and
// POST, the token being the user's credential for the service (with
// rotation). Queries go on to upstream DoH resolvers; nothing is logged.
// Anything else gets an empty 404, like the site.
package doh

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
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

	mu     sync.Mutex
	tokens map[string]bool
	until  time.Time
}

const maxMessage = 65535

func notFound(w http.ResponseWriter) {
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusNotFound)
}

func (h *Handler) accepted(ctx context.Context, token string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if time.Now().After(h.until) {
		t, err := h.Tokens(ctx)
		if err != nil {
			return false
		}
		every := h.CacheFor
		if every == 0 {
			every = 30 * time.Second
		}
		h.tokens, h.until = t, time.Now().Add(every)
	}
	return token != "" && h.tokens[token]
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.URL.Path, "/dns-query/")
	if !ok || strings.Contains(token, "/") || !h.accepted(r.Context(), token) {
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
