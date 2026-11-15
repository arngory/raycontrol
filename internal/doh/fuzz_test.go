package doh

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// roundTripFunc is an upstream in process.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// countingReader keeps what the handler reads of a request's body.
type countingReader struct {
	r    io.Reader
	n    int
	read []byte
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	c.read = append(c.read, p[:n]...)
	return n, err
}

// FuzzServeHTTP: whatever request reaches the DoH endpoint (from anyone, on
// the node's public front), a query goes upstream only on the path of a
// token the node accepts, never while its tokens cannot be read; what goes
// is the query the request carries, 12 to 65535 bytes, and of a POST body
// no more than that is read. Anything else gets the site's answer or an
// empty 404, never the upstream's.
func FuzzServeHTTP(f *testing.F) {
	const token = "6f1c2a3b-0000-4000-8000-000000000007"
	query := []byte{0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	q := base64.RawURLEncoding.EncodeToString(query)
	post := func(path, ctype, body string) string {
		return "POST " + path + " HTTP/1.1\r\nHost: doh.example\r\nContent-Type: " + ctype + "\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	}
	for _, s := range []string{
		"GET /dns-query/" + token + "?dns=" + q + " HTTP/1.1\r\nHost: doh.example\r\nAccept: application/dns-message\r\n\r\n",
		post("/dns-query/"+token, "application/dns-message", string(query)),
		"POST /dns-query/" + token + " HTTP/1.1\r\nHost: doh.example\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n" +
			"1d\r\n" + string(query) + "\r\n0\r\n\r\n",
		"GET /dns-query/6F1C2A3B-0000-4000-8000-000000000007?dns=" + q + " HTTP/1.1\r\nHost: doh.example\r\n\r\n",
		"GET /dns-query/%36f1c2a3b-0000-4000-8000-000000000007?dns=" + q + " HTTP/1.1\r\nHost: doh.example\r\n\r\n",
		"GET /dns-query/" + token + "/?dns=" + q + " HTTP/1.1\r\nHost: doh.example\r\n\r\n",
		"GET /x/../dns-query/" + token + "?dns=" + q + " HTTP/1.1\r\nHost: doh.example\r\n\r\n",
		"GET /dns-query/00000000-0000-4000-8000-000000000007?dns=" + q + " HTTP/1.1\r\nHost: doh.example\r\n\r\n",
		"GET /dns-query?dns=" + q + " HTTP/1.1\r\nHost: doh.example\r\n\r\n",
		"GET /dns-query/" + token + "?dns=AAAA HTTP/1.1\r\nHost: doh.example\r\n\r\n",
		"GET /dns-query/" + token + "?dns=" + q + "&dns=" + q + "== HTTP/1.1\r\nHost: doh.example\r\n\r\n",
		post("/dns-query/"+token, "application/dns-message; charset=x", string(query)),
		post("/dns-query/"+token, "application/dns-message", strings.Repeat("A", maxMessage+2)),
		"PUT /dns-query/" + token + " HTTP/1.1\r\nHost: doh.example\r\nContent-Length: 0\r\n\r\n",
		"GET http://doh.example/dns-query/" + token + "?dns=" + q + " HTTP/1.1\r\nHost: other\r\n\r\n",
	} {
		f.Add([]byte(s), false)
	}
	f.Add([]byte("GET /dns-query/"+token+"?dns="+q+" HTTP/1.1\r\nHost: doh.example\r\n\r\n"), true)

	answer := append([]byte{0xab, 0xcd, 0x81, 0x80}, make([]byte, 12)...)
	var forwarded []byte
	upstream := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		forwarded = b
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Content-Type": {"application/dns-message"}},
			Body: io.NopCloser(bytes.NewReader(answer)), Request: r}, nil
	})}
	site := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "the site") })
	handlers := map[bool]*Handler{
		false: {Tokens: func(context.Context) (map[string]bool, error) { return map[string]bool{token: true}, nil }},
		true:  {Tokens: func(context.Context) (map[string]bool, error) { return nil, errors.New("the store is locked") }},
	}
	for _, h := range handlers {
		h.Upstreams, h.HTTP, h.Answer, h.CacheFor = []string{"http://upstream.invalid/dns-query"}, upstream, site, time.Hour
	}
	f.Fuzz(func(t *testing.T, raw []byte, failing bool) {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			return
		}
		body := &countingReader{r: req.Body}
		req.Body = io.NopCloser(body)
		req.RemoteAddr = "198.51.100.7:40000"
		forwarded = nil
		w := httptest.NewRecorder()
		handlers[failing].ServeHTTP(w, req)

		if forwarded == nil {
			// No DNS answer: the site's, an error, or nothing (a body cut
			// short of its length gets an empty answer).
			if w.Header().Get("Content-Type") == "application/dns-message" || bytes.Equal(w.Body.Bytes(), answer) {
				t.Fatalf("%q: a DNS answer without the upstream: %d %q", raw, w.Code, w.Body)
			}
			if body.n > maxMessage+1 {
				t.Fatalf("%q: %d bytes of its body read", raw, body.n)
			}
			return
		}
		switch {
		case failing:
			t.Fatalf("%q: forwarded while the tokens cannot be read", raw)
		case req.URL.Path != "/dns-query/"+token:
			t.Fatalf("%q: forwarded for path %q", raw, req.URL.Path)
		case len(forwarded) < 12 || len(forwarded) > maxMessage:
			t.Fatalf("%q: forwarded %d bytes", raw, len(forwarded))
		case w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), answer):
			t.Fatalf("%q: forwarded, answered %d %q", raw, w.Code, w.Body)
		case body.n > maxMessage+1:
			t.Fatalf("%q: %d bytes of its body read", raw, body.n)
		}
		switch req.Method {
		case http.MethodGet:
			if q, err := base64.RawURLEncoding.DecodeString(req.URL.Query().Get("dns")); err != nil || !bytes.Equal(q, forwarded) {
				t.Fatalf("%q: forwarded %x, not its dns parameter", raw, forwarded)
			}
		case http.MethodPost:
			if req.Header.Get("Content-Type") != "application/dns-message" || !bytes.Equal(forwarded, body.read) {
				t.Fatalf("%q: forwarded %x, a body of type %q", raw, forwarded, req.Header.Get("Content-Type"))
			}
		default:
			t.Fatalf("%q: forwarded a %s", raw, req.Method)
		}
	})
}
