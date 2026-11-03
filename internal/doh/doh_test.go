package doh

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
