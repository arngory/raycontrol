package api_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/api"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// fakeRayd answers every request with what answer writes on the raw
// connection, and counts what got through; req is the last request's
// header.
type fakeRayd struct {
	url     string
	written atomic.Int64
	req     atomic.Pointer[http.Header]
}

func newFakeRayd(t *testing.T, answer func(w func([]byte) error)) *fakeRayd {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	f := &fakeRayd{url: "http://" + l.Addr().String()}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				h := req.Header.Clone()
				f.req.Store(&h)
				answer(func(b []byte) error {
					n, err := c.Write(b)
					f.written.Add(int64(n))
					return err
				})
			}()
		}
	}()
	return f
}

func (f *fakeRayd) call(max int) error {
	c := api.NewNodeClient(&http.Client{}, f.url, max)
	_, err := c.GetDeployInputs(context.Background(), connect.NewRequest(&nodev1.GetDeployInputsRequest{}))
	return err
}

func raw(s string) func(w func([]byte) error) {
	return func(w func([]byte) error) { _ = w([]byte(s)) }
}

// chunked is an answer of status with a body of n bytes of fill after
// head, sent chunked: no length to refuse it by.
func chunked(status, head string, fill byte, n int) func(w func([]byte) error) {
	return func(w func([]byte) error) {
		if w([]byte("HTTP/1.1 "+status+"\r\nContent-Type: "+contentType(status)+"\r\nTransfer-Encoding: chunked\r\n\r\n")) != nil {
			return
		}
		chunk := func(b []byte) error { return w(fmt.Appendf(nil, "%x\r\n%s\r\n", len(b), b)) }
		if head != "" && chunk([]byte(head)) != nil { // an empty chunk would end the body
			return
		}
		block := bytes.Repeat([]byte{fill}, 1<<20)
		for range n >> 20 {
			if chunk(block) != nil {
				return
			}
		}
		_ = w([]byte("0\r\n\r\n"))
	}
}

// Every error's text reaches root's terminal without what it would act
// on, rayd's own or one the client makes of what rayd sent (an HTTP
// reason phrase, a header net/http quotes); its code stays (second
// review, A).
func TestNodeClientErrorsPrintable(t *testing.T) {
	esc := "\x1b]0;owned\x07\x1b[2J\x1b[1;1Hall good"
	for _, c := range []struct {
		name   string
		answer string
		code   connect.Code
	}{
		{"rayd's error", fmt.Sprintf("HTTP/1.1 500 x\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
			len(`{"code":"internal","message":"\u001b]0;owned\u0007"}`), `{"code":"internal","message":"\u001b]0;owned\u0007"}`), connect.CodeInternal},
		{"reason phrase", "HTTP/1.1 500 " + esc + "\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n", connect.CodeUnknown},
		{"reason phrase, bad JSON", "HTTP/1.1 500 " + esc + "\r\nContent-Type: application/json\r\nContent-Length: 1\r\n\r\n{", connect.CodeUnknown},
		{"malformed header", "HTTP/1.1 200 OK\r\nX-A: " + esc + "\r\nContent-Length: 0\r\n\r\n", connect.CodeUnavailable},
		{"malformed status", "HTTP/1.1 2" + esc + "\r\n\r\n", connect.CodeUnavailable},
		{"long", "HTTP/1.1 500 " + strings.Repeat("x", 5000) + "\r\nContent-Length: 0\r\n\r\n", connect.CodeUnknown},
	} {
		err := newFakeRayd(t, raw(c.answer)).call(api.MaxAnswer)
		if err == nil || strings.ContainsFunc(err.Error(), func(r rune) bool { return r < 0x20 || r == 0x7f }) || len(err.Error()) > 600 {
			t.Errorf("%s: printed as %q", c.name, err)
		}
		if connect.CodeOf(err) != c.code {
			t.Errorf("%s: code %v, want %v", c.name, connect.CodeOf(err), c.code)
		}
	}
}

// No answer of rayd's is read past its limit, an error's either (connect
// reads one without its limit): by its length when it has one, by its
// body when it is chunked (second review, B).
func TestNodeClientAnswerCap(t *testing.T) {
	// 200 MiB declared: refused before a byte of it is read.
	f := newFakeRayd(t, func(w func([]byte) error) {
		_ = w(fmt.Appendf(nil, "HTTP/1.1 500 x\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n{\"code\":\"internal\",\"message\":\"", 200<<20))
	})
	if err := f.call(api.MaxAnswer); connect.CodeOf(err) != connect.CodeResourceExhausted || !strings.Contains(err.Error(), fmt.Sprint(200<<20)) {
		t.Errorf("200 MiB error by its length: %v", err)
	}
	// Chunked, 128 MiB: read up to the limit, no further. What got
	// through is the limit and what the sockets hold.
	for _, c := range []struct {
		name, status, head string
	}{
		{"error", "500 x", `{"code":"internal","message":"`},
		{"message", "200 OK", ""},
	} {
		f := newFakeRayd(t, chunked(c.status, c.head, 'A', 128<<20))
		err := f.call(api.MaxAnswer)
		if err == nil || strings.Contains(err.Error(), "AAAA") {
			t.Errorf("chunked %s: %.200v", c.name, err)
		}
		if n := f.written.Load(); n > 64<<20 {
			t.Errorf("chunked %s: %d MiB read of 128", c.name, n>>20)
		}
	}
	// The bounds. A message of max bytes is not too long (a backup
	// client's database at its cap), one of a byte more is (connect's
	// own limit, under the body's).
	n := 1 << 20
	f = newFakeRayd(t, chunked("200 OK", "", 0, n))
	if err := f.call(n); connect.CodeOf(err) == connect.CodeResourceExhausted {
		t.Errorf("an answer at the limit: %v", err)
	}
	f = newFakeRayd(t, chunkedBody("200 OK", make([]byte, n+1)))
	if err := f.call(n); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Errorf("an answer a byte past the limit: %v", err)
	}
	// An error's body (no limit of connect's) of max and the margin is
	// read; a byte more is not.
	errorBody := func(size int) []byte {
		head, tail := `{"code":"internal","message":"`, `"}`
		return []byte(head + strings.Repeat("B", size-len(head)-len(tail)) + tail)
	}
	f = newFakeRayd(t, chunkedBody("500 x", errorBody(n+api.AnswerMargin)))
	if err := f.call(n); connect.CodeOf(err) != connect.CodeInternal || !strings.Contains(err.Error(), "BBBB") {
		t.Errorf("an error at the limit: %.200v", err)
	}
	f = newFakeRayd(t, chunkedBody("500 x", errorBody(n+api.AnswerMargin+1)))
	if err := f.call(n); err == nil || strings.Contains(err.Error(), "BBBB") {
		t.Errorf("an error a byte past the limit: %.200v", err)
	}
}

// chunkedBody is an answer of status with body, sent chunked.
func chunkedBody(status string, body []byte) func(w func([]byte) error) {
	return func(w func([]byte) error) {
		if w([]byte("HTTP/1.1 "+status+"\r\nContent-Type: "+contentType(status)+"\r\nTransfer-Encoding: chunked\r\n\r\n")) != nil {
			return
		}
		for b := body; len(b) > 0; {
			k := min(len(b), 50000) // not a divisor of the limits: a read may cross them
			if w(fmt.Appendf(nil, "%x\r\n%s\r\n", k, b[:k])) != nil {
				return
			}
			b = b[k:]
		}
		_ = w([]byte("0\r\n\r\n"))
	}
}

// contentType is what connect wants with status: a message, or an
// error's JSON.
func contentType(status string) string {
	if strings.HasPrefix(status, "200") {
		return "application/proto"
	}
	return "application/json"
}

// rayd's answer is never unpacked: rayctl asks for no compression, and a
// gzip error body (a small one unpacks to any size) is refused as it is
// (second review, B).
func TestNodeClientNoGzip(t *testing.T) {
	var z bytes.Buffer
	w := gzip.NewWriter(&z)
	w.Write([]byte(`{"code":"internal","message":"`))
	w.Write(bytes.Repeat([]byte("A"), 32<<20))
	w.Write([]byte(`"}`))
	w.Close()
	f := newFakeRayd(t, raw(fmt.Sprintf("HTTP/1.1 500 x\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n%s", z.Len(), z.Bytes())))
	err := f.call(api.MaxAnswer)
	if err == nil || strings.Contains(err.Error(), "AAAA") {
		t.Errorf("gzip error body: %.200v", err)
	}
	h := f.req.Load()
	if h == nil {
		t.Fatal("no request")
	}
	for _, k := range []string{"Accept-Encoding", "Connect-Accept-Encoding"} {
		if strings.Contains(h.Get(k), "gzip") {
			t.Errorf("%s: %q", k, h.Get(k))
		}
	}
	// The unix socket's transport: no gzip of its own either.
	if tr, ok := api.UnixHTTPClient("/nonexistent").Transport.(*http.Transport); !ok || !tr.DisableCompression {
		t.Error("the unix socket's transport unpacks gzip")
	}
}
