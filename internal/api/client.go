package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
)

// BaseURL is the URL clients use with UnixHTTPClient; the host is ignored.
const BaseURL = "http://rayd"

// UnixHTTPClient returns an HTTP client whose connections go to the rayd
// unix socket. It asks for no gzip of its own and unpacks none.
func UnixHTTPClient(socketPath string) *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
		DisableCompression: true,
	}
	return &http.Client{Transport: tr}
}

// The most rayctl reads of one answer of rayd's: rayd is not trusted with
// root's memory (spec/apply-plan-v1.md). MaxBackupAnswer is Backup's, the
// whole database.
const (
	MaxAnswer       = 16 << 20
	MaxBackupAnswer = 256 << 20
)

// answerMargin is what an answer's body may have beyond its message's
// limit: an error's JSON around its text.
const answerMargin = 64 << 10

// NewUnixClient returns a NodeService client that talks to rayd over the
// local unix socket (NewNodeClient).
func NewUnixClient(socketPath string) nodev1connect.NodeServiceClient {
	return NewNodeClient(UnixHTTPClient(socketPath), BaseURL, MaxAnswer)
}

// NewUnixBackupClient is NewUnixClient for Backup, whose answer is the
// database.
func NewUnixBackupClient(socketPath string) nodev1connect.NodeServiceClient {
	return NewNodeClient(UnixHTTPClient(socketPath), BaseURL, MaxBackupAnswer)
}

// NewNodeClient returns a NodeService client as rayctl, root, needs it:
// answers of max bytes at most, errors too (connect reads an error's body
// without its limit), never compressed (a small body would unpack to any
// size), and every error's text without what a terminal acts on, cut to a
// length (deploy.PrintableWarning).
func NewNodeClient(hc *http.Client, url string, max int) nodev1connect.NodeServiceClient {
	return nodev1connect.NewNodeServiceClient(capped(hc, int64(max)+answerMargin), url,
		connect.WithReadMaxBytes(max), connect.WithAcceptCompression("gzip", nil, nil), connect.WithInterceptors(printableErrors()))
}

// capped is hc with each answer's body cut at limit bytes, and without
// the transport's own gzip.
func capped(hc *http.Client, limit int64) *http.Client {
	c := *hc
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	if t, ok := base.(*http.Transport); ok && !t.DisableCompression {
		t = t.Clone()
		t.DisableCompression = true
		base = t
	}
	c.Transport = capTransport{base: base, limit: limit}
	return &c
}

// capTransport refuses an answer longer than limit: by its length, before
// a byte of it is read, or when its body goes past it.
type capTransport struct {
	base  http.RoundTripper
	limit int64
}

func (t capTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.ContentLength > t.limit {
		_ = resp.Body.Close()
		return nil, connect.NewError(connect.CodeResourceExhausted, fmt.Errorf("rayd's answer: %d bytes, more than %d", resp.ContentLength, t.limit))
	}
	resp.Body = &capBody{ReadCloser: resp.Body, left: t.limit, limit: t.limit}
	return resp, nil
}

// capBody is a body that ends in an error past limit bytes.
type capBody struct {
	io.ReadCloser
	left, limit int64
}

func (b *capBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		// One byte more tells a body of exactly the limit from a longer one.
		var one [1]byte
		if n, err := b.ReadCloser.Read(one[:]); n > 0 {
			return 0, tooLarge(b.limit)
		} else if err != nil {
			return 0, err
		}
		return 0, nil
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.ReadCloser.Read(p)
	b.left -= int64(n)
	return n, err
}

// tooLarge is an answer past limit; connect keeps its code.
func tooLarge(limit int64) error {
	return connect.NewError(connect.CodeResourceExhausted, fmt.Errorf("rayd's answer is longer than %d bytes", limit))
}

// printableErrors makes the text of every error printable, the server's
// and the client's own alike (an HTTP reason phrase, a malformed header
// quoted by net/http): rayctl shows them on root's terminal. The code
// stays, and what the error wraps.
func printableErrors() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			resp, err := next(ctx, req)
			if err == nil {
				return resp, nil
			}
			var ce *connect.Error
			if !errors.As(err, &ce) {
				return resp, connect.NewError(connect.CodeOf(err), printable{err})
			}
			cause := ce.Unwrap()
			if cause == nil {
				cause = errors.New(ce.Message())
			}
			clean := connect.NewError(ce.Code(), printable{cause})
			for _, d := range ce.Details() {
				clean.AddDetail(d)
			}
			return resp, clean
		}
	}
}

// printable is an error whose text is made printable and cut to a length;
// what it wraps stays for errors.Is and errors.As.
type printable struct{ err error }

func (p printable) Error() string { return deploy.PrintableWarning(p.err.Error()) }
func (p printable) Unwrap() error { return p.err }
