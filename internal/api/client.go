package api

import (
	"context"
	"errors"
	"net"
	"net/http"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
)

// BaseURL is the URL clients use with UnixHTTPClient; the host is ignored.
const BaseURL = "http://rayd"

// UnixHTTPClient returns an HTTP client whose connections go to the rayd
// unix socket.
func UnixHTTPClient(socketPath string) *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	return &http.Client{Transport: tr}
}

// The most rayctl reads of one answer of rayd's: rayd is not trusted with
// root's memory (spec/apply-plan-v1.md). MaxBackupAnswer is Backup's, the
// whole database.
const (
	MaxAnswer       = 16 << 20
	MaxBackupAnswer = 1 << 30
)

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
// answers of max bytes at most, and the server's error messages without
// what a terminal acts on, cut to a length (deploy.PrintableWarning).
func NewNodeClient(hc *http.Client, url string, max int) nodev1connect.NodeServiceClient {
	return nodev1connect.NewNodeServiceClient(hc, url, connect.WithReadMaxBytes(max), connect.WithInterceptors(printableErrors()))
}

// printableErrors makes the messages of errors the server sent printable:
// rayctl shows them on root's terminal. Errors of the client's own (a
// dial, a timeout) keep what they wrap.
func printableErrors() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			resp, err := next(ctx, req)
			var ce *connect.Error
			if err != nil && connect.IsWireError(err) && errors.As(err, &ce) {
				return resp, connect.NewError(ce.Code(), errors.New(deploy.PrintableWarning(ce.Message())))
			}
			return resp, err
		}
	}
}
