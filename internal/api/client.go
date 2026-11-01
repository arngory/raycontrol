package api

import (
	"context"
	"net"
	"net/http"

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

// NewUnixClient returns a NodeService client that talks to rayd over the
// local unix socket.
func NewUnixClient(socketPath string) nodev1connect.NodeServiceClient {
	return nodev1connect.NewNodeServiceClient(UnixHTTPClient(socketPath), BaseURL)
}
