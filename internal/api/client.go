package api

import (
	"context"
	"net"
	"net/http"

	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
)

// NewUnixClient returns a NodeService client that talks to rayd over the
// local unix socket.
func NewUnixClient(socketPath string) nodev1connect.NodeServiceClient {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	return nodev1connect.NewNodeServiceClient(&http.Client{Transport: tr}, "http://rayd")
}
