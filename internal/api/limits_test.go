package api

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	devicev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/device/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/device/v1/devicev1connect"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
)

// A request over MaxRequest, plain or as a small gzip that unpacks to
// more, is resource_exhausted on the local socket and on the remote API,
// before any handler or caller check; one of a real request's size still
// reaches the handler.
func TestRequestLimit(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx := context.Background()
	big := strings.Repeat("x", MaxRequest+1)

	for _, opts := range [][]connect.ClientOption{nil, {connect.WithSendCompression("gzip")}} {
		c := nodev1connect.NewNodeServiceClient(UnixHTTPClient(sock), BaseURL, opts...)
		if _, err := c.SetNodeNote(ctx, connect.NewRequest(&nodev1.SetNodeNoteRequest{Note: big})); connect.CodeOf(err) != connect.CodeResourceExhausted {
			t.Fatalf("a request of %d bytes (%v): %v", len(big), opts, err)
		}
		// A certificate chain of a real size reaches SetCertificate.
		chain := bytes.Repeat([]byte("A"), 64<<10)
		if _, err := c.SetCertificate(ctx, connect.NewRequest(&nodev1.SetCertificateRequest{Service: "none", ChainPem: chain, KeyPem: chain})); err == nil ||
			connect.CodeOf(err) == connect.CodeResourceExhausted {
			t.Fatalf("a chain of 64 KiB: %v", err)
		}
	}

	if _, err := NewUnixClient(sock).CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "api", Name: "api"})); err != nil {
		t.Fatal(err)
	}
	addr, pin := startRemote(t, srv)
	d := newRemoteDevice(t, addr, pin)
	gz := devicev1connect.NewDeviceServiceClient(remoteHTTP(pin, d.cert), "https://"+addr, connect.WithSendCompression("gzip"))
	for _, dev := range []devicev1connect.DeviceServiceClient{d.dev, gz} {
		_, err := dev.Register(ctx, connect.NewRequest(&devicev1.RegisterRequest{InviteId: "0000000000000000", Minute: time.Now().Unix() / 60, Mac: []byte(big)}))
		if connect.CodeOf(err) != connect.CodeResourceExhausted {
			t.Fatalf("a remote request of %d bytes: %v", len(big), err)
		}
	}
	if _, err := d.node.SetNodeNote(ctx, connect.NewRequest(&nodev1.SetNodeNoteRequest{Note: big})); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("a remote NodeService request of %d bytes from an unknown device: %v", len(big), err)
	}
}
