package api

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"connectrpc.com/connect"

	devicev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/device/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/device/v1/devicev1connect"
)

// A remote API peer that stops answering, in the TLS handshake or on an
// HTTP/2 connection it set up, does not hold a client without a deadline
// of its own (a relay's feed): the handshake times out, and a silent
// connection is pinged and dropped.
func TestRemoteClientTimeouts(t *testing.T) {
	defer func(h, a, p time.Duration) {
		remoteHandshakeTimeout, remotePingAfter, remotePingTimeout = h, a, p
	}(remoteHandshakeTimeout, remotePingAfter, remotePingTimeout)
	remoteHandshakeTimeout, remotePingAfter, remotePingTimeout = 300*time.Millisecond, 300*time.Millisecond, 300*time.Millisecond

	cert, err := NewClientCertificate()
	if err != nil {
		t.Fatal(err)
	}
	serverCfg := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, ClientAuth: tls.RequireAnyClientCert}
	pin := CertPin(cert.Leaf)

	for _, tc := range []struct {
		name string
		// serve holds the connection: silent from the start, or after
		// the handshake.
		serve func(net.Conn)
	}{
		{"handshake", func(net.Conn) {}},
		{"h2", func(c net.Conn) {
			_ = tls.Server(c, serverCfg).Handshake()
		}},
	} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		stop := make(chan struct{})
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			tc.serve(c)
			<-stop
		}()
		dev := devicev1connect.NewDeviceServiceClient(RemoteHTTPClient(pin, cert), "https://"+ln.Addr().String())
		res := make(chan error, 1)
		go func() {
			_, err := dev.GetSelf(context.Background(), connect.NewRequest(&devicev1.GetSelfRequest{}))
			res <- err
		}()
		select {
		case err := <-res:
			if err == nil {
				t.Fatalf("%s: a silent peer answered", tc.name)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: the client waits on a silent peer", tc.name)
		}
		close(stop)
		ln.Close()
	}
}
