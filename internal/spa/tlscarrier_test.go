package spa

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"testing"
)

// The ClientHello carrier is one a TLS server parses as a browser's
// ClientHello, and gives the SPA packet back exactly (spa-v2.md §10.1).
func TestTLSCarrier(t *testing.T) {
	for _, n := range []int{MinPacketLen, 96, 160, MaxPacketLen} {
		pkt := make([]byte, n)
		rand.Read(pkt)
		rec, err := TLSCarrier(pkt)
		if err != nil {
			t.Fatal(err)
		}
		if !IsTLSCarrier(rec) || len(rec) > TLSCarrierMax {
			t.Fatalf("n=%d: record of %d bytes", n, len(rec))
		}
		got, err := FromTLSCarrier(rec)
		if err != nil || !bytes.Equal(got, pkt) {
			t.Fatalf("n=%d: %v", n, err)
		}

		// crypto/tls takes it for a ClientHello.
		cli, srv := net.Pipe()
		hello := make(chan *tls.ClientHelloInfo, 1)
		go func() {
			conn := tls.Server(srv, &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
				hello <- h
				return nil, errors.New("stop")
			}})
			conn.Handshake()
			srv.Close()
		}()
		go func() { cli.Write(rec); cli.Close() }()
		h := <-hello
		if !slices.Contains(h.SupportedVersions, tls.VersionTLS13) || !slices.Contains(h.SupportedProtos, "h2") ||
			!slices.Contains(h.SupportedCurves, tls.X25519MLKEM768) || h.ServerName != "" {
			t.Fatalf("n=%d: hello %+v", n, h)
		}
	}
	for _, bad := range [][]byte{nil, {0x16, 3, 1}, {0x16, 3, 1, 0, 4, 1, 0, 0, 0}, make([]byte, 100)} {
		if _, err := FromTLSCarrier(bad); err == nil {
			t.Errorf("%x parsed", bad)
		}
	}
	// Two carriers of the same packet share nothing outside it.
	pkt := make([]byte, 120)
	a, _ := TLSCarrier(pkt)
	b, _ := TLSCarrier(pkt)
	if bytes.Equal(a, b) {
		t.Fatal("two carriers are the same")
	}
}
