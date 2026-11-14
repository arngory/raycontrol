package h3serve

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// sizes is a server's socket that keeps the largest datagram it sent. Not
// a *net.UDPConn, as the front's socket is not (nikoipc.PacketConn).
type sizes struct {
	net.PacketConn
	largest atomic.Int64
	n       atomic.Int64
}

func (s *sizes) WriteTo(b []byte, addr net.Addr) (int, error) {
	s.n.Add(1)
	for {
		l := s.largest.Load()
		if int64(len(b)) <= l || s.largest.CompareAndSwap(l, int64(len(b))) {
			break
		}
	}
	return s.PacketConn.WriteTo(b, addr)
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "h3.test"}, DNSNames: []string{"h3.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// The server never sends a datagram longer than Chrome's QUIC packets
// (MaxPacketSize): not in the handshake, with its certificate, nor in a
// download that fills every packet; and it does not search the path's MTU
// upward, which Chrome's servers do not do either.
func TestPacketCeiling(t *testing.T) {
	if c := Config(Options{}); c.InitialPacketSize != MaxPacketSize || !c.DisablePathMTUDiscovery {
		t.Fatalf("packets of %d bytes, path MTU discovery off %v", c.InitialPacketSize, c.DisablePathMTUDiscovery)
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc := &sizes{PacketConn: udp}
	cert := selfSigned(t)
	const body = 4 << 20
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(make([]byte, body)) })
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, pc, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }, h,
			Options{Idle: time.Minute, MaxStreams: 100, PendingStreams: 10, MaxHeaderBytes: 16 << 10})
	}()
	defer func() {
		stop()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	addr := udp.LocalAddr().String()
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, //nolint:gosec // G402: the test's own server
			CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}},
		Dial: func(ctx context.Context, _ string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
			return quic.DialAddrEarly(ctx, addr, tlsConf, conf)
		}}
	defer tr.Close()
	// Long enough for quic-go's first probe of the path, which it would
	// send a few round trips after the handshake.
	for range 3 {
		req, _ := http.NewRequest(http.MethodGet, "https://h3.test/", nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		n, err := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if err != nil || n != body {
			t.Fatalf("read %d of %d bytes (%v)", n, body, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if got := pc.largest.Load(); got > MaxPacketSize || got < MaxPacketSize-20 {
		t.Fatalf("the largest of %d datagrams was %d bytes, want %d at most and full packets near it", pc.n.Load(), got, MaxPacketSize)
	}
}
