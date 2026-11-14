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
	"net/netip"
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

// asIPv6 is a server's socket on IPv4 loopback whose clients' addresses
// are IPv6's: 2001:db8:: with the port of the client's.
type asIPv6 struct{ net.PacketConn }

func (s *asIPv6) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := s.PacketConn.ReadFrom(b)
	if ua, ok := addr.(*net.UDPAddr); ok {
		addr = &net.UDPAddr{IP: net.ParseIP("2001:db8::"), Port: ua.Port}
	}
	return n, addr, err
}

func (s *asIPv6) WriteTo(b []byte, addr net.Addr) (int, error) {
	if ua, ok := addr.(*net.UDPAddr); ok {
		addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: ua.Port}
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
// (PacketSize: MaxPacketSize over IPv4, MaxPacketSizeIPv6 over IPv6): not
// in the handshake, with its certificate, nor in a download that fills
// every packet; and it does not search the path's MTU upward, which
// Chrome's servers do not do either.
func TestPacketCeiling(t *testing.T) {
	for _, family := range []struct {
		name, addr string
		want       int
	}{{"IPv4", "127.0.0.1:0", MaxPacketSize}, {"IPv6", "[::1]:0", MaxPacketSizeIPv6}, {"IPv6front", "127.0.0.1:0", MaxPacketSizeIPv6}} {
		t.Run(family.name, func(t *testing.T) {
			udp, err := net.ListenPacket("udp", family.addr)
			if err != nil {
				if family.name == "IPv6" {
					t.Skipf("no IPv6 loopback on this machine (%v): only IPv6front checks IPv6's size", err)
				}
				t.Fatal(err)
			}
			if family.name == "IPv6front" {
				// The client's packets over IPv4 loopback, its address IPv6's,
				// as the front passes one (nikoipc.PacketConn).
				udp = &asIPv6{PacketConn: udp}
			}
			if n, got := packetCeiling(t, udp); got > int64(family.want) || got <= int64(family.want-20) {
				t.Fatalf("the largest of %d datagrams was %d bytes, want %d at most and full packets near it", n, got, family.want)
			}
		})
	}
}

// packetCeiling serves three downloads on udp and returns how many
// datagrams the server sent, and the largest.
func packetCeiling(t *testing.T, udp net.PacketConn) (n, largest int64) {
	t.Helper()
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
		got, err := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if err != nil || got != body {
			t.Fatalf("read %d of %d bytes (%v)", got, body, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return pc.n.Load(), pc.largest.Load()
}

// Each connection's configuration is chosen by its client's address
// family: IPv4 in IPv6 (a dual-stack socket) is IPv4, the front gives an
// IPv4 client's address in 4 bytes (nikoipc), an address that is not
// UDP's gets IPv4's size. Nothing else differs.
func TestPacketSizeByFamily(t *testing.T) {
	base := Config(Options{Idle: time.Minute, MaxStreams: 7})
	if base.InitialPacketSize != MaxPacketSize || !base.DisablePathMTUDiscovery || base.GetConfigForClient == nil {
		t.Fatalf("packets of %d bytes, path MTU discovery off %v, per client %v",
			base.InitialPacketSize, base.DisablePathMTUDiscovery, base.GetConfigForClient != nil)
	}
	for _, c := range []struct {
		addr net.Addr
		want int
	}{
		{net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:443")), MaxPacketSize},
		{&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}, MaxPacketSize}, // 16 bytes
		{net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[::ffff:192.0.2.1]:443")), MaxPacketSize},
		{net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[2001:db8::1]:443")), MaxPacketSizeIPv6},
		{net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[::1]:443")), MaxPacketSizeIPv6},
		{&net.UnixAddr{Name: "x", Net: "unixgram"}, MaxPacketSize},
	} {
		conf, err := base.GetConfigForClient(&quic.ClientInfo{RemoteAddr: c.addr})
		if err != nil {
			t.Fatal(err)
		}
		if int(conf.InitialPacketSize) != c.want || PacketSize(c.addr) != c.want {
			t.Errorf("%v: packets of %d bytes, want %d", c.addr, conf.InitialPacketSize, c.want)
		}
		if !conf.DisablePathMTUDiscovery || conf.MaxIdleTimeout != time.Minute || conf.MaxIncomingStreams != 7 || conf.KeepAlivePeriod != 0 {
			t.Errorf("%v: the configuration differs past the packet size: %+v", c.addr, conf)
		}
	}
}
