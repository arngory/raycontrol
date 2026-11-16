package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/arngory/raycontrol/internal/naive"
)

// naiveUDP serves ns as rayd naive does with -udp on or off (naiveH3, the
// datagrams of h3Options), and sends one connect-udp request of
// spec/naive-udp-v1.md §3.2 to it: its answer and its stream.
func naiveUDP(t *testing.T, ns *naive.Server, udp bool) (*http.Response, *http3.RequestStream) {
	t.Helper()
	ns.UDP, ns.H3 = udp, naiveH3
	_, cert := naiveTest(t, sink)
	addr := serveQUIC(t, ns, cert, quicOptions{datagrams: udp})
	qc, err := quic.DialAddr(t.Context(), addr, naiveClientTLS(http3.NextProtoH3), &quic.Config{EnableDatagrams: true, MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
	rs, err := (&http3.Transport{EnableDatagrams: true}).NewClientConn(qc).OpenRequestStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodConnect, "https://naive.test/.well-known/masque/udp/%2A/%2A/", nil)
	req.Proto = naive.ConnectUDP
	req.Header.Set("Capsule-Protocol", "?1")
	req.Header.Set(naive.UDPHeader, "1")
	req.Header.Set("Padding", naive.PaddingHeader())
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("niko:"+naiveTestPassword)))
	if err := rs.SendRequestHeader(req); err != nil {
		t.Fatal(err)
	}
	resp, err := rs.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rs.CancelRead(0); rs.CancelWrite(0) })
	return resp, rs
}

// rayd naive with -udp carries UDP as HTTP/3 datagrams; without it a
// connect-udp request is the site's.
func TestNaiveUDP(t *testing.T) {
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	at := echo.LocalAddr().(*net.UDPAddr).AddrPort()
	loopback := func(a netip.Addr) bool { return a == at.Addr() }

	ns, _ := naiveTest(t, sink)
	ns.Allow = loopback
	resp, rs := naiveUDP(t, ns, true)
	if resp.StatusCode != http.StatusOK || resp.Header.Get(naive.UDPHeader) != "1" {
		t.Fatalf("-udp: %s %v", resp.Status, resp.Header)
	}
	// [Context ID 2][4][address][port][data]
	dg := append([]byte{2, 4}, at.Addr().AsSlice()...)
	dg = binary.BigEndian.AppendUint16(dg, at.Port())
	if err := rs.SendDatagram(append(dg, "ping"...)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	got, err := rs.ReceiveDatagram(ctx)
	if err != nil || string(got) != string(dg)+"ping" {
		t.Fatalf("% x %v", got, err)
	}
	// The answer counts once the connection's sender handed it to QUIC,
	// the datagram once its write returned: either may come after the
	// client has the answer.
	for end := time.Now().Add(5 * time.Second); (ns.UDPStats().Out != 1 || ns.UDPStats().In != 1) && time.Now().Before(end); {
		time.Sleep(10 * time.Millisecond)
	}
	if st := ns.UDPStats(); st.Requests != 1 || st.In != 1 || st.Out != 1 {
		t.Fatalf("%+v", st)
	}

	ns, _ = naiveTest(t, sink)
	if resp, _ := naiveUDP(t, ns, false); resp.StatusCode != http.StatusNotFound || resp.Header.Get(naive.UDPHeader) != "" {
		t.Fatalf("without -udp: %s %v", resp.Status, resp.Header)
	}
}
