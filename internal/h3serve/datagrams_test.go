package h3serve

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// datagramsResult is what the handler of TestDatagrams saw.
type datagramsResult struct {
	ok              bool
	small, tooLarge bool
	smallErr, err   error
}

// With Options.Datagrams the server announces HTTP/3 datagrams, the
// transport parameter and SETTINGS_H3_DATAGRAM, to everyone; without it
// neither, as before. Datagrams gives a request's stream only where both
// sides have them: the stream's datagrams both ways, "too large" for one
// past a QUIC packet with nothing sent, and its two ends, clean and reset.
func TestDatagrams(t *testing.T) {
	cert := selfSigned(t)
	results := make(chan datagramsResult, 1)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		take, ok := Datagrams(r.Context(), w)
		if !ok {
			results <- datagramsResult{}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Capsule-Protocol", "?1")
		st := take()
		res := datagramsResult{ok: true}
		res.small, res.smallErr = st.SendDatagram([]byte("small"))
		res.tooLarge, res.err = st.SendDatagram(make([]byte, MaxPacketSize))
		results <- res
		// The client's datagram comes back; then the end it asks for.
		b, err := st.ReceiveDatagram(r.Context())
		if err != nil {
			st.Reset()
			return
		}
		if _, err := st.SendDatagram(b); err != nil || string(b) == "reset" {
			st.Reset()
			return
		}
		_ = st.Close()
	})
	serve := func(t *testing.T, datagrams bool) string {
		t.Helper()
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctx, stop := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- Serve(ctx, pc, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }, h,
				Options{Idle: time.Minute, MaxStreams: 100, PendingStreams: 10, MaxHeaderBytes: 16 << 10, Datagrams: datagrams})
		}()
		t.Cleanup(func() {
			stop()
			if err := <-done; err != nil {
				t.Error(err)
			}
		})
		return pc.LocalAddr().String()
	}
	// open sends a connect-udp request; for a 200 it sends end in a
	// datagram, waits for it to come back and reads the stream to its end.
	open := func(t *testing.T, addr string, datagrams bool, end string) (*http3.ClientConn, *quic.Conn, *http.Response, error) {
		t.Helper()
		qc, err := quic.DialAddr(t.Context(), addr, &tls.Config{InsecureSkipVerify: true, //nolint:gosec // G402: the test's own server
			CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{http3.NextProtoH3}},
			&quic.Config{EnableDatagrams: datagrams})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
		cc := (&http3.Transport{EnableDatagrams: datagrams}).NewClientConn(qc)
		rs, err := cc.OpenRequestStream(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodConnect, "https://h3.test/x", nil)
		req.Proto = "connect-udp"
		if err := rs.SendRequestHeader(req); err != nil {
			t.Fatal(err)
		}
		resp, err := rs.ReadResponse()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			return cc, qc, resp, nil
		}
		if err := rs.SendDatagram([]byte(end)); err != nil {
			t.Fatal(err)
		}
		for {
			b, err := rs.ReceiveDatagram(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if string(b) == end {
				break
			}
		}
		_, err = io.ReadAll(rs)
		return cc, qc, resp, err
	}
	t.Run("on", func(t *testing.T) {
		addr := serve(t, true)
		cc, qc, resp, err := open(t, addr, true, "close")
		<-cc.ReceivedSettings()
		if !cc.Settings().EnableDatagrams || !qc.ConnectionState().SupportsDatagrams.Remote {
			t.Fatalf("not announced: SETTINGS %v, transport %v", cc.Settings().EnableDatagrams, qc.ConnectionState().SupportsDatagrams.Remote)
		}
		res := <-results
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Capsule-Protocol") != "?1" || !res.ok || res.small || res.smallErr != nil ||
			!res.tooLarge || res.err != nil {
			t.Fatalf("%s %v; %+v", resp.Status, resp.Header, res)
		}
		if err != nil {
			t.Fatalf("closed: %v", err)
		}
		_, _, _, err = open(t, addr, true, "reset")
		<-results
		var h3err *http3.Error
		if !errors.As(err, &h3err) || !h3err.Remote || h3err.ErrorCode != http3.ErrCodeInternalError {
			t.Fatalf("reset: %v", err)
		}
		// A client without them: no stream to give.
		_, _, resp, _ = open(t, addr, false, "")
		if res := <-results; res.ok || resp.StatusCode != http.StatusNotFound {
			t.Fatalf("a client without datagrams: %s %+v", resp.Status, res)
		}
	})
	t.Run("off", func(t *testing.T) {
		cc, qc, resp, _ := open(t, serve(t, false), true, "")
		<-cc.ReceivedSettings()
		if cc.Settings().EnableDatagrams || qc.ConnectionState().SupportsDatagrams.Remote {
			t.Fatalf("announced: SETTINGS %v, transport %v", cc.Settings().EnableDatagrams, qc.ConnectionState().SupportsDatagrams.Remote)
		}
		if res := <-results; res.ok || resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s %+v", resp.Status, res)
		}
	})
	// Both configurations, IPv4's and IPv6's, follow the option.
	for _, on := range []bool{true, false} {
		base := Config(Options{Idle: time.Minute, Datagrams: on})
		v6, _ := base.GetConfigForClient(&quic.ClientInfo{RemoteAddr: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[2001:db8::1]:443"))})
		v4, _ := base.GetConfigForClient(&quic.ClientInfo{RemoteAddr: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:443"))})
		if base.EnableDatagrams != on || v4.EnableDatagrams != on || v6.EnableDatagrams != on {
			t.Errorf("datagrams %v: %v %v %v", on, base.EnableDatagrams, v4.EnableDatagrams, v6.EnableDatagrams)
		}
	}
}
