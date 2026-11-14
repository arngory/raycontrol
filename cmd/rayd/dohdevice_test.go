package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/arngory/raycontrol/internal/site"
	"github.com/arngory/raycontrol/internal/store"
)

// DoH's tokens are the devices' (R4-37), end to end over HTTP/2 and
// HTTP/3, under each answer of the site's, silent's included: two devices
// of one user have their own tokens and both are answered; the user's
// token, which subscriptions carried before, is answered in its window
// after the upgrade. The device revoked, its token is refused from the
// next query with a quick empty 404, as is the user's token (the revoked
// device knew it), never the site's answer, which a silent site holds;
// the sibling's goes on being answered without a new subscription. A
// stranger gets the site's answer throughout, as before.
func TestDoHDeviceTokens(t *testing.T) {
	old := site.SilentHold
	site.SilentHold = 2 * time.Second
	defer func() { site.SilentHold = old }()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	svc, err := st.CreateService(ctx, store.Service{Kind: "doh", Name: "doh", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	// The window a schema 14 database opens at its upgrade (store's
	// startDoHShared), here at once.
	now := time.Now().Unix()
	if err := st.SetSetting(ctx, "doh_shared", fmt.Appendf(nil, "%d %d", now-60, now+3600)); err != nil {
		t.Fatal(err)
	}
	query, answer := bytes.Repeat([]byte{1}, 20), bytes.Repeat([]byte{2}, 30)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if !bytes.Equal(b, query) {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		w.Write(answer)
	}))
	defer upstream.Close()
	_, cert := naiveTest(t, sink)
	log := slog.New(slog.DiscardHandler)

	for _, mode := range []string{site.Answer404, site.Answer403, site.AnswerSilent} {
		name := "alice-" + mode
		u, err := st.CreateUser(ctx, store.User{Name: name, Enabled: true, Services: []int64{svc.ID}})
		if err != nil {
			t.Fatal(err)
		}
		c, err := st.Credentials(ctx, svc.ID, []int64{u.ID}, store.NewUUID)
		if err != nil {
			t.Fatal(err)
		}
		shared := c[u.ID]
		devA, keyA, err := st.CreateDevice(ctx, name, "a", "user")
		if err != nil {
			t.Fatal(err)
		}
		_, keyB, err := st.CreateDevice(ctx, name, "b", "user")
		if err != nil {
			t.Fatal(err)
		}
		a, b := store.DoHDeviceToken(shared, keyA[:]), store.DoHDeviceToken(shared, keyB[:])
		if a == b || len(a) != len(shared) {
			t.Fatalf("%s: tokens %q %q for %q", mode, a, b, shared)
		}

		_, siteAnswer := dohAnswer(`{"answer":"` + mode + `"}`)
		h := dohHandler(st, svc.ID, siteAnswer, log)
		h.Upstreams = []string{upstream.URL}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := dohHTTPServer(h, fixedCert(cert), log)
		go func() { _ = srv.ServeTLS(ln, "", "") }()
		h2 := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: naiveClientTLS("h2")}
		h3addr := serveQUIC(t, h, cert, quicOptions{})
		h3 := &http3.Transport{TLSClientConfig: naiveClientTLS(), QUICConfig: &quic.Config{MaxIdleTimeout: 30 * time.Second},
			Dial: func(ctx context.Context, _ string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
				return quic.DialAddrEarly(ctx, h3addr, tlsConf, conf)
			}}
		transports := map[string]http.RoundTripper{"h2": h2, "h3": h3}
		addr := map[string]string{"h2": ln.Addr().String(), "h3": "doh.test"}

		// ask is a GET of the query with tok: the status, or the error,
		// and how long it took.
		ask := func(proto, tok string) (string, time.Duration) {
			t.Helper()
			rctx, cancel := context.WithTimeout(ctx, 4*site.SilentHold)
			defer cancel()
			req, _ := http.NewRequestWithContext(rctx, http.MethodGet,
				"https://"+addr[proto]+"/dns-query/"+tok+"?dns="+base64.RawURLEncoding.EncodeToString(query), nil)
			start := time.Now()
			resp, err := transports[proto].RoundTrip(req)
			if err != nil {
				return "reset", time.Since(start)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			took := time.Since(start)
			if resp.StatusCode == http.StatusOK && !bytes.Equal(body, answer) {
				return "200 with another body", took
			}
			if resp.StatusCode != http.StatusOK && len(body) != 0 {
				return resp.Status + " with a body", took
			}
			return strconv.Itoa(resp.StatusCode), took
		}
		strangerWant := map[string]string{site.Answer404: "404", site.Answer403: "403", site.AnswerSilent: "reset"}[mode]
		fast := site.SilentHold / 2
		expect := func(when, proto, tok, want string, quick bool) {
			t.Helper()
			got, took := ask(proto, tok)
			if got != want {
				t.Errorf("%s, %s, %s: %s, want %s", mode, proto, when, got, want)
			}
			if quick && took > fast {
				t.Errorf("%s, %s, %s: %v, want at once", mode, proto, when, took)
			}
			if !quick && mode == site.AnswerSilent && took < site.SilentHold {
				t.Errorf("%s, %s, %s: %v, not held as the site holds", mode, proto, when, took)
			}
		}
		stranger := "00000000-0000-4000-8000-000000000000"
		for _, proto := range []string{"h2", "h3"} {
			expect("device a", proto, a, "200", true)
			expect("device b", proto, b, "200", true)
			expect("the user's token in its window", proto, shared, "200", true)
			expect("a stranger", proto, stranger, strangerWant, false)
		}

		// The revocation, and the Forget serveDoH makes at every change.
		if _, err := st.RevokeDevice(ctx, devA.ID); err != nil {
			t.Fatal(err)
		}
		h.Forget()
		for _, proto := range []string{"h2", "h3"} {
			expect("the revoked device", proto, a, "404", true)
			expect("the user's token after a revocation", proto, shared, "404", true)
			expect("the sibling after the revocation", proto, b, "200", true)
			expect("a stranger after the revocation", proto, stranger, strangerWant, false)
		}
		_ = srv.Close()
		h2.CloseIdleConnections()
		_ = h3.Close()
	}
}
