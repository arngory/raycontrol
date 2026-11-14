package main

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/api"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// RevokeDevice through the API reaches DoH's tokens by itself: the API's
// change wakes serveDoH, whose Forget makes the handler load the tokens
// again, and the revoked device's token gets the quick 404 within moments,
// not when the handler's 30 s cache runs out; the sibling's goes on.
// Nothing in the test calls Forget or wakes serveDoH.
func TestDoHRevokeThroughAPI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	params, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"reality", "doh"} {
		if _, err := provision.CreateService(ctx, st, store.Service{Kind: kind, Name: kind, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	site, err := st.ServiceByName(ctx, "site")
	if err != nil {
		t.Fatal(err)
	}
	k := newSiteKeyPair(t)
	chainPEM, _ := issueChain(t, k)
	if err := st.UpdateService(ctx, site.ID, store.ServiceUpdate{Set: map[string][]byte{
		provision.SecretTLSChain: chainPEM, provision.SecretTLSKey: k.der}}); err != nil {
		t.Fatal(err)
	}
	svc, err := st.ServiceByName(ctx, "doh")
	if err != nil {
		t.Fatal(err)
	}
	alice, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true, Services: []int64{svc.ID}})
	if err != nil {
		t.Fatal(err)
	}
	devA, keyA, err := st.CreateDevice(ctx, "alice", "a", "user")
	if err != nil {
		t.Fatal(err)
	}
	_, keyB, err := st.CreateDevice(ctx, "alice", "b", "user")
	if err != nil {
		t.Fatal(err)
	}
	c, err := st.Credentials(ctx, svc.ID, []int64{alice.ID}, store.NewUUID)
	if err != nil {
		t.Fatal(err)
	}
	a, b := store.DoHDeviceToken(c[alice.ID], keyA[:]), store.DoHDeviceToken(c[alice.ID], keyB[:])

	// rayd's wiring: the API's changes are what serveDoH wakes on.
	srv := &api.Server{Store: st, Params: params, Version: "test"}
	sock := filepath.Join(dir, "rayd.sock")
	apiDone := make(chan error, 1)
	go func() { apiDone <- srv.ServeUnix(ctx, sock, api.PeerPolicy{}) }()
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: filepath.Join(dir, "run"), Supervised: true}
	if err := os.MkdirAll(filepath.Dir(paths.DoHSocket("doh")), 0o750); err != nil {
		t.Fatal(err)
	}
	dohDone := make(chan struct{})
	go func() { serveDoH(ctx, st, paths, srv.Changes, slog.New(slog.DiscardHandler)); close(dohDone) }()
	t.Cleanup(func() { cancel(); <-dohDone; <-apiDone })
	for i := 0; ; i++ {
		_, e1 := os.Stat(paths.DoHSocket("doh"))
		_, e2 := os.Stat(sock)
		if e1 == nil && e2 == nil {
			break
		}
		if i == 400 {
			t.Fatal("no DoH or API socket")
		}
		time.Sleep(10 * time.Millisecond)
	}
	dial := passed(t, paths.DoHSocket("doh"), "doh")
	status := func(tok string) int {
		t.Helper()
		conn, _, err := dial()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := io.WriteString(conn, "PUT /dns-query/"+tok+" HTTP/1.1\r\nHost: "+reloadName+"\r\nContent-Length: 0\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if status(a) != http.StatusMethodNotAllowed || status(b) != http.StatusMethodNotAllowed {
		t.Fatal("the devices' tokens before")
	}
	if _, err := api.NewUnixClient(sock).RevokeDevice(ctx, connect.NewRequest(&nodev1.RevokeDeviceRequest{Id: devA.ID})); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for status(a) != http.StatusNotFound {
		if time.Since(start) > 5*time.Second {
			t.Fatal("the revoked device's token is still taken: the API's change did not reach DoH's Forget")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := status(b); got != http.StatusMethodNotAllowed {
		t.Errorf("the sibling's token after the revocation: %d", got)
	}
}
