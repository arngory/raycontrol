package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/api"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
)

// rayctl device revoke -overlap against a real rayd API: refused, nothing
// revoked, by a node of a release before v0.31.0; on a later one the
// device is revoked with overlap, a warning on stderr when it was its
// user's last active device; a plain revoke of it after says until when
// what it knew is still accepted.
func TestDeviceRevokeOverlapAPI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	params, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetRotation(ctx, store.DefaultRotation); err != nil {
		t.Fatal(err)
	}
	srv := &api.Server{Store: st, Params: params, Version: "v0.30.2"}
	sock := filepath.Join(dir, "rayd.sock")
	served := make(chan error, 1)
	go func() { served <- srv.ServeUnix(ctx, sock, api.PeerPolicy{}) }()
	t.Cleanup(func() {
		cancel()
		<-served
		st.Close()
	})
	for range 100 {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	c := &cli{c: api.NewUnixClient(sock)}
	svc, err := provision.CreateService(ctx, st, store.Service{Kind: "hy2-obfs", Name: "hy2", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true, Services: []int64{svc.ID}}); err != nil {
		t.Fatal(err)
	}
	phone, _, _ := st.CreateDevice(ctx, "alice", "phone", "user")
	laptop, _, _ := st.CreateDevice(ctx, "alice", "laptop", "user")
	if _, err := st.Credentials(ctx, svc.ID, []int64{1}, store.NewUUID); err != nil {
		t.Fatal(err)
	}
	// The revocations a minute after the credentials were made, as on a
	// node: one in their own second would not tell a rotation in flight.
	st.SetClock(func() time.Time { return time.Now().Add(time.Minute) })
	run := func(args ...string) (string, string, error) {
		t.Helper()
		return captureBoth(t, func() error { return c.run(ctx, args) })
	}

	// v0.30.2: refused, the phone still active.
	if _, _, err := run("device", "revoke", "-overlap", phone.ID); err == nil || !strings.Contains(err.Error(), "Nothing revoked") {
		t.Fatalf("against v0.30.2: %v", err)
	}
	if _, _, err := st.ActiveDevice(ctx, phone.ID); err != nil {
		t.Fatalf("the phone was revoked: %v", err)
	}

	// v0.31.0: revoked with overlap; the laptop stays, so no warning.
	srv.Version = "v0.31.0"
	out, errOut, err := run("device", "revoke", phone.ID, "-overlap")
	if err != nil || !strings.Contains(out, "revoked with overlap") || errOut != "" {
		t.Fatalf("with overlap: %q %q %v", out, errOut, err)
	}
	// Again, without overlap: still accepted until the end of the grace.
	out, _, err = run("device", "revoke", phone.ID)
	if err != nil || !strings.Contains(out, "revoked already, with overlap") || !strings.Contains(out, "rayctl user renew alice") {
		t.Fatalf("again: %q %v", out, err)
	}
	// The last device: a warning on stderr.
	out, errOut, err = run("device", "revoke", "-overlap", laptop.ID)
	if err != nil || !strings.Contains(out, "revoked with overlap") || !strings.Contains(errOut, "was alice's last active device") {
		t.Fatalf("the last device: %q %q %v", out, errOut, err)
	}
}
