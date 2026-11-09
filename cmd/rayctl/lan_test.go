package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/api"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
)

// captured runs f with the standard output in a pipe and returns what it
// printed.
func captured(t *testing.T, f func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	ferr := f()
	os.Stdout = saved
	w.Close()
	return <-done, ferr
}

// rayctl user lan NAME [on|off], device list's LAN column and service set
// lan_relay (lan-v1 §6) against a real rayd API on a store.
func TestLANCommands(t *testing.T) {
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
	srv := &api.Server{Store: st, Params: params, Version: "test"}
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
	run := func(args ...string) (string, error) {
		t.Helper()
		return captured(t, func() error { return c.run(ctx, args) })
	}
	for _, s := range []store.Service{{Kind: "reality", Name: "reality"}, {Kind: "yggdrasil", Name: "ygg"}, {Kind: "hy2-masq", Name: "hy2"}} {
		s.Enabled = true
		if _, err := provision.CreateService(ctx, st, s); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{
		{"user", "add", "alice", "-services", "ygg"}, {"user", "add", "bob", "-services", "hy2"},
		{"device", "add", "alice", "phone"},
	} {
		if _, err := run(args...); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}

	if out, err := run("user", "lan", "alice"); err != nil || out != "alice: LAN off\n" {
		t.Fatalf("show: %q %v", out, err)
	}
	if out, err := run("user", "lan", "alice", "on"); err != nil || !strings.Contains(out, "alice: LAN on, a new password") {
		t.Fatalf("on: %q %v", out, err)
	}
	if out, err := run("user", "lan", "alice"); err != nil || out != "alice: LAN on\n" {
		t.Fatalf("show: %q %v", out, err)
	}
	if _, err := run("user", "lan", "bob", "on"); err == nil || !strings.Contains(err.Error(), "no Yggdrasil service") {
		t.Fatalf("bob without Yggdrasil: %v", err)
	}
	for _, args := range [][]string{{"user", "lan"}, {"user", "lan", "alice", "yes"}, {"user", "lan", "alice", "on", "now"}} {
		if _, err := run(args...); !errors.Is(err, errUsage) {
			t.Errorf("%v: %v", args, err)
		}
	}
	if _, err := run("user", "lan", "nobody"); err == nil {
		t.Error("nobody shown")
	}
	c.json = true
	if out, err := run("user", "lan", "alice"); err != nil || !strings.Contains(strings.Join(strings.Fields(out), " "), `"lan": true`) { // protojson varies its spaces
		t.Fatalf("-json: %q %v", out, err)
	}
	c.json = false

	// The device's own consent, as its header last said.
	out, err := run("device", "list", "alice")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if err != nil || len(lines) != 2 || strings.Join(strings.Fields(lines[0]), " ") != "ID USER NAME ROLE CREATED REVOKED LAN API" ||
		strings.Fields(lines[1])[7] != "off" {
		t.Fatalf("device list:\n%s %v", out, err)
	}
	devs, _ := st.ListDevices(ctx, "alice")
	if _, err := st.SetDeviceLAN(ctx, devs[0].ID, true, store.LANShowEvery); err != nil {
		t.Fatal(err)
	}
	if out, _ = run("device", "list"); !strings.Contains(strings.Join(strings.Fields(out), " "), "phone user") ||
		strings.Fields(strings.Split(out, "\n")[1])[7] != "on" {
		t.Fatalf("device list:\n%s", out)
	}

	if out, err := run("service", "set", "ygg", "lan_relay=0"); err != nil || !strings.Contains(out, `"lan_relay":0`) ||
		!strings.Contains(out, "up to 0 Mbit/s a user (0: between devices in one Wi-Fi only)") {
		t.Fatalf("lan_relay=0: %q %v", out, err)
	}
	if _, err := run("service", "set", "ygg", "lan_relay=-1"); err == nil {
		t.Fatal("lan_relay=-1")
	}
	if _, err := run("user", "lan", "alice", "off"); err != nil {
		t.Fatal(err)
	}

	// Every change is audited, the refused one too; the device's header is
	// not (lan-v1 §4.3).
	audit, err := st.ListAudit(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range audit {
		if strings.HasPrefix(e.Action, "user.lan") || strings.Contains(e.Action, "lan_relay") {
			got = append(got, e.Action+" "+e.Target+" "+strings.SplitN(e.Result, ":", 2)[0])
		}
	}
	want := []string{"user.lan=off alice ok", "service.set lan_relay=-1 ygg error", "service.set lan_relay=0 ygg ok",
		"user.lan=on bob error", "user.lan=on alice ok"}
	if strings.Join(got, "; ") != strings.Join(want, "; ") {
		t.Fatalf("audit %q", got)
	}
}
