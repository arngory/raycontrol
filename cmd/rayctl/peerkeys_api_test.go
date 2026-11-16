package main

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/api"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// rayctl service peer-keys and relay ports against a real rayd API on a
// store: the keys printed are the node's and the users file's, each once;
// the relay's ports name its SSH and what it forwards.
func TestPeerKeysAndRelayPortsAPI(t *testing.T) {
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
	run := func(args ...string) string {
		t.Helper()
		out, _, err := captureBoth(t, func() error { return c.run(ctx, args) })
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return out
	}
	for _, s := range []store.Service{{Kind: "reality", Name: "reality"}, {Kind: "yggdrasil", Name: "ygg"}, {Kind: "hy2-masq", Name: "hy2"},
		{Kind: "api", Name: "api"}} {
		s.Enabled = true
		if _, err := provision.CreateService(ctx, st, s); err != nil {
			t.Fatal(err)
		}
	}
	run("user", "add", "alice", "-services", "ygg,hy2")
	run("device", "add", "alice", "phone")
	run("device", "add", "alice", "laptop")

	out := run("service", "peer-keys", "ygg")
	t.Logf("rayctl service peer-keys ygg:\n%s", out)
	m, err := render.CollectForRender(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	var ygg, inner render.Service
	for _, s := range m.Services {
		switch s.Kind {
		case "yggdrasil":
			ygg = s
		case "inner":
			inner = s
		}
	}
	_, nodeKey, _ := render.YggdrasilNode(ygg)
	want := []string{hex.EncodeToString(nodeKey)}
	for _, p := range render.YggdrasilPeers(m, ygg, inner) {
		want = append(want, hex.EncodeToString(p.Key))
	}
	if len(want) != 4 {
		t.Fatalf("%d keys", len(want))
	}
	for _, k := range want {
		if strings.Count(out, `"`+k+`"`) != 1 {
			t.Errorf("key %s not once in\n%s", k, out)
		}
	}
	if strings.Count(out, "\n  \"") != len(want) || !strings.HasPrefix(strings.SplitN(out, "AllowedPublicKeys: [\n", 2)[1], "  # the node (") {
		t.Errorf("the block:\n%s", out)
	}
	// Labels, no names, unless -names.
	for _, p := range render.YggdrasilPeers(m, ygg, inner) {
		if !strings.Contains(out, "  # "+p.Label+": ") {
			t.Errorf("no label %s in\n%s", p.Label, out)
		}
	}
	for _, name := range []string{"alice", "phone", "laptop"} {
		if strings.Contains(out, name) {
			t.Errorf("%s named without -names:\n%s", name, out)
		}
	}
	named := run("service", "peer-keys", "-names", "ygg")
	for _, line := range []string{"user alice, the user's own key", "user alice, device laptop", "user alice, device phone"} {
		if !strings.Contains(named, line) {
			t.Errorf("-names: no %q in\n%s", line, named)
		}
	}

	run("relay", "add", "msk", "198.51.100.20")
	out = run("relay", "ports", "msk")
	t.Logf("rayctl relay ports msk:\n%s", out)
	lines := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		lines[strings.Join(fields(l), "|")] = true
	}
	for _, line := range []string{"tcp|22|ssh|relay host|the relay's admin addresses; after the knock for SSH devices",
		"tcp|443|reality|the exit|after the knock", "udp|443|hy2|the exit|after the knock"} {
		if !lines[line] {
			t.Errorf("no %q in\n%s", line, out)
		}
	}
	if !strings.Contains(out, "no SPA range yet") {
		t.Errorf("no word of the SPA range:\n%s", out)
	}

	// The bundle (root: rayd answers root's socket only) names them all
	// on stderr, the SPA range and the probe endpoint with them.
	if os.Geteuid() != 0 {
		t.Skip("relay bundle: root only")
	}
	bundle := filepath.Join(dir, "msk.bundle")
	_, stderr, err := captureBoth(t, func() error {
		return c.run(ctx, []string{"relay", "bundle", "-exit", "203.0.113.7", "-admin", "192.0.2.7", "-ssh-port", "2200", "-o", bundle, "msk"})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("rayctl relay bundle -exit 203.0.113.7 -admin 192.0.2.7 -ssh-port 2200 -o msk.bundle msk (stderr):\n%s", stderr)
	var spa, probe bool
	for _, l := range strings.Split(stderr, "\n") {
		f := fields(l)
		spa = spa || len(f) == 5 && f[0] == "tcp+udp" && strings.Contains(f[1], "-") && f[2] == "spa" && f[3] == "relay host" && f[4] == "everyone"
		probe = probe || len(f) == 5 && f[0] == "tcp+udp" && f[2] == "probe" && f[3] == "relay host" && f[4] == "after the knock"
	}
	if !spa || !probe || !strings.Contains(stderr, "lets in all of these") || !strings.Contains(stderr, "tcp      2200") {
		t.Errorf("relay bundle's stderr:\n%s", stderr)
	}
	after := run("relay", "ports", "msk")
	for _, l := range strings.Split(after, "\n") {
		if strings.Contains(l, " spa ") && !strings.Contains(stderr, l) {
			t.Errorf("relay ports names another SPA range: %q", l)
		}
	}
}
