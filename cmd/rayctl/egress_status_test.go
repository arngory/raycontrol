package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/api"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/hostcheck"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
)

// rayctl egress lists what the local part lets through: a REALITY target
// on a local address, for its process only.
func TestLocalExemptLines(t *testing.T) {
	got := localExemptLines([]*nodev1.Service{
		{Kind: "reality", Name: "steal", Enabled: true, Uid: 9120, SettingsJson: `{"target":"127.0.0.1:8443","sni":"www.example.org"}`},
		{Kind: "reality", Name: "public", Enabled: true, Uid: 9121, SettingsJson: `{"target":"www.example.org:443"}`},
	})
	if len(got) != 1 || !strings.HasPrefix(got[0], "tcp 127.0.0.1:8443: REALITY steal's target, for its process only (uid 9120)") {
		t.Fatalf("%q", got)
	}
}

// localhost is both loopbacks: Xray's resolver may take either.
func TestLocalExemptLinesLocalhost(t *testing.T) {
	got := localExemptLines([]*nodev1.Service{
		{Kind: "reality", Name: "nginx", Enabled: true, Uid: 9120, SettingsJson: `{"target":"localhost:8443","sni":"www.example.org"}`},
	})
	if len(got) != 2 || !strings.HasPrefix(got[0], "tcp 127.0.0.1:8443: REALITY nginx's target") || !strings.HasPrefix(got[1], "tcp [::1]:8443: REALITY nginx's target") {
		t.Fatalf("%q", got)
	}
}

// rayctl check and the update's first look name the REALITY services
// whose target the data plane does not reach, made before the checks of
// v0.27.0 (here 0.0.0.0, written to the store as an older rayd did), with
// the command that fixes each; not one it reaches (its exemption).
func TestRealityTargetWarnings(t *testing.T) {
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
	for i, target := range []string{"0.0.0.0:8443", "127.0.0.1:8443", "localhost:9443"} {
		if _, err := st.CreateService(ctx, store.Service{Kind: "reality", Name: fmt.Sprintf("r%d", i), Enabled: true,
			Settings: fmt.Sprintf(`{"target":%q,"sni":"www.example.org","ports":["tcp/%d"]}`, target, 8000+i)}); err != nil {
			t.Fatal(err)
		}
	}
	c := &cli{c: api.NewUnixClient(sock)}
	ws := c.realityTargetWarnings(ctx)
	if len(ws) != 1 || ws[0].service != "r0" || !strings.Contains(ws[0].problem, "REALITY r0 answers no client and no prober: reality target 0.0.0.0:8443") ||
		ws[0].fix != "rayctl service set r0 target=127.0.0.1:8443" {
		t.Fatalf("%+v", ws)
	}
	if rs := realityTargetResults(ws); len(rs) != 1 || rs[0].OK || rs[0].Level != hostcheck.Advised || rs[0].Name != "reality target r0" || rs[0].Fix != ws[0].fix {
		t.Fatalf("check: %+v", rs)
	}
	text, err := captured(t, func() error { return c.targetsFirst(ctx, func(string) error { return nil })("v0.27.0") })
	if err != nil || !strings.HasPrefix(text, "warning: REALITY r0 answers no client and no prober: ") || !strings.HasSuffix(text, ": rayctl service set r0 target=127.0.0.1:8443\n") {
		t.Fatalf("update: %q %v", text, err)
	}
	if ws := (&cli{}).realityTargetWarnings(ctx); ws != nil {
		t.Fatalf("no rayd: %+v", ws)
	}
	// From a rayd before v0.27.0 (no local part), the update blocks them.
	for _, c := range []struct {
		version string
		local   bool
		want    bool
	}{{"v0.26.3", false, true}, {"v0.27.0", false, false}, {"v0.27.0", true, true}, {"test", false, false}, {"", true, true}} {
		if got := localBlocked(c.version, c.local); got != c.want {
			t.Errorf("localBlocked(%q, %v) = %v", c.version, c.local, got)
		}
	}
}

// rayctl status's egress line says what is true: on a node with a
// perimeter the policy, on one of rayd serve -supervise that nothing of
// it is the kernel's there (no rayspa by default, and the local part never
// covers rayd's UID).
func TestEgressStatusLine(t *testing.T) {
	e := &nodev1.Egress{Local: true, Smtp: true}
	if got := egressStatusLine(e, false); got != "blocked: smtp (tcp 25), local networks (rayctl egress)" {
		t.Errorf("a node: %q", got)
	}
	got := egressStatusLine(e, true)
	for _, want := range []string{"set: blocked: smtp (tcp 25), local networks;", "local networks: not in the kernel here",
		"smtp and bittorrent: only where a rayspa runs", "(rayctl egress)"} {
		if !strings.Contains(got, want) {
			t.Errorf("supervised: %q lacks %q", got, want)
		}
	}
	if strings.HasPrefix(got, "blocked") {
		t.Errorf("supervised reads as blocked: %q", got)
	}
	if got := egressStatusLine(&nodev1.Egress{}, true); got != "set: nothing blocked (rayctl egress)" {
		t.Errorf("supervised, nothing set: %q", got)
	}
}
