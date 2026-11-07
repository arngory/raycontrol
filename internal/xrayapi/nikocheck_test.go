package xrayapi_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/testca"
)

// TestRenderedConfigsWithNikoServer renders a node with every service the
// niko-server front and backends serve, their options on (dnstt and
// masterdns with dnsauth and the seal required, the probe and the apex,
// Brutal ceilings, Yggdrasil peers), and has the pinned niko-server check
// the front's config and every backend's. An option the pinned version
// does not know fails here, not on a node, where the front refuses its
// whole config and TCP 443, UDP 443 and UDP 53 go down with it. Set
// NIKO_SERVER_BIN.
func TestRenderedConfigsWithNikoServer(t *testing.T) {
	niko := os.Getenv("NIKO_SERVER_BIN")
	if niko == "" {
		t.Skip("set NIKO_SERVER_BIN to the pinned niko-server")
	}
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.test"}); err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for _, s := range []store.Service{
		{Kind: "reality", Name: "reality"},
		{Kind: "hy2-obfs", Name: "hy2o"},
		{Kind: "hy2-masq", Name: "hy2m"},
		{Kind: "naive", Name: "naive"},
		{Kind: "doh", Name: "doh"},
		{Kind: "yggdrasil", Name: "ygg"},
		{Kind: "dnstt", Name: "dns"},
		{Kind: "masterdns", Name: "mdns"},
		// The front's zone with the tag check (niko-server v0.13.0).
		{Kind: "slipstream", Name: "slip"},
	} {
		s.Enabled = true
		svc, err := provision.CreateService(ctx, st, s)
		if err != nil {
			t.Fatalf("%s: %v", s.Kind, err)
		}
		ids = append(ids, svc.ID)
	}
	for _, o := range [][3]string{
		{"dns", "auth", "required"},
		{"dns", "seal", "required"},
		{"mdns", "auth", "required"},
		{"mdns", "seal", "required"},
		{"hy2o", "up_mbps", "100"},
		{"hy2m", "down_mbps", "50"},
		{"ygg", "peers", "tls://192.0.2.10:443"},
		{"reality", "open", "true"},
		// Spare zones (niko-server v0.11.0): dnstt's options.zones, front
		// entries, masterdns's list.
		{"dns", "spare_zones", "2"},
		{"mdns", "spare_zones", "1"},
	} {
		if _, err := provision.SetServiceOption(ctx, st, o[0], o[1], o[2]); err != nil {
			t.Fatalf("%s %s=%s: %v", o[0], o[1], o[2], err)
		}
	}
	// A switched seal key: the file holds two.
	if _, err := provision.RotateSealKey(ctx, st, "dns", time.Now(), time.Hour, false); err != nil {
		t.Fatal(err)
	}
	ca, err := testca.New([]string{"*.example.test", "example.test"}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provision.SetCertificate(ctx, st, "site", ca.ChainPEM, ca.KeyPEM, time.Now()); err != nil {
		t.Fatal(err)
	}
	st.SetSetting(ctx, "dns_ns_name", []byte("ns9.example.test"))
	if _, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	st.SetUserServices(ctx, "alice", ids)
	if _, _, err := st.CreateDevice(ctx, "alice", "phone", "user"); err != nil {
		t.Fatal(err)
	}

	m, err := render.CollectForRender(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: filepath.Join(dir, "run")}
	files, skipped, err := render.Render(m, paths)
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped: %v", skipped)
	}
	var configs []string
	for _, f := range files {
		if err := os.MkdirAll(filepath.Dir(f.Path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.Path, f.Content, 0o600); err != nil {
			t.Fatal(err)
		}
		if base := filepath.Base(f.Path); base == "front.json" || base == "backend.json" {
			configs = append(configs, f.Path)
		}
	}
	// The front (its routes take naive and DoH to rayd), and a backend for
	// each of the others.
	for _, want := range []string{"front", "hy2o", "hy2m", "ygg", "dns", "mdns"} {
		if !strings.Contains(strings.Join(configs, " "), "/"+want+"/") {
			t.Errorf("no config of %s among %v", want, configs)
		}
	}
	for _, c := range configs {
		out, err := exec.Command(niko, "check", "-c", c).CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != "ok" {
			t.Errorf("niko-server check %s: %v\n%s", strings.TrimPrefix(c, dir), err, out)
		}
	}
}
