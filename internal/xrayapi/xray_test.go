package xrayapi_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/xrayapi"
)

// TestInnerWithXray runs the rendered inner config on a real Xray built from
// arngory/xray-core and manages its users through the API. Set XRAY_BIN.
func TestInnerWithXray(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("set XRAY_BIN to an Xray built from arngory/xray-core")
	}
	dir := t.TempDir()
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: filepath.Join(dir, "run"), Credentials: filepath.Join(dir, "cred")}
	for _, d := range []string{"inner", "inner-api"} {
		if err := os.MkdirAll(filepath.Join(paths.Run, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	seed := make([]byte, 64)
	rand.Read(seed)
	m := render.Model{
		Services: []render.Service{{
			Service: store.Service{ID: 1, Kind: "inner", Name: "inner", Enabled: true, Settings: "{}"},
			Secrets: map[string][]byte{provision.SecretMLKEMSeed: seed},
		}},
		Inner: map[int64]string{7: "6f1c2a3b-0000-4000-8000-000000000007"},
	}
	files, _, err := render.Render(m, paths)
	if err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "xray.json")
	if err := os.WriteFile(cfg, files[0].Content, 0o600); err != nil {
		t.Fatal(err)
	}

	if out, err := exec.Command(bin, "run", "-test", "-c", cfg).CombinedOutput(); err != nil {
		t.Fatalf("xray -test: %v\n%s", err, out)
	}
	cmd := exec.Command(bin, "run", "-c", cfg)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()

	api := paths.InnerAPISocket("inner")
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(api); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := xrayapi.Dial(api)

	users, err := c.VLESSUsers(ctx, render.InnerTag)
	if err != nil {
		t.Fatal(err)
	}
	if users["u7"] != m.Inner[7] {
		t.Fatalf("users from config: %v", users)
	}

	want := map[string]string{
		"u7": "6f1c2a3b-0000-4000-8000-000000000077", // rotated
		"u8": "6f1c2a3b-0000-4000-8000-000000000008", // new
	}
	added, removed, err := c.SyncVLESS(ctx, render.InnerTag, want)
	if err != nil {
		t.Fatal(err)
	}
	if added != 2 || removed != 1 {
		t.Fatalf("added %d removed %d", added, removed)
	}
	users, err = c.VLESSUsers(ctx, render.InnerTag)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(users)
	exp, _ := json.Marshal(want)
	if string(got) != string(exp) {
		t.Fatalf("after sync %s, want %s", got, exp)
	}
	if added, removed, err = c.SyncVLESS(ctx, render.InnerTag, want); err != nil || added+removed != 0 {
		t.Fatalf("second sync: +%d -%d %v", added, removed, err)
	}

	// A user added through the API gets through VLESS with ML-KEM-768.
	_, encryption, err := render.VLESSEncryption(seed)
	if err != nil {
		t.Fatal(err)
	}
	proxyThroughInner(t, bin, files[0].Content, encryption, want["u8"])
}

// proxyThroughInner runs a copy of the inner config on TCP (Xray clients
// cannot dial a unix socket) without the private-network block, and an Xray
// client in front of it, then fetches a local page through both.
func proxyThroughInner(t *testing.T, bin string, innerCfg []byte, encryption, id string) {
	var cfg map[string]any
	if err := json.Unmarshal(innerCfg, &cfg); err != nil {
		t.Fatal(err)
	}
	serverPort, socksPort := freePort(t), freePort(t)
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	in["listen"], in["port"] = "127.0.0.1", serverPort
	settings := in["settings"].(map[string]any)
	settings["clients"] = []map[string]string{{"id": id, "email": "u8"}}
	delete(cfg, "api")
	delete(cfg, "dns")
	delete(cfg, "routing")
	// Xray's freedom also refuses private targets by default; allow the
	// loopback page for this test only.
	cfg["outbounds"] = []map[string]any{{"protocol": "freedom", "settings": map[string]any{
		"finalRules": []map[string]any{{"action": "allow", "ip": []string{"127.0.0.0/8"}}}}}}
	server := writeJSON(t, cfg)

	client := writeJSON(t, map[string]any{
		"log":      map[string]string{"loglevel": "warning"},
		"inbounds": []map[string]any{{"listen": "127.0.0.1", "port": socksPort, "protocol": "socks", "settings": map[string]any{"udp": false}}},
		"outbounds": []map[string]any{{"protocol": "vless", "settings": map[string]any{
			"vnext": []map[string]any{{"address": "127.0.0.1", "port": serverPort,
				"users": []map[string]string{{"id": id, "encryption": encryption}}}}}}},
	})
	for _, c := range []string{server, client} {
		cmd := exec.Command(bin, "run", "-c", c)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	}

	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "through inner") }))
	defer page.Close()
	proxy, _ := url.Parse("socks5://127.0.0.1:" + strconv.Itoa(socksPort))
	hc := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 5 * time.Second}
	var lastErr error
	for i := 0; i < 30; i++ {
		resp, err := hc.Get(page.URL)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) != "through inner" {
				t.Fatalf("body %q", body)
			}
			return
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("no response through inner: %v", lastErr)
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func writeJSON(t *testing.T, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "cfg.json")
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}
