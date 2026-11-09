package xrayapi_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
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

// TestRevokeCutsXrayConnections: a user that SyncVLESS removes loses its open
// connections at once, not only new ones (arngory/xray-core
// raycontrol/v26.10.31: RemoveUser closes the user's connections). A pin to an
// Xray without that patch fails here. Set XRAY_BIN.
func TestRevokeCutsXrayConnections(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("set XRAY_BIN to an Xray built from arngory/xray-core")
	}
	dir := t.TempDir()
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: filepath.Join(dir, "run")}
	for _, d := range []string{"inner", "inner-api"} {
		if err := os.MkdirAll(filepath.Join(paths.Run, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	seed := make([]byte, 64)
	rand.Read(seed)
	const kept, gone = "6f1c2a3b-0000-4000-8000-000000000007", "6f1c2a3b-0000-4000-8000-000000000008"
	m := render.Model{
		Services: []render.Service{{
			Service: store.Service{ID: 1, Kind: "inner", Name: "inner", Enabled: true, Settings: "{}"},
			Secrets: map[string][]byte{provision.SecretMLKEMSeed: seed},
		}},
		Inner: map[int64]string{7: kept, 8: gone},
	}
	files, _, err := render.Render(m, paths)
	if err != nil {
		t.Fatal(err)
	}
	// The rendered inner config on TCP (Xray clients cannot dial a unix
	// socket), its API kept, the loopback target allowed for this test.
	var cfg map[string]any
	if err := json.Unmarshal(files[0].Content, &cfg); err != nil {
		t.Fatal(err)
	}
	serverPort := freePort(t)
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	in["listen"], in["port"] = "127.0.0.1", serverPort
	delete(cfg, "dns")
	delete(cfg, "routing")
	cfg["outbounds"] = []map[string]any{{"protocol": "freedom", "settings": map[string]any{
		"finalRules": []map[string]any{{"action": "allow", "ip": []string{"127.0.0.0/8"}}}}}}
	start := func(c string) {
		cmd := exec.Command(bin, "run", "-c", c)
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	}
	start(writeJSON(t, cfg))

	_, encryption, err := render.VLESSEncryption(seed)
	if err != nil {
		t.Fatal(err)
	}
	// A target that keeps every connection open and sends a byte a tick.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					if _, err := c.Write([]byte{'.'}); err != nil {
						return
					}
					time.Sleep(50 * time.Millisecond)
				}
			}()
		}
	}()
	// One Xray client per user, each a SOCKS inbound.
	stream := func(id string) net.Conn {
		port := freePort(t)
		start(writeJSON(t, map[string]any{
			"log":      map[string]string{"loglevel": "warning"},
			"inbounds": []map[string]any{{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"udp": false}}},
			"outbounds": []map[string]any{{"protocol": "vless", "settings": map[string]any{
				"vnext": []map[string]any{{"address": "127.0.0.1", "port": serverPort,
					"users": []map[string]string{{"id": id, "encryption": encryption}}}}}}},
			"policy": map[string]any{"levels": map[string]any{"0": map[string]int{"uplinkOnly": 0, "downlinkOnly": 0}}},
		}))
		tp := target.Addr().(*net.TCPAddr).Port
		for i := 0; i < 50; i++ {
			c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
			if err == nil {
				// SOCKS5, no auth, CONNECT 127.0.0.1:tp.
				req := []byte{5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, byte(tp >> 8), byte(tp)}
				buf := make([]byte, 12)
				c.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err = c.Write(req); err == nil {
					if _, err = io.ReadFull(c, buf); err == nil && buf[1] == 0 && buf[3] == 0 {
						if _, err = io.ReadFull(c, buf[:1]); err == nil {
							return c
						}
					}
				}
				c.Close()
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("no stream through inner for %s", id)
		return nil
	}
	keptConn, goneConn := stream(kept), stream(gone)
	defer keptConn.Close()
	defer goneConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := xrayapi.Dial(paths.APISocket("inner"))
	if _, removed, err := c.SyncVLESS(ctx, render.InnerTag, "", map[string]string{store.CredentialName(7, kept): kept}); err != nil || removed != 1 {
		t.Fatalf("sync: removed %d, %v", removed, err)
	}
	cut := time.Now()

	// The removed user's stream ends within a second; the other one goes on.
	goneConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 256)
	for {
		if _, err := goneConn.Read(buf); err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatal("the removed user's stream still runs 3 s after SyncVLESS")
			}
			break
		}
	}
	if d := time.Since(cut); d > time.Second {
		t.Fatalf("the removed user's stream ended %v after SyncVLESS", d)
	}
	keptConn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(keptConn, buf[:3]); err != nil {
		t.Fatalf("the remaining user's stream: %v", err)
	}
}
