package xrayapi_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/connlimit"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/traffic"
	"github.com/arngory/raycontrol/internal/xrayapi"
)

// TestConnLimitWithXray: the inner config rendered with the connection
// limits on (spec/conn-limit-v1.md §3.3) and no traffic limit runs on the
// pinned fork, which takes its policy.levels.0.limits and stats; with the
// limit of connections at once lowered to one, a user's second connection
// is refused, the fork counts it as user>>>u<id>>>>limit>>>tcp, and rayd's
// monitor reads it as a refusal of u<id> on inner. Set XRAY_BIN.
func TestConnLimitWithXray(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("set XRAY_BIN to an Xray built from arngory/xray-core")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dir := t.TempDir()
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: filepath.Join(dir, "run")}
	for _, d := range []string{"inner", "inner-api"} {
		if err := os.MkdirAll(filepath.Join(paths.Run, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	seed := make([]byte, 64)
	rand.Read(seed)
	const id = "6f1c2a3b-0000-4000-8000-000000000009"
	const user = 9
	m := render.Model{
		Services: []render.Service{{Service: store.Service{ID: 1, Kind: "inner", Name: "inner", Enabled: true},
			Secrets: map[string][]byte{provision.SecretMLKEMSeed: seed}}},
		Inner: map[int64]string{user: id},
	}
	files, _, err := render.Render(m, paths)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(files[0].Content, &cfg); err != nil {
		t.Fatal(err)
	}
	level := cfg["policy"].(map[string]any)["levels"].(map[string]any)["0"].(map[string]any)
	limits := level["limits"].(map[string]any)
	if cfg["stats"] == nil || limits["connections"] != float64(1024) || limits["foldAt"] != "-" || level["statsUserUplink"] != nil {
		t.Fatalf("rendered:\n%s", files[0].Content)
	}
	// The rendered limits, one connection at once instead of 1024; on TCP
	// (an Xray client cannot dial a unix socket), the loopback target
	// allowed.
	limits["connections"] = 1
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
	api := paths.APISocket("inner")
	waitFile(t, api)

	// rayd's monitor over the real process: just started, so its first
	// reading counts (nothing yet).
	mon := &connlimit.Monitor{Proc: t.TempDir(), Sources: func(context.Context) ([]connlimit.Source, error) {
		return []connlimit.Source{{Service: "inner", SameRun: traffic.SameBoot, Read: func(ctx context.Context) (connlimit.Reading, error) {
			r, err := traffic.ReadXray(ctx, api)
			return connlimit.Reading{Boot: r.Boot, Age: r.Age, AgeKnown: r.AgeKnown, Limits: r.Limits}, err
		}}}, nil
	}}
	mon.Round(ctx)
	if s := mon.Snapshot(); len(s.Users) != 0 || len(s.Services) != 1 {
		t.Fatalf("before: %+v", s)
	}

	// A target that holds what it accepts.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	_, encryption, err := render.VLESSEncryption(seed)
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	start(writeJSON(t, map[string]any{
		"log":      map[string]string{"loglevel": "warning"},
		"inbounds": []map[string]any{{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"udp": false}}},
		"outbounds": []map[string]any{{"protocol": "vless", "settings": map[string]any{
			"vnext": []map[string]any{{"address": "127.0.0.1", "port": serverPort,
				"users": []map[string]string{{"id": id, "encryption": encryption}}}}}}},
	}))
	// open asks the client's SOCKS for the target and sends a byte, which
	// carries the VLESS request to inner.
	tp := target.Addr().(*net.TCPAddr).Port
	open := func() net.Conn {
		t.Helper()
		for range 50 {
			c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			c.SetDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 12)
			if _, err = c.Write([]byte{5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, byte(tp >> 8), byte(tp)}); err == nil {
				if _, err = io.ReadFull(c, buf); err == nil && buf[1] == 0 && buf[3] == 0 {
					if _, err = c.Write([]byte("x")); err == nil {
						return c
					}
				}
			}
			c.Close()
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("no SOCKS stream")
		return nil
	}
	// The first connection: through to the target, and held. The client's
	// first connection to inner may fail (its 0-RTT ticket): try again.
	var first net.Conn
	for i := 0; first == nil; i++ {
		c := open()
		select {
		case held := <-accepted:
			defer held.Close()
			first = c
		case <-time.After(3 * time.Second):
			c.Close()
			if i == 3 {
				t.Fatal("the first connection never reached the target")
			}
		}
	}
	defer first.Close()
	// The second at once: refused, closed with no data, never dialed.
	second := open()
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := second.Read(make([]byte, 1)); err == nil || n != 0 {
		t.Fatalf("the second connection read %d bytes, %v", n, err)
	}
	select {
	case c := <-accepted:
		c.Close()
		t.Fatal("the second connection reached the target")
	case <-time.After(300 * time.Millisecond):
	}

	// The refusal in Xray's stats, by base name, and in rayd's monitor.
	name := "u" + strconv.Itoa(user)
	var r xrayapi.StatsReading
	for range 50 {
		if r, err = xrayapi.DialStats(api).Read(ctx); err == nil && r.Limits[name]["tcp"] > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || r.Limits[name]["tcp"] < 1 || len(r.Users) != 0 {
		t.Fatalf("stats: limits %v users %v %v", r.Limits, r.Users, err)
	}
	mon.Round(ctx)
	s := mon.Snapshot()
	if len(s.Users) != 1 || s.Users[0].ID != user || s.Users[0].Service != "inner" || s.Refused[[2]string{"inner", "tcp"}] != uint64(r.Limits[name]["tcp"]) {
		t.Fatalf("monitor: %+v", s)
	}
}
