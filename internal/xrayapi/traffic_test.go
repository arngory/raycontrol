package xrayapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/traffic"
	"github.com/arngory/raycontrol/internal/xrayapi"
)

// TestTrafficWithXray: the inner config rendered with counting on
// (traffic-limit-v1 §2.1) makes a real Xray count a user's bytes through
// VLESS, and rayd's traffic loop reads them from its API socket, adds them
// to the user's period, leaves no connection behind its reads, tells a
// restart of Xray, and takes the user off once over the limit. Set
// XRAY_BIN.
func TestTrafficWithXray(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("set XRAY_BIN to an Xray built from arngory/xray-core")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	inner, err := st.CreateService(ctx, store.Service{Kind: "inner", Name: "inner", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	dns, err := st.CreateService(ctx, store.Service{Kind: "dnstt", Name: "dns", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	limit := int64(1 << 20)
	u, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true, TrafficLimit: &limit})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserServices(ctx, "alice", []int64{dns.ID}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // the limit a second before Xray starts

	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: filepath.Join(dir, "run")}
	for _, d := range []string{"inner", "inner-api"} {
		if err := os.MkdirAll(filepath.Join(paths.Run, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	seed := make([]byte, 64)
	rand.Read(seed)
	const id = "6f1c2a3b-0000-4000-8000-000000000007"
	m := render.Model{
		Services: []render.Service{{Service: inner, Secrets: map[string][]byte{provision.SecretMLKEMSeed: seed}}},
		Inner:    map[int64]string{u.ID: id},
		Traffic:  true,
	}
	files, _, err := render.Render(m, paths)
	if err != nil {
		t.Fatal(err)
	}
	// The rendered config on TCP (an Xray client cannot dial a unix
	// socket), its API and stats kept, the loopback target allowed.
	var cfg map[string]any
	if err := json.Unmarshal(files[0].Content, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["stats"] == nil {
		t.Fatalf("no stats:\n%s", files[0].Content)
	}
	serverPort := freePort(t)
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	in["listen"], in["port"] = "127.0.0.1", serverPort
	delete(cfg, "dns")
	delete(cfg, "routing")
	cfg["outbounds"] = []map[string]any{{"protocol": "freedom", "settings": map[string]any{
		"finalRules": []map[string]any{{"action": "allow", "ip": []string{"127.0.0.0/8"}}}}}}
	start := func(c string) *exec.Cmd {
		cmd := exec.Command(bin, "run", "-c", c)
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
		return cmd
	}
	serverCfg := writeJSON(t, cfg)
	server := start(serverCfg)
	api := paths.APISocket("inner")
	waitFile(t, api)

	// The loop over the store, its source the real process.
	hb := &health.Board{}
	woken := 0
	acct := &traffic.Accountant{Store: st, Sources: traffic.Processes(paths), Health: hb, Notify: func() { woken++ }}
	round := func() {
		t.Helper()
		acct.Round(ctx, "", true)
		for _, l := range hb.Loops() {
			if l.Failing() {
				t.Fatalf("loop %s: %s", l.Name, l.Err)
			}
		}
	}
	round()

	// A target that takes as many bytes as the client says in its first
	// four and answers three times as many.
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
				var n [4]byte
				if _, err := io.ReadFull(c, n[:]); err != nil {
					return
				}
				size := int64(binary.BigEndian.Uint32(n[:]))
				if _, err := io.CopyN(io.Discard, c, size-4); err != nil {
					return
				}
				_, _ = c.Write(bytes.Repeat([]byte("d"), int(3*size)))
			}()
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
	// try sends up bytes through inner and takes three times as many back.
	try := func(up int) error {
		tp := target.Addr().(*net.TCPAddr).Port
		var conn net.Conn
		for i := 0; i < 50 && conn == nil; i++ {
			c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			req := []byte{5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, byte(tp >> 8), byte(tp)}
			buf := make([]byte, 12)
			c.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err = c.Write(req); err == nil {
				if _, err = io.ReadFull(c, buf); err == nil && buf[1] == 0 && buf[3] == 0 {
					conn = c
					break
				}
			}
			c.Close()
			time.Sleep(100 * time.Millisecond)
		}
		if conn == nil {
			return errors.New("no stream through inner")
		}
		defer conn.Close()
		msg := bytes.Repeat([]byte("u"), up)
		binary.BigEndian.PutUint32(msg, uint32(up)) //nolint:gosec // G115: a test's size
		if _, err := conn.Write(msg); err != nil {
			return err
		}
		_, err := io.ReadFull(conn, make([]byte, 3*up))
		return err
	}
	transfer := func(up int) {
		t.Helper()
		// The client's first connection to a restarted Xray fails (its
		// 0-RTT ticket is the old process's): the next one goes.
		var err error
		for range 5 {
			if err = try(up); err == nil {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatal(err)
	}
	const upload = 100 << 10
	transfer(upload)

	// Xray's counters: the payload each way, at the destination's side.
	users, uptime, err := xrayapi.DialStats(api).Users(ctx)
	if err != nil || uptime > time.Minute {
		t.Fatalf("stats: %v %v", users, err)
	}
	if c := users[store.CredentialName(u.ID, id)]; c.Up != upload || c.Down != 3*upload {
		t.Fatalf("Xray counted %+v, want %d/%d", c, upload, 3*upload)
	}
	round()
	got, _ := st.UserByName(ctx, "alice")
	if got.TrafficUp != upload || got.TrafficDown != 3*upload || got.OverLimit(time.Now()) {
		t.Fatalf("the loop counted %d/%d", got.TrafficUp, got.TrafficDown)
	}

	// Read again, many times: nothing twice, and no connection left open
	// by a read, in rayd or in Xray.
	fds := func() int {
		e, _ := os.ReadDir("/proc/" + strconv.Itoa(server.Process.Pid) + "/fd")
		return len(e)
	}
	runtime.GC()
	g0, f0 := runtime.NumGoroutine(), fds()
	for range 300 {
		if _, err := traffic.ReadXray(ctx, api); err != nil {
			t.Fatal(err)
		}
		round()
	}
	time.Sleep(200 * time.Millisecond)
	if g, f := runtime.NumGoroutine(), fds(); g > g0+5 || f > f0+5 {
		t.Fatalf("after 600 reads: goroutines %d -> %d, Xray's files %d -> %d", g0, g, f0, f)
	}
	if again, _ := st.UserByName(ctx, "alice"); again.TrafficUp != upload || again.TrafficDown != 3*upload {
		t.Fatalf("again %d/%d", again.TrafficUp, again.TrafficDown)
	}

	// Xray restarts (a new socket, counters from zero): the loop reaches
	// it again and counts its new counters whole.
	server.Process.Kill()
	server.Wait()
	_ = os.Remove(api)
	server = start(serverCfg)
	waitFile(t, api)
	for i := 0; ; i++ { // its inbound up
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(serverPort), time.Second)
		if err == nil {
			c.Close()
			break
		}
		if i == 50 {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	const again = 10 << 10
	transfer(again)
	round()
	if got, _ = st.UserByName(ctx, "alice"); got.TrafficUp != upload+again || got.TrafficDown != 3*(upload+again) {
		t.Fatalf("after Xray's restart %d/%d, want %d/%d", got.TrafficUp, got.TrafficDown, upload+again, 3*(upload+again))
	}

	// A limit under the count: off at the next poll, apply woken.
	low := int64(200 << 10)
	if _, err := st.SetUserTraffic(ctx, "alice", store.TrafficChange{Limit: &low}); err != nil {
		t.Fatal(err)
	}
	acct.Round(ctx, "", false)
	if got, _ = st.UserByName(ctx, "alice"); got.Active(time.Now()) || woken != 1 {
		t.Fatalf("active %v, woken %d", got.Active(time.Now()), woken)
	}
}
