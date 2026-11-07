package xrayapi_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/dnsstats"
	nodepkg "github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
)

// TestSlipstreamWithNikoServer: a slipstream service as rendered
// (spec/slipstream-v1.md), the whole path. The client of the fork
// (client/pin-alpn-sni), built from the subscription's link with the
// device's dnsauth-v2 key, reaches the pinned slipstream server through
// the pinned niko-server front, which checks every query's tag; an Xray
// client then carries VLESS through the tunnel into inner and fetches a
// page. A client without the key gets nowhere: the front counts its
// queries untagged and the server sees none. Set XRAY_BIN,
// NIKO_SERVER_BIN (v0.13.0 or later), SLIPSTREAM_SERVER_BIN and
// SLIPSTREAM_CLIENT_BIN.
func TestSlipstreamWithNikoServer(t *testing.T) {
	bin, niko := os.Getenv("XRAY_BIN"), os.Getenv("NIKO_SERVER_BIN")
	server, client := os.Getenv("SLIPSTREAM_SERVER_BIN"), os.Getenv("SLIPSTREAM_CLIENT_BIN")
	if bin == "" || niko == "" || server == "" || client == "" {
		t.Skip("set XRAY_BIN, NIKO_SERVER_BIN, SLIPSTREAM_SERVER_BIN and SLIPSTREAM_CLIENT_BIN")
	}
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := provision.Init(ctx, st, provision.Options{Host: "127.0.0.1", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	slip, err := provision.CreateService(ctx, st, store.Service{Kind: "slipstream", Name: "slip", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	st.SetUserServices(ctx, "alice", []int64{slip.ID})
	_, devKey, err := st.CreateDevice(ctx, "alice", "phone", "user")
	if err != nil {
		t.Fatal(err)
	}
	params, err := nodepkg.LoadParams(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	m, err := render.CollectForRender(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	// Short paths: unix sockets take 107 bytes.
	run, err := os.MkdirTemp("", "rc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(run)
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: run}
	files, _, err := render.Render(m, paths)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		os.MkdirAll(filepath.Dir(f.Path), 0o755)
		if err := os.WriteFile(f.Path, f.Content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// What systemd and tmpfiles make for the units.
	for _, d := range []string{"inner", "inner-api", "slip", "front"} {
		os.MkdirAll(filepath.Join(run, d), 0o700)
	}
	os.MkdirAll(paths.FrontDir("slip"), 0o700)
	copyFile := func(from, to string) {
		t.Helper()
		b, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(to, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	copyFile(filepath.Join(paths.Rendered, "slip", render.SlipstreamKey), paths.Credential("slip", render.SlipstreamKey))
	copyFile(filepath.Join(paths.Rendered, "front", render.DNSProbeKeyFile), paths.FrontDNSProbe())

	// inner, as rendered but for the page on loopback: Xray's freedom
	// refuses private targets.
	var inner map[string]any
	b, _ := os.ReadFile(filepath.Join(paths.Rendered, "inner", "xray.json"))
	if err := json.Unmarshal(b, &inner); err != nil {
		t.Fatal(err)
	}
	delete(inner, "api")
	delete(inner, "dns")
	delete(inner, "routing")
	delete(inner, "stats")
	delete(inner, "policy")
	inner["inbounds"] = inner["inbounds"].([]any)[:1]
	inner["outbounds"] = []map[string]any{{"protocol": "freedom", "settings": map[string]any{
		"finalRules": []map[string]any{{"action": "allow", "ip": []string{"127.0.0.0/8"}}}}}}
	runXray(t, bin, writeJSON(t, inner))
	waitFile(t, paths.InnerSocket("inner"))

	// The server, with the unit's arguments; the front is this user.
	args, err := render.SlipstreamArgs(render.Service{Service: slip}, "inner", paths)
	if err != nil {
		t.Fatal(err)
	}
	for i := range args {
		if args[i] == "--front-uid" {
			args[i+1] = strconv.Itoa(os.Getuid())
		}
	}
	srv := exec.Command(server, args...)
	var srvLog bytes.Buffer
	srv.Stdout, srv.Stderr = &srvLog, &srvLog
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		srv.Process.Kill()
		srv.Wait()
		if t.Failed() {
			t.Logf("slipstream-server:\n%s", srvLog.String())
		}
	})
	waitFile(t, paths.FrontSocket("slip", "packet"))

	// The front on a port of the test's.
	port := freeUDP(t)
	runNiko(t, niko, "front", filepath.Join(paths.Rendered, "front", "front.json"), func(cfg map[string]any) {
		cfg["dns"].(map[string]any)["listen"] = []string{"127.0.0.1:" + strconv.Itoa(port)}
		for _, ref := range cfg["backends"].(map[string]any) {
			ref.(map[string]any)["uid"] = os.Getuid()
		}
	})

	// The client, from the link.
	profiles, err := sub.Profiles(m, m.Users[0])
	if err != nil || len(profiles) != 1 {
		t.Fatalf("profiles %+v %v", profiles, err)
	}
	link, err := url.Parse(profiles[0].Link)
	if err != nil {
		t.Fatal(err)
	}
	q := link.Query()
	dnsf := strings.Split(q.Get("niko-dns"), ";")
	slipf := strings.Split(q.Get("niko-slip"), ";")
	if len(dnsf) != 4 || dnsf[0] != "slipstream" || len(slipf) != 4 || slipf[0] != "v1" || q.Get("niko-dnsauth") != "v1" {
		t.Fatalf("link %s", profiles[0].Link)
	}
	svcID, _ := strconv.Atoi(q.Get("niko-svc"))
	k := spa.DNSAuthKey(devKey, params.NodeID, uint16(svcID))
	startClient := func(key []byte) (int, *bytes.Buffer) {
		t.Helper()
		tcp := freePort(t)
		args := []string{"-l", strconv.Itoa(tcp), "-r", "127.0.0.1:" + strconv.Itoa(port), "-d", dnsf[2],
			"--pin", slipf[1], "--alpn", slipf[2], "--sni", slipf[3], "--quiet"}
		cmd := exec.Command(client, args...)
		if key != nil {
			cmd.Args = append(cmd.Args, "--dnsauth")
			cmd.Env = append(os.Environ(), "SLIPSTREAM_DNSAUTH_KEY="+hex.EncodeToString(key))
		}
		var logs bytes.Buffer
		cmd.Stdout, cmd.Stderr = &logs, &logs
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cmd.Process.Kill()
			cmd.Wait()
			if t.Failed() {
				t.Logf("slipstream-client %v:\n%s", key != nil, logs.String())
			}
		})
		return tcp, &logs
	}
	tcp, _ := startClient(k[:])

	// VLESS through the tunnel into inner.
	socks := freePort(t)
	runXray(t, bin, writeJSON(t, map[string]any{
		"log":      map[string]string{"loglevel": "warning"},
		"inbounds": []map[string]any{{"listen": "127.0.0.1", "port": socks, "protocol": "socks", "settings": map[string]any{"udp": false}}},
		"outbounds": []map[string]any{{"protocol": "vless", "settings": map[string]any{
			"vnext": []map[string]any{{"address": "127.0.0.1", "port": tcp,
				"users": []map[string]string{{"id": link.User.Username(), "encryption": q.Get("encryption")}}}}}}},
	}))
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, strings.Repeat("through slipstream ", 4096))
	}))
	defer page.Close()
	proxy, _ := url.Parse("socks5://127.0.0.1:" + strconv.Itoa(socks))
	hc := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 20 * time.Second}
	var lastErr error
	got := false
	for range 30 {
		resp, err := hc.Get(page.URL)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) != strings.Repeat("through slipstream ", 4096) {
				t.Fatalf("body of %d bytes", len(body))
			}
			got = true
			break
		}
		lastErr = err
		time.Sleep(time.Second)
	}
	if !got {
		t.Fatalf("nothing through slipstream: %v", lastErr)
	}
	before, err := dnsstats.ReadFront(ctx, paths.FrontStats())
	if err != nil {
		t.Fatal(err)
	}
	if before.Forwarded == 0 || before.Answers == 0 || before.Queries[dnsf[2]] == 0 {
		t.Errorf("the front's counters: %+v", before)
	}

	// Without the key: the front lets none of it through.
	startClient(nil)
	time.Sleep(3 * time.Second)
	after, err := dnsstats.ReadFront(ctx, paths.FrontStats())
	if err != nil {
		t.Fatal(err)
	}
	if after.Untagged <= before.Untagged {
		t.Errorf("no untagged queries counted: before %+v, after %+v", before, after)
	}
}
