package xrayapi_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/doh"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/site"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
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
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: filepath.Join(dir, "run")}
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

	api := paths.APISocket("inner")
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
	added, removed, err := c.SyncVLESS(ctx, render.InnerTag, "", want)
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
	if added, removed, err = c.SyncVLESS(ctx, render.InnerTag, "", want); err != nil || added+removed != 0 {
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

// TestRealityWithXray runs a rendered REALITY service on a real Xray: a
// client built from the subscription link gets through VLESS + REALITY +
// Vision with the ML-KEM-768 layer, a user added through the API with the
// Vision flow too, and a TLS client without credentials sees the target's
// certificate. Set XRAY_BIN.
func TestRealityWithXray(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("set XRAY_BIN to an Xray built from arngory/xray-core")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	dir := t.TempDir()

	// The target answers everyone who is not a client: a TLS 1.3 site.
	targetCert := selfSignedCert(t, "target.test")
	target, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{targetCert}, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go http.Serve(target, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "decoy") }))

	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := provision.Init(ctx, st, provision.Options{Host: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	settings := fmt.Sprintf(`{"target":%q,"sni":"target.test","ports":["tcp/%d"]}`, target.Addr().String(), port)
	svc, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "reality", Enabled: true, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	user, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserServices(ctx, "alice", []int64{svc.ID}); err != nil {
		t.Fatal(err)
	}
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: filepath.Join(dir, "run")}
	if err := os.MkdirAll(filepath.Dir(paths.APISocket("reality")), 0o755); err != nil {
		t.Fatal(err)
	}
	files, _, err := render.Render(m, paths)
	if err != nil {
		t.Fatal(err)
	}
	var serverCfg map[string]any
	if err := json.Unmarshal(files[0].Content, &serverCfg); err != nil {
		t.Fatal(err)
	}
	// Loopback page: Xray's freedom refuses private targets by default.
	delete(serverCfg, "dns")
	delete(serverCfg, "routing")
	serverCfg["outbounds"] = []map[string]any{{"protocol": "freedom", "settings": map[string]any{
		"finalRules": []map[string]any{{"action": "allow", "ip": []string{"127.0.0.0/8"}}}}}}
	if os.Getenv("XRAY_DEBUG") != "" {
		serverCfg["log"] = map[string]string{"loglevel": "debug"}
		in := serverCfg["inbounds"].([]any)[0].(map[string]any)
		in["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)["show"] = true
	}
	server := writeJSON(t, serverCfg)
	if out, err := exec.Command(bin, "run", "-test", "-c", server).CombinedOutput(); err != nil {
		t.Fatalf("xray -test: %v\n%s", err, out)
	}
	runXray(t, bin, server)

	link, err := sub.RealityLink(m, m.Services[slices.IndexFunc(m.Services, func(s render.Service) bool { return s.Kind == "reality" })], user.ID)
	if err != nil {
		t.Fatal(err)
	}
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "through reality") }))
	defer page.Close()
	fetchThroughLink(t, bin, link, "", page.URL)

	// A user added through the API, with the Vision flow.
	api := paths.APISocket("reality")
	waitFile(t, api)
	newID := "6f1c2a3b-0000-4000-8000-000000000009"
	want := map[string]string{render.InnerEmail(user.ID): m.Creds[svc.ID][user.ID], "u9": newID}
	if added, removed, err := xrayapi.Dial(api).SyncVLESS(ctx, render.RealityTag, render.RealityFlow, want); err != nil || added != 1 || removed != 0 {
		t.Fatalf("sync: +%d -%d %v", added, removed, err)
	}
	fetchThroughLink(t, bin, link, newID, page.URL)

	// No credentials: the REALITY port shows the target's certificate.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", "127.0.0.1:"+strconv.Itoa(port),
		&tls.Config{ServerName: "target.test", InsecureSkipVerify: true}) //nolint:gosec // looking at the certificate
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := conn.ConnectionState().PeerCertificates[0].Raw; !bytes.Equal(got, targetCert.Certificate[0]) {
		t.Fatal("a probe without credentials does not get the target's certificate")
	}
}

// fetchThroughLink runs an Xray client built from a share link (id replaces
// the link's UUID if set) and fetches page through it.
func fetchThroughLink(t *testing.T, bin, link, id, page string) {
	t.Helper()
	if err := tryThroughLink(t, bin, link, id, page, 30); err != nil {
		t.Fatalf("no response through REALITY: %v", err)
	}
}

// tryThroughLink is fetchThroughLink returning the last error after tries.
func tryThroughLink(t *testing.T, bin, link, id, page string, tries int) error {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	port, _ := strconv.Atoi(u.Port())
	if id == "" {
		id = u.User.Username()
	}
	socksPort := freePort(t)
	level := "warning"
	if os.Getenv("XRAY_DEBUG") != "" {
		level = "debug"
	}
	client := writeJSON(t, map[string]any{
		"log":      map[string]string{"loglevel": level},
		"inbounds": []map[string]any{{"listen": "127.0.0.1", "port": socksPort, "protocol": "socks", "settings": map[string]any{"udp": false}}},
		"outbounds": []map[string]any{{
			"protocol": "vless",
			"settings": map[string]any{"vnext": []map[string]any{{"address": u.Hostname(), "port": port,
				"users": []map[string]string{{"id": id, "encryption": q.Get("encryption"), "flow": q.Get("flow")}}}}},
			"streamSettings": map[string]any{
				"network": q.Get("type"), "security": q.Get("security"),
				"realitySettings": map[string]any{"serverName": q.Get("sni"), "fingerprint": q.Get("fp"),
					"publicKey": q.Get("pbk"), "shortId": q.Get("sid"), "mldsa65Verify": q.Get("pqv"),
					"show": os.Getenv("XRAY_DEBUG") != ""},
			},
		}},
	})
	stop := runXray(t, bin, client)
	defer stop()
	proxy, _ := url.Parse("socks5://127.0.0.1:" + strconv.Itoa(socksPort))
	hc := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 5 * time.Second}
	var lastErr error
	for i := 0; i < tries; i++ {
		resp, err := hc.Get(page)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) != "through reality" {
				return fmt.Errorf("body %q", body)
			}
			return nil
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	return lastErr
}

func runXray(t *testing.T, bin, cfg string) (stop func()) {
	t.Helper()
	cmd := exec.Command(bin, "run", "-c", cfg)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop = func() { once.Do(func() { cmd.Process.Kill(); cmd.Wait() }) }
	t.Cleanup(stop)
	return stop
}

func waitFile(t *testing.T, path string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s did not appear", path)
}

func selfSignedCert(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// REALITY pads its own certificate (with the ML-DSA-65 signature, about
	// 3.5 KB) to the length of the target's: real sites send chains of a few
	// KB, so the test target gets a padded certificate of that size.
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 1}, Value: make([]byte, 4096)}}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestRealitySelfStealWithXray: REALITY with the node's own decoy site as
// target, as rendered for a node with a domain. The site runs on its unix
// socket with a chain long enough for ML-DSA-65; a client from the link gets
// through, a probe without credentials gets the site.
func TestRealitySelfStealWithXray(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("set XRAY_BIN to an Xray built from arngory/xray-core")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := provision.Init(ctx, st, provision.Options{Host: "127.0.0.1", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	svc, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "reality", Enabled: true,
		Settings: fmt.Sprintf(`{"ports":["tcp/%d"]}`, port)})
	if err != nil {
		t.Fatal(err)
	}
	// DoH behind REALITY's port, passed on by the site (R3-2).
	dohSvc, err := provision.CreateService(ctx, st, store.Service{Kind: "doh", Name: "doh", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	var dohName struct{ SNI string }
	json.Unmarshal([]byte(dohSvc.Settings), &dohName)
	siteSvc, err := st.ServiceByName(ctx, "site")
	if err != nil {
		t.Fatal(err)
	}
	name := provision.SiteName(siteSvc)

	// Key rotation (R4-7), prepared before the certificate so that it covers
	// the next name too, as the manager does it: new keys and a new name of
	// the node's own domain.
	day := 24 * time.Hour
	epoch := provision.RealityEpoch{Period: 90 * day, Lead: 3 * day, Prepare: day}
	resolves := func(context.Context, string) error { return nil }
	if n, err := provision.RotateReality(ctx, st, svc.CreatedAt.Add(86*day), epoch, resolves, nil); err != nil || n != 1 {
		t.Fatalf("prepare: %d %v", n, err)
	}
	prepared, _ := st.ServiceByName(ctx, "reality")
	nextName := provision.ParseRealityState(prepared).SNINext

	// The certificate the manager would get: a chain long enough for REALITY.
	rootKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	interKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	leafKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	mk := func(cn string, isCA bool, dns []string, pub any, parent *x509.Certificate, signer any) *x509.Certificate {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, DNSNames: dns,
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true}
		if isCA {
			tmpl.KeyUsage = x509.KeyUsageCertSign
		}
		if parent == nil {
			parent = tmpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	root := mk("Test Root", true, nil, &rootKey.PublicKey, nil, rootKey)
	inter := mk("Test Intermediate", true, nil, &interKey.PublicKey, root, rootKey)
	leaf := mk(name, false, []string{name, nextName, dohName.SNI}, &leafKey.PublicKey, inter, interKey)
	var chainPEM bytes.Buffer
	for _, c := range []*x509.Certificate{leaf, inter, root} {
		pem.Encode(&chainPEM, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	st.SetServiceSecret(ctx, siteSvc.ID, provision.SecretTLSKey, keyDER)
	st.SetServiceSecret(ctx, siteSvc.ID, provision.SecretTLSChain, chainPEM.Bytes())
	if n, err := provision.RotateReality(ctx, st, svc.CreatedAt.Add(86*day+time.Minute), epoch, resolves, nil); err != nil || n != 1 {
		t.Fatalf("publish: %d %v", n, err)
	}

	user, _ := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	st.SetUserServices(ctx, "alice", []int64{svc.ID, dohSvc.ID})
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: filepath.Join(dir, "run")}
	for _, d := range []string{filepath.Dir(paths.APISocket("reality")), filepath.Dir(paths.SiteSocket("site"))} {
		os.MkdirAll(d, 0o755)
	}
	files, skipped, err := render.Render(m, paths)
	if err != nil || len(skipped) != 0 {
		t.Fatalf("render: %v, skipped %v", err, skipped)
	}
	var serverCfg map[string]any
	for _, f := range files {
		os.MkdirAll(filepath.Dir(f.Path), 0o755)
		os.WriteFile(f.Path, f.Content, 0o644)
		if f.Service == "reality" {
			json.Unmarshal(f.Content, &serverCfg)
		}
	}

	// The site, as rayd site runs it.
	siteDir := filepath.Join(paths.Rendered, "site")
	chain, _ := os.ReadFile(filepath.Join(siteDir, render.SiteChain))
	key, _ := os.ReadFile(filepath.Join(siteDir, render.SiteKey))
	roots := x509.NewCertPool()
	roots.AddCert(root)
	cert, err := site.LoadCertificate(chain, key, provision.RealityChainMin(), roots)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", paths.SiteSocket("site"))
	if err != nil {
		t.Fatal(err)
	}
	// As rayd site runs it: the default answer, 404 to everything.
	handler, err := site.Responder(provision.SiteAnswer(siteSvc), filepath.Join(siteDir, render.SiteRoot))
	if err != nil {
		t.Fatal(err)
	}
	routes, err := site.LoadRoutes(filepath.Join(siteDir, render.SiteRoutes))
	if err != nil || len(routes) != 1 {
		t.Fatalf("site routes %v %v", routes, err)
	}
	go site.Serve(ctx, site.Routed(ln, routes, slog.New(slog.NewTextHandler(io.Discard, nil))), handler, cert, slog.New(slog.NewTextHandler(io.Discard, nil)))

	delete(serverCfg, "dns")
	delete(serverCfg, "routing")
	serverCfg["outbounds"] = []map[string]any{{"protocol": "freedom", "settings": map[string]any{
		"finalRules": []map[string]any{{"action": "allow", "ip": []string{"127.0.0.0/8"}}}}}}
	server := writeJSON(t, serverCfg)
	if out, err := exec.Command(bin, "run", "-test", "-c", server).CombinedOutput(); err != nil {
		t.Fatalf("xray -test: %v\n%s", err, out)
	}
	stopServer := runXray(t, bin, server)

	link, err := sub.RealityLink(m, m.Services[slices.IndexFunc(m.Services, func(s render.Service) bool { return s.Kind == "reality" })], user.ID)
	if err != nil {
		t.Fatal(err)
	}
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "through reality") }))
	defer page.Close()
	fetchThroughLink(t, bin, link, "", page.URL)

	// A probe without credentials: the site's certificate and its pages.
	probe := func(name string) {
		t.Helper()
		hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port), &tls.Config{ServerName: name, RootCAs: roots, NextProtos: []string{"h2"}})
			},
			ForceAttemptHTTP2: true,
		}}
		resp, err := hc.Get("https://" + name + "/about.html")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		// A real certificate for the name, and nothing else: 404, no body.
		if resp.StatusCode != 404 || resp.ProtoMajor != 2 || len(body) != 0 ||
			!bytes.Equal(resp.TLS.PeerCertificates[0].Raw, leaf.Raw) {
			t.Fatalf("probe %s: %s %s\n%s", name, resp.Status, resp.Proto, body)
		}
	}
	probe(name)

	// DoH through REALITY's port: REALITY hands the site what is not its
	// own, the site passes the DoH name on to rayd's endpoint.
	answer := bytes.Repeat([]byte{7}, 40)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(answer) }))
	defer upstream.Close()
	token := m.Creds[dohSvc.ID][user.ID]
	os.MkdirAll(filepath.Dir(paths.DoHSocket("doh")), 0o755)
	dl, err := net.Listen("unix", paths.DoHSocket("doh"))
	if err != nil {
		t.Fatal(err)
	}
	dohSrv := &http.Server{Handler: &doh.Handler{Upstreams: []string{upstream.URL},
		Tokens: func(context.Context) (map[string]bool, error) { return map[string]bool{token: true}, nil }},
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
			Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}}}
	go dohSrv.ServeTLS(dl, "", "")
	defer dohSrv.Close()
	dc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port), &tls.Config{ServerName: dohName.SNI, RootCAs: roots, NextProtos: []string{"h2"}})
		},
		ForceAttemptHTTP2: true,
	}}
	dohLink := sub.DoHLink(m, m.Services[slices.IndexFunc(m.Services, func(s render.Service) bool { return s.ID == dohSvc.ID })], token)
	u, _ := url.Parse(dohLink)
	resp, err := dc.Get("https://" + u.Host + u.Path + "?dns=" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 20)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Equal(body, answer) || resp.ProtoMajor != 2 {
		t.Fatalf("DoH through REALITY: %s %s %q", resp.Status, resp.Proto, body)
	}

	// The switch: the subscription had the next link; the node renders the
	// next keys and name, the site follows the name.
	profiles, err := sub.Profiles(m, m.Users[0])
	if err != nil || profiles[0].Next == nil {
		t.Fatalf("no next in the subscription: %v", err)
	}
	if n, err := provision.RotateReality(ctx, st, svc.CreatedAt.Add(90*day), epoch, resolves, nil); err != nil || n != 1 {
		t.Fatalf("switch: %d %v", n, err)
	}
	m, err = render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if files, skipped, err = render.Render(m, paths); err != nil || len(skipped) != 0 {
		t.Fatalf("render: %v, skipped %v", err, skipped)
	}
	serverCfg = nil
	for _, f := range files {
		os.WriteFile(f.Path, f.Content, 0o644)
		if f.Service == "reality" {
			json.Unmarshal(f.Content, &serverCfg)
		}
	}
	stopServer()
	os.Remove(paths.APISocket("reality"))
	delete(serverCfg, "dns")
	delete(serverCfg, "routing")
	serverCfg["outbounds"] = []map[string]any{{"protocol": "freedom", "settings": map[string]any{
		"finalRules": []map[string]any{{"action": "allow", "ip": []string{"127.0.0.0/8"}}}}}}
	runXray(t, bin, writeJSON(t, serverCfg))

	newLink, err := sub.RealityLink(m, m.Services[slices.IndexFunc(m.Services, func(s render.Service) bool { return s.Kind == "reality" })], user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if newLink != profiles[0].Next.Link || !strings.Contains(newLink, "sni="+nextName) {
		t.Fatalf("after the switch:\n%s\nnext was\n%s", newLink, profiles[0].Next.Link)
	}
	fetchThroughLink(t, bin, newLink, "", page.URL)
	if err := tryThroughLink(t, bin, link, "", page.URL, 3); err == nil {
		t.Fatal("the previous keys still work after the switch")
	}
	probe(nextName)
}

// TestHysteriaWithXray: both Hysteria2 services as rendered (R3-1) on the
// pinned Xray, with the site's certificate under their own names; a client
// built from the subscription link gets through, also after the Xray API
// adds a user; a wrong password does not.
func TestHysteriaWithXray(t *testing.T) {
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
	if _, err := provision.Init(ctx, st, provision.Options{Host: "127.0.0.1", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	masqPort, obfsPort := freeUDP(t), freeUDP(t)
	masq, err := provision.CreateService(ctx, st, store.Service{Kind: "hy2-masq", Name: "hy2", Enabled: true,
		Settings: fmt.Sprintf(`{"ports":["udp/%d"]}`, masqPort)})
	if err != nil {
		t.Fatal(err)
	}
	obfs, err := provision.CreateService(ctx, st, store.Service{Kind: "hy2-obfs", Name: "hy2o", Enabled: true,
		Settings: fmt.Sprintf(`{"ports":["udp/%d"]}`, obfsPort)})
	if err != nil {
		t.Fatal(err)
	}
	// The site's certificate: a wildcard of the node's domain, as DNS-01 gets.
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)
	leafDER, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"*.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}, root, &leafKey.PublicKey, rootKey)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	site, _ := st.ServiceByName(ctx, "site")
	st.UpdateService(ctx, site.ID, store.ServiceUpdate{Set: map[string][]byte{
		provision.SecretTLSChain: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), provision.SecretTLSKey: keyDER}})
	rootFile := filepath.Join(dir, "root.pem")
	os.WriteFile(rootFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0o644)

	st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	st.SetUserServices(ctx, "alice", []int64{masq.ID, obfs.ID})
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: filepath.Join(dir, "run")}
	files, _, err := render.Render(m, paths)
	if err != nil {
		t.Fatal(err)
	}
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "through reality") }))
	defer page.Close()
	profiles, err := sub.Profiles(m, m.Users[0])
	if err != nil || len(profiles) != 2 {
		t.Fatalf("profiles %v %v", profiles, err)
	}
	for _, svc := range []store.Service{masq, obfs} {
		var serverCfg map[string]any
		for _, f := range files {
			if f.Service != svc.Name {
				continue
			}
			os.MkdirAll(filepath.Dir(f.Path), 0o755)
			os.WriteFile(f.Path, f.Content, 0o644)
			if filepath.Base(f.Path) == render.HysteriaKey {
				// What the unit's ExecStartPre does: the key in the runtime directory.
				os.MkdirAll(filepath.Dir(paths.Credential(svc.Name, render.HysteriaKey)), 0o755)
				os.WriteFile(paths.Credential(svc.Name, render.HysteriaKey), f.Content, 0o600)
			}
			if filepath.Base(f.Path) == "xray.json" {
				json.Unmarshal(f.Content, &serverCfg)
			}
		}
		os.MkdirAll(filepath.Dir(paths.APISocket(svc.Name)), 0o755)
		delete(serverCfg, "dns")
		delete(serverCfg, "routing")
		serverCfg["outbounds"] = []map[string]any{{"protocol": "freedom", "settings": map[string]any{
			"finalRules": []map[string]any{{"action": "allow", "ip": []string{"127.0.0.0/8"}}}}}}
		server := writeJSON(t, serverCfg)
		if out, err := exec.Command(bin, "run", "-test", "-c", server).CombinedOutput(); err != nil {
			t.Fatalf("%s: xray -test: %v\n%s", svc.Name, err, out)
		}
		runXray(t, bin, server)

		link := profiles[slices.IndexFunc(profiles, func(p sub.Profile) bool { return p.Name == svc.Name })].Link
		if err := tryHysteria(t, bin, link, "", rootFile, page.URL, 30); err != nil {
			t.Fatalf("%s: no response through Hysteria2: %v", svc.Name, err)
		}
		// A user added through the API.
		api := paths.APISocket(svc.Name)
		waitFile(t, api)
		_, want := render.XrayUsers(m, m.Services[slices.IndexFunc(m.Services, func(s render.Service) bool { return s.ID == svc.ID })])
		want["u9"] = "a-password-for-u9"
		if added, _, err := xrayapi.Dial(api).SyncHysteria(ctx, render.HysteriaTag, want); err != nil || added != 1 {
			t.Fatalf("%s: sync: +%d %v", svc.Name, added, err)
		}
		if err := tryHysteria(t, bin, link, "a-password-for-u9", rootFile, page.URL, 30); err != nil {
			t.Fatalf("%s: added user: %v", svc.Name, err)
		}
		if err := tryHysteria(t, bin, link, "wrong", rootFile, page.URL, 3); err == nil {
			t.Fatalf("%s: a wrong password got through", svc.Name)
		}
	}
}

func freeUDP(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// tryHysteria runs an Xray client from a hysteria2:// link (auth replaces
// the link's password if set), trusting root, and fetches page through it.
func tryHysteria(t *testing.T, bin, link, auth, root, page string, tries int) error {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if auth == "" {
		auth = u.User.Username()
	}
	port, _ := strconv.Atoi(u.Port())
	tlsSettings := map[string]any{"serverName": q.Get("sni"), "alpn": []string{"h3"}, "curvePreferences": []string{"X25519MLKEM768"},
		"disableSystemRoot": true, "certificates": []map[string]string{{"certificateFile": root, "usage": "verify"}}}
	if pin := q.Get("pinSHA256"); pin != "" {
		// hy2-obfs: a self-signed certificate, pinned.
		tlsSettings = map[string]any{"serverName": q.Get("sni"), "alpn": []string{"h3"}, "curvePreferences": []string{"X25519MLKEM768"},
			"pinnedPeerCertSha256": pin}
	}
	stream := map[string]any{
		"network":          "hysteria",
		"security":         "tls",
		"tlsSettings":      tlsSettings,
		"hysteriaSettings": map[string]any{"version": 2, "auth": auth},
	}
	if q.Get("obfs") == "salamander" {
		stream["finalmask"] = map[string]any{"udp": []map[string]any{{"type": "salamander", "settings": map[string]string{"password": q.Get("obfs-password")}}}}
	}
	socksPort := freePort(t)
	client := writeJSON(t, map[string]any{
		"log":      map[string]string{"loglevel": "warning"},
		"inbounds": []map[string]any{{"listen": "127.0.0.1", "port": socksPort, "protocol": "socks", "settings": map[string]any{"udp": false}}},
		"outbounds": []map[string]any{{
			"protocol":       "hysteria",
			"settings":       map[string]any{"version": 2, "address": u.Hostname(), "port": port},
			"streamSettings": stream,
		}},
	})
	stop := runXray(t, bin, client)
	defer stop()
	proxy, _ := url.Parse("socks5://127.0.0.1:" + strconv.Itoa(socksPort))
	hc := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 5 * time.Second}
	var lastErr error
	for i := 0; i < tries; i++ {
		resp, err := hc.Get(page)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) != "through reality" {
				return fmt.Errorf("body %q", body)
			}
			return nil
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	return lastErr
}
