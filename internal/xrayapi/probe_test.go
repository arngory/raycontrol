package xrayapi_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/probe"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
)

// TestProbeThroughXray: the inner stage as rendered sends the probe name to
// the subscription endpoint on loopback (R4-16), so a client measures the
// tunnel with the same requests, auth and limits as directly; any other
// loopback target stays blocked. Set XRAY_BIN.
func TestProbeThroughXray(t *testing.T) {
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
	provision.Init(ctx, st, provision.Options{Host: "127.0.0.1", Domain: "example.com"})
	dns, err := provision.CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	st.SetUserServices(ctx, "alice", []int64{dns.ID})
	dev, key, err := st.CreateDevice(ctx, "alice", "phone", "user")
	if err != nil {
		t.Fatal(err)
	}

	// The subscription endpoint with probes, on its port, as rayd runs it.
	m, err := render.CollectForRender(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	port := m.SubscriptionPort()
	svc, _ := st.ServiceByName(ctx, provision.SubscriptionService)
	secrets, _ := st.ServiceSecrets(ctx, svc.ID)
	tlsCfg, err := sub.TLSConfig(secrets[provision.SecretTLSCert], secrets[provision.SecretTLSKey])
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := provision.LoadNodeKeys(ctx, st)
	srv := &sub.Server{Store: st, Keys: keys, Log: slog.New(slog.DiscardHandler)}
	srv.Probe = &probe.Server{Auth: srv.Device, Log: srv.Log, UDPPort: port}
	pc, err := net.ListenPacket("udp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go srv.Probe.ServeUDP(pc)
	go srv.Serve(ctx, "127.0.0.1:"+strconv.Itoa(port), tlsCfg)

	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: filepath.Join(dir, "run")}
	files, _, err := render.Render(m, paths)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	for _, f := range files {
		if f.Service == "inner" {
			json.Unmarshal(f.Content, &cfg)
		}
	}
	// Inner on TCP for the Xray client (it cannot dial a unix socket); the
	// routing and outbounds as rendered.
	serverPort, socksPort := freePort(t), freePort(t)
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	in["listen"], in["port"] = "127.0.0.1", serverPort
	in["settings"].(map[string]any)["clients"] = []map[string]string{{"id": m.Inner[1], "email": "u1"}}
	delete(cfg, "api")
	delete(cfg, "dns")
	server := writeJSON(t, cfg)
	inner, _ := st.ServiceByName(ctx, "inner")
	innerSecrets, _ := st.ServiceSecrets(ctx, inner.ID)
	_, encryption, _ := render.VLESSEncryption(innerSecrets[provision.SecretMLKEMSeed])
	client := writeJSON(t, map[string]any{
		"log": map[string]string{"loglevel": "warning"},
		"inbounds": []map[string]any{{"listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
			"settings": map[string]any{"udp": true, "ip": "127.0.0.1"}}},
		"outbounds": []map[string]any{{"protocol": "vless", "settings": map[string]any{
			"vnext": []map[string]any{{"address": "127.0.0.1", "port": serverPort,
				"users": []map[string]string{{"id": m.Inner[1], "encryption": encryption}}}}}}},
	})
	for _, c := range []string{server, client} {
		if out, err := exec.Command(bin, "run", "-test", "-c", c).CombinedOutput(); err != nil {
			t.Fatalf("xray -test: %v\n%s", err, out)
		}
		cmd := exec.Command(bin, "run", "-c", c)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	}

	// The client of the endpoint, through the tunnel: the probe name, any
	// port; the pin and the device's auth as directly.
	sc := sub.Client{Addr: net.JoinHostPort(render.ProbeName, "443"), Pin: mustPin(t, secrets[provision.SecretTLSCert]),
		DeviceID: dev.ID, DeviceKey: key}
	hc := sc.HTTP()
	proxy, _ := url.Parse("socks5h://127.0.0.1:" + strconv.Itoa(socksPort))
	hc.Transport.(*http.Transport).Proxy = http.ProxyURL(proxy)
	c := probe.Client{HTTP: hc, Base: "https://" + sc.Addr, Authorize: sc.Authorize}
	var down probe.Transfer
	for i := 0; i < 30; i++ {
		if down, err = c.Down(ctx, 2<<20); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil || down.Bytes != 2<<20 || down.Server.Bytes != 2<<20 {
		t.Fatalf("down through inner: %+v %v", down, err)
	}
	if up, err := c.Up(ctx, 1<<20); err != nil || up.Server.Bytes != 1<<20 {
		t.Fatalf("up through inner: %+v %v", up, err)
	}

	// UDP through the tunnel: a session over HTTPS through it, then the
	// datagrams to the probe name (SOCKS5 UDP to Xray, VLESS UDP to inner).
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.Base+probe.PathUDP, nil)
	sc.Authorize(req)
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var sess probe.UDPSession
	json.NewDecoder(resp.Body).Decode(&sess)
	resp.Body.Close()
	token, _ := base64.RawURLEncoding.DecodeString(sess.Token)
	udp, relay := socksUDP(t, socksPort)
	header := append([]byte{0, 0, 0, 3, byte(len(render.ProbeName))}, render.ProbeName...)
	header = binary.BigEndian.AppendUint16(header, uint16(sess.Port))
	echoed := 0
	got := make([]byte, 2048)
	for seq := range 5 {
		d := make([]byte, 200)
		copy(d, token)
		binary.BigEndian.PutUint32(d[16:], uint32(seq))
		udp.WriteTo(append(slices.Clone(header), d...), relay)
		udp.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := udp.ReadFrom(got)
		// The reply carries a SOCKS header of its own; the datagram follows.
		if err == nil && n >= 200 && bytes.Equal(got[n-200:n-200+16], token) && binary.BigEndian.Uint32(got[n-200+16:]) == uint32(seq) {
			echoed++
		}
	}
	if echoed != 5 {
		t.Fatalf("UDP through inner: %d of 5 echoed", echoed)
	}

	// Loopback stays out for anything else, the endpoint's own address too.
	direct := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy),
		TLSClientConfig: hc.Transport.(*http.Transport).TLSClientConfig}}
	if resp, err := direct.Get("https://127.0.0.1:" + strconv.Itoa(port) + sub.Path); err == nil {
		resp.Body.Close()
		t.Fatal("loopback reached through inner")
	}
}

func mustPin(t *testing.T, certDER []byte) string {
	pin, err := provision.SPKIPin(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return pin
}

// socksUDP opens a SOCKS5 UDP association (RFC 1928) and returns the local
// socket and the relay's address; the TCP control connection lives with
// the test.
func socksUDP(t *testing.T, port int) (*net.UDPConn, *net.UDPAddr) {
	t.Helper()
	ctl, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ctl.Close() })
	ctl.Write([]byte{5, 1, 0})
	b := make([]byte, 262)
	if _, err := io.ReadFull(ctl, b[:2]); err != nil || b[1] != 0 {
		t.Fatalf("socks greeting: %v %x", err, b[:2])
	}
	ctl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	if _, err := io.ReadFull(ctl, b[:4]); err != nil || b[1] != 0 {
		t.Fatalf("socks UDP associate: %v %x", err, b[:4])
	}
	var ip net.IP
	switch b[3] {
	case 1:
		io.ReadFull(ctl, b[:4])
		ip = net.IP(slices.Clone(b[:4]))
	case 4:
		io.ReadFull(ctl, b[:16])
		ip = net.IP(slices.Clone(b[:16]))
	default:
		t.Fatalf("socks bound address type %d", b[3])
	}
	io.ReadFull(ctl, b[:2])
	relay := &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(b[:2]))}
	if relay.IP.IsUnspecified() {
		relay.IP = net.IPv4(127, 0, 0, 1)
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	return udp, relay
}
