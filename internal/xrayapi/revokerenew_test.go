package xrayapi_test

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
	"github.com/arngory/raycontrol/internal/traffic"
)

// A revocation with the processes running (R4-36): the device's user gets
// new credentials, so the user's other device, which holds the same old
// credential, is cut too and refused with it; with the new one, which its
// next subscription carries, it gets in again. The user's bytes are
// counted once through it all, on the old credential and the new one.

// refused reports whether a stream through a client's SOCKS port fails to
// carry an exchange within a few seconds: the node refused the client's
// credential.
func refused(socks int, target net.Addr) bool {
	tp := target.(*net.TCPAddr).Port
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(socks), time.Second)
	if err != nil {
		return true
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	req := []byte{5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, byte(tp >> 8), byte(tp)}
	buf := make([]byte, 12)
	if _, err := c.Write(req); err != nil {
		return true
	}
	if _, err := c.Read(buf); err != nil || buf[1] != 0 {
		return true
	}
	var y tally
	return y.exchange(c, 100) != nil
}

// twoDevices enrolls two devices of alice: the one to revoke, and the one kept.
func twoDevices(t *testing.T, ctx context.Context, st *store.Store) (revoked, kept store.Device) {
	t.Helper()
	revoked, _, err := st.CreateDevice(ctx, "alice", "phone", "user")
	if err != nil {
		t.Fatal(err)
	}
	kept, _, err = st.CreateDevice(ctx, "alice", "laptop", "user")
	if err != nil {
		t.Fatal(err)
	}
	return revoked, kept
}

// TestRevokeRenewsWithXray: the inner stage on a real Xray, its users
// synced through the API as rayd does. Set XRAY_BIN.
func TestRevokeRenewsWithXray(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("set XRAY_BIN to an Xray built from arngory/xray-core")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	st, paths, a, _ := switchNode(t, ctx, "dnstt")
	phone, _ := twoDevices(t, ctx, st)
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	inner := m.Services[slices.IndexFunc(m.Services, func(s render.Service) bool { return s.Kind == "inner" })]
	uid := m.Users[0].ID
	old := m.Inner[uid]

	// The rendered inner config on TCP, its API and stats kept, the
	// loopback target allowed.
	rendered, err := os.ReadFile(filepath.Join(paths.Rendered, inner.Name, "xray.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(rendered, &cfg); err != nil {
		t.Fatal(err)
	}
	serverPort := freePort(t)
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	in["listen"], in["port"] = "127.0.0.1", serverPort
	delete(cfg, "dns")
	delete(cfg, "routing")
	cfg["outbounds"] = []map[string]any{{"protocol": "freedom", "settings": map[string]any{
		"finalRules": []map[string]any{{"action": "allow", "ip": []string{"127.0.0.0/8"}}}}}}
	for _, d := range []string{inner.Name, inner.Name + "-api"} {
		os.MkdirAll(filepath.Join(paths.Run, d), 0o755)
	}
	runXray(t, bin, writeJSON(t, cfg))
	waitFile(t, paths.APISocket(inner.Name))
	_, encryption, err := render.VLESSEncryption(inner.Secrets[provision.SecretMLKEMSeed])
	if err != nil {
		t.Fatal(err)
	}
	client := func(id string) int {
		port := freePort(t)
		runXray(t, bin, writeJSON(t, map[string]any{
			"log":      map[string]string{"loglevel": "warning"},
			"inbounds": []map[string]any{{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"udp": false}}},
			"outbounds": []map[string]any{{"protocol": "vless", "settings": map[string]any{
				"vnext": []map[string]any{{"address": "127.0.0.1", "port": serverPort,
					"users": []map[string]string{{"id": id, "encryption": encryption}}}}}}},
			"policy": map[string]any{"levels": map[string]any{"0": map[string]int{"uplinkOnly": 0, "downlinkOnly": 0}}},
		}))
		return port
	}
	target := exchangeTarget(t)
	hb := &health.Board{}
	acct := &traffic.Accountant{Store: st, Sources: traffic.Processes(paths), Health: hb}
	var y tally
	counted(t, ctx, st, acct, hb, "alice", &y)

	// Both devices on the old credential, the revoked one and the other.
	onPhone, onLaptop := y.open(t, client(old), target), y.open(t, client(old), target)
	if err := y.exchange(onLaptop, 20000); err != nil {
		t.Fatal(err)
	}
	counted(t, ctx, st, acct, hb, "alice", &y)
	if err := y.exchange(onPhone, 5000); err != nil {
		t.Fatal(err)
	}

	// The revocation, applied as rayd does: no restart, the old
	// credential removed through the API, both streams cut.
	if r, err := st.RevokeDevice(ctx, phone.ID); err != nil || r.Credentials == 0 {
		t.Fatalf("revoke: %+v %v", r, err)
	}
	if err := a.Apply(ctx); err != nil && !render.Partial(err) {
		t.Fatal(err)
	}
	for name, c := range map[string]net.Conn{"revoked device": onPhone, "other device": onLaptop} {
		if ok, d := cut(c, 3*time.Second); !ok || d > time.Second {
			t.Fatalf("the %s's stream on the old credential: cut %v after %v", name, ok, d)
		}
		c.Close()
	}
	// Its bytes since the last poll are counted.
	counted(t, ctx, st, acct, hb, "alice", &y)
	if !refused(client(old), target) {
		t.Fatal("the old credential still gets in after the apply")
	}
	m, _ = render.Collect(ctx, st)
	fresh := m.Inner[uid]
	if fresh == old || m.Sets[inner.ID][uid].Next != "" || m.Sets[inner.ID][uid].Prev != "" {
		t.Fatalf("after the revocation: %+v", m.Sets[inner.ID][uid])
	}
	// The other device's next subscription carries the new one: it works,
	// and counts on for the same user.
	onLaptop = y.open(t, client(fresh), target)
	if err := y.exchange(onLaptop, 7000); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		counted(t, ctx, st, acct, hb, "alice", &y)
	}
}

// TestRevokeRenewsWithNikoServer: the same on Hysteria2 (hy2-obfs on
// niko-server behind its UDP front, Xray as the client). Set XRAY_BIN and
// NIKO_SERVER_BIN (v0.15.0 or later).
func TestRevokeRenewsWithNikoServer(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("set XRAY_BIN to an Xray built from arngory/xray-core")
	}
	niko := os.Getenv("NIKO_SERVER_BIN")
	if niko == "" {
		t.Skip("set NIKO_SERVER_BIN to niko-server v0.15.0 or later")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	st, paths, a, svc := switchNode(t, ctx, "hy2-obfs")
	phone, _ := twoDevices(t, ctx, st)
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	uid := m.Users[0].ID
	old := m.Creds[svc.ID][uid]
	usersFile := filepath.Join(paths.Rendered, svc.Name, render.HysteriaUsers)
	copies := map[string]string{
		filepath.Join(paths.Rendered, svc.Name, render.HysteriaKey):    paths.Credential(svc.Name, render.HysteriaKey),
		filepath.Join(paths.Rendered, svc.Name, render.HysteriaObfs):   paths.Credential(svc.Name, render.HysteriaObfs),
		filepath.Join(paths.Rendered, "front", svc.Name+".salamander"): paths.FrontSalamander(svc.Name),
	}
	for from, to := range copies {
		b, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		os.MkdirAll(filepath.Dir(to), 0o755)
		os.WriteFile(to, b, 0o600)
	}
	os.MkdirAll(paths.FrontDir(svc.Name), 0o755)
	backend := startNiko(t, niko, "backend", filepath.Join(paths.Rendered, svc.Name, "backend.json"), func(cfg map[string]any) {
		cfg["front_uid"] = os.Getuid()
		cfg["log"] = map[string]string{"level": "info"}
	})
	port := freeUDP(t)
	startNiko(t, niko, "front", filepath.Join(paths.Rendered, "front", "front.json"), func(cfg map[string]any) {
		cfg["udp"].(map[string]any)["listen"] = []string{"127.0.0.1:" + strconv.Itoa(port)}
		for _, ref := range cfg["backends"].(map[string]any) {
			ref.(map[string]any)["uid"] = os.Getuid()
		}
		delete(cfg, "tcp")
		delete(cfg, "dns")
	})
	backend.waitReload(t)

	profiles, err := sub.Profiles(m, m.Users[0])
	if err != nil || len(profiles) != 1 {
		t.Fatalf("profiles %v %v", profiles, err)
	}
	link := strings.Replace(profiles[0].Link, ":443/", ":"+strconv.Itoa(port)+"/", 1)
	client := func(password string) int {
		socks, _ := hysteriaSocks(t, bin, link, password, "")
		return socks
	}
	target := exchangeTarget(t)
	hb := &health.Board{}
	acct := &traffic.Accountant{Store: st, Sources: traffic.Processes(paths), Health: hb}
	var y tally
	counted(t, ctx, st, acct, hb, "alice", &y)
	onPhone, onLaptop := y.open(t, client(old), target), y.open(t, client(old), target)
	if err := y.exchange(onLaptop, 20000); err != nil {
		t.Fatal(err)
	}
	counted(t, ctx, st, acct, hb, "alice", &y)

	if _, err := st.RevokeDevice(ctx, phone.ID); err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(ctx); err != nil && !render.Partial(err) {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(usersFile); strings.Contains(string(b), old) {
		t.Fatalf("the users file keeps the old password:\n%s", b)
	}
	if closed := backend.reload(t); closed != 2 {
		t.Fatalf("the revocation closed %d connections, want both devices'", closed)
	}
	for name, c := range map[string]net.Conn{"revoked device": onPhone, "other device": onLaptop} {
		if ok, d := cut(c, 3*time.Second); !ok {
			t.Fatalf("the %s's stream on the old password: not cut after %v", name, d)
		}
		c.Close()
	}
	counted(t, ctx, st, acct, hb, "alice", &y)
	if !refused(client(old), target) {
		t.Fatal("the old password still gets in after the apply")
	}
	m, _ = render.Collect(ctx, st)
	onLaptop = y.open(t, client(m.Creds[svc.ID][uid]), target)
	if err := y.exchange(onLaptop, 7000); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		counted(t, ctx, st, acct, hb, "alice", &y)
	}
}
