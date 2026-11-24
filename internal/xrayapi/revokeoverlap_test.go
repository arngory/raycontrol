package xrayapi_test

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/live"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/traffic"
)

// A revocation with overlap with the processes running (R4-43): the
// device's user's credentials rotate. The next one is accepted at once and
// nothing is cut: the revoked device and the user's other device go on on
// the old one, and the other device, whose next subscription carries the
// next one, gets in with it too. At the switch nothing changes for the
// processes; at the grace's end the old credential goes, the streams on
// it are cut, the revoked device's among them, and it is refused. The
// user's bytes are counted once through it all, on the old credential and
// the next one. Without overlap: revokerenew_test.go.

// revocationStep moves the store's credentials to their state at a time
// of the revocation's rotation (its switch, the end of its grace), as
// rayd's rotation does, and applies.
func revocationStep(t *testing.T, ctx context.Context, st *store.Store, a *live.Applier, at time.Time) {
	t.Helper()
	if n, err := st.RotateCredentials(ctx, at, store.DefaultRotation, render.NewUUID); err != nil || n == 0 {
		t.Fatalf("rotation at %v: %d %v", at, n, err)
	}
	if err := a.Apply(ctx); err != nil && !render.Partial(err) {
		t.Fatal(err)
	}
}

// TestRevokeOverlapWithXray: the inner stage on a real Xray, its users
// synced through the API as rayd does. Set XRAY_BIN.
func TestRevokeOverlapWithXray(t *testing.T) {
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

	// The revocation with overlap, applied as rayd does: no restart, the
	// next credential added through the API, nothing cut.
	rev, err := st.RevokeDeviceOverlap(ctx, phone.ID)
	if err != nil || rev.Credentials == 0 {
		t.Fatalf("revoke: %+v %v", rev, err)
	}
	if err := a.Apply(ctx); err != nil && !render.Partial(err) {
		t.Fatal(err)
	}
	m, _ = render.Collect(ctx, st)
	next := m.Sets[inner.ID][uid].Next
	if m.Inner[uid] != old || next == "" || next == old {
		t.Fatalf("after the revocation: %+v", m.Sets[inner.ID][uid])
	}
	for name, c := range map[string]net.Conn{"revoked device": onPhone, "other device": onLaptop} {
		if err := y.exchange(c, 3000); err != nil {
			t.Fatalf("the %s's stream on the old credential, cut by the revocation: %v", name, err)
		}
	}
	counted(t, ctx, st, acct, hb, "alice", &y)
	// The other device's next subscription carries the next one: it works
	// at once, and counts for the same user.
	onNext := y.open(t, client(next), target)
	if err := y.exchange(onNext, 7000); err != nil {
		t.Fatal(err)
	}
	counted(t, ctx, st, acct, hb, "alice", &y)

	// The switch, a lead later: nothing synced, every stream goes on.
	revocationStep(t, ctx, st, a, rev.SwitchAt)
	if m, _ = render.Collect(ctx, st); m.Inner[uid] != next || m.Sets[inner.ID][uid].Prev != old {
		t.Fatalf("not switched: %+v", m.Sets[inner.ID][uid])
	}
	for i, c := range []net.Conn{onPhone, onLaptop, onNext} {
		if err := y.exchange(c, 4000+i); err != nil {
			t.Fatalf("a stream after the switch: %v", err)
		}
	}
	counted(t, ctx, st, acct, hb, "alice", &y)
	if err := y.exchange(onPhone, 5000); err != nil {
		t.Fatal(err)
	}

	// The grace's end: the old credential removed through the API, the
	// streams on it cut, the revoked device's too; its bytes since the
	// last poll are counted; it gets in no more. The next one goes on.
	revocationStep(t, ctx, st, a, rev.Until)
	for name, c := range map[string]net.Conn{"revoked device": onPhone, "other device": onLaptop} {
		if ok, d := cut(c, 3*time.Second); !ok || d > time.Second {
			t.Fatalf("the %s's stream on the old credential at the grace's end: cut %v after %v", name, ok, d)
		}
		c.Close()
	}
	counted(t, ctx, st, acct, hb, "alice", &y)
	if !refused(t, client(old), target) {
		t.Fatal("the old credential still gets in after the grace")
	}
	if err := y.exchange(onNext, 6000); err != nil {
		t.Fatalf("the next credential's stream at the grace's end: %v", err)
	}
	for range 2 {
		counted(t, ctx, st, acct, hb, "alice", &y)
	}
}

// TestRevokeOverlapWithNikoServer: the same on Hysteria2 (hy2-obfs on
// niko-server behind its UDP front, Xray as the client), each device on
// its own line: its own salamander password, which the front takes off
// (spec/salamander-device-v1.md). Here the revoked device does not go on
// on the old credential: the apply after the revocation takes its
// password off the front's list (§4.2), and its stream carries nothing
// more, its datagrams opening under none of the passwords left, the
// other device's among them; its line gets in no more, not with the
// next credential either. The other device goes on as above. Set
// XRAY_BIN and NIKO_SERVER_BIN (v0.19.3 or later).
func TestRevokeOverlapWithNikoServer(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("set XRAY_BIN to an Xray built from arngory/xray-core")
	}
	niko := os.Getenv("NIKO_SERVER_BIN")
	if niko == "" {
		t.Skip("set NIKO_SERVER_BIN to niko-server v0.19.3 or later")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	st, paths, a, svc := switchNode(t, ctx, "hy2-obfs")
	phone, laptop := twoDevices(t, ctx, st)
	if err := a.Apply(ctx); err != nil && !render.Partial(err) {
		t.Fatal(err)
	}
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	uid := m.Users[0].ID
	old := m.Creds[svc.ID][uid]
	usersFile := filepath.Join(paths.Rendered, svc.Name, render.HysteriaUsers)
	secret := string(m.Services[slices.IndexFunc(m.Services, func(s render.Service) bool { return s.ID == svc.ID })].Secrets[provision.SecretObfsPassword])
	pPhone, pLaptop := store.SalamanderDevicePassword(secret, phone.Key[:]), store.SalamanderDevicePassword(secret, laptop.Key[:])
	if got := salamanderKeys(t, paths, svc.Name); len(got) != 2 || !slices.Contains(got, pPhone) || !slices.Contains(got, pLaptop) {
		t.Fatalf("the front's salamander passwords: %d, want both devices'", len(got))
	}
	backend, front, port := startObfs(t, niko, paths, svc.Name)

	phoneLink, laptopLink := obfsLink(t, m, svc.Name, phone.Key[:], port), obfsLink(t, m, svc.Name, laptop.Key[:], port)
	client := func(link, password string) int {
		socks, _ := hysteriaSocks(t, bin, link, password, "")
		return socks
	}
	target := exchangeTarget(t)
	hb := &health.Board{}
	acct := &traffic.Accountant{Store: st, Sources: traffic.Processes(paths), Health: hb}
	var y tally
	counted(t, ctx, st, acct, hb, "alice", &y)
	onPhone, onLaptop := y.open(t, client(phoneLink, old), target), y.open(t, client(laptopLink, old), target)
	if err := y.exchange(onLaptop, 20000); err != nil {
		t.Fatal(err)
	}
	counted(t, ctx, st, acct, hb, "alice", &y)

	rev, err := st.RevokeDeviceOverlap(ctx, phone.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(ctx); err != nil && !render.Partial(err) {
		t.Fatal(err)
	}
	m, _ = render.Collect(ctx, st)
	next := m.Sets[svc.ID][uid].Next
	published, _ := os.ReadFile(usersFile)
	if next == "" || !strings.Contains(string(published), old) || !strings.Contains(string(published), next) {
		t.Fatalf("the users file after the revocation:\n%s", published)
	}
	if got := salamanderKeys(t, paths, svc.Name); !slices.Equal(got, []string{pLaptop}) {
		t.Fatalf("the front's salamander passwords after the revocation: %d, want the other device's", len(got))
	}
	if closed := backend.reload(t); closed != 0 {
		t.Fatalf("the revocation closed %d connections", closed)
	}
	// The front's next read of its list: the revoked device's flow is
	// forgotten, its next datagrams open under no password left.
	front.keysRead(t, 1)
	if err := y.exchange(onLaptop, 3000); err != nil {
		t.Fatalf("the other device's stream on the old password, cut by the revocation: %v", err)
	}
	if !stalled(onPhone, 3*time.Second) {
		t.Fatal("the revoked device's stream on the old password still carries after the apply")
	}
	onPhone.Close()
	if !refused(t, client(phoneLink, next), target) {
		t.Fatal("the revoked device's salamander password still gets in after the apply")
	}
	onNext := y.open(t, client(laptopLink, next), target)
	counted(t, ctx, st, acct, hb, "alice", &y)

	// The switch: the same file; read again, it cuts nothing.
	revocationStep(t, ctx, st, a, rev.SwitchAt)
	if b, _ := os.ReadFile(usersFile); string(b) != string(published) {
		t.Fatalf("the switch changed the users file:\n%s\nthen\n%s", published, b)
	}
	if closed := backend.reload(t); closed != 0 {
		t.Fatalf("the switch closed %d connections", closed)
	}
	for i, c := range []net.Conn{onLaptop, onNext} {
		if err := y.exchange(c, 4000+i); err != nil {
			t.Fatalf("a stream after the switch: %v", err)
		}
	}
	counted(t, ctx, st, acct, hb, "alice", &y)

	// The grace's end: the old password gone, the other device's stream
	// on it cut; it gets in no more; the next one goes on. The backend
	// still had the revoked device's connection too (its idle timeout is
	// 60 s; the front only drops its datagrams): it closes both.
	revocationStep(t, ctx, st, a, rev.Until)
	if b, _ := os.ReadFile(usersFile); strings.Contains(string(b), old) {
		t.Fatalf("the users file keeps the old password after the grace:\n%s", b)
	}
	if closed := backend.reload(t); closed != 2 {
		t.Fatalf("the grace's end closed %d connections, want both devices' on the old password", closed)
	}
	if ok, d := cut(onLaptop, 3*time.Second); !ok {
		t.Fatalf("the other device's stream on the old password: not cut after %v", d)
	}
	onLaptop.Close()
	counted(t, ctx, st, acct, hb, "alice", &y)
	if !refused(t, client(laptopLink, old), target) {
		t.Fatal("the old password still gets in after the grace")
	}
	if err := y.exchange(onNext, 7000); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		counted(t, ctx, st, acct, hb, "alice", &y)
	}
}
