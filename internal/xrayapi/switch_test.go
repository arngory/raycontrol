package xrayapi_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/live"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
	"github.com/arngory/raycontrol/internal/traffic"
	"github.com/arngory/raycontrol/internal/xrayapi"
)

// A credential rotation (R4-1) with the processes running: since v0.23.0
// each credential has a name of its own for its whole life
// (store.CredentialName), so the switch (the next credential becoming
// current, the current one previous) leaves Xray's and niko-server's users
// as they were, and a connection on either credential goes on. Before,
// the names went by the role (u5, u5-n, u5-p), moved at the switch, and
// Xray and niko-server cut the connections of a name that changed: the
// update from those names cuts once, as these tests show too. Every byte
// is counted once through it all.

// exchangeTarget answers each message on a connection, its length in its
// first four bytes, with three times as many bytes, for as long as the
// connection lasts.
func exchangeTarget(t *testing.T) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					var n [4]byte
					if _, err := io.ReadFull(c, n[:]); err != nil {
						return
					}
					size := int64(binary.BigEndian.Uint32(n[:]))
					if _, err := io.CopyN(io.Discard, c, size-4); err != nil {
						return
					}
					if _, err := c.Write(bytes.Repeat([]byte("d"), int(3*size))); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr()
}

// tally is what went through the streams: up to the target, and down,
// three times as much.
type tally struct{ up, down int64 }

// exchange sends a message of size bytes on a stream and takes the answer.
func (y *tally) exchange(c net.Conn, size int) error {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	msg := bytes.Repeat([]byte("u"), size)
	binary.BigEndian.PutUint32(msg, uint32(size))
	if _, err := c.Write(msg); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, make([]byte, 3*size)); err != nil {
		return err
	}
	y.up, y.down = y.up+int64(size), y.down+3*int64(size)
	return nil
}

// open opens a stream to target through a client's SOCKS port and makes
// one exchange on it; it waits for the client to listen.
func (y *tally) open(t *testing.T, socks int, target net.Addr) net.Conn {
	t.Helper()
	tp := target.(*net.TCPAddr).Port
	var last error
	for range 50 {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(socks), time.Second)
		if err != nil {
			last = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		// SOCKS5, no auth, CONNECT 127.0.0.1:tp.
		c.SetDeadline(time.Now().Add(5 * time.Second))
		req := []byte{5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, byte(tp >> 8), byte(tp)}
		buf := make([]byte, 12)
		if _, err = c.Write(req); err == nil {
			if _, err = io.ReadFull(c, buf); err == nil && (buf[1] != 0 || buf[3] != 0) {
				err = errors.New("SOCKS refused")
			}
		}
		if err == nil {
			c.SetDeadline(time.Time{})
			if err = y.exchange(c, 1000); err == nil {
				return c
			}
		}
		last = err
		c.Close()
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no stream through the client on %d: %v", socks, last)
	return nil
}

// cut waits up to limit for a stream to end, and reports whether it did
// and when.
func cut(c net.Conn, limit time.Duration) (bool, time.Duration) {
	start := time.Now()
	c.SetReadDeadline(start.Add(limit))
	defer c.SetReadDeadline(time.Time{})
	_, err := c.Read(make([]byte, 1))
	if err == nil {
		return false, time.Since(start)
	}
	var ne net.Error
	timedOut := errors.As(err, &ne) && ne.Timeout()
	return !timedOut, time.Since(start)
}

// counted runs the traffic loop over the processes and checks that the
// user's count is what went through.
func counted(t *testing.T, ctx context.Context, st *store.Store, acct *traffic.Accountant, hb *health.Board, user string, want *tally) {
	t.Helper()
	acct.Round(ctx, "", true)
	for _, l := range hb.Loops() {
		if l.Failing() {
			t.Fatalf("loop %s: %s", l.Name, l.Err)
		}
	}
	u, err := st.UserByName(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	if u.TrafficUp != want.up || u.TrafficDown != want.down {
		t.Fatalf("counted %d/%d, went through %d/%d", u.TrafficUp, u.TrafficDown, want.up, want.down)
	}
}

// switchNode is a node with a limit on alice (counting on), as rayd runs
// it: the store and an applier over the rendered files, which may restart
// nothing once started.
func switchNode(t *testing.T, ctx context.Context, kind string) (*store.Store, render.Paths, *live.Applier, store.Service) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := provision.Init(ctx, st, provision.Options{Host: "127.0.0.1", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	svc, err := provision.CreateService(ctx, st, store.Service{Kind: kind, Name: "svc", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	limit := int64(1 << 40)
	if _, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true, TrafficLimit: &limit}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserServices(ctx, "alice", []int64{svc.ID}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // the limit a second before the processes start
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: filepath.Join(dir, "run")}
	started := false
	a := &live.Applier{Store: st, Paths: paths, Log: slog.New(slog.DiscardHandler),
		Restart: func(_ context.Context, _, unit string) error {
			if started {
				t.Errorf("%s restarted", unit)
			}
			return nil
		}}
	if err := a.Apply(ctx); err != nil && !render.Partial(err) {
		t.Fatal(err)
	}
	started = true
	return st, paths, a, svc
}

// rotate moves the store's credentials to their state at now+at, as rayd's
// rotation does, and applies.
func rotate(t *testing.T, ctx context.Context, st *store.Store, a *live.Applier, at time.Duration) {
	t.Helper()
	r := store.Rotation{Period: 30 * 24 * time.Hour, Lead: 3 * 24 * time.Hour, Grace: 2 * 24 * time.Hour}
	if n, err := st.RotateCredentials(ctx, time.Now().Add(at), r, render.NewUUID); err != nil || n == 0 {
		t.Fatalf("rotation at %v: %d %v", at, n, err)
	}
	if err := a.Apply(ctx); err != nil && !render.Partial(err) {
		t.Fatal(err)
	}
}

const day = 24 * time.Hour

// TestCredentialSwitchWithXray: the inner stage on a real Xray, its users
// synced through the API as rayd does. It starts with the names of
// v0.22.0 (u1); the update's sync renames the credential and cuts its
// connection once. Then a rotation: published, the next credential is
// added and nothing is cut; at the switch nothing is synced and both
// credentials' connections go on; at the grace's end the previous one is
// removed and only its connection is cut. Xray keeps a removed name's
// counter: the loop counts every byte once, those since the last poll
// before a removal too. Set XRAY_BIN.
func TestCredentialSwitchWithXray(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("set XRAY_BIN to an Xray built from arngory/xray-core")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	st, paths, a, _ := switchNode(t, ctx, "dnstt")
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	inner := m.Services[slices.IndexFunc(m.Services, func(s render.Service) bool { return s.Kind == "inner" })]
	uid := m.Users[0].ID
	first := m.Inner[uid]

	// The rendered inner config on TCP (an Xray client cannot dial a unix
	// socket), its API and stats kept, the loopback target allowed; its
	// users named as v0.22.0 named them.
	rendered, err := os.ReadFile(filepath.Join(paths.Rendered, inner.Name, "xray.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(rendered, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["stats"] == nil {
		t.Fatal("no stats with a limit")
	}
	serverPort := freePort(t)
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	in["listen"], in["port"] = "127.0.0.1", serverPort
	in["settings"].(map[string]any)["clients"] = []map[string]string{{"id": first, "email": render.InnerEmail(uid)}}
	delete(cfg, "dns")
	delete(cfg, "routing")
	cfg["outbounds"] = []map[string]any{{"protocol": "freedom", "settings": map[string]any{
		"finalRules": []map[string]any{{"action": "allow", "ip": []string{"127.0.0.0/8"}}}}}}
	for _, d := range []string{inner.Name, inner.Name + "-api"} {
		os.MkdirAll(filepath.Join(paths.Run, d), 0o755)
	}
	runXray(t, bin, writeJSON(t, cfg))
	api := paths.APISocket(inner.Name)
	waitFile(t, api)

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
			// A cut reaches the SOCKS stream at once, not after the
			// default second of one way only.
			"policy": map[string]any{"levels": map[string]any{"0": map[string]int{"uplinkOnly": 0, "downlinkOnly": 0}}},
		}))
		return port
	}
	target := exchangeTarget(t)
	hb := &health.Board{}
	acct := &traffic.Accountant{Store: st, Sources: traffic.Processes(paths), Health: hb}
	var y tally
	counted(t, ctx, st, acct, hb, "alice", &y)
	xc := xrayapi.Dial(api)
	users := func() map[string]string {
		t.Helper()
		got, err := xc.VLESSUsers(ctx, render.InnerTag)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	// v0.22.0: the credential as u1.
	clientA := client(first)
	onA := y.open(t, clientA, target)
	counted(t, ctx, st, acct, hb, "alice", &y)
	if err := y.exchange(onA, 20000); err != nil {
		t.Fatal(err)
	}

	// The update: rayd syncs the credentials' own names. The credential's
	// connection is cut once (renamed); its bytes since the last poll stay
	// in u1's counter and are counted.
	_, want := render.XrayUsers(m, inner)
	if added, removed, err := xc.SyncVLESS(ctx, render.InnerTag, "", want); err != nil || added != 1 || removed != 1 {
		t.Fatalf("the update's sync: +%d -%d %v", added, removed, err)
	}
	if ok, d := cut(onA, 3*time.Second); !ok || d > time.Second {
		t.Fatalf("the renamed credential's stream: cut %v after %v", ok, d)
	}
	onA.Close()
	counted(t, ctx, st, acct, hb, "alice", &y)
	onA = y.open(t, clientA, target)
	if err := y.exchange(onA, 3000); err != nil {
		t.Fatal(err)
	}
	counted(t, ctx, st, acct, hb, "alice", &y)
	named := users()
	if !sameUsers(named, map[string]string{store.CredentialName(uid, first): first}) {
		t.Fatalf("after the update: %v", named)
	}

	// Published: the next credential added, nothing cut.
	rotate(t, ctx, st, a, 28*day)
	m, _ = render.Collect(ctx, st)
	next := m.Sets[inner.ID][uid].Next
	if next == "" || len(users()) != 2 || users()[store.CredentialName(uid, next)] != next {
		t.Fatalf("published: %v", users())
	}
	if err := y.exchange(onA, 4000); err != nil {
		t.Fatalf("the current credential's stream after the next one was published: %v", err)
	}
	onB := y.open(t, client(next), target)
	counted(t, ctx, st, acct, hb, "alice", &y)

	// The switch: the same users, both streams go on.
	before := users()
	rotate(t, ctx, st, a, 31*day)
	if m, _ = render.Collect(ctx, st); m.Inner[uid] != next || m.Sets[inner.ID][uid].Prev != first {
		t.Fatalf("not switched: %+v", m.Sets[inner.ID][uid])
	}
	if after := users(); !sameUsers(after, before) {
		t.Fatalf("the switch changed Xray's users: %v, then %v", before, after)
	}
	for i, c := range []net.Conn{onA, onB, onA, onB} {
		if err := y.exchange(c, 5000+i); err != nil {
			t.Fatalf("a stream after the switch: %v", err)
		}
	}
	counted(t, ctx, st, acct, hb, "alice", &y)
	if err := y.exchange(onA, 7000); err != nil {
		t.Fatal(err)
	}

	// The grace's end: the previous credential removed, its stream cut;
	// its bytes since the last poll are counted, nothing twice.
	rotate(t, ctx, st, a, 34*day)
	if after := users(); !sameUsers(after, map[string]string{store.CredentialName(uid, next): next}) {
		t.Fatalf("the grace's end: %v", after)
	}
	if ok, d := cut(onA, 3*time.Second); !ok || d > time.Second {
		t.Fatalf("the previous credential's stream: cut %v after %v", ok, d)
	}
	if err := y.exchange(onB, 6000); err != nil {
		t.Fatalf("the current credential's stream at the grace's end: %v", err)
	}
	counted(t, ctx, st, acct, hb, "alice", &y)
	for range 3 {
		counted(t, ctx, st, acct, hb, "alice", &y)
	}
}

// TestCredentialSwitchWithNikoServer: the same on Hysteria2 (hy2-obfs on
// niko-server behind its UDP front, Xray as the client), its users file
// written as rayd does and read again on SIGHUP. Set XRAY_BIN and
// NIKO_SERVER_BIN (v0.15.0 or later: users cut, byte counters).
func TestCredentialSwitchWithNikoServer(t *testing.T) {
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
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	uid := m.Users[0].ID
	first := m.Creds[svc.ID][uid]
	usersFile := filepath.Join(paths.Rendered, svc.Name, render.HysteriaUsers)
	rendered, err := os.ReadFile(usersFile)
	if err != nil {
		t.Fatal(err)
	}
	// The users file as v0.22.0 wrote it: the credential as u1.
	legacy, _ := json.Marshal(map[string]any{"users": []map[string]any{{"name": render.InnerEmail(uid), "enabled": true,
		"hy2": map[string]string{"password": first}}}})
	if err := os.WriteFile(usersFile, legacy, 0o644); err != nil {
		t.Fatal(err)
	}
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
		cfg["log"] = map[string]string{"level": "info"} // the reloads' lines
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
	backend.waitReload(t) // read at the start

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
	counted(t, ctx, st, acct, hb, "alice", &y) // from here on, all of it

	// v0.22.0: the credential as u1.
	clientA := client(first)
	onA := y.open(t, clientA, target)
	counted(t, ctx, st, acct, hb, "alice", &y)
	if err := y.exchange(onA, 20000); err != nil {
		t.Fatal(err)
	}

	// The update: rayd writes the credentials' own names, niko-server
	// reads them and cuts the renamed credential's connection, once; its
	// bytes since the last poll stay in u1's counter and are counted.
	if err := a.Apply(ctx); err != nil && !render.Partial(err) {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(usersFile); !bytes.Equal(b, rendered) {
		t.Fatalf("the update wrote\n%s", b)
	}
	if closed := backend.reload(t); closed != 1 {
		t.Fatalf("the update closed %d connections", closed)
	}
	if ok, d := cut(onA, 3*time.Second); !ok {
		t.Fatalf("the renamed credential's stream: not cut after %v", d)
	}
	onA.Close()
	counted(t, ctx, st, acct, hb, "alice", &y)
	onA = y.open(t, clientA, target)
	counted(t, ctx, st, acct, hb, "alice", &y)

	// Published: the next credential in the file, nothing cut.
	rotate(t, ctx, st, a, 28*day)
	m, _ = render.Collect(ctx, st)
	next := m.Sets[svc.ID][uid].Next
	published, _ := os.ReadFile(usersFile)
	if next == "" || !bytes.Contains(published, []byte(store.CredentialName(uid, next))) {
		t.Fatalf("published:\n%s", published)
	}
	if closed := backend.reload(t); closed != 0 {
		t.Fatalf("publishing closed %d connections", closed)
	}
	if err := y.exchange(onA, 4000); err != nil {
		t.Fatalf("the current credential's stream after the next one was published: %v", err)
	}
	onB := y.open(t, client(next), target)
	counted(t, ctx, st, acct, hb, "alice", &y)

	// The switch: the same file; read again, it cuts nothing.
	rotate(t, ctx, st, a, 31*day)
	if m, _ = render.Collect(ctx, st); m.Creds[svc.ID][uid] != next {
		t.Fatal("not switched")
	}
	if b, _ := os.ReadFile(usersFile); !bytes.Equal(b, published) {
		t.Fatalf("the switch changed the users file:\n%s\nthen\n%s", published, b)
	}
	if closed := backend.reload(t); closed != 0 {
		t.Fatalf("the switch closed %d connections", closed)
	}
	for i, c := range []net.Conn{onA, onB, onA, onB} {
		if err := y.exchange(c, 5000+i); err != nil {
			t.Fatalf("a stream after the switch: %v", err)
		}
	}
	counted(t, ctx, st, acct, hb, "alice", &y)
	if err := y.exchange(onA, 7000); err != nil {
		t.Fatal(err)
	}

	// The grace's end: the previous credential gone, its connection cut;
	// its bytes since the last poll are counted, nothing twice.
	rotate(t, ctx, st, a, 34*day)
	if closed := backend.reload(t); closed != 1 {
		t.Fatalf("the grace's end closed %d connections", closed)
	}
	if ok, d := cut(onA, 3*time.Second); !ok {
		t.Fatalf("the previous credential's stream: not cut after %v", d)
	}
	if err := y.exchange(onB, 6000); err != nil {
		t.Fatalf("the current credential's stream at the grace's end: %v", err)
	}
	counted(t, ctx, st, acct, hb, "alice", &y)
	for range 3 {
		counted(t, ctx, st, acct, hb, "alice", &y)
	}
}

// sameUsers reports whether two user sets are the same.
func sameUsers(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// nikoProc is a niko-server process the test signals, with its log.
type nikoProc struct {
	cmd  *exec.Cmd
	mu   sync.Mutex
	logs bytes.Buffer
	seen int // reload lines read
}

func (p *nikoProc) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.logs.Write(b)
}

// reloadLine is the backend's line at each read of its users file.
var reloadLine = regexp.MustCompile(`(\d+) users(?:, (\d+) connections of removed users closed)?`)

// waitReload waits for the backend's next read of its users file, after
// the seen ones, and returns the connections it closed.
func (p *nikoProc) waitReload(t *testing.T) int {
	t.Helper()
	for range 100 {
		p.mu.Lock()
		lines := reloadLine.FindAllStringSubmatch(p.logs.String(), -1)
		p.mu.Unlock()
		if len(lines) > p.seen {
			l := lines[p.seen]
			p.seen++
			closed, _ := strconv.Atoi(l[2])
			return closed
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the backend did not read its users file:\n%s", p.logs.String())
	return 0
}

// reload has the backend read its users file now (SIGHUP) and returns the
// connections it closed; a closed connection is gone by then.
func (p *nikoProc) reload(t *testing.T) int {
	t.Helper()
	if err := p.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	return p.waitReload(t)
}

// startNiko runs a niko-server process from a rendered config, adjusted
// for the test; it may reach any address (the loopback target).
func startNiko(t *testing.T, niko, role, rendered string, adjust func(map[string]any)) *nikoProc {
	t.Helper()
	var cfg map[string]any
	b, err := os.ReadFile(rendered)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	adjust(cfg)
	path := writeJSON(t, cfg)
	if out, err := exec.Command(niko, "check", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("niko-server check %s: %v\n%s", rendered, err, out)
	}
	p := &nikoProc{cmd: exec.Command(niko, role, "-c", path)}
	p.cmd.Env = append(os.Environ(), "NIKO_SERVER_UNSAFE_ANY_DESTINATION=1")
	p.cmd.Stderr = p
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.cmd.Process.Kill()
		p.cmd.Wait()
		if t.Failed() {
			p.mu.Lock()
			t.Logf("niko-server %s:\n%s", role, p.logs.String())
			p.mu.Unlock()
		}
	})
	time.Sleep(300 * time.Millisecond)
	return p
}
