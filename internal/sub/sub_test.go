package sub_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/probe"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
	"github.com/arngory/raycontrol/internal/summary"
)

type fixture struct {
	st     *store.Store
	keys   provision.NodeKeys
	device store.Device
	key    [spa.KeySize]byte
	cert   []byte
	tlsCfg *tls.Config
}

func setup(t *testing.T) fixture {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	dns, err := provision.CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	st.SetUserServices(ctx, "alice", []int64{dns.ID})
	d, key, err := st.CreateDevice(ctx, "alice", "phone", "user")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := provision.LoadNodeKeys(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := st.ServiceByName(ctx, provision.SubscriptionService)
	secrets, _ := st.ServiceSecrets(ctx, svc.ID)
	cfg, err := sub.TLSConfig(secrets[provision.SecretTLSCert], secrets[provision.SecretTLSKey])
	if err != nil {
		t.Fatal(err)
	}
	return fixture{st, keys, d, key, secrets[provision.SecretTLSCert], cfg}
}

func TestSignVerify(t *testing.T) {
	f := setup(t)
	pub := f.keys.PublicJSON()
	env, err := sub.Sign(sub.Payload{V: 1, NodeID: "n", Seq: 3}, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	p, err := sub.Verify(env, pub)
	if err != nil || p.Seq != 3 {
		t.Fatalf("verify: %+v %v", p, err)
	}
	for _, which := range []string{"payload", "ed25519", "mldsa65"} {
		bad := sub.Envelope{Payload: env.Payload, Sig: map[string]string{"ed25519": env.Sig["ed25519"], "mldsa65": env.Sig["mldsa65"]}}
		switch which {
		case "payload":
			body, _ := base64.RawURLEncoding.DecodeString(env.Payload)
			bad.Payload = base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(body), `"seq":3`, `"seq":4`, 1)))
		default:
			raw, _ := base64.RawURLEncoding.DecodeString(env.Sig[which])
			raw[0] ^= 1
			bad.Sig[which] = base64.RawURLEncoding.EncodeToString(raw)
		}
		if _, err := sub.Verify(bad, pub); err == nil {
			t.Errorf("tampered %s accepted", which)
		}
	}
}

func TestAuth(t *testing.T) {
	var key [spa.KeySize]byte
	now := time.Unix(1767225600, 0)
	tok := sub.AuthToken(key, now.Unix()/60)
	if !sub.CheckAuth(tok, key, now) || !sub.CheckAuth(tok, key, now.Add(2*time.Minute)) {
		t.Fatal("valid token refused")
	}
	if sub.CheckAuth(tok, key, now.Add(4*time.Minute)) {
		t.Fatal("stale token accepted")
	}
	key[0] = 1
	if sub.CheckAuth(tok, key, now) {
		t.Fatal("token of another device accepted")
	}
	if sub.CheckAuth("Bearer x", key, now) {
		t.Fatal("other scheme accepted")
	}
}

func TestEndpoint(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	srv := &sub.Server{Store: f.st, Keys: f.keys, Log: quiet()}
	// Channel probes on the same endpoint, with the device's auth (R4-16).
	srv.Probe = &probe.Server{Auth: srv.Device, Log: quiet(),
		Report: func(context.Context, string, netip.Addr, io.Reader) error { return nil }}
	go srv.Serve(ctx, addr, f.tlsCfg)
	time.Sleep(200 * time.Millisecond)

	pin := func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		c, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		want, _ := provision.SPKIPin(f.cert)
		if base64.RawURLEncoding.EncodeToString(sum[:]) != want {
			return errors.New("pin mismatch")
		}
		return nil
	}
	client := func(curves ...tls.CurveID) *http.Client {
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, VerifyPeerCertificate: pin, CurvePreferences: curves}}}
	}
	get := func(c *http.Client, auth bool) (*http.Response, error) {
		req, _ := http.NewRequest("GET", "https://"+addr+sub.Path, nil)
		if auth {
			req.Header.Set(sub.DeviceHeader, f.device.ID)
			req.Header.Set("Authorization", sub.AuthToken(f.key, time.Now().Unix()/60))
		}
		return c.Do(req)
	}

	if _, err := get(client(tls.X25519), true); err == nil {
		t.Fatal("classic key exchange accepted")
	}
	pq := client(tls.X25519MLKEM768)
	resp, err := get(pq, false)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unauthenticated: %d", resp.StatusCode)
	}

	resp, err = get(pq, true)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var env sub.Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	p, err := sub.Verify(env, f.keys.PublicJSON())
	if err != nil {
		t.Fatal(err)
	}
	if p.V != 1 || p.Seq != 1 || p.Expires-p.Issued != int64(sub.Lifetime/time.Second) || len(p.Profiles) != 1 ||
		p.Probe == nil || p.Probe.V != 1 || p.Probe.UDP || p.Probe.Tunnel != probe.Name ||
		len(p.Probe.TunnelSvc) != 1 || p.Probe.TunnelSvc[0] != p.Profiles[0].Svc ||
		// The report fields beyond the first ones of v1 (Niko §20).
		!slices.Equal(p.Probe.Report, []string{"udp_mtu", "path"}) ||
		// The SPA carriers: UDP only without -spa-tcp.
		p.SPA == nil || !slices.Equal(p.SPA.Carriers, []string{"udp"}) {
		t.Fatalf("payload %+v", p)
	}
	for _, auth := range []bool{false, true} {
		req, _ := http.NewRequest("GET", "https://"+addr+probe.PathDown+"?bytes=1000", nil)
		if auth {
			req.Header.Set(sub.DeviceHeader, f.device.ID)
			req.Header.Set("Authorization", sub.AuthToken(f.key, time.Now().Unix()/60))
		}
		r, err := pq.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		n, _ := io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if want := map[bool]int{false: 404, true: 200}[auth]; r.StatusCode != want || (auth && n != 1000) {
			t.Fatalf("probe, auth %v: %d, %d bytes", auth, r.StatusCode, n)
		}
	}
	link, err := url.Parse(p.Profiles[0].Link)
	if err != nil {
		t.Fatal(err)
	}
	q := link.Query()
	dnsParts := strings.Split(q.Get("niko-dns"), ";")
	if link.Scheme != "vless" || !strings.HasPrefix(q.Get("encryption"), "mlkem768x25519plus.native.0rtt.") ||
		q.Get("niko-node") != p.NodeID || len(dnsParts) != 4 || dnsParts[0] != "dnstt" || len(dnsParts[3]) != 64 {
		t.Fatalf("link %s", p.Profiles[0].Link)
	}

	resp2, err := get(pq, true)
	if err != nil {
		t.Fatal(err)
	}
	var env2 sub.Envelope
	json.NewDecoder(resp2.Body).Decode(&env2)
	resp2.Body.Close()
	if p2, _ := sub.Verify(env2, f.keys.PublicJSON()); p2.Seq <= p.Seq {
		t.Fatalf("seq did not grow: %d then %d", p.Seq, p2.Seq)
	}

	// A revoked device gets nothing.
	if err := f.st.RevokeDevice(context.Background(), f.device.ID); err != nil {
		t.Fatal(err)
	}
	resp3, err := get(pq, true)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusNotFound {
		t.Fatalf("revoked device: %d", resp3.StatusCode)
	}
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestClient(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	srv := &sub.Server{Store: f.st, Keys: f.keys, Log: quiet()}
	go srv.Serve(ctx, addr, f.tlsCfg)
	time.Sleep(200 * time.Millisecond)

	pin, _ := provision.SPKIPin(f.cert)
	c := sub.Client{Addr: addr, Pin: pin, DeviceID: f.device.ID, DeviceKey: f.key, NodeKeys: f.keys.PublicJSON()}
	p, err := c.Fetch(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Profiles) != 1 {
		t.Fatalf("profiles %+v", p.Profiles)
	}

	bad := c
	bad.Pin = strings.Repeat("A", 43)
	if _, err := bad.Fetch(ctx, time.Now()); err == nil || !strings.Contains(err.Error(), "pin") {
		t.Fatalf("wrong pin: %v", err)
	}
	bad = c
	bad.DeviceKey[0] ^= 1
	if _, err := bad.Fetch(ctx, time.Now()); !errors.Is(err, sub.ErrRefused) {
		t.Fatalf("wrong key: %v", err)
	}
	bad = c
	bad.NodeID = "00"
	if _, err := bad.Fetch(ctx, time.Now()); err == nil || !strings.Contains(err.Error(), "node") {
		t.Fatalf("wrong node: %v", err)
	}
}

func TestRealityLink(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "2001:db8::7"})
	svc, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true, Settings: `{"target":"www.example.org:443"}`})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	st.SetUserServices(ctx, "alice", []int64{svc.ID})
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := sub.Profiles(m, m.Users[0])
	if err != nil || len(profiles) != 1 {
		t.Fatalf("profiles %v %v", profiles, err)
	}
	link, err := url.Parse(profiles[0].Link)
	if err != nil {
		t.Fatal(err)
	}
	q := link.Query()
	pbk, _ := base64.RawURLEncoding.DecodeString(q.Get("pbk"))
	pqv, _ := base64.RawURLEncoding.DecodeString(q.Get("pqv"))
	if link.Scheme != "vless" || link.Host != "[2001:db8::7]:443" || link.User.Username() != m.Creds[svc.ID][u.ID] ||
		q.Get("security") != "reality" || q.Get("flow") != "xtls-rprx-vision" || q.Get("sni") != "www.example.org" ||
		q.Get("fp") != "chrome" || len(pbk) != 32 || len(pqv) != 1952 || q.Get("niko-svc") != strconv.FormatInt(svc.ID, 10) ||
		!strings.HasPrefix(q.Get("encryption"), "mlkem768x25519plus.native.0rtt.") || q.Get("sid") == "" {
		t.Fatalf("link %s", profiles[0].Link)
	}
}

func TestRotationInSubscription(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7"})
	svc, _ := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true, Settings: `{"target":"www.example.org:443"}`})
	u, _ := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	st.SetUserServices(ctx, "alice", []int64{svc.ID})
	m, _ := render.Collect(ctx, st)
	first := m.Creds[svc.ID][u.ID]

	r := store.Rotation{Period: 30 * 24 * time.Hour, Lead: 3 * 24 * time.Hour, Grace: 2 * 24 * time.Hour}
	day := 24 * time.Hour
	if n, err := st.RotateCredentials(ctx, time.Now().Add(28*day), r, render.NewUUID); err != nil || n != 1 {
		t.Fatalf("publish: %d %v", n, err)
	}
	m, _ = render.Collect(ctx, st)
	profiles, err := sub.Profiles(m, m.Users[0])
	if err != nil {
		t.Fatal(err)
	}
	next := m.Sets[svc.ID][u.ID].Next
	p := profiles[0]
	if p.Next == nil || !strings.Contains(p.Next.Link, next) || !strings.Contains(p.Link, first) ||
		p.Next.From != m.Sets[svc.ID][u.ID].NextFrom.Unix() {
		t.Fatalf("profile %+v", p)
	}
	_, users := render.XrayUsers(m, m.Services[slices.IndexFunc(m.Services, func(s render.Service) bool { return s.ID == svc.ID })])
	if len(users) != 2 || users["u"+strconv.FormatInt(u.ID, 10)+"-n"] != next {
		t.Fatalf("server accepts %v while rotating", users)
	}

	// After the switch the old UUID stays accepted for the grace period.
	if _, err := st.RotateCredentials(ctx, time.Now().Add(31*day), r, render.NewUUID); err != nil {
		t.Fatal(err)
	}
	m, _ = render.Collect(ctx, st)
	_, users = render.XrayUsers(m, m.Services[slices.IndexFunc(m.Services, func(s render.Service) bool { return s.ID == svc.ID })])
	if m.Creds[svc.ID][u.ID] != next || users["u"+strconv.FormatInt(u.ID, 10)+"-p"] != first {
		t.Fatalf("after the switch: current %s, users %v", m.Creds[svc.ID][u.ID], users)
	}
	if profiles, _ = sub.Profiles(m, m.Users[0]); profiles[0].Next != nil {
		t.Fatalf("next after the switch: %+v", profiles[0].Next)
	}
}

func TestRealityKeysInSubscription(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7"})
	svc, _ := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true, Settings: `{"target":"www.example.org:443"}`})
	u, _ := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	st.SetUserServices(ctx, "alice", []int64{svc.ID})
	day := 24 * time.Hour
	now := time.Now()
	epoch := provision.RealityEpoch{Period: 90 * day, Lead: 3 * day, Prepare: day}

	render.Collect(ctx, st) // creates the credentials
	// A credential switch on day 30, published on day 28.
	r := store.Rotation{Period: 30 * day, Lead: 3 * day, Grace: 2 * day}
	if n, err := st.RotateCredentials(ctx, now.Add(28*day), r, render.NewUUID); err != nil || n != 1 {
		t.Fatalf("credentials: %d %v", n, err)
	}
	m, _ := render.Collect(ctx, st)
	set := m.Sets[svc.ID][u.ID]
	profiles, _ := sub.Profiles(m, m.Users[0])
	if p := profiles[0].Next; p == nil || p.From != set.NextFrom.Unix() {
		t.Fatalf("credential next: %+v", p)
	}

	// New keys requested for day 29: they come first, with the next UUID,
	// which the server already accepts.
	if err := provision.RequestRealityRotation(ctx, st, "r", now.Add(26*day), epoch.Lead, false); err != nil {
		t.Fatal(err)
	}
	if n, err := provision.RotateReality(ctx, st, now.Add(26*day), epoch, nil, nil); err != nil || n != 1 {
		t.Fatalf("keys: %d %v", n, err)
	}
	m, _ = render.Collect(ctx, st)
	profiles, _ = sub.Profiles(m, m.Users[0])
	p := profiles[0]
	cur, _ := url.Parse(p.Link)
	if p.Next == nil || p.Next.From != now.Add(29*day).Unix() {
		t.Fatalf("next %+v", p.Next)
	}
	next, _ := url.Parse(p.Next.Link)
	if next.User.Username() != set.Next || next.Query().Get("pbk") == cur.Query().Get("pbk") ||
		next.Query().Get("pqv") == cur.Query().Get("pqv") || next.Query().Get("encryption") == cur.Query().Get("encryption") ||
		next.Query().Get("sni") != "www.example.org" {
		t.Fatalf("next link %s\ncurrent %s", p.Next.Link, p.Link)
	}
	// The server keeps its keys until the switch.
	svcNow := m.Services[slices.IndexFunc(m.Services, func(s render.Service) bool { return s.ID == svc.ID })]
	if pbk, _, _ := render.RealityKeys(svcNow); pbk != cur.Query().Get("pbk") {
		t.Fatal("server keys changed before the switch")
	}
}

// The hint of the network goes into the signed subscription (R4-21), only
// for the client's own services, and not for a request from the node.
func TestHintsInSubscription(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "203.0.113.7"})
	svc, _ := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true, Settings: `{"target":"www.example.org:443"}`})
	st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	st.SetUserServices(ctx, "alice", []int64{svc.ID})
	keys, err := provision.LoadNodeKeys(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	var asked []uint16
	s := &sub.Server{Store: st, Keys: keys, Hints: func(_ context.Context, addr netip.Addr, svcs []uint16) *summary.Hints {
		asked = svcs
		if addr.String() != "198.51.100.20" {
			return nil
		}
		return &summary.Hints{Order: svcs, Devices: 12, Days: 7}
	}}
	nodeKeys := keys.PublicJSON()
	payload := func(addr string) sub.Payload {
		t.Helper()
		var a netip.Addr
		if addr != "" {
			a = netip.MustParseAddr(addr)
		}
		e, err := s.BuildFor(ctx, "alice", a, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		p, err := sub.Verify(e, nodeKeys)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := payload("198.51.100.20")
	if p.Hints == nil || !slices.Equal(p.Hints.Order, []uint16{uint16(svc.ID)}) || p.Hints.Devices != 12 || !slices.Equal(asked, []uint16{uint16(svc.ID)}) {
		t.Fatalf("hints %+v, asked about %v", p.Hints, asked)
	}
	for _, addr := range []string{"", "127.0.0.1", "203.0.113.99"} {
		if p := payload(addr); p.Hints != nil {
			t.Fatalf("hints for %q: %+v", addr, p.Hints)
		}
	}
}

// With -spa-tcp the hint lists the TCP carriers in the order to try them:
// the ClientHello before bare TCP.
func TestCarrierHintOrder(t *testing.T) {
	f := setup(t)
	srv := &sub.Server{Store: f.st, Keys: f.keys, Log: quiet(), TCPCarrier: true}
	env, err := srv.Build(context.Background(), "alice", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p, err := sub.Verify(env, f.keys.PublicJSON())
	if err != nil {
		t.Fatal(err)
	}
	if p.SPA == nil || !slices.Equal(p.SPA.Carriers, []string{"udp", "tls", "tcp"}) {
		t.Fatalf("carriers %+v", p.SPA)
	}
}

// Relays in the subscription (relay-v1 §4): once a relay has its bundle it
// is listed with its own SPA, and the profiles it forwards name it in via;
// DNS tunnels do not go through relays.
func TestRelaysInSubscription(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	srv := &sub.Server{Store: f.st, Keys: f.keys, Log: quiet()}
	build := func() sub.Payload {
		t.Helper()
		env, err := srv.Build(ctx, "alice", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		p, err := sub.Verify(env, f.keys.PublicJSON())
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	reality, err := provision.CreateService(ctx, f.st, store.Service{Kind: "reality", Name: "reality", Enabled: true,
		Settings: `{"target":"www.example.org:443"}`})
	if err != nil {
		t.Fatal(err)
	}
	dns, _ := f.st.ServiceByName(ctx, "dns")
	if err := f.st.SetUserServices(ctx, "alice", []int64{dns.ID, reality.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.CreateRelay(ctx, "r1", netip.MustParseAddr("198.51.100.20")); err != nil {
		t.Fatal(err)
	}
	if p := build(); len(p.Relays) != 0 {
		t.Fatalf("a relay without a bundle listed: %+v", p.Relays)
	}
	if err := f.st.SetRelayCertPin(ctx, "r1", "pin"); err != nil {
		t.Fatal(err)
	}
	p := build()
	params, err := provision.RelayParams(ctx, f.st, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Relays) != 1 || p.Relays[0].ID != "r1" || p.Relays[0].Host != "198.51.100.20" || p.Relays[0].SPA != node.FromParams(params) {
		t.Fatalf("relays %+v", p.Relays)
	}
	kinds := map[uint16]string{uint16(dns.ID): "dnstt", uint16(reality.ID): "reality"}
	if len(p.Profiles) != 2 {
		t.Fatalf("profiles %+v", p.Profiles)
	}
	for _, pr := range p.Profiles {
		wantVia := kinds[pr.Svc] == "reality"
		if (len(pr.Via) == 1 && pr.Via[0] == "r1") != wantVia {
			t.Errorf("%s (%s): via %v", pr.Name, kinds[pr.Svc], pr.Via)
		}
	}

	// The probe endpoint (relay-v1 §9.2): with a bundle that has one, and
	// only while the relay's rayd relay is there.
	if p.Relays[0].Probe != nil {
		t.Fatalf("a probe endpoint from a bundle without one: %+v", p.Relays[0].Probe)
	}
	b, _ := json.Marshal(node.FromParams(params))
	if err := f.st.IssueRelay(ctx, "r1", store.RelayIssue{SPA: b, SSHPort: 22, Admin: []string{"192.0.2.7/32"}, CertPin: "pin2",
		ProbePort: 31000, ProbePin: "probe-pin"}); err != nil {
		t.Fatal(err)
	}
	up := false
	srv.RelayProbe = func(name string) bool { return up && name == "r1" }
	if p := build(); p.Relays[0].Probe != nil {
		t.Fatalf("a probe endpoint while rayd relay is away: %+v", p.Relays[0].Probe)
	}
	up = true
	want := sub.RelayProbeHint{V: 1, Port: 31000, Pin: "probe-pin", Svc: provision.RelayProbeSvc, UDP: true}
	if p := build(); p.Relays[0].Probe == nil || *p.Relays[0].Probe != want {
		t.Fatalf("probe endpoint %+v, want %+v", p.Relays[0].Probe, want)
	}
	// It takes reports when the node does.
	srv.Probe = &probe.Server{}
	if p := build(); p.Relays[0].Probe == nil || *p.Relays[0].Probe != want {
		t.Fatalf("probe endpoint of a node without reports %+v", p.Relays[0].Probe)
	}
	srv.Probe = &probe.Server{Report: func(context.Context, string, netip.Addr, io.Reader) error { return nil }}
	want.Report = true
	if p := build(); p.Relays[0].Probe == nil || *p.Relays[0].Probe != want {
		t.Fatalf("probe endpoint with reports %+v", p.Relays[0].Probe)
	}

	// Asked for through the relay: the relay's address, whose hints are
	// not the client's (relay-v1 §9.3).
	srv.Hints = func(context.Context, netip.Addr, []uint16) *summary.Hints { return &summary.Hints{Days: 30} }
	for addr, want := range map[string]bool{"198.51.100.20": false, "::ffff:198.51.100.20": false, "203.0.113.9": true} {
		env, err := srv.BuildFor(ctx, "alice", netip.MustParseAddr(addr), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		p, _ := sub.Verify(env, f.keys.PublicJSON())
		if (p.Hints != nil) != want {
			t.Errorf("from %s: hints %+v", addr, p.Hints)
		}
	}
}
