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
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
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
	if p.V != 1 || p.Seq != 1 || p.Expires-p.Issued != int64(sub.Lifetime/time.Second) || len(p.Profiles) != 1 {
		t.Fatalf("payload %+v", p)
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
