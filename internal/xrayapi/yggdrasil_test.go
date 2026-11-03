package xrayapi_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
)

// yggMeta is the start of a Yggdrasil link (yggdrasil-go 0.5, no password):
// "meta", the length, version and key TLVs, an ed25519 signature over the
// BLAKE2b-512 of the key.
func yggMeta(key ed25519.PrivateKey) []byte {
	public := key.Public().(ed25519.PublicKey)
	b := []byte{'m', 'e', 't', 'a', 0, 0, 0, 0, 0, 2, 0, 0, 0, 1, 0, 2, 0, 5, 0, 2, 0, 32}
	b = append(b, public...)
	b = append(b, 0, 3, 0, 1, 0)
	hash := blake2b.Sum512(public)
	b = append(b, ed25519.Sign(key, hash[:])...)
	binary.BigEndian.PutUint16(b[4:], uint16(len(b)-6))
	return b
}

// TestYggdrasilWithNikoServer: the Yggdrasil service as rendered (R4-15),
// on niko-server behind its TCP front. The key of the subscription link
// gets the node's handshake back, signed by the node's key in the link; a
// key that is not a user's gets nothing; anything else on the name gets
// the site's 404. Set NIKO_SERVER_BIN (v0.4 or later).
func TestYggdrasilWithNikoServer(t *testing.T) {
	niko := os.Getenv("NIKO_SERVER_BIN")
	if niko == "" {
		t.Skip("set NIKO_SERVER_BIN to niko-server v0.4 or later (yggdrasil)")
	}
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "127.0.0.1", Domain: "example.com"})
	port := freePort(t)
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "reality", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	y, err := provision.CreateService(ctx, st, store.Service{Kind: "yggdrasil", Name: "ygg", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	var settings render.YggdrasilSettings
	json.Unmarshal([]byte(y.Settings), &settings)
	siteSvc, _ := st.ServiceByName(ctx, "site")
	keyDER, certDER, _ := provision.SelfSigned(settings.SNI)
	st.SetServiceSecret(ctx, siteSvc.ID, provision.SecretTLSChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	st.SetServiceSecret(ctx, siteSvc.ID, provision.SecretTLSKey, keyDER)
	st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	st.SetUserServices(ctx, "alice", []int64{y.ID})

	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: filepath.Join(dir, "run")}
	files, _, err := render.Render(m, paths)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		os.MkdirAll(filepath.Dir(f.Path), 0o755)
		os.WriteFile(f.Path, f.Content, 0o600)
	}
	// What systemd copies for the unit (Paths.Credential).
	for _, name := range []string{render.YggdrasilTLSKey, render.YggdrasilNodeKey} {
		b, err := os.ReadFile(filepath.Join(paths.Rendered, "ygg", name))
		if err != nil {
			t.Fatal(err)
		}
		os.MkdirAll(filepath.Join(paths.Run, "ygg"), 0o700)
		os.WriteFile(paths.Credential("ygg", name), b, 0o600)
	}
	backend := filepath.Join(paths.Rendered, "ygg", "backend.json")
	var probe map[string]any
	b, _ := os.ReadFile(backend)
	json.Unmarshal(b, &probe)
	probe["front_uid"] = os.Getuid()
	if out, err := exec.Command(niko, "check", "-c", writeJSON(t, probe)).CombinedOutput(); err != nil {
		if strings.Contains(string(out), "not served by this niko-server release") || strings.Contains(string(out), `unknown field "exit_ports"`) {
			t.Skipf("niko-server older than v0.4: %s", bytes.TrimSpace(out))
		}
		t.Fatalf("niko-server check: %v\n%s", err, out)
	}
	runNiko(t, niko, "backend", backend, func(cfg map[string]any) { cfg["front_uid"] = os.Getuid() })
	runFront(t, niko, filepath.Join(paths.Rendered, "front", "front.json"), port)

	profiles, err := sub.Profiles(m, m.Users[0])
	if err != nil || len(profiles) != 1 {
		t.Fatalf("profiles %+v %v", profiles, err)
	}
	link, _ := url.Parse(profiles[0].Link)
	peerURI, keyHex, _ := strings.Cut(link.Query().Get("niko-ygg"), ";")
	peer, _ := url.Parse(peerURI)
	seed, _ := hex.DecodeString(keyHex)
	nodeKey := peer.Query().Get("key")

	link1 := func(key ed25519.PrivateKey) ([]byte, error) {
		c, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port), &tls.Config{ServerName: peer.Query().Get("sni"),
			InsecureSkipVerify: true, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{"h2", "http/1.1"}})
		if err != nil {
			return nil, err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(yggMeta(key)); err != nil {
			return nil, err
		}
		head := make([]byte, 6)
		if _, err := io.ReadFull(c, head); err != nil {
			return nil, err
		}
		rest := make([]byte, binary.BigEndian.Uint16(head[4:]))
		_, err = io.ReadFull(c, rest)
		return append(head, rest...), err
	}
	reply, err := link1(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatalf("the user's link: %v", err)
	}
	if !bytes.HasPrefix(reply, []byte("meta")) || !bytes.Contains(reply, mustHex(t, nodeKey)) {
		t.Fatalf("the node's handshake %x does not carry its key %s", reply, nodeKey)
	}
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	if reply, err := link1(stranger); err == nil {
		t.Fatalf("a key that is not a user's got %x", reply)
	}

	// Not a link: the site's empty 404, h2.
	tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{ServerName: settings.SNI, InsecureSkipVerify: true,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, "127.0.0.1:"+strconv.Itoa(port))
		}}
	resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://" + settings.SNI + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || resp.ProtoMajor != 2 || len(body) != 0 {
		t.Fatalf("not a link: %s %d, %d bytes", resp.Proto, resp.StatusCode, len(body))
	}
}

func mustHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
