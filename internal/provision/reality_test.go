package provision

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

func target(t *testing.T, pad int, cfg func(*tls.Config)) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "target.test"}, DNSNames: []string{"target.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	if pad > 0 {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 1}, Value: make([]byte, pad)}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	realityRoots = x509.NewCertPool()
	realityRoots.AddCert(cert)
	t.Cleanup(func() { realityRoots = nil })
	c := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"h2", "http/1.1"}}
	if cfg != nil {
		cfg(c)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go http.Serve(ln, http.NotFoundHandler())
	return ln.Addr().String()
}

func TestCheckRealityTarget(t *testing.T) {
	ctx := context.Background()
	if err := CheckRealityTarget(ctx, target(t, 4096, nil), "target.test"); err != nil {
		t.Fatalf("good target: %v", err)
	}
	for name, tc := range map[string]struct {
		pad  int
		cfg  func(*tls.Config)
		sni  string
		want string
	}{
		"short chain": {pad: 0, want: "certificate chain"},
		"no ML-KEM":   {pad: 4096, cfg: func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.X25519} }, want: "X25519MLKEM768"},
		"TLS 1.2":     {pad: 4096, cfg: func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 }, want: "TLS 1.3"},
		"no HTTP/2":   {pad: 4096, cfg: func(c *tls.Config) { c.NextProtos = []string{"http/1.1"} }, want: "HTTP/2"},
		"wrong name":  {pad: 4096, sni: "other.test", want: "certificate"},
	} {
		sni := tc.sni
		if sni == "" {
			sni = "target.test"
		}
		err := CheckRealityTarget(ctx, target(t, tc.pad, tc.cfg), sni)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error about %s", name, err, tc.want)
		}
	}
	if err := CheckRealityTarget(ctx, "/run/niko/site/site.sock", "x.example.com"); err != nil {
		t.Fatalf("unix target: %v", err)
	}
}

// A REALITY target on a local address (R4-38, spec/egress-policy-v1.md
// §10): by its address and port it is the data plane's exemption, and so
// is localhost (127.0.0.1 and ::1: Xray's resolver may take either); by
// any other name it is none, and the check says so instead of passing on
// rayd's path, which the data plane's dial would not take. 0.0.0.0 and ::
// are none: the kernel dials loopback for them.
func TestRealityLocalTarget(t *testing.T) {
	svc := func(settings string) store.Service {
		return store.Service{Kind: "reality", Enabled: true, Settings: settings, UID: 9120}
	}
	for settings, want := range map[string]string{
		`{"target":"127.0.0.1:8443","sni":"www.example.org"}`: "127.0.0.1:8443",
		`{"target":"[::1]:8443","sni":"www.example.org"}`:     "[::1]:8443",
		`{"target":"10.0.0.7:443","sni":"www.example.org"}`:   "10.0.0.7:443",
		`{"target":"168.63.129.16:443","sni":"x.example"}`:    "168.63.129.16:443",
		`{"target":"localhost:8443","sni":"www.example.org"}`: "127.0.0.1:8443 [::1]:8443",
		`{"target":"LocalHost:8443","sni":"www.example.org"}`: "127.0.0.1:8443 [::1]:8443",
		`{"target":"localhost:0","sni":"www.example.org"}`:    "",
		`{"target":"localhost.example:8443","sni":"x.test"}`:  "",
		`{"target":"0.0.0.0:8443","sni":"www.example.org"}`:   "",
		`{"target":"[::]:8443","sni":"www.example.org"}`:      "",
		`{"target":"www.example.org:443"}`:                    "",
		`{"target":"1.1.1.1:443","sni":"one.one.one.one"}`:    "",
		`{"target":"/run/x.sock","sni":"www.example.org"}`:    "",
		`{"site":"site","sni":"www.example.org"}`:             "",
		`{"target":"127.0.0.1:0","sni":"www.example.org"}`:    "",
	} {
		var got []string
		for _, ap := range RealityLocalTarget(svc(settings)) {
			got = append(got, ap.String())
		}
		if strings.Join(got, " ") != want {
			t.Errorf("%s: %q, want %q", settings, got, want)
		}
	}
	off := svc(`{"target":"127.0.0.1:8443","sni":"www.example.org"}`)
	off.Enabled = false
	if RealityLocalTarget(off) != nil {
		t.Error("a disabled service")
	}
	off.Enabled, off.Kind = true, "naive"
	if RealityLocalTarget(off) != nil {
		t.Error("not REALITY")
	}
}

// fakeHost makes the host's addresses and its resolver's answers these,
// until the test ends.
func fakeHost(t *testing.T, own []string, names map[string][]string) {
	t.Helper()
	savedOwn, savedLookup := ownAddrs, lookupNetIP
	t.Cleanup(func() { ownAddrs, lookupNetIP = savedOwn, savedLookup })
	m := map[netip.Addr]bool{netip.MustParseAddr("127.0.0.1"): true, netip.IPv6Loopback(): true}
	for _, a := range own {
		m[netip.MustParseAddr(a)] = true
	}
	ownAddrs = func() map[netip.Addr]bool { return m }
	lookupNetIP = func(_ context.Context, _, host string) ([]netip.Addr, error) {
		as, ok := names[strings.ToLower(host)]
		if !ok {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		var out []netip.Addr
		for _, a := range as {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
}

// The check of a target refuses what the data plane does not reach: a
// name (but localhost) that resolves to a local address, the node's own
// addresses but loopback, by address or by name, 0.0.0.0 and ::. Each
// refusal is a TargetError that says what to give instead; for a service
// that has the target already (rayd's check of the targets) it names the
// commands. localhost passes on to the site's own checks.
func TestCheckRealityTargetReach(t *testing.T) {
	fakeHost(t, []string{"203.0.113.5", "10.0.0.4"}, map[string][]string{
		"intranet.example": {"10.0.0.9"}, "self.example": {"203.0.113.5"}, "meta.example": {"198.51.100.1", "169.254.169.254"}})
	ctx := context.Background()
	addr := target(t, 4096, nil) // 127.0.0.1:port
	_, port, _ := strings.Cut(addr, ":")
	if err := CheckRealityTarget(ctx, "localhost:"+port, "target.test"); err != nil {
		t.Fatalf("localhost: %v", err)
	}
	for target, want := range map[string]string{
		"intranet.example:443": "resolves to 10.0.0.9, a local address",
		"meta.example:443":     "resolves to 169.254.169.254, a local address",
		"self.example:8443":    "resolves to 203.0.113.5, the node's own address",
		"203.0.113.5:8443":     "is the node's own address",
		"10.0.0.4:8443":        "is the node's own address",
		"0.0.0.0:8443":         "is no address to dial",
		"[::]:8443":            "is no address to dial",
	} {
		err := CheckRealityTarget(ctx, target, "www.example.org")
		var te *TargetError
		if !errors.As(err, &te) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", target, err, want)
			continue
		}
		use := "use 127.0.0.1:" + te.Use.String()[strings.LastIndex(te.Use.String(), ":")+1:]
		if te.Own != strings.Contains(err.Error(), use) {
			t.Errorf("%s: %v, want %q", target, err, use)
		}
		fixed := ForService("r1", err).Error()
		switch {
		case te.Own && !strings.HasSuffix(fixed, ": rayctl service set r1 target=127.0.0.1:8443"):
			t.Errorf("%s for a service: %q", target, fixed)
		case !te.Own && !strings.HasSuffix(fixed, ": rayctl service set r1 target="+te.Use.String()+" (the sni stays), or rayctl egress allow local"):
			t.Errorf("%s for a service: %q", target, fixed)
		}
	}
	// What is not a TargetError stays as it is.
	if err := ForService("r1", errors.New("no HTTP/2")); err.Error() != "no HTTP/2" {
		t.Errorf("another error: %v", err)
	}
	// Static, for the creation and rayctl service set: names pass on to
	// the check.
	for target, bad := range map[string]bool{"0.0.0.0:443": true, "[::]:443": true, "203.0.113.5:443": true, "[::ffff:203.0.113.5]:443": true,
		"127.0.0.1:8443": false, "127.0.0.2:8443": false, "[::1]:8443": false, "10.0.0.9:443": false, "self.example:443": false, "/run/x.sock": false} {
		if err := CheckTargetAddr(target); (err != nil) != bad {
			t.Errorf("CheckTargetAddr(%s): %v", target, err)
		}
	}
}

// rayctl check, status and the update's first look: the REALITY services
// whose target the data plane does not reach, with the commands that fix
// each; none for an address it reaches (its exemption), localhost, a name
// that resolves elsewhere, the node's site or a socket.
func TestRealityTargetWarning(t *testing.T) {
	fakeHost(t, []string{"203.0.113.5"}, map[string][]string{
		"nginx.internal": {"10.0.0.9"}, "self.example": {"203.0.113.5"}, "www.example.org": {"93.184.215.14"}})
	own := ownAddrs()
	ctx := context.Background()
	svc := func(target string) store.Service {
		return store.Service{Kind: "reality", Name: "r1", Enabled: true, Settings: `{"target":"` + target + `","sni":"www.example.org"}`}
	}
	// The problem and its fix as rayctl update says them.
	RealityTargetWarning := func(ctx context.Context, svc store.Service, local bool, own map[netip.Addr]bool) string {
		p, fix := RealityTargetWarning(ctx, svc, local, own)
		if (p == "") != (fix == "") {
			t.Fatalf("%s: problem %q, fix %q", svc.Settings, p, fix)
		}
		if p == "" {
			return ""
		}
		return p + ": " + fix
	}
	for target, want := range map[string]string{
		"nginx.internal:8443":  "REALITY r1 answers no client and no prober: reality target nginx.internal:8443 resolves to 10.0.0.9, a local address",
		"self.example:8443":    "resolves to 203.0.113.5, the node's own address",
		"203.0.113.5:8443":     "is the node's own address",
		"0.0.0.0:8443":         "is no address to dial",
		"localhost:8443":       "",
		"LOCALHOST:8443":       "",
		"127.0.0.1:8443":       "",
		"10.0.0.9:8443":        "",
		"www.example.org:443":  "",
		"no-such.invalid:443":  "",
		"/run/site/reality.sk": "",
	} {
		got := RealityTargetWarning(ctx, svc(target), true, own)
		if (want == "") != (got == "") || !strings.Contains(got, want) {
			t.Errorf("%s: %q, want %q", target, got, want)
		}
		if got != "" && !strings.Contains(got, ": rayctl service set r1 target=") {
			t.Errorf("%s: no fix in %q", target, got)
		}
	}
	if got := RealityTargetWarning(ctx, svc("nginx.internal:8443"), true, own); !strings.HasSuffix(got,
		": rayctl service set r1 target=10.0.0.9:8443 (the sni stays), or rayctl egress allow local") {
		t.Errorf("the fix of a name: %q", got)
	}
	// Local networks allowed (rayctl egress allow local): the name is
	// reached; the node's own address is not, whatever the policy.
	if got := RealityTargetWarning(ctx, svc("nginx.internal:8443"), false, own); got != "" {
		t.Errorf("local allowed: %q", got)
	}
	if got := RealityTargetWarning(ctx, svc("self.example:8443"), false, own); !strings.HasSuffix(got, ": rayctl service set r1 target=127.0.0.1:8443") {
		t.Errorf("the node's own, local allowed: %q", got)
	}
	off := svc("nginx.internal:8443")
	off.Enabled = false
	if got := RealityTargetWarning(ctx, off, true, own); got != "" {
		t.Errorf("a disabled service: %q", got)
	}
	site := store.Service{Kind: "reality", Name: "r2", Enabled: true, Settings: `{"site":"site","sni":"www.example.com"}`}
	if got := RealityTargetWarning(ctx, site, true, own); got != "" {
		t.Errorf("self-steal: %q", got)
	}
}

func TestRealityTarget(t *testing.T) {
	for in, want := range map[string]string{
		`{"target":"www.example.org:443"}`:               "www.example.org:443 www.example.org",
		`{"target":"203.0.113.9:443","sni":"a.example"}`: "203.0.113.9:443 a.example",
		`{"target":"203.0.113.9:443"}`:                   "error",
		`{}`:                                             "error",
		`{"target":"www.example.org"}`:                   "error",
		`{"target":"/run/site.sock","sni":"s.example"}`:  "/run/site.sock s.example",
	} {
		target, sni, err := RealityTargetFromJSON(in)
		got := target + " " + sni
		if err != nil {
			got = "error"
		}
		if got != want {
			t.Errorf("%s: %q, want %q (%v)", in, got, want, err)
		}
	}
}

// rayctl service set NAME target=HOST:PORT (spec/egress-policy-v1.md §10):
// the fix of a target set before the local networks were blocked, checked
// as at creation; the keys, the shortIds and the server name stay, so the
// clients' links do not change. Not for a service that steals from the
// node's own site; not an address the data plane does not reach, which
// creation refuses too.
func TestRealityTargetOption(t *testing.T) {
	fakeHost(t, []string{"203.0.113.5"}, nil)
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := Init(ctx, st, Options{Host: "203.0.113.5", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	r, err := CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true,
		Settings: `{"target":"nginx.internal:8443","sni":"www.example.org"}`})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := st.ServiceSecrets(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"localhost:8443", "127.0.0.1:9443", "10.0.0.9:8443", "[::1]:8443", "www.example.org:443"} {
		after, err := SetServiceOption(ctx, st, "r", "target", target)
		if err != nil {
			t.Fatalf("target=%s: %v", target, err)
		}
		got, sni, _ := RealityTargetFromJSON(after.Settings)
		stored, _ := st.ServiceByName(ctx, "r")
		if got != target || sni != "www.example.org" || stored.Settings != after.Settings {
			t.Fatalf("target=%s: %q %q, stored %s", target, got, sni, stored.Settings)
		}
		now, err := st.ServiceSecrets(ctx, r.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{SecretRealityKey, SecretRealityMLDSA, SecretShortIDs, SecretMLKEMSeed} {
			if len(keys[name]) == 0 || !bytes.Equal(now[name], keys[name]) {
				t.Fatalf("target=%s changed %s", target, name)
			}
		}
	}
	for _, bad := range []string{"0.0.0.0:8443", "[::]:8443", "203.0.113.5:8443", "nginx.internal", ":8443", "nginx.internal:0",
		"nginx.internal:http", "/run/site/site.sock", ""} {
		if _, err := SetServiceOption(ctx, st, "r", "target", bad); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("target=%s: %v", bad, err)
		}
	}
	if _, err := SetServiceOption(ctx, st, "r", "target", "0.0.0.0:8443"); err == nil || !strings.Contains(err.Error(), "use 127.0.0.1:8443") {
		t.Errorf("0.0.0.0: %v", err)
	}
	// The node's own site: its server name is the site's.
	if _, err := CreateService(ctx, st, store.Service{Kind: "reality", Name: "self", Enabled: true, Settings: `{"ports":["tcp/8444"]}`}); err != nil {
		t.Fatal(err)
	}
	if _, err := SetServiceOption(ctx, st, "self", "target", "www.example.org:443"); !errors.Is(err, store.ErrInvalid) || !strings.Contains(err.Error(), "own site") {
		t.Errorf("self-steal: %v", err)
	}
	// Creation refuses the same addresses.
	for i, bad := range []string{"0.0.0.0:8443", "203.0.113.5:8443"} {
		_, err := CreateService(ctx, st, store.Service{Kind: "reality", Name: fmt.Sprintf("bad%d", i), Enabled: true,
			Settings: fmt.Sprintf(`{"target":%q,"sni":"www.example.org","ports":["tcp/%d"]}`, bad, 9000+i)})
		if !errors.Is(err, store.ErrInvalid) || !strings.Contains(err.Error(), "use 127.0.0.1:8443") {
			t.Errorf("creation with %s: %v", bad, err)
		}
	}
}
