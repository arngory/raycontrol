package sub_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
	"github.com/arngory/raycontrol/internal/testca"
)

// The pins of spec/cert-pin-v1.md §9 (provision's TestPublicKeyPinVectors
// checks them against their SubjectPublicKeyInfo): P-256 keys with the
// private scalars 01..20 and 21..40.
const (
	vectorPinCurrent = "8dWUSbcnFl3nMr8oMzgSK5liimFZGP7cZ9h4__z0fac"
	vectorPinNext    = "aKDy1GvP0Ev823jJBZeuwhvSD4gJN1ax7KUDa0YLvnM"
)

func vectorKey(t *testing.T, first byte) *ecdsa.PrivateKey {
	t.Helper()
	d := make([]byte, 32)
	for i := range d {
		d[i] = first + byte(i)
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// vectorModel is the node of the spec's sample lines: a site whose leaf has
// the first vector's key and whose next key is the second, and the three
// services that answer with its certificate.
func vectorModel(t *testing.T, siteSettings string) render.Model {
	t.Helper()
	cur, next := vectorKey(t, 0x01), vectorKey(t, 0x21)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"*.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, cur.Public(), cur)
	if err != nil {
		t.Fatal(err)
	}
	curDER, _ := x509.MarshalPKCS8PrivateKey(cur)
	nextDER, _ := x509.MarshalPKCS8PrivateKey(next)
	svc := func(id int64, kind, name, settings string) store.Service {
		return store.Service{ID: id, Kind: kind, Name: name, Enabled: true, Settings: settings}
	}
	return render.Model{NodeID: "00112233445566778899aabbccddeeff", Host: "203.0.113.7", Services: []render.Service{
		{Service: svc(2, "site", "site", siteSettings), Secrets: map[string][]byte{
			provision.SecretTLSChain:                     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			provision.SecretTLSKey:                       curDER,
			provision.NextSecret(provision.SecretTLSKey): nextDER,
		}},
		{Service: svc(5, "naive", "naive", `{"site":"site","sni":"n4k2.example.com"}`)},
		{Service: svc(6, "hy2-masq", "hy2-masq", `{"site":"site","sni":"h7q9.example.com"}`)},
		{Service: svc(7, "doh", "doh", `{"site":"site","sni":"d3x8.example.com"}`)},
	}}
}

// The sample lines of spec/cert-pin-v1.md §9, byte for byte: what the node
// writes for the three kinds, the pins through a comma, which the query
// carries as %2C (as niko-dns-spare's).
func TestSitePinLines(t *testing.T) {
	m := vectorModel(t, `{"sni":"s0p1.example.com"}`)
	pins := vectorPinCurrent + "%2C" + vectorPinNext
	for _, c := range []struct{ name, got, want string }{
		{"naive", sub.NaiveLink(m, m.Services[1], "f3b1c0de-0000-4000-8000-000000000001"),
			"naive+https://niko:f3b1c0de-0000-4000-8000-000000000001@203.0.113.7:443?niko-node=00112233445566778899aabbccddeeff" +
				"&niko-pin=" + pins + "&niko-svc=5&sni=n4k2.example.com&uot=2#naive"},
		{"hy2-masq", sub.HysteriaLink(m, m.Services[2], "f3b1c0de-0000-4000-8000-000000000002"),
			"hysteria2://f3b1c0de-0000-4000-8000-000000000002@203.0.113.7:443/?niko-ack=1&niko-node=00112233445566778899aabbccddeeff" +
				"&niko-pin=" + pins + "&niko-svc=6&sni=h7q9.example.com#hy2-masq"},
		{"doh", sub.DoHLink(m, m.Services[3], "f3b1c0de-0000-4000-8000-000000000003"),
			"https://d3x8.example.com/dns-query/f3b1c0de-0000-4000-8000-000000000003?niko-node=00112233445566778899aabbccddeeff" +
				"&niko-pin=" + pins + "&niko-svc=7#doh"},
	} {
		if c.got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, c.got, c.want)
		}
		// What the client reads back: the two pins, the leaf's first.
		u, err := url.Parse(c.got)
		if err != nil {
			t.Fatal(err)
		}
		if got := u.Query().Get("niko-pin"); got != vectorPinCurrent+","+vectorPinNext {
			t.Errorf("%s: niko-pin reads back as %s", c.name, got)
		}
		for _, problem := range strictProblems(c.name, c.got) {
			t.Errorf("%s: %s", c.name, problem)
		}
	}
}

// No niko-pin on the three lines where the node promises nothing about the
// key of the next certificate (cert-pin-v1 §7): the operator's own
// certificate, and a site without a next key (no certificate manager, or
// its first check still to come). The lines are then the ones of before
// cert-pin-v1.
func TestSitePinsAbsent(t *testing.T) {
	links := func(m render.Model) []string {
		return []string{sub.NaiveLink(m, m.Services[1], "p"), sub.HysteriaLink(m, m.Services[2], "p"), sub.DoHLink(m, m.Services[3], "p")}
	}
	imported := vectorModel(t, `{"sni":"s0p1.example.com","tls_imported":true}`)
	noNext := vectorModel(t, `{"sni":"s0p1.example.com"}`)
	delete(noNext.Services[0].Secrets, provision.NextSecret(provision.SecretTLSKey))
	// A service under another site, which has no certificate here.
	other := vectorModel(t, `{"sni":"s0p1.example.com"}`)
	for i := 1; i <= 3; i++ {
		other.Services[i].Settings = strings.Replace(other.Services[i].Settings, `"site":"site"`, `"site":"site2"`, 1)
	}
	for name, m := range map[string]render.Model{"the operator's certificate": imported, "no next key": noNext, "another site": other} {
		for _, link := range links(m) {
			if strings.Contains(link, "niko-pin") || strings.Contains(link, "pinSHA256") {
				t.Errorf("%s: %s", name, link)
			}
		}
	}
	want := []string{
		"naive+https://niko:p@203.0.113.7:443?niko-node=00112233445566778899aabbccddeeff&niko-svc=5&sni=n4k2.example.com&uot=2#naive",
		"hysteria2://p@203.0.113.7:443/?niko-ack=1&niko-node=00112233445566778899aabbccddeeff&niko-svc=6&sni=h7q9.example.com#hy2-masq",
		"https://d3x8.example.com/dns-query/p?niko-node=00112233445566778899aabbccddeeff&niko-svc=7#doh",
	}
	for i, link := range links(imported) {
		if link != want[i] {
			t.Errorf("without pins:\n got %s\nwant %s", link, want[i])
		}
	}
}

// The same through the store: rayctl service cert takes the pins off the
// subscription's lines, and they are there before it.
func TestSitePinsLeaveWithImport(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for _, kind := range []string{"reality", "naive", "hy2-masq", "doh", "hy2-obfs"} {
		svc, err := provision.CreateService(ctx, st, store.Service{Kind: kind, Name: kind, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, svc.ID)
	}
	if _, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserServices(ctx, "alice", ids); err != nil {
		t.Fatal(err)
	}
	site, err := st.ServiceByName(ctx, "site")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	node, err := testca.New([]string{"*.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// The node's own certificate, as the certificate manager stores it,
	// and its next key.
	block, _ := pem.Decode(node.KeyPEM)
	st.SetServiceSecret(ctx, site.ID, provision.SecretTLSChain, node.ChainPEM)
	st.SetServiceSecret(ctx, site.ID, provision.SecretTLSKey, block.Bytes)
	if _, err := provision.EnsureSiteNextKey(ctx, st, site.ID, now); err != nil {
		t.Fatal(err)
	}
	pinsOf := func() map[string]string {
		t.Helper()
		m, err := render.Collect(ctx, st)
		if err != nil {
			t.Fatal(err)
		}
		profiles, err := sub.Profiles(m, m.Users[0])
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, p := range profiles {
			u, err := url.Parse(p.Link)
			if err != nil {
				t.Fatal(err)
			}
			out[p.Name] = u.Query().Get("niko-pin")
		}
		return out
	}
	before := pinsOf()
	for _, name := range []string{"naive", "hy2-masq", "doh"} {
		if strings.Count(before[name], ",") != 1 {
			t.Errorf("%s before the import: niko-pin %q", name, before[name])
		}
	}
	if before["naive"] != before["hy2-masq"] || before["naive"] != before["doh"] || before["hy2-obfs"] == "" || before["reality"] != "" {
		t.Fatalf("pins before the import: %v", before)
	}
	// The operator's certificate, another key.
	own, err := testca.New([]string{"*.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	c, err := provision.SetCertificate(ctx, st, "site", own.ChainPEM, own.KeyPEM, now)
	if err != nil || !c.Unpinned {
		t.Fatalf("import: %+v %v", c, err)
	}
	after := pinsOf()
	for _, name := range []string{"naive", "hy2-masq", "doh", "reality"} {
		if after[name] != "" {
			t.Errorf("%s after the import: niko-pin %q", name, after[name])
		}
	}
	// hy2-obfs has its own certificate: its pin stays.
	if after["hy2-obfs"] != before["hy2-obfs"] {
		t.Fatalf("hy2-obfs: pin %q, before %q", after["hy2-obfs"], before["hy2-obfs"])
	}
}
