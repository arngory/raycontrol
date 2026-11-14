package sub_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
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

// The pins of spec/cert-pin-v1.md §10 (provision's TestPublicKeyPinVectors
// checks them against their SubjectPublicKeyInfo): P-256 keys with the
// private scalars 01..20, 21..40 and 41..60.
const (
	vectorPinCurrent = "8dWUSbcnFl3nMr8oMzgSK5liimFZGP7cZ9h4__z0fac"
	vectorPinNext    = "aKDy1GvP0Ev823jJBZeuwhvSD4gJN1ax7KUDa0YLvnM"
	vectorPinBefore  = "YZcjdu03922roQ30O9I6r26d48YyWMiges0KEq_U8Z0"
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

// The sample lines of spec/cert-pin-v1.md §10, byte for byte: what the node
// writes for the three kinds, the pins through a comma, which the query
// carries as %2C (as niko-dns-spare's).
func TestSitePinLines(t *testing.T) {
	m := vectorModel(t, `{"sni":"s0p1.example.com"}`)
	pins := vectorPinCurrent + "%2C" + vectorPinNext
	for _, c := range []struct{ name, got, want string }{
		{"naive", sub.NaiveLink(m, m.Services[1], "f3b1c0de-0000-4000-8000-000000000001"),
			"naive+https://niko:f3b1c0de-0000-4000-8000-000000000001@203.0.113.7:443?niko-ack=1&niko-node=00112233445566778899aabbccddeeff" +
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

// For an hour after a switch that was not forced the list has a third pin,
// the key before, last (§2, §5): the sample line of §10, and the list of
// two again once the hour is over, by the model's time.
func TestSitePinLinesAfterSwitch(t *testing.T) {
	until := time.Unix(1767229200, 0)
	m := vectorModel(t, `{"sni":"s0p1.example.com","tls_next_pin":"`+vectorPinNext+`","tls_prev_pin":"`+vectorPinBefore+
		`","tls_prev_until":1767229200}`)
	m.Now = until.Add(-time.Second)
	three := vectorPinCurrent + "%2C" + vectorPinNext + "%2C" + vectorPinBefore
	want := "naive+https://niko:f3b1c0de-0000-4000-8000-000000000001@203.0.113.7:443?niko-ack=1&niko-node=00112233445566778899aabbccddeeff" +
		"&niko-pin=" + three + "&niko-svc=5&sni=n4k2.example.com&uot=2#naive"
	got := sub.NaiveLink(m, m.Services[1], "f3b1c0de-0000-4000-8000-000000000001")
	if got != want {
		t.Errorf("an hour after a switch:\n got %s\nwant %s", got, want)
	}
	for _, link := range []string{got, sub.HysteriaLink(m, m.Services[2], "p"), sub.DoHLink(m, m.Services[3], "p")} {
		u, err := url.Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		if pins := u.Query().Get("niko-pin"); pins != vectorPinCurrent+","+vectorPinNext+","+vectorPinBefore {
			t.Errorf("niko-pin reads back as %s: %s", pins, link)
		}
	}
	for kind, link := range map[string]string{"naive": got, "hy2-masq": sub.HysteriaLink(m, m.Services[2], "p"), "doh": sub.DoHLink(m, m.Services[3], "p")} {
		for _, problem := range strictProblems(kind, link) {
			t.Errorf("%s: %s", kind, problem)
		}
	}
	m.Now = until
	if u, _ := url.Parse(sub.NaiveLink(m, m.Services[1], "p")); u.Query().Get("niko-pin") != vectorPinCurrent+","+vectorPinNext {
		t.Errorf("when the hour is over: niko-pin %s", u.Query().Get("niko-pin"))
	}
}

// The lead of a site's next key and the age a forced switch asks of the key
// in use are measured against how long a client may use a list.
func TestSiteKeyMinAgeIsTheLifetime(t *testing.T) {
	if provision.SiteKeyMinAge != sub.Lifetime {
		t.Fatalf("provision.SiteKeyMinAge is %v, a subscription lives %v", provision.SiteKeyMinAge, sub.Lifetime)
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
		"naive+https://niko:p@203.0.113.7:443?niko-ack=1&niko-node=00112233445566778899aabbccddeeff&niko-svc=5&sni=n4k2.example.com&uot=2#naive",
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
	// Refused as long as it is not forced: it would cut every client that
	// holds the pins. Nothing changes.
	if _, err := provision.SetCertificate(ctx, st, "site", own.ChainPEM, own.KeyPEM, now, false); !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("an import of another key under pinned links, without force: %v", err)
	}
	if kept := pinsOf(); kept["naive"] != before["naive"] {
		t.Fatalf("the refused import changed the pins: %v", kept)
	}
	c, err := provision.SetCertificate(ctx, st, "site", own.ChainPEM, own.KeyPEM, now, true)
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

// The pin of the key before a switch is in the list for its hour by the
// subscription's own time, in the signed answer a device gets.
func TestSubscriptionPinOfTheKeyBefore(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	var ids []int64
	for _, kind := range []string{"reality", "naive"} {
		svc, err := provision.CreateService(ctx, f.st, store.Service{Kind: kind, Name: kind, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, svc.ID)
	}
	if err := f.st.SetUserServices(ctx, "alice", ids); err != nil {
		t.Fatal(err)
	}
	site, err := f.st.ServiceByName(ctx, "site")
	if err != nil {
		t.Fatal(err)
	}
	keyDER, certDER, err := provision.SelfSigned("site.example.com")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	var settings map[string]any
	json.Unmarshal([]byte(site.Settings), &settings)
	settings["tls_next_pin"], settings["tls_next_at"] = vectorPinNext, now.Unix()
	settings["tls_prev_pin"], settings["tls_prev_until"] = vectorPinBefore, now.Add(time.Hour).Unix()
	b, _ := json.Marshal(settings)
	leaf, err := provision.SPKIPin(certDER)
	if err != nil {
		t.Fatal(err)
	}
	next := []byte("the next key: its pin is stored beside it, the key is not parsed")
	if err := f.st.UpdateService(ctx, site.ID, store.ServiceUpdate{Settings: string(b), Set: map[string][]byte{
		provision.SecretTLSChain: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), provision.SecretTLSKey: keyDER, provision.NextSecret(provision.SecretTLSKey): next}}); err != nil {
		t.Fatal(err)
	}
	srv := &sub.Server{Store: f.st, Keys: f.keys, Log: quiet()}
	pins := func(at time.Time) string {
		t.Helper()
		env, err := srv.Build(ctx, "alice", at)
		if err != nil {
			t.Fatal(err)
		}
		p, err := sub.Verify(env, f.keys.PublicJSON())
		if err != nil {
			t.Fatal(err)
		}
		for _, profile := range p.Profiles {
			if strings.HasPrefix(profile.Link, "naive+https://") {
				u, err := url.Parse(profile.Link)
				if err != nil {
					t.Fatal(err)
				}
				return u.Query().Get("niko-pin")
			}
		}
		t.Fatal("no naive profile")
		return ""
	}
	if got := pins(now.Add(59 * time.Minute)); got != leaf+","+vectorPinNext+","+vectorPinBefore {
		t.Fatalf("within the hour: niko-pin %s", got)
	}
	if got := pins(now.Add(time.Hour)); got != leaf+","+vectorPinNext {
		t.Fatalf("after the hour: niko-pin %s", got)
	}
}

// Pins this rayd made reach no subscription before its settle time
// (ClockSeqAfter): an update rolled back in its first minutes puts back the
// database of before its start, without them, and a client that took them
// would refuse the node's leaf (Niko 1.45.0 on hy2-masq). The certificate
// manager held back the first next key only; a site ordered for seconds
// after the start (a switch, which makes a next key) published two pins at
// once. Pins the database had at the start go out as before: a restart
// that is no update does not take them away for ten minutes.
func TestSubscriptionHoldsPinsOfTheFirstMinutes(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	var ids []int64
	for _, kind := range []string{"reality", "naive"} {
		svc, err := provision.CreateService(ctx, f.st, store.Service{Kind: kind, Name: kind, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, svc.ID)
	}
	if err := f.st.SetUserServices(ctx, "alice", ids); err != nil {
		t.Fatal(err)
	}
	site, err := f.st.ServiceByName(ctx, "site")
	if err != nil {
		t.Fatal(err)
	}
	keyDER, certDER, err := provision.SelfSigned("site.example.com")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := provision.SPKIPin(certDER)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().Truncate(time.Second)
	nextAt := func(at time.Time) {
		t.Helper()
		var settings map[string]any
		json.Unmarshal([]byte(site.Settings), &settings)
		settings["tls_next_pin"], settings["tls_next_at"] = vectorPinNext, at.Unix()
		b, _ := json.Marshal(settings)
		if err := f.st.UpdateService(ctx, site.ID, store.ServiceUpdate{Settings: string(b), Set: map[string][]byte{
			provision.SecretTLSChain: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), provision.SecretTLSKey: keyDER,
			provision.NextSecret(provision.SecretTLSKey): []byte("the next key")}}); err != nil {
			t.Fatal(err)
		}
	}
	srv := &sub.Server{Store: f.st, Keys: f.keys, Log: quiet(), ClockSeqAfter: start.Add(10 * time.Minute), PinsSince: start}
	pins := func(at time.Time) string {
		t.Helper()
		env, err := srv.Build(ctx, "alice", at)
		if err != nil {
			t.Fatal(err)
		}
		p, err := sub.Verify(env, f.keys.PublicJSON())
		if err != nil {
			t.Fatal(err)
		}
		for _, profile := range p.Profiles {
			if strings.HasPrefix(profile.Link, "naive+https://") {
				u, err := url.Parse(profile.Link)
				if err != nil {
					t.Fatal(err)
				}
				return u.Query().Get("niko-pin")
			}
		}
		t.Fatal("no naive profile")
		return ""
	}
	want := leaf + "," + vectorPinNext
	// Pins from before the start: in the lists from the first second.
	nextAt(start.Add(-24 * time.Hour))
	if got := pins(start.Add(5 * time.Second)); got != want {
		t.Fatalf("pins from before the start, 5 s in: niko-pin %q", got)
	}
	// Made 5 s after the start: held back until the settle time.
	nextAt(start.Add(5 * time.Second))
	for _, at := range []time.Duration{5 * time.Second, 10*time.Minute - time.Second} {
		if got := pins(start.Add(at)); got != "" {
			t.Fatalf("pins made after the start, %v in: niko-pin %q", at, got)
		}
	}
	if got := pins(start.Add(10 * time.Minute)); got != want {
		t.Fatalf("at the settle time: niko-pin %q", got)
	}
	// A test stand's PinsAfter (RAYCONTROL_UNSAFE_SITE_KEY_SETTLE_NOW):
	// the pins come at it, the seq's clock keeps ClockSeqAfter.
	srv.PinsAfter = start.Add(10 * time.Second)
	if got := pins(start.Add(9 * time.Second)); got != "" {
		t.Fatalf("before the stand's settle time: niko-pin %q", got)
	}
	if got := pins(start.Add(10 * time.Second)); got != want {
		t.Fatalf("at the stand's settle time: niko-pin %q", got)
	}
	if srv.ClockSeqAfter != start.Add(10*time.Minute) {
		t.Fatal("PinsAfter moved the seq's clock")
	}
	srv.PinsAfter = time.Time{}
	// Without a start (tests, a server of no rayd), nothing is held.
	srv.PinsSince = time.Time{}
	if got := pins(start.Add(5 * time.Second)); got != want {
		t.Fatalf("no start: niko-pin %q", got)
	}
}
