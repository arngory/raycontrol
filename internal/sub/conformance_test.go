package sub_test

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
)

// TestLinksForStrictClient checks every link the node hands out against the
// rules Niko 1.26 parses subscription lines by (RAYCONTROL.md §22,
// subscription-v1.md §4): a line that breaks one is dropped by the client
// without a word, so a mismatch has to fail here, before a node release.
// All kinds of services, the DNS tunnels with their modes and spare zones,
// and the next links of a rotation, which a client switches to unattended.
func TestLinksForStrictClient(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	kinds := []struct{ kind, name, settings string }{
		{"reality", "reality", ""}, // self-steal: brings the site
		{"reality", "reality-foreign", `{"target":"www.example.org:443","sni":"www.example.org"}`},
		{"hy2-masq", "hy2", ""},
		{"hy2-obfs", "hy2o", ""},
		{"naive", "naive", ""},
		{"doh", "doh", ""},
		{"dnstt", "dns", ""},
		{"dnstt", "dns-spare", `{"spare_zones":2}`},
		{"masterdns", "mdns", `{"auth":"optional","seal":"optional"}`},
		{"masterdns", "mdns-strict", `{"auth":"required","seal":"required","spare_zones":["s.example.net","u.example.org"]}`},
		{"yggdrasil", "ygg", ""},
		{"slipstream", "slip", ""},
	}
	var ids []int64
	for _, k := range kinds {
		svc, err := provision.CreateService(ctx, st, store.Service{Kind: k.kind, Name: k.name, Enabled: true, Settings: k.settings})
		if err != nil {
			t.Fatalf("%s: %v", k.kind, err)
		}
		ids = append(ids, svc.ID)
	}
	// The site's certificate: the services behind it are handed out then.
	site, err := st.ServiceByName(ctx, "site")
	if err != nil {
		t.Fatal(err)
	}
	keyDER, certDER, err := provision.SelfSigned("site.example.com")
	if err != nil {
		t.Fatal(err)
	}
	st.SetServiceSecret(ctx, site.ID, provision.SecretTLSChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	st.SetServiceSecret(ctx, site.ID, provision.SecretTLSKey, keyDER)
	if _, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserServices(ctx, "alice", ids); err != nil {
		t.Fatal(err)
	}

	// A rotation under way: new credentials published, and new REALITY keys
	// (with a new name for the self-steal one).
	now := time.Now()
	day := 24 * time.Hour
	render.Collect(ctx, st) // makes the credentials
	if _, err := st.RotateCredentials(ctx, now.Add(28*day), store.Rotation{Period: 30 * day, Lead: 3 * day, Grace: 2 * day}, render.NewUUID); err != nil {
		t.Fatal(err)
	}
	epoch := provision.RealityEpoch{Period: 90 * day, Lead: 3 * day, Prepare: day}
	for _, name := range []string{"reality", "reality-foreign"} {
		if err := provision.RequestRealityRotation(ctx, st, name, now.Add(26*day), epoch.Lead, false); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := provision.RotateReality(ctx, st, now.Add(26*day), epoch, nil, nil); err != nil {
		t.Fatal(err)
	}

	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := sub.Profiles(m, m.Users[0])
	if err != nil {
		t.Fatal(err)
	}
	// Every kind is handed out: a kind that silently goes missing fails too.
	byName := map[string]sub.Profile{}
	for _, p := range profiles {
		byName[p.Name] = p
	}
	for _, k := range kinds {
		p, ok := byName[k.name]
		if !ok {
			t.Errorf("%s (%s) has no profile", k.name, k.kind)
			continue
		}
		if p.Next == nil {
			t.Errorf("%s (%s): no next link while rotating", k.name, k.kind)
		}
		for _, link := range []string{p.Link, nextLink(p)} {
			if link == "" {
				continue
			}
			for _, problem := range strictProblems(k.kind, link) {
				t.Errorf("%s (%s): %s\n  %s", k.name, k.kind, problem, link)
			}
		}
	}
	// The DNS tunnels' parameters are there to be checked.
	for name, keys := range map[string][]string{
		"dns-spare":   {"niko-dnsauth", "niko-dnsseal", "niko-dns-spare"},
		"mdns":        {"niko-dnsauth", "niko-mdseal"},
		"mdns-strict": {"niko-dnsauth", "niko-mdseal", "niko-dns-spare"},
		"slip":        {"niko-dnsauth", "niko-slip"},
	} {
		u, _ := url.Parse(byName[name].Link)
		for _, key := range keys {
			if !u.Query().Has(key) {
				t.Errorf("%s: no %s in %s", name, key, byName[name].Link)
			}
		}
	}
}

// The DNS parameters' rules catch what the client would drop.
func TestDNSProblems(t *testing.T) {
	good := url.Values{"niko-dns": {"masterdns;;m.example.com;5"}, "niko-dnskey": {"k"}, "niko-mdseal": {"v1;required"},
		"niko-dnsauth": {"v1"}, "niko-dns-spare": {"a.example.net,b.example.org"}}
	if p := dnsProblems("masterdns", good); len(p) != 0 {
		t.Fatalf("good line: %v", p)
	}
	for key, bad := range map[string]string{
		"niko-mdseal":    "v1;strict",
		"niko-dnsauth":   "v2",
		"niko-dnsseal":   "v1;AAAA",
		"niko-dns-spare": "a.example.net,m.example.com",
	} {
		q := url.Values{}
		for k, v := range good {
			q[k] = v
		}
		q.Set(key, bad)
		if p := dnsProblems("masterdns", q); len(p) == 0 {
			t.Errorf("%s=%s passed", key, bad)
		}
	}
	for _, spares := range []string{"a.example.net,a.example.net", "A.example.net", "a.example.net.", "x", "a.ex.net,b.ex.net,c.ex.net,d.ex.net,e.ex.net"} {
		if p := dnsProblems("dnstt", url.Values{"niko-dns": {"dnstt;;t.example.com;" + strings.Repeat("ab", 32)}, "niko-dns-spare": {spares}}); len(p) == 0 {
			t.Errorf("niko-dns-spare=%s passed", spares)
		}
	}
	if p := dnsProblems("reality", url.Values{"niko-mdseal": {"v1"}}); len(p) == 0 {
		t.Error("niko-mdseal on a REALITY line passed")
	}
	pin := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	slip := url.Values{"niko-dns": {"slipstream;;s.example.com;7"}, "niko-svc": {"7"}, "niko-dnsauth": {"v1"},
		"niko-slip": {"v1;" + pin + ";abcdefgh2;quiet.dev"}}
	if p := dnsProblems("slipstream", slip); len(p) != 0 {
		t.Fatalf("good slipstream line: %v", p)
	}
	for _, c := range [][2]string{
		{"niko-dns", "slipstream;;s.example.com;8"},            // not the line's service
		{"niko-dns", "slipstream;;abcdefghijkl.example.com;7"}, // 24 characters
		{"niko-dns", "slipstream;x;s.example.com;7"},
		{"niko-dnsauth", ""},
		{"niko-slip", "v1;" + pin + ";picoquic_sample;quiet.dev"},
		{"niko-dns-spare", "a.example.net"},
	} {
		key, bad := c[0], c[1]
		q := url.Values{}
		for k, v := range slip {
			q[k] = v
		}
		if bad == "" {
			q.Del(key)
		} else {
			q.Set(key, bad)
		}
		if p := dnsProblems("slipstream", q); len(p) == 0 {
			t.Errorf("slipstream %s=%q passed", key, bad)
		}
	}
	for _, v := range []string{"v2;" + pin + ";abcdefgh;quiet.dev", "v1;AAAA;abcdefgh;quiet.dev", "v1;" + pin + ";abcdefgh;quiet", "v1;" + pin + ";abcdefgh"} {
		q := url.Values{}
		for k, vv := range slip {
			q[k] = vv
		}
		q.Set("niko-slip", v)
		if p := dnsProblems("slipstream", q); len(p) == 0 {
			t.Errorf("niko-slip=%s passed", v)
		}
	}
}

func nextLink(p sub.Profile) string {
	if p.Next == nil {
		return ""
	}
	return p.Next.Link
}

// strictProblems lists what Niko 1.26's strict parser holds against a line.
func strictProblems(kind, link string) []string {
	var out []string
	u, err := url.Parse(link)
	if err != nil {
		return []string{"does not parse: " + err.Error()}
	}
	q := u.Query()
	allowed := []string{"vless", "hysteria2", "naive+https", "naive+quic", "https"}
	if !slices.Contains(allowed, u.Scheme) {
		out = append(out, "scheme "+u.Scheme+" is not one of "+strings.Join(allowed, ", "))
	}
	if u.Scheme == "https" && kind != "doh" {
		out = append(out, "https:// is for DoH only")
	}
	for key := range q {
		if k := strings.ToLower(key); k == "insecure" || k == "allowinsecure" {
			out = append(out, "has "+key+" (any value is refused)")
		}
	}
	switch u.Scheme {
	case "vless":
		if e := q.Get("encryption"); e == "" || e == "none" {
			out = append(out, "VLESS without encryption")
		}
		if q.Get("security") == "reality" && (q.Get("pqv") == "" || q.Get("pbk") == "") {
			out = append(out, "REALITY without pqv or pbk")
		}
	case "hysteria2":
		if q.Get("obfs") != "" && q.Get("niko-pin") == "" {
			out = append(out, "hy2 with obfs but no niko-pin")
		}
	case "naive+https", "naive+quic":
		// The node's address in the host: the name goes in sni.
		if q.Get("sni") == "" {
			out = append(out, "naive without sni")
		}
		// UDP over TCP v2 (naive-uot-v1 §1): the node carries it.
		if q.Get("uot") != "2" {
			out = append(out, "naive without uot=2")
		}
		// The client ignores these; the node must not rely on them.
		for _, key := range []string{"cert", "extra-headers"} {
			if q.Has(key) {
				out = append(out, "naive with "+key+", which the client ignores")
			}
		}
	}
	if q.Get("niko-node") == "" || q.Get("niko-svc") == "" {
		out = append(out, "no niko-node or niko-svc")
	}
	return append(out, dnsProblems(kind, q)...)
}

// dnsProblems lists what the client holds against a DNS tunnel's
// parameters (subscription-v1 §4, mdseal-v1 §6, dnszones-v1 §2): each on
// the lines of its kinds only, in its form; the spare zones DNS names, up
// to 4, apart from the main zone and from each other.
func dnsProblems(kind string, q url.Values) []string {
	var out []string
	for key, kinds := range map[string][]string{
		"niko-dns": {"dnstt", "masterdns", "slipstream"}, "niko-dnsauth": {"dnstt", "masterdns", "slipstream"},
		"niko-dns-spare": {"dnstt", "masterdns"}, "niko-dnsseal": {"dnstt"}, "niko-dnskey": {"masterdns"}, "niko-mdseal": {"masterdns"},
		"niko-slip": {"slipstream"},
	} {
		if q.Has(key) && !slices.Contains(kinds, kind) {
			out = append(out, key+" on a "+kind+" line")
		}
	}
	if kind != "dnstt" && kind != "masterdns" && kind != "slipstream" {
		return out
	}
	f := strings.Split(q.Get("niko-dns"), ";")
	if len(f) != 4 || f[0] != kind || !dnsName.MatchString(f[2]) || f[3] == "" {
		return append(out, "niko-dns "+q.Get("niko-dns"))
	}
	if kind == "slipstream" {
		// slipstream-v1 §4: the zone (at most 20 characters) and the
		// line's service; the pin, ALPN and name; signed always.
		if len(f[2]) > provision.MaxSlipstreamZone || f[3] != q.Get("niko-svc") || f[1] != "" {
			out = append(out, "niko-dns "+q.Get("niko-dns"))
		}
		if q.Get("niko-dnsauth") != "v1" {
			out = append(out, "slipstream without niko-dnsauth=v1")
		}
		s := strings.Split(q.Get("niko-slip"), ";")
		if len(s) != 4 || s[0] != "v1" {
			return append(out, "niko-slip "+q.Get("niko-slip"))
		}
		if b, err := base64.RawURLEncoding.DecodeString(s[1]); err != nil || len(b) != 32 {
			out = append(out, "niko-slip pin "+s[1])
		}
		if !regexp.MustCompile(`^[a-z0-9]{8,12}$`).MatchString(s[2]) || !regexp.MustCompile(`^[a-z][a-z0-9]{2,9}\.[a-z]{2,6}$`).MatchString(s[3]) {
			out = append(out, "niko-slip ALPN or name "+s[2]+" "+s[3])
		}
	}
	if q.Has("niko-dnsauth") && q.Get("niko-dnsauth") != "v1" {
		out = append(out, "niko-dnsauth "+q.Get("niko-dnsauth"))
	}
	if q.Has("niko-dnsseal") {
		k, ok := strings.CutPrefix(q.Get("niko-dnsseal"), "v1;")
		if b, err := base64.RawURLEncoding.DecodeString(k); !ok || err != nil || len(b) != 32 {
			out = append(out, "niko-dnsseal "+q.Get("niko-dnsseal"))
		}
	}
	if v := q.Get("niko-mdseal"); q.Has("niko-mdseal") && v != "v1" && v != "v1;required" {
		out = append(out, "niko-mdseal "+v)
	}
	if kind == "masterdns" && q.Get("niko-dnskey") == "" {
		out = append(out, "masterdns without niko-dnskey")
	}
	if q.Has("niko-dns-spare") {
		spares := strings.Split(q.Get("niko-dns-spare"), ",")
		if len(spares) > 4 {
			out = append(out, "niko-dns-spare with more than 4 zones")
		}
		seen := []string{f[2]}
		for _, z := range spares {
			if !dnsName.MatchString(z) || slices.Contains(seen, z) {
				out = append(out, "niko-dns-spare zone "+z)
			}
			seen = append(seen, z)
		}
	}
	return out
}

// dnsName is a zone as links carry it: a DNS name of two labels or more,
// lower case, without the final dot.
var dnsName = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
