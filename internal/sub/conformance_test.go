package sub_test

import (
	"context"
	"encoding/pem"
	"net/url"
	"path/filepath"
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
// All kinds of services, and the next links of a rotation, which a client
// switches to unattended.
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
		{"masterdns", "mdns", ""},
		{"yggdrasil", "ygg", ""},
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
	return out
}
