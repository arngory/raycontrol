package sub_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/clientver"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
)

// Links by name (spec/names-v1.md §4): to a client that resolves names,
// each link's host is the name it sends as SNI when that is one label
// under the node's domain, the node's own name otherwise, and niko-ip
// has the node's address; to the others, the address as before.
func TestLinksByName(t *testing.T) {
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
	for _, s := range []store.Service{
		{Kind: "reality", Name: "r", Enabled: true},
		{Kind: "naive", Name: "nv", Enabled: true},
		{Kind: "hy2-masq", Name: "hm", Enabled: true},
		{Kind: "hy2-obfs", Name: "ho", Enabled: true},
	} {
		svc, err := provision.CreateService(ctx, st, s)
		if err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
		ids = append(ids, svc.ID)
	}
	st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	st.SetUserServices(ctx, "alice", ids)
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(m.DNSName, ".example.com") || strings.Count(m.DNSName, ".") != 2 {
		t.Fatalf("the node's name %q", m.DNSName)
	}
	// Kept: devices hold it.
	if again, _ := provision.NodeDNSName(ctx, st); again != m.DNSName {
		t.Fatalf("the node's name moved: %q, then %q", m.DNSName, again)
	}

	byAddr, err := sub.Profiles(m, m.Users[0])
	if err != nil || len(byAddr) != 4 {
		t.Fatalf("profiles %v %v", byAddr, err)
	}
	m.ByName = true
	byName, err := sub.Profiles(m, m.Users[0])
	if err != nil || len(byName) != 4 {
		t.Fatalf("profiles %v %v", byName, err)
	}
	for i := range byName {
		a, err := url.Parse(byAddr[i].Link)
		if err != nil {
			t.Fatal(err)
		}
		n, err := url.Parse(byName[i].Link)
		if err != nil {
			t.Fatal(err)
		}
		if a.Hostname() != "203.0.113.7" || a.Query().Has("niko-ip") {
			t.Errorf("%s by address: %s", byAddr[i].Name, byAddr[i].Link)
		}
		want := n.Query().Get("sni")
		if byName[i].Name == "ho" {
			want = m.DNSName // its SNI is no name of the node's
		}
		if n.Hostname() != want || n.Port() != a.Port() || n.Query().Get("niko-ip") != "203.0.113.7" {
			t.Errorf("%s by name: host %q, want %q: %s", byName[i].Name, n.Hostname(), want, byName[i].Link)
		}
		// Everything else as by address.
		qa, qn := a.Query(), n.Query()
		qn.Del("niko-ip")
		if qa.Encode() != qn.Encode() {
			t.Errorf("%s: by name differs beyond host and niko-ip:\n%s\n%s", byName[i].Name, byAddr[i].Link, byName[i].Link)
		}
	}
}

// A node whose host is a name gives no niko-ip, and a REALITY service with
// a foreign target sends a client that resolves names to the node's own
// name: its SNI is someone else's.
func TestLinksByNameEdges(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	provision.Init(ctx, st, provision.Options{Host: "node.example.net", Domain: "example.com"})
	svc, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true, Settings: `{"target":"www.example.org:443"}`})
	if err != nil {
		t.Fatal(err)
	}
	st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	st.SetUserServices(ctx, "alice", []int64{svc.ID})
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	m.ByName = true
	p, err := sub.Profiles(m, m.Users[0])
	if err != nil || len(p) != 1 {
		t.Fatalf("profiles %v %v", p, err)
	}
	u, _ := url.Parse(p[0].Link)
	if u.Hostname() != m.DNSName || u.Query().Get("sni") != "www.example.org" || u.Query().Has("niko-ip") {
		t.Fatalf("link %s", p[0].Link)
	}
}

// No domain: no name, and links by address whatever the client says.
func TestLinksByNameWithoutDomain(t *testing.T) {
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
	m, err := render.Collect(ctx, st)
	if err != nil || m.DNSName != "" {
		t.Fatalf("name %q %v", m.DNSName, err)
	}
	m.ByName = true
	p, _ := sub.Profiles(m, m.Users[0])
	if u, _ := url.Parse(p[0].Link); u.Hostname() != "203.0.113.7" || u.Query().Get("niko-ip") != "203.0.113.7" {
		t.Fatalf("link %s", p[0].Link)
	}
}

// The subscription's request says the client resolves names
// (X-Raycontrol-Features: names): its links go by name; the payload names
// the node and its addresses to every client (spec/names-v1.md §4).
func TestSubscriptionByName(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	// A service with the node's address in its link, beside the DNS
	// tunnel's.
	r, err := provision.CreateService(ctx, f.st, store.Service{Kind: "reality", Name: "r", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	dns, _ := f.st.ServiceByName(ctx, "dns")
	if err := f.st.SetUserServices(ctx, "alice", []int64{dns.ID, r.ID}); err != nil {
		t.Fatal(err)
	}
	render.Collect(ctx, f.st) // the credentials
	srv := &sub.Server{Store: f.st, Keys: f.keys, Log: quiet(), Requests: &sub.Requests{}}
	fetch := func(features string) sub.Payload {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, sub.Path, nil)
		req.Header.Set(sub.DeviceHeader, f.device.ID)
		req.Header.Set("Authorization", sub.AuthToken(f.key, time.Now().Unix()/60))
		if features != "" {
			req.Header.Set(clientver.FeaturesHeader, features)
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%q: %d", features, rec.Code)
		}
		var env sub.Envelope
		if err := json.NewDecoder(rec.Body).Decode(&env); err != nil {
			t.Fatal(err)
		}
		p, err := sub.Verify(env, f.keys.PublicJSON())
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	for features, byName := range map[string]bool{"": false, "names": true, "other, names": true, "namesx": false} {
		p := fetch(features)
		if !strings.HasSuffix(p.DNSName, ".example.com") || len(p.Addrs) != 1 || p.Addrs[0] != "203.0.113.7" || len(p.Profiles) == 0 {
			t.Fatalf("%q: name %q, addrs %v, %d profiles", features, p.DNSName, p.Addrs, len(p.Profiles))
		}
		checked := 0
		for _, pr := range p.Profiles {
			if strings.Contains(pr.Link, "@inner:1") {
				continue // a DNS tunnel's: no node address in it
			}
			checked++
			u, _ := url.Parse(pr.Link)
			if strings.Contains(pr.Link, "niko-ip=") != byName || (u.Hostname() != "203.0.113.7") == !byName {
				t.Errorf("%q: %s", features, pr.Link)
			}
		}
		if checked == 0 {
			t.Fatalf("%q: no link with the node's address", features)
		}
	}
}
