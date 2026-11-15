package sub_test

import (
	"context"
	"encoding/pem"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
)

// naive's next name in its profile (R4-42, subscription-v1 §3): the next
// link is the line under the new sni, nothing else changed (niko-pin
// included: the site keeps its key), from the switch's time. One next per
// profile, the earliest switch: with a password switch before it, next is
// that one (the name as it is); after it, the new name with the next
// password, which the node takes from its publication on.
func TestNaiveNextName(t *testing.T) {
	const day = 24 * time.Hour
	for _, c := range []struct {
		name      string
		passwords bool          // a password switch published on day 28, at day 31
		ask       time.Duration // the name's switch asked then, a lead (3 days) ahead
		newName   bool          // next has the new name
	}{
		{"name only", false, 26 * day, true},
		{"name first", true, 26 * day, true},
		{"together", true, 28 * day, true},
		{"password first", true, 28*day + time.Hour, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"})
			provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true})
			nv, err := provision.CreateService(ctx, st, store.Service{Kind: "naive", Name: "nv", Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			site, _ := st.ServiceByName(ctx, "site")
			keyDER, certDER, _ := provision.SelfSigned("*.example.com")
			st.SetServiceSecret(ctx, site.ID, provision.SecretTLSChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
			st.SetServiceSecret(ctx, site.ID, provision.SecretTLSKey, keyDER)
			provision.EnsureSiteNextKey(ctx, st, site.ID, time.Now())
			u, _ := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
			st.SetUserServices(ctx, "alice", []int64{nv.ID})
			now := time.Now()
			render.Collect(ctx, st) // the credentials
			if c.passwords {
				if _, err := st.RotateCredentials(ctx, now.Add(28*day), store.Rotation{Period: 30 * day, Lead: 3 * day, Grace: 2 * day}, render.NewUUID); err != nil {
					t.Fatal(err)
				}
			}
			e := provision.RealityEpoch{Lead: 3 * day, Prepare: day}
			if err := provision.RequestRotation(ctx, st, "nv", now.Add(c.ask), e.Lead, false); err != nil {
				t.Fatal(err)
			}
			if _, err := provision.RotateReality(ctx, st, now.Add(c.ask), e, nil, nil); err != nil {
				t.Fatal(err)
			}
			m, err := render.Collect(ctx, st)
			if err != nil {
				t.Fatal(err)
			}
			nv, _ = st.ServiceByName(ctx, "nv")
			ns := provision.ParseNaiveState(nv)
			if ns.NextFrom != now.Add(c.ask+e.Lead).Unix() {
				t.Fatalf("not published: %+v", ns)
			}
			profiles, err := sub.Profiles(m, m.Users[0])
			if err != nil || len(profiles) != 1 || profiles[0].Next == nil {
				t.Fatalf("profiles %+v %v", profiles, err)
			}
			p := profiles[0]
			cur, _ := url.Parse(p.Link)
			next, _ := url.Parse(p.Next.Link)
			set := m.Sets[nv.ID][u.ID]
			wantSNI, wantFrom, wantPassword := ns.SNI, set.NextFrom.Unix(), set.Next
			if c.newName {
				wantSNI, wantFrom = ns.SNINext, ns.NextFrom
				if !c.passwords {
					wantPassword = m.Creds[nv.ID][u.ID]
				}
			}
			password, _ := next.User.Password()
			if next.Query().Get("sni") != wantSNI || p.Next.From != wantFrom || password != wantPassword || cur.Query().Get("sni") != ns.SNI {
				t.Fatalf("next %s from %d, want sni %s from %d\ncurrent %s", p.Next.Link, p.Next.From, wantSNI, wantFrom, p.Link)
			}
			// The rest of the line as it is, niko-pin first of all.
			q, nq := cur.Query(), next.Query()
			q.Del("sni")
			nq.Del("sni")
			if q.Encode() != nq.Encode() || !nq.Has("niko-pin") || next.Host != cur.Host || next.Fragment != cur.Fragment {
				t.Fatalf("next differs beyond sni and password:\n%s\n%s", p.Link, p.Next.Link)
			}
		})
	}
}

// A node without a domain, naive under the operator's own name: made, a
// rotation round is clean, and its profile has that name and no next (as
// before R4-42); every render, as for each subscription, gives up nothing.
func TestNaiveWithoutDomain(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	var nv store.Service
	for _, s := range []store.Service{
		{Kind: "site", Name: "site", Settings: `{"sni":"www.example.org"}`},
		{Kind: "reality", Name: "r"},
		{Kind: "naive", Name: "nv", Settings: `{"sni":"nv.example.org"}`},
	} {
		s.Enabled = true
		if nv, err = provision.CreateService(ctx, st, s); err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
	}
	site, _ := st.ServiceByName(ctx, "site")
	keyDER, certDER, _ := provision.SelfSigned("www.example.org")
	st.SetServiceSecret(ctx, site.ID, provision.SecretTLSChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	st.SetServiceSecret(ctx, site.ID, provision.SecretTLSKey, keyDER)
	if _, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	st.SetUserServices(ctx, "alice", []int64{nv.ID})
	e := provision.RealityEpoch{Period: 90 * 24 * time.Hour, Lead: 72 * time.Hour, Prepare: 24 * time.Hour, Grace: 48 * time.Hour, NaivePeriod: 90 * 24 * time.Hour}
	for range 2 {
		m, err := render.Collect(ctx, st)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := provision.RotateReality(ctx, st, time.Now(), e, nil, nil); err != nil {
			t.Fatalf("rotation round: %v", err)
		}
		profiles, err := sub.Profiles(m, m.Users[0])
		if err != nil || len(profiles) != 1 || profiles[0].Next != nil {
			t.Fatalf("profiles %+v %v", profiles, err)
		}
		if l, _ := url.Parse(profiles[0].Link); l.Query().Get("sni") != "nv.example.org" {
			t.Fatalf("link %s", profiles[0].Link)
		}
	}
	if got, _ := st.ServiceByName(ctx, "nv"); got.Settings != nv.Settings {
		t.Fatalf("naive's settings changed: %s, was %s", got.Settings, nv.Settings)
	}
}
