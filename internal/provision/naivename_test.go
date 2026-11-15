package provision

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

// naiveEpoch is rayd's default schedule: 90 days, published 3 days ahead,
// a day for a certificate, REALITY's grace (a naive switch joined to
// REALITY's comes 2 minutes early with it).
var naiveEpoch = RealityEpoch{Period: 90 * day, Lead: 3 * day, Prepare: day, Grace: 2 * day, NaivePeriod: 90 * day}

// naiveNode is a node with REALITY on its site, naive beside it, and a
// certificate for names on the site.
func naiveNode(t *testing.T, names ...string) (context.Context, *store.Store, store.Service) {
	t.Helper()
	ctx, st := rotationNode(t)
	if _, err := CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	nv, err := CreateService(ctx, st, store.Service{Kind: "naive", Name: "nv", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(names) > 0 {
		storeCert(t, ctx, st, "site", names...)
	}
	return ctx, st, nv
}

func naiveState(t *testing.T, ctx context.Context, st *store.Store, name string) NaiveState {
	t.Helper()
	svc, err := st.ServiceByName(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	return ParseNaiveState(svc)
}

// rotateAt runs a round and fails on its error.
func rotateAt(t *testing.T, ctx context.Context, st *store.Store, at time.Time, e RealityEpoch) int {
	t.Helper()
	n, err := RotateReality(ctx, st, at, e, func(context.Context, string) error { return nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// allNames are the names every service has in its settings: the current,
// next and previous ones; none may be two services'.
func allNames(t *testing.T, ctx context.Context, st *store.Store) map[string]string {
	t.Helper()
	all, err := st.ListServices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, s := range all {
		ns := ParseNaiveState(s) // sni, sni_next, sni_prev of any kind
		for _, n := range []string{ns.SNI, ns.SNINext, ns.SNIPrev} {
			if n == "" {
				continue
			}
			// The site follows its REALITY: one name, two services by
			// design (the site is not routed).
			if other, ok := seen[n]; ok && other != s.Name && s.Kind != "site" && other != "site" {
				t.Fatalf("%s is %s's and %s's", n, other, s.Name)
			}
			seen[n] = s.Name
		}
		for _, z := range Zones(s) {
			if other, ok := seen[z]; ok {
				t.Fatalf("zone %s is %s's name", z, other)
			}
		}
	}
	return seen
}

// Under a wildcard certificate a naive name changes every period: the next
// one is chosen at creation, published a lead ahead, and at the switch the
// current one becomes the previous one and a new next is chosen.
func TestNaiveNameEpoch(t *testing.T) {
	ctx, st, nv := naiveNode(t, "*.example.com")
	created := nv.CreatedAt
	first := naiveState(t, ctx, st, "nv")
	if first.SNINext == "" || first.SNINext == first.SNI || !strings.HasSuffix(first.SNINext, ".example.com") || first.NextFrom != 0 {
		t.Fatalf("at creation: %+v", first)
	}
	allNames(t, ctx, st)
	// REALITY's own switch would be joined: moved out of the way here.
	if _, err := SetServiceOption(ctx, st, "r", "rotate_sni", "off"); err != nil {
		t.Fatal(err)
	}
	e := naiveEpoch
	e.Period = 0

	if n := rotateAt(t, ctx, st, created.Add(86*day), e); n != 0 {
		t.Fatalf("changed %d before the lead", n)
	}
	if n := rotateAt(t, ctx, st, created.Add(87*day), e); n != 1 {
		t.Fatalf("publish: %d", n)
	}
	pub := naiveState(t, ctx, st, "nv")
	if pub.NextFrom != created.Add(90*day).Unix() || pub.SNINext != first.SNINext || pub.SNI != first.SNI || pub.PreparedAt != 0 {
		t.Fatalf("published: %+v", pub)
	}
	if n := rotateAt(t, ctx, st, created.Add(90*day-time.Second), e); n != 0 {
		t.Fatal("switched early")
	}
	if n := rotateAt(t, ctx, st, created.Add(90*day), e); n != 1 {
		t.Fatal("not switched")
	}
	sw := naiveState(t, ctx, st, "nv")
	if sw.SNI != first.SNINext || sw.SNIPrev != first.SNI || sw.SNINext == "" || sw.SNINext == first.SNI || sw.SNINext == first.SNINext ||
		sw.RotatedAt != created.Add(90*day).Unix() || sw.NextFrom != 0 || sw.RotateAt != 0 {
		t.Fatalf("after the switch: %+v", sw)
	}
	allNames(t, ctx, st)
	// The next round counts from the switch; the previous name stays until
	// the switch after, then gives way.
	if n := rotateAt(t, ctx, st, created.Add(176*day), e); n != 0 {
		t.Fatal("published early in the second round")
	}
	rotateAt(t, ctx, st, created.Add(177*day), e)
	rotateAt(t, ctx, st, created.Add(180*day), e)
	second := naiveState(t, ctx, st, "nv")
	if second.SNI != sw.SNINext || second.SNIPrev != sw.SNI || second.SNINext == first.SNI {
		t.Fatalf("second switch: %+v", second)
	}
	allNames(t, ctx, st)
}

// The owner's answer 2: a scheduled naive switch moves to the switch of a
// REALITY on the same site within half a period of it, and both switch in
// one round (one render, one restart of the front). With REALITY's
// rotation off naive keeps its own time.
func TestNaiveNameJoinsReality(t *testing.T) {
	for _, c := range []struct {
		name    string
		offset  time.Duration // naive's last switch after REALITY's
		reality bool          // REALITY rotates by schedule
		at      time.Duration // naive's switch after REALITY's creation
	}{
		{"naive 10 days later", 10 * day, true, 90 * day},
		{"naive 10 days earlier", -10 * day, true, 90 * day},
		{"naive 50 days later: REALITY's next", 50 * day, true, 180 * day},
		{"REALITY off", 10 * day, false, 100 * day},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, st, nv := naiveNode(t, "*.example.com")
			r := mustService(t, ctx, st, "r")
			rotated := r.CreatedAt.Add(c.offset).Unix()
			if err := naiveFields(ctx, st, nv, map[string]any{"rotated_at": rotated}); err != nil {
				t.Fatal(err)
			}
			e := naiveEpoch
			if !c.reality {
				e.Period = 0
			}
			var naiveAt, realityAt time.Time
			for at := r.CreatedAt.Add(70 * day); at.Before(r.CreatedAt.Add(200*day)) && naiveAt.IsZero(); at = at.Add(time.Hour) {
				rotateAt(t, ctx, st, at, e)
				if naiveAt.IsZero() && naiveState(t, ctx, st, "nv").RotatedAt != rotated {
					naiveAt = at
				}
				if realityAt.IsZero() && ParseRealityState(mustService(t, ctx, st, "r")).RotatedAt != r.CreatedAt.Unix() {
					realityAt = at
				}
			}
			want := r.CreatedAt.Add(c.at)
			if got := naiveState(t, ctx, st, "nv").RotatedAt; got != want.Unix() {
				t.Fatalf("naive switched at %v, want %v", time.Unix(got, 0), want)
			}
			// Joined: in the round REALITY switched in.
			if c.reality && c.at == 90*day && !naiveAt.Equal(realityAt) {
				t.Fatalf("naive switched in the round of %v, REALITY in that of %v", naiveAt, realityAt)
			}
			allNames(t, ctx, st)
		})
	}
}

func mustService(t *testing.T, ctx context.Context, st *store.Store, name string) store.Service {
	t.Helper()
	svc, err := st.ServiceByName(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// rotate_sni at a scheduled switch: auto changes the name only under a
// wildcard certificate, on under any (the next name is asked of the
// certificate at once, an epoch ahead, and published once covered), off
// never; with the period 0 only the operator's switches happen.
func TestNaiveNameSchedule(t *testing.T) {
	for _, c := range []struct {
		name     string
		wildcard bool
		option   string
		period   time.Duration
		switches bool
	}{
		{"listed names, auto", false, "", 90 * day, false},
		{"wildcard, auto", true, "", 90 * day, true},
		{"listed names, on", false, "on", 90 * day, true},
		{"wildcard, off", true, "off", 90 * day, false},
		{"wildcard, period 0", true, "", 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, st, nv := naiveNode(t)
			site := mustService(t, ctx, st, "site")
			first := ParseNaiveState(nv)
			if c.wildcard {
				storeCert(t, ctx, st, "site", "*.example.com")
			} else {
				storeCert(t, ctx, st, "site", SiteName(site), first.SNI)
			}
			SetServiceOption(ctx, st, "r", "rotate_sni", "off")
			if c.option != "" {
				if _, err := SetServiceOption(ctx, st, "nv", "rotate_sni", c.option); err != nil {
					t.Fatal(err)
				}
			}
			e := naiveEpoch
			e.Period, e.NaivePeriod = 0, c.period
			rotateAt(t, ctx, st, nv.CreatedAt.Add(time.Hour), e)
			ordered := naiveState(t, ctx, st, "nv").PreparedAt != 0
			if want := c.switches && !c.wildcard; ordered != want {
				t.Fatalf("next name asked of the certificate %v, want %v", ordered, want)
			}
			all, _ := st.ListServices(ctx)
			if _, next := SiteNames(site, all); slices.Contains(next, first.SNINext) != ordered {
				t.Fatalf("site's next names %v", next)
			}
			if ordered {
				// The certificate manager's order.
				storeCert(t, ctx, st, "site", SiteName(site), first.SNI, first.SNINext)
			}
			for _, at := range []time.Duration{87 * day, 90 * day, 200 * day} {
				rotateAt(t, ctx, st, nv.CreatedAt.Add(at), e)
			}
			if got := naiveState(t, ctx, st, "nv"); (got.SNI != first.SNI) != c.switches {
				t.Fatalf("after 200 days: %+v", got)
			}
		})
	}
}

// rayctl service rotate on naive: a lead away, or at once (-now) to the
// next name the front routes already; under listed names the next name
// waits for its certificate first, and is given up after -reality-prepare.
// rotate_sni does not stop it.
func TestNaiveNameRequest(t *testing.T) {
	t.Run("lead, listed names", func(t *testing.T) {
		ctx, st, nv := naiveNode(t)
		site := mustService(t, ctx, st, "site")
		first := ParseNaiveState(nv)
		storeCert(t, ctx, st, "site", SiteName(site), first.SNI)
		SetServiceOption(ctx, st, "nv", "rotate_sni", "off")
		now := nv.CreatedAt.Add(5 * day)
		if err := RequestRotation(ctx, st, "nv", now, naiveEpoch.Lead, false); err != nil {
			t.Fatal(err)
		}
		if n := rotateAt(t, ctx, st, now, naiveEpoch); n != 1 || naiveState(t, ctx, st, "nv").PreparedAt != now.Unix() {
			t.Fatalf("not asked of the certificate: %+v", naiveState(t, ctx, st, "nv"))
		}
		if n := rotateAt(t, ctx, st, now.Add(time.Hour), naiveEpoch); n != 0 {
			t.Fatal("published without a certificate")
		}
		storeCert(t, ctx, st, "site", SiteName(site), first.SNI, first.SNINext)
		rotateAt(t, ctx, st, now.Add(2*time.Hour), naiveEpoch)
		// A full lead from the publication: clients have the name that long.
		from := now.Add(2*time.Hour + naiveEpoch.Lead)
		if got := naiveState(t, ctx, st, "nv"); got.NextFrom != from.Unix() || got.PreparedAt != 0 {
			t.Fatalf("published: %+v", got)
		}
		if n := rotateAt(t, ctx, st, from.Add(-time.Second), naiveEpoch); n != 0 {
			t.Fatal("switched early")
		}
		rotateAt(t, ctx, st, from, naiveEpoch)
		if got := naiveState(t, ctx, st, "nv"); got.SNI != first.SNINext || got.SNIPrev != first.SNI {
			t.Fatalf("switched: %+v", got)
		}
	})
	t.Run("now, wildcard", func(t *testing.T) {
		ctx, st, nv := naiveNode(t, "*.example.com")
		first := ParseNaiveState(nv)
		now := nv.CreatedAt.Add(5 * day)
		if err := RequestRotation(ctx, st, "nv", now, naiveEpoch.Lead, true); err != nil {
			t.Fatal(err)
		}
		// Published and switched in one round: the name is routed already.
		if n := rotateAt(t, ctx, st, now, naiveEpoch); n != 1 {
			t.Fatalf("round: %d", n)
		}
		got := naiveState(t, ctx, st, "nv")
		if got.SNI != first.SNINext || got.SNIPrev != first.SNI || got.RotatedAt != now.Unix() || got.RotateAt != 0 || got.NextFrom != 0 {
			t.Fatalf("after -now: %+v", got)
		}
		// Again, with the next name published a lead ahead: moved to now.
		later := now.Add(10 * day)
		if err := RequestRotation(ctx, st, "nv", later, naiveEpoch.Lead, false); err != nil {
			t.Fatal(err)
		}
		rotateAt(t, ctx, st, later, naiveEpoch)
		if naiveState(t, ctx, st, "nv").NextFrom != later.Add(naiveEpoch.Lead).Unix() {
			t.Fatal("not published")
		}
		if err := RequestRotation(ctx, st, "nv", later.Add(time.Hour), naiveEpoch.Lead, true); err != nil {
			t.Fatal(err)
		}
		rotateAt(t, ctx, st, later.Add(time.Hour), naiveEpoch)
		if again := naiveState(t, ctx, st, "nv"); again.SNI != got.SNINext || again.SNIPrev != got.SNI {
			t.Fatalf("second -now: %+v", again)
		}
		allNames(t, ctx, st)
	})
	t.Run("now, no certificate", func(t *testing.T) {
		ctx, st, nv := naiveNode(t)
		site := mustService(t, ctx, st, "site")
		first := ParseNaiveState(nv)
		storeCert(t, ctx, st, "site", SiteName(site), first.SNI)
		now := nv.CreatedAt.Add(5 * day)
		if err := RequestRotation(ctx, st, "nv", now, naiveEpoch.Lead, true); err != nil {
			t.Fatal(err)
		}
		rotateAt(t, ctx, st, now, naiveEpoch)
		if n := rotateAt(t, ctx, st, now.Add(day-time.Minute), naiveEpoch); n != 0 {
			t.Fatal("gave up early")
		}
		if n := rotateAt(t, ctx, st, now.Add(day), naiveEpoch); n != 1 {
			t.Fatal("did not give up")
		}
		got := naiveState(t, ctx, st, "nv")
		if got.SNI != first.SNI || got.SNINext != first.SNINext || got.RotateAt != 0 || got.PreparedAt != 0 || got.NextFrom != 0 {
			t.Fatalf("given up: %+v", got)
		}
		all, _ := st.ListServices(ctx)
		if _, next := SiteNames(site, all); slices.Contains(next, first.SNINext) {
			t.Fatal("the certificate still asked for the name")
		}
	})
	t.Run("kinds", func(t *testing.T) {
		ctx, st, _ := naiveNode(t)
		if err := RequestRotation(ctx, st, "site", time.Now(), day, false); err == nil {
			t.Fatal("site rotated as REALITY or naive")
		}
	})
}

// A store without the next name (a node from before R4-42, a restored
// backup made before it): the render gives one first, once, whoever asks;
// the round that finds none chooses it and publishes nothing yet.
func TestNaiveNameRestored(t *testing.T) {
	ctx, st, nv := naiveNode(t, "*.example.com")
	first := ParseNaiveState(nv)
	bare, err := setFields(nv.Settings, map[string]any{"sni_next": nil})
	if err != nil {
		t.Fatal(err)
	}
	st.UpdateService(ctx, nv.ID, store.ServiceUpdate{Settings: bare})
	nv = mustService(t, ctx, st, "nv")
	var wg sync.WaitGroup
	got := make([]string, 8)
	for i := range got {
		wg.Go(func() {
			s, err := EnsureNaiveNext(ctx, st, nv)
			if err != nil {
				t.Error(err)
			}
			got[i] = ParseNaiveState(s).SNINext
		})
	}
	wg.Wait()
	stored := naiveState(t, ctx, st, "nv").SNINext
	for _, n := range got {
		if n != stored || n == "" || n == first.SNI {
			t.Fatalf("next names %v, stored %s", got, stored)
		}
	}
	allNames(t, ctx, st)

	// The round alone, 100 days on (due, a wildcard): it chooses, then
	// publishes in a later round.
	st.UpdateService(ctx, nv.ID, store.ServiceUpdate{Settings: bare})
	SetServiceOption(ctx, st, "r", "rotate_sni", "off")
	e := naiveEpoch
	e.Period = 0
	at := nv.CreatedAt.Add(100 * day)
	if n := rotateAt(t, ctx, st, at, e); n != 1 {
		t.Fatalf("round: %d", n)
	}
	if got := naiveState(t, ctx, st, "nv"); got.SNINext == "" || got.NextFrom != 0 {
		t.Fatalf("first round: %+v", got)
	}
	rotateAt(t, ctx, st, at.Add(time.Minute), e)
	if got := naiveState(t, ctx, st, "nv"); got.NextFrom != at.Add(time.Minute+e.Lead).Unix() {
		t.Fatalf("second round: %+v", got)
	}
}

// Two naive services switching in one round get names of their own, and
// none of any other service's; a DNS tunnel's zone takes none of them.
func TestNaiveNamesApart(t *testing.T) {
	ctx, st, _ := naiveNode(t, "*.example.com")
	for _, s := range []store.Service{{Kind: "naive", Name: "nv2"}, {Kind: "doh", Name: "dh"}, {Kind: "hy2-masq", Name: "hy"}, {Kind: "dnstt", Name: "dns"}} {
		s.Enabled = true
		if _, err := CreateService(ctx, st, s); err != nil {
			t.Fatal(err)
		}
	}
	SetServiceOption(ctx, st, "r", "rotate_sni", "off")
	now := time.Now()
	for range 5 {
		now = now.Add(time.Hour)
		for _, n := range []string{"nv", "nv2"} {
			if err := RequestRotation(ctx, st, n, now, naiveEpoch.Lead, true); err != nil {
				t.Fatal(err)
			}
		}
		if n := rotateAt(t, ctx, st, now, naiveEpoch); n != 2 {
			t.Fatalf("round: %d", n)
		}
		allNames(t, ctx, st)
	}
	prev := naiveState(t, ctx, st, "nv").SNIPrev
	if _, err := SetServiceOption(ctx, st, "dns", "spare_zones", prev); err == nil {
		t.Fatalf("a spare zone took naive's previous name %s: %s", prev, mustService(t, ctx, st, "dns").Settings)
	}
}
