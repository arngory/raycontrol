package provision

import (
	"context"
	"path/filepath"
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
		ns := ParseNaiveState(s) // sni, sni_next, sni_prev of any kind; naive's older ones
		for _, n := range append([]string{ns.SNI, ns.SNINext}, ns.Previous()...) {
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

// The joint switch does not hang on the phase of rayd's minute rounds, nor
// on REALITY publishing on time: naive publishes REALITY's time exactly,
// though its round comes up to a minute after its lead began, waits for a
// REALITY that waits for its certificate, and switches in the round
// REALITY switches in. So the front's routes change in one round only (one
// render, one restart of the front for both).
func TestNaiveNameJoinsRealityRound(t *testing.T) {
	type node struct {
		ctx   context.Context
		st    *store.Store
		r, nv store.Service
	}
	wildcard := func(t *testing.T) node {
		ctx, st, nv := naiveNode(t, "*.example.com")
		return node{ctx, st, mustService(t, ctx, st, "r"), nv}
	}
	// Listed names, rotate_sni on for both: REALITY waits for a
	// certificate of its new name in vain, then publishes without it, a
	// round after its lead began.
	listed := func(t *testing.T) node {
		ctx, st, nv := naiveNode(t)
		for _, s := range []string{"r", "nv"} {
			if _, err := SetServiceOption(ctx, st, s, "rotate_sni", "on"); err != nil {
				t.Fatal(err)
			}
		}
		ns, site := ParseNaiveState(nv), mustService(t, ctx, st, "site")
		storeCert(t, ctx, st, "site", SiteName(site), ns.SNI, ns.SNINext)
		return node{ctx, st, mustService(t, ctx, st, "r"), mustService(t, ctx, st, "nv")}
	}
	for _, c := range []struct {
		name  string
		setup func(*testing.T) node
		phase time.Duration    // of the rounds
		down  [2]time.Duration // rayd down, after REALITY's creation
		now   time.Duration    // rotate REALITY -now, after its creation
	}{
		{"wildcard, phase 0", wildcard, 0, [2]time.Duration{}, 0},
		{"wildcard, phase 17s", wildcard, 17 * time.Second, [2]time.Duration{}, 0},
		{"wildcard, phase 59s", wildcard, 59 * time.Second, [2]time.Duration{}, 0},
		{"REALITY waits for its certificate, phase 17s", listed, 17 * time.Second, [2]time.Duration{}, 0},
		{"REALITY waits for its certificate, phase 59s", listed, 59 * time.Second, [2]time.Duration{}, 0},
		// REALITY prepares 3 hours late, publishes a round after, 3 hours
		// past its time; naive's lead began meanwhile.
		{"rayd down as REALITY would prepare", wildcard, 17 * time.Second, [2]time.Duration{86*day - time.Hour, 87*day + 2*time.Hour}, 0},
		{"rayd down, REALITY waits for its certificate", listed, 17 * time.Second, [2]time.Duration{86*day - time.Hour, 86*day + 3*time.Hour}, 0},
		// REALITY published on time; naive's first round in its lead
		// comes 10 minutes, an hour late (rayd down, the host asleep):
		// past the slack, it still takes REALITY's time (review 2).
		{"rayd down as naive's lead begins, 10 minutes", wildcard, 17 * time.Second, [2]time.Duration{87*day - time.Minute, 87*day + 10*time.Minute}, 0},
		{"rayd down as naive's lead begins, an hour", wildcard, 17 * time.Second, [2]time.Duration{87*day - time.Minute, 87*day + time.Hour}, 0},
		// rotate REALITY -now, 10 days before naive's time: naive goes
		// with it, at once, its next name routed since its last switch.
		{"rotate REALITY -now", wildcard, 17 * time.Second, [2]time.Duration{}, 80 * day},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := c.setup(t)
			ctx, st := n.ctx, n.st
			// naive's own time 10 days after REALITY's: it joins REALITY's.
			rotated := n.r.CreatedAt.Add(10 * day).Unix()
			if err := naiveFields(ctx, st, n.nv, map[string]any{"rotated_at": rotated}); err != nil {
				t.Fatal(err)
			}
			e := naiveEpoch
			X := n.r.CreatedAt.Add(e.Period)
			// What the front routes: naive's three names, REALITY's.
			routes := func() string {
				ns, rs := naiveState(t, ctx, st, "nv"), mustService(t, ctx, st, "r")
				return strings.Join([]string{ns.SNI, ns.SNIPrev, ns.SNINext, SiteName(rs)}, " ")
			}
			var naiveAt, realityAt time.Time
			var changes []time.Time
			last := routes()
			// By the hour, by the minute about the leads and the switches.
			near := func(at time.Time) bool {
				for _, p := range []time.Time{X.Add(-e.Lead - e.Prepare), X.Add(-e.Lead), X, n.r.CreatedAt.Add(c.now)} {
					if at.After(p.Add(-2*time.Hour)) && at.Before(p.Add(5*time.Hour)) {
						return true
					}
				}
				return false
			}
			asked := false
			for at := n.r.CreatedAt.Add(80*day + c.phase); at.Before(X.Add(day)); {
				if c.now != 0 && !asked && !at.Before(n.r.CreatedAt.Add(c.now)) {
					if err := RequestRotation(ctx, st, "r", at, e.Lead, true); err != nil {
						t.Fatal(err)
					}
					asked = true
				}
				if down := at.After(n.r.CreatedAt.Add(c.down[0])) && at.Before(n.r.CreatedAt.Add(c.down[1])); !down {
					rotateAt(t, ctx, st, at, e)
				}
				if naiveAt.IsZero() && naiveState(t, ctx, st, "nv").RotatedAt != rotated {
					naiveAt = at
				}
				if realityAt.IsZero() && ParseRealityState(mustService(t, ctx, st, "r")).RotatedAt != n.r.CreatedAt.Unix() {
					realityAt = at
				}
				if r := routes(); r != last {
					changes, last = append(changes, at), r
				}
				if near(at) {
					at = at.Add(time.Minute)
				} else {
					at = at.Add(time.Hour)
				}
			}
			if naiveAt.IsZero() || !naiveAt.Equal(realityAt) {
				t.Fatalf("REALITY switched in the round of %v, naive in that of %v", realityAt, naiveAt)
			}
			if len(changes) != 1 {
				t.Fatalf("the front's routes changed in the rounds of %v", changes)
			}
			// naive's time is REALITY's: the next epoch counts from it.
			if got, want := naiveState(t, ctx, st, "nv").RotatedAt, ParseRealityState(mustService(t, ctx, st, "r")).RotatedAt; got != want {
				t.Fatalf("naive switched for %v, REALITY for %v", time.Unix(got, 0), time.Unix(want, 0))
			}
			allNames(t, ctx, st)
		})
	}
}

// A naive switch published for a time a little apart from REALITY's (one
// of them published late) goes in REALITY's round, before its time or
// after; one further apart keeps its own.
func TestNaiveNameJoinsRealityApart(t *testing.T) {
	for _, c := range []struct {
		name   string
		offset time.Duration // naive's published time after REALITY's
		joined bool
	}{
		{"4 minutes before", -4 * time.Minute, true},
		{"40 seconds before", -40 * time.Second, true},
		{"40 seconds after", 40 * time.Second, true},
		{"4 minutes after", 4 * time.Minute, true},
		{"10 minutes before", -10 * time.Minute, false},
		{"10 minutes after", 10 * time.Minute, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, st, nv := naiveNode(t, "*.example.com")
			r := mustService(t, ctx, st, "r")
			e := naiveEpoch
			X := r.CreatedAt.Add(e.Period)
			if err := naiveFields(ctx, st, nv, map[string]any{"rotated_at": r.CreatedAt.Add(10 * day).Unix()}); err != nil {
				t.Fatal(err)
			}
			rotateAt(t, ctx, st, X.Add(-e.Lead-e.Prepare), e)
			rotateAt(t, ctx, st, X.Add(-e.Lead), e)
			if rs, ns := ParseRealityState(mustService(t, ctx, st, "r")), naiveState(t, ctx, st, "nv"); rs.NextFrom != X.Unix() || ns.NextFrom != X.Unix() {
				t.Fatalf("published for %d and %d, want %d", rs.NextFrom, ns.NextFrom, X.Unix())
			}
			from := X.Add(c.offset)
			if err := naiveFields(ctx, st, mustService(t, ctx, st, "nv"), map[string]any{"next_from": from.Unix()}); err != nil {
				t.Fatal(err)
			}
			var naiveAt, realityAt time.Time
			for at := X.Add(-20 * time.Minute); at.Before(X.Add(20 * time.Minute)); at = at.Add(time.Minute) {
				rotateAt(t, ctx, st, at, e)
				if naiveAt.IsZero() && naiveState(t, ctx, st, "nv").NextFrom == 0 {
					naiveAt = at
				}
				if realityAt.IsZero() && ParseRealityState(mustService(t, ctx, st, "r")).NextFrom == 0 {
					realityAt = at
				}
			}
			if realityAt != X.Add(-RealityEarly) {
				t.Fatalf("REALITY switched at %v", realityAt)
			}
			switch {
			case c.joined && !naiveAt.Equal(realityAt):
				t.Fatalf("naive switched at %v, REALITY at %v", naiveAt, realityAt)
			case !c.joined && !naiveAt.Equal(from):
				t.Fatalf("naive switched at %v, want its own time %v", naiveAt, from)
			}
			if got := naiveState(t, ctx, st, "nv").RotatedAt; got != from.Unix() {
				t.Fatalf("naive switched for %v, want %v", time.Unix(got, 0), from)
			}
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
			s, err := EnsureNaiveNext(ctx, st, nv, "example.com")
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
	// Five switches within an hour each: three previous names routed, the
	// oldest of them taken by no zone either.
	older := naiveState(t, ctx, st, "nv").SNIOlder
	if len(older) != 2 {
		t.Fatalf("older names %+v", older)
	}
	if _, err := SetServiceOption(ctx, st, "dns", "spare_zones", older[1].SNI); err == nil {
		t.Fatalf("a spare zone took naive's older name %s", older[1].SNI)
	}
}

// The owner's answer 3: the previous name is accepted the whole epoch. A
// second switch within the period keeps the name before the first too:
// rayctl service rotate -now twice, or right after the scheduled switch
// because the new name is blocked at once (devices that cannot fetch went
// back to link, the name before). Names go at a switch only, a period
// after the one that left them, 3 at most; the request says which.
func TestNaiveNamePreviousNames(t *testing.T) {
	routed := func(t *testing.T, ctx context.Context, st *store.Store, names ...string) {
		t.Helper()
		got := naiveState(t, ctx, st, "nv")
		all, _ := st.ListServices(ctx)
		site, _ := st.ServiceByName(ctx, "site")
		certified, _ := SiteNames(site, all)
		for _, n := range names {
			if n != got.SNI && n != got.SNINext && !slices.Contains(got.Previous(), n) {
				t.Fatalf("%s no longer routed: %+v", n, got)
			}
			if !slices.Contains(certified, n) && n != got.SNINext {
				t.Fatalf("%s not among the certificate's names %v", n, certified)
			}
		}
	}
	t.Run("-now twice", func(t *testing.T) {
		ctx, st, nv := naiveNode(t, "*.example.com")
		a := ParseNaiveState(nv)
		now := nv.CreatedAt.Add(5 * day)
		var asked []NaiveSwitchNames
		for i := range 2 {
			at := now.Add(time.Duration(i) * time.Hour)
			n, err := RequestRotationNames(ctx, st, "nv", at, naiveEpoch.Lead, true, naiveEpoch.NaivePeriod)
			if err != nil {
				t.Fatal(err)
			}
			asked = append(asked, n)
			rotateAt(t, ctx, st, at, naiveEpoch)
		}
		got := naiveState(t, ctx, st, "nv")
		routed(t, ctx, st, a.SNI, a.SNINext)
		if got.SNIPrev != a.SNINext || len(got.SNIOlder) != 1 || got.SNIOlder[0] != (NaiveRetired{a.SNI, now.Unix()}) {
			t.Fatalf("after two switches: %+v", got)
		}
		if !slices.Equal(asked[1].Kept, []string{a.SNINext, a.SNI}) || asked[1].Dropped != nil {
			t.Fatalf("the second request said %+v", asked[1])
		}
		allNames(t, ctx, st)
	})
	t.Run("scheduled, then -now", func(t *testing.T) {
		ctx, st, nv := naiveNode(t, "*.example.com")
		SetServiceOption(ctx, st, "r", "rotate_sni", "off")
		e := naiveEpoch
		e.Period = 0
		a := ParseNaiveState(nv)
		rotateAt(t, ctx, st, nv.CreatedAt.Add(87*day), e)
		rotateAt(t, ctx, st, nv.CreatedAt.Add(90*day), e) // a → b
		b := naiveState(t, ctx, st, "nv")
		later := nv.CreatedAt.Add(92 * day) // b blocked
		if err := RequestRotation(ctx, st, "nv", later, e.Lead, true); err != nil {
			t.Fatal(err)
		}
		rotateAt(t, ctx, st, later, e) // b → c
		routed(t, ctx, st, a.SNI, b.SNI)
		// The next scheduled switch, a period after: b goes, a too.
		rotateAt(t, ctx, st, later.Add(87*day), e)
		rotateAt(t, ctx, st, later.Add(90*day), e)
		got := naiveState(t, ctx, st, "nv")
		if prev := got.Previous(); len(prev) != 1 || slices.Contains(prev, a.SNI) || slices.Contains(prev, b.SNI) {
			t.Fatalf("a period on: %+v", got)
		}
	})
	t.Run("by the schedule: one previous name", func(t *testing.T) {
		ctx, st, nv := naiveNode(t, "*.example.com")
		SetServiceOption(ctx, st, "r", "rotate_sni", "off")
		e := naiveEpoch
		e.Period = 0
		for _, d := range []time.Duration{87, 90, 177, 180, 267, 270} {
			rotateAt(t, ctx, st, nv.CreatedAt.Add(d*day), e)
		}
		if got := naiveState(t, ctx, st, "nv"); got.SNIPrev == "" || got.SNIOlder != nil || got.RotatedAt != nv.CreatedAt.Add(270*day).Unix() {
			t.Fatalf("three scheduled switches: %+v", got)
		}
	})
	t.Run("at most three", func(t *testing.T) {
		ctx, st, nv := naiveNode(t, "*.example.com")
		a := ParseNaiveState(nv)
		now := nv.CreatedAt.Add(5 * day)
		var last NaiveSwitchNames
		for i := range 4 {
			at := now.Add(time.Duration(i) * time.Hour)
			n, err := RequestRotationNames(ctx, st, "nv", at, naiveEpoch.Lead, true, 0)
			if err != nil {
				t.Fatal(err)
			}
			last = n
			rotateAt(t, ctx, st, at, naiveEpoch)
		}
		got := naiveState(t, ctx, st, "nv")
		if prev := got.Previous(); len(prev) != NaivePrevCap || slices.Contains(prev, a.SNI) || got.SNIPrev != prev[0] {
			t.Fatalf("after four switches: %+v", got)
		}
		if len(last.Kept) != NaivePrevCap || !slices.Equal(last.Dropped, []string{a.SNI}) {
			t.Fatalf("the fourth request said %+v", last)
		}
		allNames(t, ctx, st)
	})
	t.Run("period 0: 90 days", func(t *testing.T) {
		state := NaiveState{SNI: "c", SNINext: "d", SNIPrev: "b", RotatedAt: 1000, SNIOlder: []NaiveRetired{{"a", 500}}}
		day := int64(24 * 3600)
		if kept, dropped := NaivePrevious(state, 500+90*day-1, 0); len(kept) != 3 || dropped != nil {
			t.Fatalf("within 90 days: %v %v", kept, dropped)
		}
		if kept, dropped := NaivePrevious(state, 500+90*day, 0); len(kept) != 2 || !slices.Equal(dropped, []string{"a"}) {
			t.Fatalf("90 days on: %v %v", kept, dropped)
		}
		if kept, _ := NaivePrevious(state, 500+day, 30*24*time.Hour); len(kept) != 3 {
			t.Fatalf("a day on, a period of 30 days: %v", kept)
		}
	})
}

// A node initialised without a domain, naive under the operator's own name
// (as it worked before R4-42): its names have nowhere to move, so nothing
// rotates. It is made, every rotation round is clean (REALITY's keys still
// switch, under the name it has), rayctl service rotate says why it does
// nothing, and the render's EnsureNaiveNext returns without the lock or a
// read.
func TestNaiveNameWithoutDomain(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := Init(ctx, st, Options{Host: "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []store.Service{
		{Kind: "site", Name: "site", Settings: `{"sni":"www.example.org"}`},
		{Kind: "reality", Name: "r"},
		{Kind: "naive", Name: "nv", Settings: `{"sni":"nv.example.org"}`},
	} {
		s.Enabled = true
		if _, err := CreateService(ctx, st, s); err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
	}
	nv := mustService(t, ctx, st, "nv")
	if ns := ParseNaiveState(nv); ns.SNI != "nv.example.org" || ns.SNINext != "" {
		t.Fatalf("naive made: %s", nv.Settings)
	}
	storeCert(t, ctx, st, "site", "www.example.org", "nv.example.org")
	// rotate_sni on everywhere: still nothing to move to.
	for _, s := range []string{"r", "nv"} {
		if _, err := SetServiceOption(ctx, st, s, "rotate_sni", "on"); err != nil {
			t.Fatal(err)
		}
	}
	if err := RequestRotation(ctx, st, "nv", nv.CreatedAt, naiveEpoch.Lead, true); err == nil || !strings.Contains(err.Error(), "no domain") {
		t.Fatalf("rotate naive: %v", err)
	}
	if err := RequestRotation(ctx, st, "r", nv.CreatedAt.Add(10*day), naiveEpoch.Lead, false); err != nil {
		t.Fatal(err)
	}
	for _, d := range []time.Duration{time.Hour, 10 * day, 11 * day, 13 * day, 87 * day, 90 * day, 200 * day} {
		if _, err := RotateReality(ctx, st, nv.CreatedAt.Add(d), naiveEpoch, func(context.Context, string) error { return nil }, nil); err != nil {
			t.Fatalf("round at %v: %v", d, err)
		}
	}
	if got := ParseNaiveState(mustService(t, ctx, st, "nv")); got.SNI != "nv.example.org" || got.SNINext != "" || got.Previous() != nil ||
		got.RotateAt != 0 || got.PreparedAt != 0 || got.NextFrom != 0 || got.RotatedAt != nv.CreatedAt.Unix() {
		t.Fatalf("naive after the rounds: %+v", got)
	}
	r := ParseRealityState(mustService(t, ctx, st, "r"))
	if r.RotatedAt == mustService(t, ctx, st, "r").CreatedAt.Unix() || SiteName(mustService(t, ctx, st, "r")) != "www.example.org" {
		t.Fatalf("REALITY's keys did not switch, or its name moved: %s", mustService(t, ctx, st, "r").Settings)
	}
	// The render's call, while a round holds the lock.
	settingsMu.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := EnsureNaiveNext(ctx, st, nv, "")
		done <- err
	}()
	select {
	case err := <-done:
		settingsMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		settingsMu.Unlock()
		t.Fatal("EnsureNaiveNext waited for the lock on a node without a domain")
	}
}
