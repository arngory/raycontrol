package render_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
)

func naiveNames(t *testing.T, ctx context.Context, st *store.Store, name string) provision.NaiveState {
	t.Helper()
	svc, err := st.ServiceByName(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	return provision.ParseNaiveState(svc)
}

// routes checks that exactly names go to service over TCP and over UDP
// (naive-quic) and no other name does.
func (fc frontConfig) routes(t *testing.T, service string, names ...string) {
	t.Helper()
	for _, table := range []struct {
		routes  map[string]string
		backend string
	}{{fc.tcp, service}, {fc.udp, service + "/quic"}} {
		n := 0
		for _, b := range table.routes {
			if b == table.backend {
				n++
			}
		}
		for _, name := range names {
			if table.routes[name] != table.backend {
				t.Fatalf("%s routed to %q, want %s:\n%s", name, table.routes[name], table.backend, fc.raw)
			}
		}
		if n != len(names) {
			t.Fatalf("%s has %d names, want %v:\n%s", table.backend, n, names, fc.raw)
		}
	}
}

// naive's names on the front (R4-42): the current one and the next one
// from the start, the previous one after a switch, over TCP and UDP. The
// publication changes nothing in front.json: the front restarts once an
// epoch, at the switch. Two REALITY services on the site keep theirs, old
// ones included, and no name is in two routes.
func TestNaiveRoutesOneRestartAnEpoch(t *testing.T) {
	ctx := context.Background()
	st := node(t)
	for _, s := range [][2]string{{"reality", "r1"}, {"reality", "r2"}, {"naive", "nv"}, {"doh", "dh"}} {
		if _, err := provision.CreateService(ctx, st, store.Service{Kind: s[0], Name: s[1], Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	siteCert(t, ctx, st, "*.example.com")
	// REALITY's own schedule off: its switches here are the operator's.
	e := provision.RealityEpoch{Lead: 3 * day, Prepare: day, Grace: 2 * day, NaivePeriod: 90 * day}
	ok := func(context.Context, string) error { return nil }
	rotate := func(at time.Time) {
		t.Helper()
		if _, err := provision.RotateReality(ctx, st, at, e, ok, nil); err != nil {
			t.Fatal(err)
		}
	}
	nv, _ := st.ServiceByName(ctx, "nv")
	created := nv.CreatedAt
	first := naiveNames(t, ctx, st, "nv")

	start := renderFront(t, ctx, st)
	if start.err != nil {
		t.Fatal(start.err)
	}
	start.routes(t, "nv", first.SNI, first.SNINext)

	// r2 moves to a new name early in the epoch (the operator's switch, too
	// far from naive's for naive to join it); its grace ends.
	r2old := sni(t, ctx, st, "r2")
	if err := provision.RequestRotation(ctx, st, "r2", created.Add(20*day), e.Lead, false); err != nil {
		t.Fatal(err)
	}
	rotate(created.Add(20 * day))
	rotate(created.Add(20*day + time.Minute))
	rotate(created.Add(20*day + time.Minute + e.Lead))
	if sni(t, ctx, st, "r2") == r2old || naiveNames(t, ctx, st, "nv").NextFrom != 0 {
		t.Fatalf("r2 did not switch, or naive went with it: %+v", naiveNames(t, ctx, st, "nv"))
	}
	rotate(created.Add(30 * day))
	mid := renderFront(t, ctx, st)
	mid.routes(t, "nv", first.SNI, first.SNINext)

	// Published three days ahead: subscriptions change, the front does not.
	rotate(created.Add(87 * day))
	if naiveNames(t, ctx, st, "nv").NextFrom == 0 {
		t.Fatal("not published")
	}
	if pub := renderFront(t, ctx, st); !bytes.Equal(pub.raw, mid.raw) {
		t.Fatalf("the publication changed front.json:\n%s\n%s", mid.raw, pub.raw)
	}

	// The switch: one change of front.json, the old name still served.
	beforeSwitch := renderFront(t, ctx, st)
	rotate(created.Add(90*day - provision.RealityEarly))
	sw := naiveNames(t, ctx, st, "nv")
	if sw.SNI != first.SNINext || sw.SNIPrev != first.SNI {
		t.Fatalf("not switched: %+v", sw)
	}
	after := renderFront(t, ctx, st)
	if bytes.Equal(after.raw, beforeSwitch.raw) {
		t.Fatal("the switch did not change front.json")
	}
	after.routes(t, "nv", sw.SNI, sw.SNIPrev, sw.SNINext)
	after.routes(t, "dh", sni(t, ctx, st, "dh"))
	if after.tcp[sni(t, ctx, st, "r1")] != "r1" || after.tcp[r2old] != "r2" || after.tcp[sni(t, ctx, st, "r2")] != "r2" || after.def != "r1" {
		t.Fatalf("REALITY's names: %v", after.tcp)
	}
	if len(after.tcp) != 7 || len(after.udp) != 4 {
		t.Fatalf("names: TCP %v, UDP %v", after.tcp, after.udp)
	}

	// The next epoch's publication, and r2's grace ending: front.json as
	// it was after the switch.
	rotate(created.Add(170 * day))
	rotate(created.Add(177 * day))
	if naiveNames(t, ctx, st, "nv").NextFrom == 0 {
		t.Fatal("second epoch not published")
	}
	if again := renderFront(t, ctx, st); !bytes.Equal(again.raw, after.raw) {
		t.Fatalf("the epoch changed front.json before its switch:\n%s\n%s", after.raw, again.raw)
	}
}

// A naive service from before R4-42 (a node updated from v0.28.0, a
// restored backup without sni_next): the first render gives it its next
// name and routes it, and the renders after change nothing: the front
// restarts once, with the update.
func TestNaiveRoutesUpdatedNode(t *testing.T) {
	ctx := context.Background()
	st := node(t)
	for _, s := range [][2]string{{"reality", "r"}, {"naive", "nv"}} {
		if _, err := provision.CreateService(ctx, st, store.Service{Kind: s[0], Name: s[1], Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	siteCert(t, ctx, st, "*.example.com")
	nv, _ := st.ServiceByName(ctx, "nv")
	before := provision.ParseNaiveState(nv)
	var old map[string]any
	if err := json.Unmarshal([]byte(nv.Settings), &old); err != nil {
		t.Fatal(err)
	}
	delete(old, "sni_next")
	b, _ := json.Marshal(old)
	if err := st.UpdateService(ctx, nv.ID, store.ServiceUpdate{Settings: string(b)}); err != nil {
		t.Fatal(err)
	}
	first := renderFront(t, ctx, st)
	got := naiveNames(t, ctx, st, "nv")
	if got.SNINext == "" || got.SNINext == before.SNI {
		t.Fatalf("no next name after the first render: %+v", got)
	}
	first.routes(t, "nv", got.SNI, got.SNINext)
	if second := renderFront(t, ctx, st); !bytes.Equal(second.raw, first.raw) {
		t.Fatal("the second render changed front.json")
	}
}
