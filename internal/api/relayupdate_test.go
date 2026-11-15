package api

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/nodeupdate"
)

// The exit names a release to its relays only after an update of its own
// that is done, by request or by hand, not with -no-relays, that put in
// the release this rayd runs, while no other update waits or runs
// (spec/relay-update-remote-v1.md §3.3).
func TestRelayOffer(t *testing.T) {
	now := time.Date(2026, 11, 20, 3, 40, 0, 0, time.UTC)
	done := nodeupdate.Status{ID: "6f1c0e2a9b3d4c5e", State: nodeupdate.Done, From: "v0.27.0", To: "v0.28.0", Target: "latest", Kind: nodeupdate.Remote,
		Started: now.Add(-3 * time.Minute), Ended: now.Add(-time.Minute)}
	o := relayOffer(done, nodeupdate.Request{}, false, "v0.28.0", now)
	if o == nil || o.Id != done.ID || o.Version != "v0.28.0" || o.EndedAt != done.Ended.Unix() {
		t.Fatalf("done: %v", o)
	}
	with := func(f func(*nodeupdate.Status)) nodeupdate.Status {
		s := done
		f(&s)
		return s
	}
	for name, c := range map[string]struct {
		st      nodeupdate.Status
		req     nodeupdate.Request
		waiting bool
		version string
		offer   bool
	}{
		"auto":                    {with(func(s *nodeupdate.Status) { s.Kind = nodeupdate.Auto }), nodeupdate.Request{}, false, "v0.28.0", true},
		"by hand":                 {with(func(s *nodeupdate.Status) { s.Kind = nodeupdate.Local }), nodeupdate.Request{}, false, "v0.28.0", true},
		"-no-relays":              {with(func(s *nodeupdate.Status) { s.Kind, s.NoRelays = nodeupdate.Local, true }), nodeupdate.Request{}, false, "v0.28.0", false},
		"rolled back":             {with(func(s *nodeupdate.Status) { s.State, s.To = nodeupdate.RolledBack, "v0.27.0" }), nodeupdate.Request{}, false, "v0.27.0", false},
		"failed":                  {with(func(s *nodeupdate.Status) { s.State = nodeupdate.Failed }), nodeupdate.Request{}, false, "v0.28.0", false},
		"running":                 {with(func(s *nodeupdate.Status) { s.State = nodeupdate.Running }), nodeupdate.Request{}, false, "v0.28.0", false},
		"a relay's":               {with(func(s *nodeupdate.Status) { s.Kind = nodeupdate.Exit }), nodeupdate.Request{}, false, "v0.28.0", false},
		"no kind":                 {with(func(s *nodeupdate.Status) { s.Kind = "" }), nodeupdate.Request{}, false, "v0.28.0", false},
		"installed by hand since": {done, nodeupdate.Request{}, false, "v0.28.1", false},
		"a dev build":             {with(func(s *nodeupdate.Status) { s.To = "dev" }), nodeupdate.Request{}, false, "dev", false},
		"-local":                  {with(func(s *nodeupdate.Status) { s.Kind, s.To = nodeupdate.Local, "local" }), nodeupdate.Request{}, false, "local", false},
		"no id":                   {with(func(s *nodeupdate.Status) { s.ID = "" }), nodeupdate.Request{}, false, "v0.28.0", false},
		"a strange id":            {with(func(s *nodeupdate.Status) { s.ID = "../x" }), nodeupdate.Request{}, false, "v0.28.0", false},
		"a request waits":         {done, nodeupdate.Request{ID: "ab", At: now.Add(-time.Minute)}, true, "v0.28.0", false},
		// One never taken is no update under way.
		"a stale request": {done, nodeupdate.Request{ID: "ab", At: now.Add(-nodeupdate.Stale)}, true, "v0.28.0", true},
	} {
		if got := relayOffer(c.st, c.req, c.waiting, c.version, now); (got != nil) != c.offer {
			t.Errorf("%s: %v", name, got)
		}
	}
}

// The queue (§3.3): one relay at a time by name; a relay passes with an
// outcome, on the release, with remote off, never heard of and with no
// feed, silent for TurnTimeout, or TurnTimeout after its turn began; one
// given its turn keeps it, and nobody else updates meanwhile.
func TestRelayQueue(t *testing.T) {
	now := time.Date(2026, 11, 20, 4, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	o := &perimeterv1.RelayUpdateOffer{Id: "aa", Version: "v0.28.0"}
	idle := relayRecord{Reported: nodeupdate.Idle, Version: "v0.27.0", Remote: true, ChangedAt: ago(time.Hour).Unix()}
	rec := func(state, id, version string, remote bool, changed time.Duration) relayRecord {
		r := relayRecord{Reported: state, UpdateID: id, Version: version, Remote: remote, ChangedAt: ago(changed).Unix()}
		if id != "" {
			r.Since = r.ChangedAt
		}
		return r
	}
	// since is r first reported on its id at, earlier than it changed.
	since := func(r relayRecord, d time.Duration) relayRecord {
		r.Since = ago(d).Unix()
		return r
	}
	view := func(name string, r relayRecord, feeds int) relayView {
		return relayView{Name: name, Rec: r, Feeds: feeds, ClosedAt: ago(2 * time.Hour)}
	}
	given := func(v relayView, at time.Duration) relayView {
		v.OfferID, v.OfferedAt = o.Id, ago(at)
		return v
	}
	closed := func(v relayView, at time.Duration) relayView {
		v.ClosedAt = ago(at)
		return v
	}
	for _, c := range []struct {
		name   string
		o      *perimeterv1.RelayUpdateOffer
		views  []relayView
		offers []string
		passed []string
	}{
		{"nothing heard, no feeds: no one to wait for", o,
			[]relayView{view("r1", relayRecord{}, 0), view("r2", relayRecord{}, 0)}, []string{"r1", "r2"}, []string{"r1", "r2"}},
		{"the first by name", o,
			[]relayView{view("r1", relayRecord{}, 1), view("r2", idle, 1), view("r3", idle, 1)}, []string{"r1"}, nil},
		// Given the offer and gone without a word: it may be updating.
		{"never reported, given its turn, no feed", o,
			[]relayView{given(view("r1", relayRecord{}, 0), time.Minute), view("r2", idle, 1)}, []string{"r1"}, nil},
		{"never reported, given its turn TurnTimeout ago", o,
			[]relayView{given(view("r1", relayRecord{}, 0), TurnTimeout+time.Second), view("r2", idle, 1)}, []string{"r1", "r2"}, []string{"r1"}},
		{"after an outcome, the next; the first keeps it, on the release", o,
			[]relayView{view("r1", rec(nodeupdate.Done, "aa", "v0.28.0", true, time.Minute), 1), view("r2", idle, 1), view("r3", idle, 1)},
			[]string{"r1", "r2"}, []string{"r1"}},
		{"failed or rolled back: passed, and no offer while another updates", o,
			[]relayView{view("r1", rec(nodeupdate.Failed, "aa", "v0.27.0", true, time.Minute), 1), view("r2", rec(nodeupdate.RolledBack, "aa", "v0.27.0", true, time.Minute), 1),
				given(view("r3", rec(nodeupdate.Running, "aa", "v0.27.0", true, time.Minute), 1), 2*time.Minute)},
			[]string{"r3"}, []string{"r1", "r2"}},
		{"on the release or newer, without an update", o,
			[]relayView{view("r1", rec(nodeupdate.Idle, "", "v0.29.0", true, time.Hour), 1), view("r2", idle, 1)}, []string{"r1", "r2"}, []string{"r1"}},
		{"remote off", o,
			[]relayView{view("r1", rec(nodeupdate.Idle, "", "v0.27.0", false, time.Hour), 1), view("r2", idle, 1)}, []string{"r1", "r2"}, []string{"r1"}},
		{"remote off with an update under way: it goes on, the others wait", o,
			[]relayView{given(view("r1", rec(nodeupdate.Running, "aa", "v0.27.0", false, 2*time.Minute), 0), 3*time.Minute), view("r2", idle, 1)},
			[]string{"r1"}, nil},
		{"updating, its feed down while rayd relay restarts", o,
			[]relayView{given(closed(view("r1", rec(nodeupdate.Running, "aa", "v0.27.0", true, 5*time.Minute), 0), time.Minute), 6*time.Minute), view("r2", idle, 1)},
			[]string{"r1"}, nil},
		{"given its turn, no word for TurnTimeout", o,
			[]relayView{given(view("r1", idle, 1), TurnTimeout+time.Second), view("r2", idle, 1)}, []string{"r1", "r2"}, []string{"r1"}},
		{"given its turn, not yet TurnTimeout", o,
			[]relayView{given(view("r1", idle, 1), TurnTimeout-time.Second), view("r2", idle, 1)}, []string{"r1"}, nil},
		{"silent, its feed gone a while", o,
			[]relayView{closed(view("r1", idle, 0), 10*time.Minute), view("r2", idle, 1)}, []string{"r1"}, nil},
		{"silent, its feed gone TurnTimeout", o,
			[]relayView{closed(view("r1", idle, 0), TurnTimeout+time.Second), view("r2", idle, 1)}, []string{"r1", "r2"}, []string{"r1"}},
		{"silent after it took the offer: its last word is an update under way", o,
			[]relayView{closed(view("r1", rec(nodeupdate.Requested, "aa", "v0.27.0", true, 5*time.Minute), 0), TurnTimeout+time.Second), view("r2", idle, 1)},
			[]string{"r1"}, nil},
		// The exit restarted: no offer given in memory, the records only.
		{"after a restart: running, from its report", o,
			[]relayView{view("r1", rec(nodeupdate.Running, "aa", "v0.27.0", true, 5*time.Minute), 0), view("r2", idle, 1)}, []string{"r1"}, nil},
		{"after a restart: running since TurnTimeout", o,
			[]relayView{view("r1", rec(nodeupdate.Running, "aa", "v0.27.0", true, TurnTimeout+time.Second), 0), view("r2", idle, 1)},
			[]string{"r1", "r2"}, []string{"r1"}},
		{"after a restart: done, and the next", o,
			[]relayView{view("r1", rec(nodeupdate.Done, "aa", "v0.28.0", true, time.Hour), 1), view("r2", rec(nodeupdate.Done, "aa", "v0.28.0", true, time.Hour), 0),
				view("r3", idle, 1)}, []string{"r1", "r2", "r3"}, []string{"r1", "r2"}},
		// A relay before the one updating that wants its turn now.
		{"back, while another holds its turn", o,
			[]relayView{view("r1", idle, 1), given(view("r2", rec(nodeupdate.Requested, "aa", "v0.27.0", true, time.Minute), 1), 2*time.Minute)},
			[]string{"r2"}, nil},
		// The node updated again while a relay still updates to the previous.
		{"a newer offer while a relay updates to the last", &perimeterv1.RelayUpdateOffer{Id: "bb", Version: "v0.28.1"},
			[]relayView{view("r1", rec(nodeupdate.Done, "aa", "v0.28.0", true, 10*time.Minute), 1),
				given(view("r2", rec(nodeupdate.Running, "aa", "v0.27.0", true, 3*time.Minute), 1), 4*time.Minute)},
			nil, nil},
		// A relay holds the others back TurnTimeout at most, whatever it says.
		{"said requested, then running, for TurnTimeout", o,
			[]relayView{view("r1", since(rec(nodeupdate.Running, "aa", "v0.27.0", true, time.Minute), TurnTimeout+time.Second), 1), view("r2", idle, 1)},
			[]string{"r1", "r2"}, []string{"r1"}},
		{"updating for an id never given to it", o,
			[]relayView{view("r1", idle, 1), view("r2", rec(nodeupdate.Running, "ff", "v0.27.0", true, time.Minute), 1)}, []string{"r1"}, nil},
		{"updating for an id never given to it, no feed for TurnTimeout", o,
			[]relayView{closed(view("r1", rec(nodeupdate.Running, "ff", "v0.27.0", true, time.Minute), 0), TurnTimeout+time.Second), view("r2", idle, 1)},
			[]string{"r1", "r2"}, []string{"r1"}},
		{"updating for an id never given to it, remote off", o,
			[]relayView{view("r1", rec(nodeupdate.Running, "ff", "v0.27.0", false, time.Minute), 1), view("r2", idle, 1)}, []string{"r1", "r2"}, []string{"r1"}},
		{"after a restart: running for an earlier offer", &perimeterv1.RelayUpdateOffer{Id: "bb", Version: "v0.28.1"},
			[]relayView{view("r1", rec(nodeupdate.Done, "aa", "v0.28.0", true, 10*time.Minute), 1), view("r2", rec(nodeupdate.Running, "aa", "v0.27.0", true, time.Minute), 1)},
			[]string{"r1"}, nil},
		// A relay whose update never ended (its rollback failed: no rayspa,
		// no rayd relay), and the node updated again.
		{"stuck since an earlier offer, no feed for TurnTimeout", &perimeterv1.RelayUpdateOffer{Id: "bb", Version: "v0.28.1"},
			[]relayView{closed(given(view("r1", rec(nodeupdate.Running, "aa", "v0.27.0", true, 2*time.Hour), 0), 2*time.Hour), TurnTimeout+time.Second),
				view("r2", idle, 1)},
			[]string{"r1", "r2"}, []string{"r1"}},
		{"a newer offer once it ended", &perimeterv1.RelayUpdateOffer{Id: "bb", Version: "v0.28.1"},
			[]relayView{view("r1", rec(nodeupdate.Done, "aa", "v0.28.0", true, 10*time.Minute), 1),
				given(view("r2", rec(nodeupdate.Done, "aa", "v0.28.0", true, time.Minute), 1), 4*time.Minute)},
			[]string{"r1"}, nil},
	} {
		turns := relayQueue(c.o, c.views, now)
		var offers, passed []string
		for i, tu := range turns {
			if tu.Offer {
				offers = append(offers, c.views[i].Name)
			}
			if tu.Passed {
				passed = append(passed, c.views[i].Name)
			}
		}
		if !slices.Equal(offers, c.offers) || !slices.Equal(passed, c.passed) {
			t.Errorf("%s: offers %v, passed %v; want %v, %v", c.name, offers, passed, c.offers, c.passed)
		}
	}
}

// testClock is a clock the test moves.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// relayNode is an exit of version with the relays named, each with its
// bundle, at 198.51.100.20 and on, its update files in a directory of the
// test's and a clock the test moves.
func relayNode(t *testing.T, version string, names ...string) (*Server, map[string]node.RelayBundle, func(time.Duration), func() time.Time) {
	t.Helper()
	srv, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "api", Name: "api"})); err != nil {
		t.Fatal(err)
	}
	bundles := map[string]node.RelayBundle{}
	for i, name := range names {
		addr := fmt.Sprintf("198.51.100.%d", 20+i)
		if _, err := c.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: name, Address: addr})); err != nil {
			t.Fatal(err)
		}
		enc, err := srv.issueRelayBundle(ctx, &nodev1.IssueRelayBundleRequest{Name: name, ExitAddress: "203.0.113.7", Admin: []string{"192.0.2.7"}})
		if err != nil {
			t.Fatal(err)
		}
		b, err := node.DecodeRelayBundle(enc.Bundle)
		if err != nil {
			t.Fatal(err)
		}
		bundles[name] = b
	}
	dir := t.TempDir()
	clock := &testClock{t: time.Date(2026, 11, 20, 3, 40, 0, 0, time.UTC)}
	srv.Version = version
	srv.NodeUpdate = &NodeUpdate{Request: filepath.Join(dir, "update-request"), Status: filepath.Join(dir, "status.json"),
		Policy: filepath.Join(dir, "policy.json"), Unit: filepath.Join(dir, "unit"), Now: clock.now}
	return srv, bundles, clock.advance, clock.now
}

// setRecord puts relay name's record in place, as a report would.
func setRecord(t *testing.T, srv *Server, name string, r relayRecord) {
	t.Helper()
	b, _ := json.Marshal(r)
	if err := srv.Store.SetSetting(context.Background(), relayUpdateKey+name, b); err != nil {
		t.Fatal(err)
	}
}

// A relay's turn begins when its feed has the offer as its turn: an offer
// to a relay past its turn (remote off, say) starts none, so that a root
// turning remote on later does not make it one that holds the others back.
// A feed that looked before a kick which found another offer for it is
// woken again.
func TestRelayTurnGiven(t *testing.T) {
	var ru relayUpdates
	now := time.Date(2026, 11, 20, 4, 0, 0, 0, time.UTC)
	o := &perimeterv1.RelayUpdateOffer{Id: "aa", Version: "v0.28.0", EndedAt: 1}
	if ru.sentOffer("r1", relayOffered{o, false}, 0, now) || ru.relays["r1"].offerID != "" {
		t.Fatal("an offer past the relay's turn began one")
	}
	if !ru.sentOffer("r1", relayOffered{o, true}, 0, now.Add(time.Minute)) || ru.relays["r1"].offerID != "aa" || !ru.relays["r1"].offeredAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("its turn: %+v", ru.relays["r1"])
	}
	if ru.sentOffer("r1", relayOffered{o, true}, 0, now.Add(2*time.Minute)) || !ru.relays["r1"].offeredAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("its turn again: %+v", ru.relays["r1"])
	}
	wake, kicks := ru.changes("r2", now)
	ru.relays["r2"].kicks++
	ru.relays["r2"].want = offerKey(o)
	ru.sentOffer("r2", relayOffered{}, kicks, now)
	select {
	case <-wake:
	default:
		t.Fatal("a feed that looked before the kick sleeps on")
	}
	wake, kicks = ru.changes("r2", now)
	ru.sentOffer("r2", relayOffered{o, true}, kicks, now)
	select {
	case <-wake:
		t.Fatal("a feed woken for nothing")
	default:
	}
}

// After a restart of the exit the queue is the records': a relay that
// reported its outcome passes at once, the next is offered.
func TestRelayQueueRestart(t *testing.T) {
	srv, _, advance, now := relayNode(t, "v0.28.0", "r1", "r2", "r3")
	ctx := context.Background()
	st := nodeupdate.Status{ID: "6f1c0e2a9b3d4c5e", State: nodeupdate.Done, From: "v0.27.0", To: "v0.28.0", Kind: nodeupdate.Remote, Ended: now()}
	if err := nodeupdate.WriteStatus(srv.NodeUpdate.Status, st); err != nil {
		t.Fatal(err)
	}
	setRecord(t, srv, "r1", relayRecord{Reported: nodeupdate.Done, UpdateID: st.ID, Version: "v0.28.0", Remote: true, ChangedAt: now().Unix()})
	setRecord(t, srv, "r2", relayRecord{Reported: nodeupdate.Running, UpdateID: st.ID, Version: "v0.27.0", Remote: true, ChangedAt: now().Unix(), Since: now().Unix()})
	setRecord(t, srv, "r3", relayRecord{Reported: nodeupdate.Idle, Version: "v0.27.0", Remote: true, ChangedAt: now().Unix()})
	offers := func() []string {
		t.Helper()
		m, err := srv.relayOffers(ctx, now())
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for name, of := range m {
			if of.o.Id != st.ID || of.o.Version != "v0.28.0" {
				t.Fatalf("offer %v", of.o)
			}
			names = append(names, name)
		}
		slices.Sort(names)
		return names
	}
	// r2 updates (its feed down while it restarts): r3 waits.
	if got := offers(); !slices.Equal(got, []string{"r1", "r2"}) {
		t.Fatalf("after the restart: %v", got)
	}
	// r3's feed was there before the restart and is not since: it waits for
	// r2's TurnTimeout, then for its own silence's.
	advance(TurnTimeout + time.Second)
	if got := offers(); !slices.Equal(got, []string{"r1", "r2", "r3"}) {
		t.Fatalf("after TurnTimeout: %v", got)
	}
	// A relay removed is no longer in the queue.
	setRecord(t, srv, "r2", relayRecord{Reported: nodeupdate.Running, UpdateID: st.ID, Version: "v0.27.0", Remote: true, ChangedAt: now().Unix(), Since: now().Unix()})
	if got := offers(); !slices.Equal(got, []string{"r1", "r2"}) {
		t.Fatalf("r2 at it again: %v", got)
	}
	if err := srv.Store.DeleteRelay(ctx, "r2"); err != nil {
		t.Fatal(err)
	}
	if got := offers(); !slices.Equal(got, []string{"r1", "r3"}) {
		t.Fatalf("r2 removed: %v", got)
	}
}
