package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protowire"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1/perimeterv1connect"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/store"
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
// feed, silent for TurnTimeout, or TurnTimeout after the exit gave it its
// turn; one given its turn keeps it, and nobody else updates meanwhile.
// The exit gives a turn to the relay whose turn came, with a feed; a relay
// past its turn has the offer once the queue is through, and a later turn
// if it takes it then. A relay counts as updating only in a turn the exit
// gave it.
func TestRelayQueue(t *testing.T) {
	now := time.Date(2026, 11, 20, 4, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	o := &perimeterv1.RelayUpdateOffer{Id: "aa", Version: "v0.28.0"}
	newer := &perimeterv1.RelayUpdateOffer{Id: "bb", Version: "v0.28.1"}
	idle := relayRecord{Reported: nodeupdate.Idle, Version: "v0.27.0", Remote: true, ChangedAt: ago(time.Hour).Unix()}
	rec := func(state, id, version string, remote bool, changed time.Duration) relayRecord {
		return relayRecord{Reported: state, UpdateID: id, Version: version, Remote: remote, ChangedAt: ago(changed).Unix()}
	}
	view := func(name string, r relayRecord, feeds int) relayView {
		return relayView{Name: name, Rec: r, Feeds: feeds, ClosedAt: ago(2 * time.Hour)}
	}
	// given is v given its turn for update id at ago.
	given := func(v relayView, id string, at time.Duration) relayView {
		v.Rec.TurnID, v.Rec.TurnAt = id, ago(at).Unix()
		return v
	}
	closed := func(v relayView, at time.Duration) relayView {
		v.ClosedAt = ago(at)
		return v
	}
	// over is v with its outcome on its turn in, its turn over.
	over := func(v relayView) relayView {
		v.Rec.TurnOver = true
		return v
	}
	for _, c := range []struct {
		name   string
		o      *perimeterv1.RelayUpdateOffer
		views  []relayView
		offers []string
		passed []string
		give   []string
	}{
		{"nothing heard, no feeds: no one to wait for", o,
			[]relayView{view("r1", relayRecord{}, 0), view("r2", relayRecord{}, 0)}, []string{"r1", "r2"}, []string{"r1", "r2"}, nil},
		{"the first by name, given its turn", o,
			[]relayView{view("r1", relayRecord{}, 1), view("r2", idle, 1), view("r3", idle, 1)}, []string{"r1"}, nil, []string{"r1"}},
		// Given the offer and gone without a word: it may be updating.
		{"never reported, given its turn, no feed", o,
			[]relayView{given(view("r1", relayRecord{}, 0), "aa", time.Minute), view("r2", idle, 1)}, []string{"r1"}, nil, nil},
		{"never reported, given its turn TurnTimeout ago", o,
			[]relayView{given(view("r1", relayRecord{}, 0), "aa", TurnTimeout+time.Second), view("r2", idle, 1)}, []string{"r2"}, []string{"r1"},
			[]string{"r2"}},
		{"after an outcome, the next; the first keeps it, on the release", o,
			[]relayView{view("r1", rec(nodeupdate.Done, "aa", "v0.28.0", true, time.Minute), 1), view("r2", idle, 1), view("r3", idle, 1)},
			[]string{"r1", "r2"}, []string{"r1"}, []string{"r2"}},
		{"failed or rolled back: passed, and no offer while another updates", o,
			[]relayView{view("r1", rec(nodeupdate.Failed, "aa", "v0.27.0", true, time.Minute), 1), view("r2", rec(nodeupdate.RolledBack, "aa", "v0.27.0", true, time.Minute), 1),
				given(view("r3", rec(nodeupdate.Running, "aa", "v0.27.0", true, time.Minute), 1), "aa", 2*time.Minute)},
			[]string{"r3"}, []string{"r1", "r2"}, nil},
		// rayd relay refuses an offer it will not take as an outcome on it.
		{"given its turn, refused it", o,
			[]relayView{given(view("r1", rec(nodeupdate.Failed, "aa", "v0.27.0", true, time.Minute), 1), "aa", 2*time.Minute), view("r2", idle, 1)},
			[]string{"r2"}, []string{"r1"}, []string{"r2"}},
		{"on the release or newer, without an update", o,
			[]relayView{view("r1", rec(nodeupdate.Idle, "", "v0.29.0", true, time.Hour), 1), view("r2", idle, 1)}, []string{"r1", "r2"}, []string{"r1"},
			[]string{"r2"}},
		// Its new rayd relay says so as soon as the install restarts it,
		// before root's check: still updating.
		{"updating, on the release already", o,
			[]relayView{given(view("r1", rec(nodeupdate.Running, "aa", "v0.28.0", true, time.Minute), 1), "aa", 5*time.Minute), view("r2", idle, 1)},
			[]string{"r1"}, nil, nil},
		{"remote off", o,
			[]relayView{view("r1", rec(nodeupdate.Idle, "", "v0.27.0", false, time.Hour), 1), view("r2", idle, 1)}, []string{"r2"}, []string{"r1"},
			[]string{"r2"}},
		{"remote off with an update under way in its turn: it goes on, the others wait", o,
			[]relayView{given(view("r1", rec(nodeupdate.Running, "aa", "v0.27.0", false, 2*time.Minute), 0), "aa", 3*time.Minute), view("r2", idle, 1)},
			[]string{"r1"}, nil, nil},
		{"updating, its feed down while rayd relay restarts", o,
			[]relayView{given(closed(view("r1", rec(nodeupdate.Running, "aa", "v0.27.0", true, 5*time.Minute), 0), time.Minute), "aa", 6*time.Minute),
				view("r2", idle, 1)},
			[]string{"r1"}, nil, nil},
		{"given its turn, no word for TurnTimeout", o,
			[]relayView{given(view("r1", idle, 1), "aa", TurnTimeout+time.Second), view("r2", idle, 1)}, []string{"r2"}, []string{"r1"}, []string{"r2"}},
		{"given its turn, not yet TurnTimeout", o,
			[]relayView{given(view("r1", idle, 1), "aa", TurnTimeout-time.Second), view("r2", idle, 1)}, []string{"r1"}, nil, nil},
		// Its turn came, and it has no feed to take it: the queue waits.
		{"silent, its feed gone a while", o,
			[]relayView{closed(view("r1", idle, 0), 10*time.Minute), view("r2", idle, 1)}, nil, nil, nil},
		{"silent, its feed gone TurnTimeout", o,
			[]relayView{closed(view("r1", idle, 0), TurnTimeout+time.Second), view("r2", idle, 1)}, []string{"r2"}, []string{"r1"}, []string{"r2"}},
		{"silent after it took the offer, its turn TurnTimeout ago", o,
			[]relayView{given(closed(view("r1", rec(nodeupdate.Requested, "aa", "v0.27.0", true, 5*time.Minute), 0), TurnTimeout), "aa",
				TurnTimeout+time.Second), view("r2", idle, 1)},
			[]string{"r2"}, []string{"r1"}, []string{"r2"}},
		// The exit restarted: the turns are in the records.
		{"after a restart: running in its turn", o,
			[]relayView{given(view("r1", rec(nodeupdate.Running, "aa", "v0.27.0", true, 5*time.Minute), 0), "aa", 6*time.Minute), view("r2", idle, 1)},
			[]string{"r1"}, nil, nil},
		{"after a restart: its turn TurnTimeout ago", o,
			[]relayView{given(view("r1", rec(nodeupdate.Running, "aa", "v0.27.0", true, 5*time.Minute), 0), "aa", TurnTimeout+time.Second),
				view("r2", idle, 1)},
			[]string{"r2"}, []string{"r1"}, []string{"r2"}},
		{"after a restart: done, and the next", o,
			[]relayView{view("r1", rec(nodeupdate.Done, "aa", "v0.28.0", true, time.Hour), 1), view("r2", rec(nodeupdate.Done, "aa", "v0.28.0", true, time.Hour), 0),
				view("r3", idle, 1)}, []string{"r1", "r2", "r3"}, []string{"r1", "r2"}, []string{"r3"}},
		// A relay before the one updating that wants its turn now.
		{"back, while another holds its turn", o,
			[]relayView{view("r1", idle, 1), given(view("r2", rec(nodeupdate.Requested, "aa", "v0.27.0", true, time.Minute), 1), "aa", 2*time.Minute)},
			[]string{"r2"}, nil, nil},
		// The node updated again while a relay still updates to the
		// previous: the new offer after it, to it too.
		{"a newer offer while a relay updates in its turn for the last", newer,
			[]relayView{view("r1", rec(nodeupdate.Done, "aa", "v0.28.0", true, 10*time.Minute), 1),
				given(view("r2", rec(nodeupdate.Running, "aa", "v0.27.0", true, 3*time.Minute), 1), "aa", 4*time.Minute)},
			nil, nil, nil},
		{"after a restart: a newer offer while a relay updates in its turn for the last, no feed", newer,
			[]relayView{view("r1", rec(nodeupdate.Done, "aa", "v0.28.0", true, 10*time.Minute), 1),
				given(view("r2", rec(nodeupdate.Running, "aa", "v0.27.0", true, 3*time.Minute), 0), "aa", 4*time.Minute)},
			nil, nil, nil},
		{"a newer offer, the last turn TurnTimeout ago", newer,
			[]relayView{view("r1", rec(nodeupdate.Done, "aa", "v0.28.0", true, 10*time.Minute), 1),
				given(view("r2", rec(nodeupdate.Running, "aa", "v0.27.0", true, 3*time.Minute), 1), "aa", TurnTimeout+time.Second)},
			[]string{"r1"}, nil, []string{"r1"}},
		{"a newer offer once it ended", newer,
			[]relayView{view("r1", rec(nodeupdate.Done, "aa", "v0.28.0", true, 10*time.Minute), 1),
				given(view("r2", rec(nodeupdate.Done, "aa", "v0.28.0", true, time.Minute), 1), "aa", 4*time.Minute)},
			[]string{"r1"}, nil, []string{"r1"}},
		// A relay holds the others back in its turn only, whatever it says.
		{"updating for the offer, never given it", o,
			[]relayView{view("r1", idle, 1), view("r2", rec(nodeupdate.Running, "aa", "v0.27.0", true, time.Minute), 1)}, []string{"r1"}, nil,
			[]string{"r1"}},
		{"updating for the offer, never given it, no feed", o,
			[]relayView{view("r1", idle, 1), closed(view("r2", rec(nodeupdate.Running, "aa", "v0.27.0", true, time.Minute), 0), time.Minute)},
			[]string{"r1"}, nil, []string{"r1"}},
		{"updating for an id never given to it", o,
			[]relayView{view("r1", idle, 1), view("r2", rec(nodeupdate.Running, "ff", "v0.27.0", true, time.Minute), 1)}, []string{"r1"}, nil,
			[]string{"r1"}},
		{"updating for an id never given to it, no feed for TurnTimeout", o,
			[]relayView{closed(view("r1", rec(nodeupdate.Running, "ff", "v0.27.0", true, time.Minute), 0), TurnTimeout+time.Second), view("r2", idle, 1)},
			[]string{"r2"}, []string{"r1"}, []string{"r2"}},
		{"updating for an id never given to it, remote off", o,
			[]relayView{view("r1", rec(nodeupdate.Running, "ff", "v0.27.0", false, time.Minute), 1), view("r2", idle, 1)}, []string{"r2"}, []string{"r1"},
			[]string{"r2"}},
		{"running for an earlier offer never given to it", newer,
			[]relayView{view("r1", rec(nodeupdate.Done, "aa", "v0.28.0", true, 10*time.Minute), 1), view("r2", rec(nodeupdate.Running, "aa", "v0.27.0", true, time.Minute), 1)},
			[]string{"r1"}, nil, []string{"r1"}},
		// A relay whose update never ended (its rollback failed: no rayspa,
		// no rayd relay), and the node updated again.
		{"stuck since an earlier offer, no feed for TurnTimeout", newer,
			[]relayView{closed(given(view("r1", rec(nodeupdate.Running, "aa", "v0.27.0", true, 2*time.Hour), 0), "aa", 2*time.Hour), TurnTimeout+time.Second),
				view("r2", idle, 1)},
			[]string{"r2"}, []string{"r1"}, []string{"r2"}},
		// Through: every relay passed. One that failed before any change
		// has the offer while nobody updates, and its retry is a turn.
		{"through: the offer to one that failed, no turn", o,
			[]relayView{given(view("r1", rec(nodeupdate.Failed, "aa", "v0.27.0", true, 6*time.Hour), 1), "aa", 7*time.Hour),
				view("r2", rec(nodeupdate.Done, "aa", "v0.28.0", true, 5*time.Hour), 1)},
			[]string{"r1", "r2"}, []string{"r1", "r2"}, nil},
		{"through: it asks again, a later turn", o,
			[]relayView{given(view("r1", rec(nodeupdate.Requested, "aa", "v0.27.0", true, time.Minute), 1), "aa", 7*time.Hour),
				view("r2", rec(nodeupdate.Done, "aa", "v0.28.0", true, 5*time.Hour), 1)},
			[]string{"r1", "r2"}, []string{"r1", "r2"}, []string{"r1"}},
		{"through: back after its turn ran out, it takes it, a later turn", o,
			[]relayView{given(view("r1", rec(nodeupdate.Requested, "aa", "v0.27.0", true, time.Minute), 1), "aa", TurnTimeout+10*time.Minute),
				view("r2", rec(nodeupdate.Done, "aa", "v0.28.0", true, 5*time.Minute), 1)},
			[]string{"r1", "r2"}, []string{"r1", "r2"}, []string{"r1"}},
		{"through: under way, never given it, a turn", o,
			[]relayView{view("r1", rec(nodeupdate.Running, "aa", "v0.27.0", false, time.Minute), 1), view("r2", rec(nodeupdate.Done, "aa", "v0.28.0", true, 5*time.Minute), 1)},
			[]string{"r1", "r2"}, []string{"r1", "r2"}, []string{"r1"}},
		{"through: its word from its turn, no later one", o,
			[]relayView{given(view("r1", rec(nodeupdate.Running, "aa", "v0.27.0", true, TurnTimeout), 1), "aa", TurnTimeout+time.Minute),
				view("r2", rec(nodeupdate.Done, "aa", "v0.28.0", true, 5*time.Minute), 1)},
			[]string{"r1", "r2"}, []string{"r1", "r2"}, nil},
		{"through: it asks again with no feed", o,
			[]relayView{given(closed(view("r1", rec(nodeupdate.Requested, "aa", "v0.27.0", true, time.Minute), 0), TurnTimeout+time.Second), "aa", 7*time.Hour),
				view("r2", rec(nodeupdate.Done, "aa", "v0.28.0", true, 5*time.Hour), 1)},
			[]string{"r1", "r2"}, []string{"r1", "r2"}, nil},
		{"not through: one that failed waits for the others", o,
			[]relayView{given(view("r1", rec(nodeupdate.Requested, "aa", "v0.27.0", true, time.Minute), 1), "aa", 7*time.Hour), view("r2", idle, 1)},
			[]string{"r2"}, []string{"r1"}, []string{"r2"}},
		// Its outcome ended its turn: taken again within the time the turn
		// had, it is a later turn all the same.
		{"through: it declined in its turn, takes it within the time", o,
			[]relayView{over(given(view("r1", rec(nodeupdate.Requested, "aa", "v0.27.0", true, time.Minute), 1), "aa", 12*time.Minute)),
				view("r2", rec(nodeupdate.Done, "aa", "v0.28.0", true, 5*time.Minute), 1)},
			[]string{"r1", "r2"}, []string{"r1", "r2"}, []string{"r1"}},
		{"not through: it declined in its turn and takes it, the others first", o,
			[]relayView{over(given(view("r1", rec(nodeupdate.Requested, "aa", "v0.27.0", true, time.Minute), 1), "aa", 12*time.Minute)),
				view("r2", idle, 1)},
			[]string{"r2"}, []string{"r1"}, []string{"r2"}},
		{"its outcome in, idle since", o,
			[]relayView{over(given(view("r1", idle, 1), "aa", 5*time.Minute)), view("r2", idle, 1)}, []string{"r2"}, []string{"r1"}, []string{"r2"}},
		// Given its turn for the last offer, its word on it lost.
		{"a newer offer while a relay holds its turn for the last, silent", newer,
			[]relayView{view("r1", rec(nodeupdate.Done, "aa", "v0.28.0", true, 10*time.Minute), 1), given(view("r2", idle, 1), "aa", 4*time.Minute)},
			nil, nil, nil},
		{"a newer offer, the last turn held with no feed, never a word", newer,
			[]relayView{view("r1", rec(nodeupdate.Done, "aa", "v0.28.0", true, 10*time.Minute), 1), given(view("r2", relayRecord{}, 0), "aa", 4*time.Minute)},
			nil, nil, nil},
		{"a newer offer, the last turn TurnTimeout ago, silent", newer,
			[]relayView{view("r1", rec(nodeupdate.Done, "aa", "v0.28.0", true, 10*time.Minute), 1), given(view("r2", idle, 1), "aa", TurnTimeout)},
			[]string{"r1"}, nil, []string{"r1"}},
		{"a newer offer, the last turn ended by its outcome", newer,
			[]relayView{view("r1", rec(nodeupdate.Done, "aa", "v0.28.0", true, 10*time.Minute), 1),
				given(view("r2", rec(nodeupdate.Failed, "aa", "v0.27.0", true, time.Minute), 1), "aa", 4*time.Minute)},
			[]string{"r1"}, nil, []string{"r1"}},
		{"through: another one asks again while it updates", o,
			[]relayView{given(view("r1", rec(nodeupdate.Requested, "aa", "v0.27.0", true, time.Minute), 1), "aa", 7*time.Hour),
				given(view("r2", rec(nodeupdate.Running, "aa", "v0.27.0", true, time.Minute), 1), "aa", 2*time.Minute)},
			[]string{"r2"}, []string{"r1"}, nil},
	} {
		turns := relayQueue(c.o, c.views, now)
		var offers, passed, give []string
		for i, tu := range turns {
			if tu.Offer {
				offers = append(offers, c.views[i].Name)
			}
			if tu.Passed {
				passed = append(passed, c.views[i].Name)
			}
			if tu.Give {
				give = append(give, c.views[i].Name)
			}
		}
		if !slices.Equal(offers, c.offers) || !slices.Equal(passed, c.passed) || !slices.Equal(give, c.give) {
			t.Errorf("%s: offers %v, passed %v, given %v; want %v, %v, %v", c.name, offers, passed, give, c.offers, c.passed, c.give)
		}
	}
}

// A time of the queue's is held on the monotonic clock from when it is
// first seen: the clock's steps after move it with the clock, so that it
// stays as long ago as it was; one ahead of the clock is taken as then.
func TestSteady(t *testing.T) {
	c := newTestClock()
	var s steady
	at := c.now().Add(-5 * time.Minute).Unix()
	if got := s.of(at, c.now(), c.mono()); got != at {
		t.Fatalf("first seen: %d, kept %d", got, at)
	}
	c.advance(time.Minute)
	c.step(-2 * time.Hour)
	if got := s.of(at, c.now(), c.mono()); got != c.now().Add(-6*time.Minute).Unix() {
		t.Fatalf("set back: %v ago", c.now().Sub(time.Unix(got, 0)))
	}
	c.step(5 * time.Hour)
	if got := s.of(at, c.now(), c.mono()); got != c.now().Add(-6*time.Minute).Unix() {
		t.Fatalf("set on: %v ago", c.now().Sub(time.Unix(got, 0)))
	}
	ahead := c.now().Add(3 * time.Hour).Unix()
	if got := s.of(ahead, c.now(), c.mono()); got != c.now().Unix() {
		t.Fatalf("ahead: %v ago", c.now().Sub(time.Unix(got, 0)))
	}
	c.advance(time.Minute)
	if got := s.of(ahead, c.now(), c.mono()); got != c.now().Add(-time.Minute).Unix() {
		t.Fatalf("ahead, a minute on: %v ago", c.now().Sub(time.Unix(got, 0)))
	}
	if got := s.of(0, c.now(), c.mono()); got != 0 {
		t.Fatalf("none: %d", got)
	}
}

// testClock is a clock the test moves, with a monotonic one beside it: a
// step moves the clock alone, as one set back or on does.
type testClock struct {
	mu      sync.Mutex
	t       time.Time
	start   time.Time
	stepped time.Duration
}

func newTestClock() *testClock {
	t := time.Date(2026, 11, 20, 3, 40, 0, 0, time.UTC)
	return &testClock{t: t, start: t}
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) mono() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t.Sub(c.start) - c.stepped
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (c *testClock) step(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t, c.stepped = c.t.Add(d), c.stepped+d
}

// relayNode is an exit of version with the relays named, each with its
// bundle, at 198.51.100.20 and on, its update files in a directory of the
// test's and a clock the test moves; sock is its API's socket.
func relayNode(t *testing.T, version string, names ...string) (srv *Server, bundles map[string]node.RelayBundle, advance func(time.Duration),
	now func() time.Time, sock string) {
	t.Helper()
	srv, bundles, clock, sock := relayNodeClock(t, version, names...)
	return srv, bundles, clock.advance, clock.now, sock
}

// relayNodeClock is relayNode with its clock.
func relayNodeClock(t *testing.T, version string, names ...string) (srv *Server, bundles map[string]node.RelayBundle, clock *testClock, sock string) {
	t.Helper()
	srv, sock, _ = startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "api", Name: "api"})); err != nil {
		t.Fatal(err)
	}
	bundles = map[string]node.RelayBundle{}
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
	clock = newTestClock()
	srv.Version = version
	srv.NodeUpdate = &NodeUpdate{Request: filepath.Join(dir, "update-request"), Status: filepath.Join(dir, "status.json"),
		Policy: filepath.Join(dir, "policy.json"), Unit: filepath.Join(dir, "unit"), Now: clock.now, Mono: clock.mono}
	return srv, bundles, clock, sock
}

// setRecord puts relay name's record in place, as a report would.
func setRecord(t *testing.T, srv *Server, name string, r relayRecord) {
	t.Helper()
	b, _ := json.Marshal(r)
	if err := srv.Store.SetSetting(context.Background(), relayUpdateKey+name, b); err != nil {
		t.Fatal(err)
	}
}

// The exit gives a relay its turn as the queue reaches it and writes it in
// the relay's record before any feed sends the offer: once, whatever the
// looks after; an offer to a relay past its turn (remote off, say) gives
// none, so that a root turning remote on later does not make it one that
// holds the others back. A feed that looked before a kick which found
// another offer for it is woken again.
func TestRelayTurnGiven(t *testing.T) {
	srv, _, advance, now, _ := relayNode(t, "v0.28.0", "r1", "r2")
	ctx := context.Background()
	st := nodeupdate.Status{ID: "6f1c0e2a9b3d4c5e", State: nodeupdate.Done, From: "v0.27.0", To: "v0.28.0", Kind: nodeupdate.Remote, Ended: now()}
	if err := nodeupdate.WriteStatus(srv.NodeUpdate.Status, st); err != nil {
		t.Fatal(err)
	}
	setRecord(t, srv, "r1", relayRecord{Reported: nodeupdate.Idle, Version: "v0.27.0", ChangedAt: now().Unix()})
	setRecord(t, srv, "r2", relayRecord{Reported: nodeupdate.Idle, Version: "v0.27.0", Remote: true, ChangedAt: now().Unix()})
	srv.relayUpd.opened("r1", now())
	srv.relayUpd.opened("r2", now())
	record := func(name string) relayRecord {
		t.Helper()
		r, err := readRelayRecord(ctx, srv.Store, name)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	offers, gave, err := srv.relayOffers(ctx, now())
	if err != nil || !gave || offers["r1"] != nil || offers["r2"] == nil {
		t.Fatalf("r1 remote off, r2's turn: %v %v %v", offers, gave, err)
	}
	if r := record("r1"); r.TurnID != "" {
		t.Fatalf("an offer past the relay's turn gave one: %+v", r)
	}
	given := record("r2")
	if given.TurnID != st.ID || given.TurnAt != now().Unix() {
		t.Fatalf("r2's turn: %+v", given)
	}
	advance(time.Minute)
	if _, gave, err := srv.relayOffers(ctx, now()); err != nil || gave || record("r2") != given {
		t.Fatalf("its turn again: %v %v %+v", gave, err, record("r2"))
	}
	// Root on r1 turns remote on: r1 is before r2, which holds its turn.
	setRecord(t, srv, "r1", relayRecord{Reported: nodeupdate.Idle, Version: "v0.27.0", Remote: true, ChangedAt: now().Unix()})
	if offers, gave, _ := srv.relayOffers(ctx, now()); gave || offers["r1"] != nil || offers["r2"] == nil {
		t.Fatalf("r1 while r2 holds its turn: %v %v", offers, gave)
	}

	var ru relayUpdates
	o := &perimeterv1.RelayUpdateOffer{Id: "aa", Version: "v0.28.0", EndedAt: 1}
	wake, kicks := ru.changes("r2", now())
	ru.relays["r2"].kicks++
	ru.relays["r2"].want = offerKey(o)
	ru.sentOffer("r2", nil, kicks, now())
	select {
	case <-wake:
	default:
		t.Fatal("a feed that looked before the kick sleeps on")
	}
	wake, kicks = ru.changes("r2", now())
	ru.sentOffer("r2", o, kicks, now())
	select {
	case <-wake:
		t.Fatal("a feed woken for nothing")
	default:
	}
}

// After a restart of the exit the queue is the records': a relay that
// reported its outcome passes at once, the next is offered.
func TestRelayQueueRestart(t *testing.T) {
	srv, _, advance, now, _ := relayNode(t, "v0.28.0", "r1", "r2", "r3")
	ctx := context.Background()
	st := nodeupdate.Status{ID: "6f1c0e2a9b3d4c5e", State: nodeupdate.Done, From: "v0.27.0", To: "v0.28.0", Kind: nodeupdate.Remote, Ended: now()}
	if err := nodeupdate.WriteStatus(srv.NodeUpdate.Status, st); err != nil {
		t.Fatal(err)
	}
	setRecord(t, srv, "r1", relayRecord{Reported: nodeupdate.Done, UpdateID: st.ID, Version: "v0.28.0", Remote: true, ChangedAt: now().Unix()})
	setRecord(t, srv, "r2", relayRecord{Reported: nodeupdate.Running, UpdateID: st.ID, Version: "v0.27.0", Remote: true, ChangedAt: now().Unix(), TurnID: st.ID,
		TurnAt: now().Unix()})
	setRecord(t, srv, "r3", relayRecord{Reported: nodeupdate.Idle, Version: "v0.27.0", Remote: true, ChangedAt: now().Unix()})
	offers := func() []string {
		t.Helper()
		m, _, err := srv.relayOffers(ctx, now())
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for name, o := range m {
			if o.Id != st.ID || o.Version != "v0.28.0" {
				t.Fatalf("offer %v", o)
			}
			names = append(names, name)
		}
		slices.Sort(names)
		return names
	}
	// r2 updates in its turn (its feed down while it restarts): r3 waits.
	if got := offers(); !slices.Equal(got, []string{"r1", "r2"}) {
		t.Fatalf("after the restart: %v", got)
	}
	// r3's feed was there before the restart and is not since: it waits for
	// r2's TurnTimeout, then for its own silence's.
	advance(TurnTimeout + time.Second)
	if got := offers(); !slices.Equal(got, []string{"r1", "r2", "r3"}) {
		t.Fatalf("after TurnTimeout: %v", got)
	}
	// A relay removed mid-update is no longer in the queue: r2 updating,
	// as its record says, in a turn given a moment ago.
	setRecord(t, srv, "r2", relayRecord{Reported: nodeupdate.Running, UpdateID: st.ID, Version: "v0.27.0", Remote: true, ChangedAt: now().Unix(), TurnID: st.ID,
		TurnAt: now().Unix()})
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

// updateClient is relay b's RelayService at the exit's addr.
func updateClient(t *testing.T, b node.RelayBundle, addr string) perimeterv1connect.RelayServiceClient {
	t.Helper()
	cert, err := DecodeClientCertificate([]byte(b.Cert))
	if err != nil {
		t.Fatal(err)
	}
	return perimeterv1connect.NewRelayServiceClient(remoteHTTP(b.API.Pin, cert), "https://"+addr)
}

// relayAudit are the audit lines of relay updates, oldest first.
func relayAudit(t *testing.T, srv *Server) []string {
	t.Helper()
	entries, err := srv.Store.ListAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range slices.Backward(entries) {
		if strings.HasPrefix(e.Action, "relay.update ") {
			out = append(out, e.Actor+": "+e.Action+" "+e.Target)
		}
	}
	return out
}

// A relay's word on its updates (spec/relay-update-remote-v1.md §3.2,
// §3.6, §8.3): from the relay only, within its bounds, its error cleaned
// again; kept only when it says something new, audited then with codes and
// versions alone; and the next relay's turn comes with it.
func TestReportUpdate(t *testing.T) {
	srv, bundles, advance, now, _ := relayNode(t, "v0.28.0", "r1", "r2")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	at1, _ := serveRemoteFrom(t, srv, "198.51.100.20:40000")
	at2, _ := serveRemoteFrom(t, srv, "198.51.100.21:40000")
	elsewhere, _ := serveRemoteFrom(t, srv, "198.51.100.99:40000")
	r1 := updateClient(t, bundles["r1"], at1)
	st := nodeupdate.Status{ID: "6f1c0e2a9b3d4c5e", State: nodeupdate.Done, From: "v0.27.0", To: "v0.28.0", Kind: nodeupdate.Auto, Ended: now()}
	nodeupdate.WriteStatus(srv.NodeUpdate.Status, st)
	report := func(c perimeterv1connect.RelayServiceClient, u *perimeterv1.RelayUpdate) error {
		_, err := c.ReportUpdate(ctx, connect.NewRequest(&perimeterv1.ReportUpdateRequest{Update: u}))
		return err
	}
	record := func(name string) relayRecord {
		t.Helper()
		r, err := readRelayRecord(ctx, srv.Store, name)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	// Nobody but the relay: its certificate from elsewhere, another
	// relay's from its address.
	idle := &perimeterv1.RelayUpdate{Version: "v0.27.0", Remote: true, State: nodeupdate.Idle}
	for name, c := range map[string]perimeterv1connect.RelayServiceClient{
		"from another address":       updateClient(t, bundles["r1"], elsewhere),
		"r2's certificate from r1's": updateClient(t, bundles["r2"], at1),
		"r1's certificate from r2's": updateClient(t, bundles["r1"], at2),
	} {
		if err := report(c, idle); connect.CodeOf(err) != connect.CodeNotFound {
			t.Errorf("%s: %v", name, err)
		}
	}
	if r := record("r1"); r != (relayRecord{}) {
		t.Fatalf("a stranger's report kept: %+v", r)
	}

	// Out of bounds.
	long := strings.Repeat("9", 40)
	for name, u := range map[string]*perimeterv1.RelayUpdate{
		"no update":            nil,
		"a version not one":    {Version: "v0.28", State: nodeupdate.Idle},
		"a dev build's commit": {Version: "1a2b3c4", State: nodeupdate.Idle},
		"a version too long":   {Version: "v0.28." + long, State: nodeupdate.Idle},
		"a target not one":     {Version: "v0.27.0", Target: "latest", State: nodeupdate.Requested, Id: "aa"},
		"a state unknown":      {Version: "v0.27.0", State: "paused"},
		"no state":             {Version: "v0.27.0"},
		"an id not hex":        {Version: "v0.27.0", State: nodeupdate.Failed, Id: "../x"},
		"an id too long":       {Version: "v0.27.0", State: nodeupdate.Failed, Id: strings.Repeat("a", 33)},
		"an id in capitals":    {Version: "v0.27.0", State: nodeupdate.Failed, Id: "AA"},
		"a reason not a code":  {Version: "v0.27.0", State: nodeupdate.Failed, Id: "aa", Reason: "Download"},
		"a reason too long":    {Version: "v0.27.0", State: nodeupdate.Failed, Id: "aa", Reason: strings.Repeat("a", 33)},
		"an error too long":    {Version: "v0.27.0", State: nodeupdate.Failed, Id: "aa", Error: strings.Repeat("x", maxUpdateError+1)},
	} {
		advance(5 * time.Second) // within the minute's 12
		if err := report(r1, u); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	advance(5 * time.Second)
	big := &perimeterv1.ReportUpdateRequest{Update: idle}
	big.ProtoReflect().SetUnknown(protowire.AppendBytes(protowire.AppendTag(nil, 99, protowire.BytesType), make([]byte, maxUpdateReport)))
	if _, err := r1.ReportUpdate(ctx, connect.NewRequest(big)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("over 1 KiB: %v", err)
	}
	if r := record("r1"); r != (relayRecord{}) {
		t.Fatalf("a refused report kept: %+v", r)
	}
	advance(time.Minute) // the refused ones counted against the minute's

	// What rayd relay sends (step 7): an idle relay of a dev build, at 0,
	// remote off.
	if err := report(r1, &perimeterv1.RelayUpdate{State: nodeupdate.Idle}); err != nil {
		t.Fatal(err)
	}
	if r := record("r1"); r.Reported != nodeupdate.Idle || r.Version != "" || r.Remote || r.ChangedAt != now().Unix() || r.SeenAt != now().Unix() {
		t.Fatalf("idle: %+v", r)
	}
	// Remote on, its version: a change, audited.
	advance(time.Minute)
	if err := report(r1, idle); err != nil {
		t.Fatal(err)
	}
	first := record("r1")
	if first.Reported != nodeupdate.Idle || first.Version != "v0.27.0" || !first.Remote || first.ChangedAt != now().Unix() {
		t.Fatalf("idle, remote on: %+v", first)
	}
	// The same again: nothing written, nothing audited.
	advance(time.Minute)
	if err := report(r1, idle); err != nil {
		t.Fatal(err)
	}
	if r := record("r1"); r != first {
		t.Fatalf("the same report written again: %+v, was %+v", r, first)
	}
	// The same after relaySeenEvery: only when it was heard of.
	advance(relaySeenEvery)
	if err := report(r1, idle); err != nil {
		t.Fatal(err)
	}
	if r := record("r1"); r.SeenAt != now().Unix() || r.ChangedAt != first.ChangedAt {
		t.Fatalf("heard of: %+v, was %+v", r, first)
	}

	// The exit gives it its turn (relayOffers, as its feed with updates
	// looks), and nothing it says after moves it.
	if _, _, err := srv.updateRelayRecord(ctx, "r1", func(r *relayRecord) { r.TurnID, r.TurnAt = st.ID, now().Unix() }); err != nil {
		t.Fatal(err)
	}
	turn := record("r1")
	sameTurn := func(r relayRecord) bool { return r.TurnID == turn.TurnID && r.TurnAt == turn.TurnAt }
	// It takes the offer, runs it, fails with a text the exit cleans
	// again: an address, a key, what a terminal acts on, cut to 200 bytes;
	// a reason this exit does not know is taken by its form.
	advance(time.Minute)
	if err := report(r1, &perimeterv1.RelayUpdate{Version: "v0.27.0", Remote: true, State: nodeupdate.Requested, Id: st.ID, Target: "v0.28.0"}); err != nil {
		t.Fatal(err)
	}
	asked := record("r1")
	if !sameTurn(asked) || asked.TurnOver || asked.UpdateID != st.ID || asked.ChangedAt != now().Unix() {
		t.Fatalf("requested: %+v", asked)
	}
	// Not a word of no update in between, nor of another.
	advance(time.Minute)
	if err := report(r1, idle); err != nil {
		t.Fatal(err)
	}
	advance(time.Minute)
	if err := report(r1, &perimeterv1.RelayUpdate{Version: "v0.27.0", Remote: true, State: nodeupdate.Running, Id: "0123456789abcdef", Target: "v0.28.0"}); err != nil {
		t.Fatal(err)
	}
	advance(time.Minute)
	if err := report(r1, &perimeterv1.RelayUpdate{Version: "v0.27.0", Remote: true, State: nodeupdate.Requested, Id: st.ID, Target: "v0.28.0"}); err != nil {
		t.Fatal(err)
	}
	if r := record("r1"); !sameTurn(r) {
		t.Fatalf("requested again: %+v, its turn %+v", r, turn)
	}
	advance(time.Minute)
	if err := report(r1, &perimeterv1.RelayUpdate{Version: "v0.27.0", Remote: true, State: nodeupdate.Running, Id: st.ID, Target: "v0.28.0"}); err != nil {
		t.Fatal(err)
	}
	if r := record("r1"); !sameTurn(r) || r.ChangedAt != now().Unix() || r.UnderwayAt != now().Add(-time.Minute).Unix() {
		t.Fatalf("running: %+v, its turn %+v", r, turn)
	}
	advance(time.Minute)
	text := "install: no first snapshot from 203.0.113.7 \x1b[31mwith key " + strings.Repeat("Ab", 20) + " é" + strings.Repeat("x", 150)
	if err := report(r1, &perimeterv1.RelayUpdate{Version: "v0.27.0", Remote: true, State: nodeupdate.RolledBack, Id: st.ID, Target: "v0.28.0",
		Reason: "quota", Error: text[:maxUpdateError-1]}); err != nil {
		t.Fatal(err)
	}
	back := record("r1")
	if back.Reported != nodeupdate.RolledBack || back.Reason != "quota" || strings.Contains(back.Error, "203.0.113.7") ||
		strings.Contains(back.Error, "AbAb") || strings.ContainsRune(back.Error, 0x1b) || !strings.HasPrefix(back.Error, "install: no first snapshot from <ip4:") ||
		len(back.Error) > maxUpdateError || !utf8.ValidString(back.Error) || !sameTurn(back) || !back.TurnOver {
		t.Fatalf("rolled back: %+v", back)
	}
	// The same text again stays the same: nothing new.
	if err := report(r1, &perimeterv1.RelayUpdate{Version: "v0.27.0", Remote: true, State: nodeupdate.RolledBack, Id: st.ID, Target: "v0.28.0",
		Reason: "quota", Error: text[:maxUpdateError-1]}); err != nil {
		t.Fatal(err)
	}
	if r := record("r1"); r != back {
		t.Fatalf("the same text again: %+v, was %+v", r, back)
	}
	// Another text alone, or another reason: kept for the phone, and no
	// more (§6: the audit log and the journal have codes and versions).
	advance(time.Second)
	if err := report(r1, &perimeterv1.RelayUpdate{Version: "v0.27.0", Remote: true, State: nodeupdate.RolledBack, Id: st.ID, Target: "v0.28.0",
		Reason: "check", Error: "another text"}); err != nil {
		t.Fatal(err)
	}
	if r := record("r1"); r.Error != "another text" || r.Reason != "check" || r.ChangedAt != back.ChangedAt {
		t.Fatalf("another text: %+v, was %+v", r, back)
	}
	want := []string{
		"relay r1: relay.update idle -, remote off r1",
		"relay r1: relay.update idle v0.27.0 r1",
		"relay r1: relay.update requested v0.27.0 to v0.28.0 r1",
		"relay r1: relay.update idle v0.27.0 r1",
		"relay r1: relay.update running v0.27.0 to v0.28.0 r1",
		"relay r1: relay.update requested v0.27.0 to v0.28.0 r1",
		"relay r1: relay.update running v0.27.0 to v0.28.0 r1",
		"relay r1: relay.update rolled_back v0.27.0 to v0.28.0 (quota) r1",
	}
	if got := relayAudit(t, srv); !slices.Equal(got, want) {
		t.Fatalf("audit\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// r1's outcome is r2's turn: its feed gets the offer.
	f2 := feedMsgs(ctx, t, bundles["r2"], at2, &perimeterv1.WatchRelayRequest{Probe: true, Updates: true})
	if m := nextMsg(t, f2, "r2"); m.Update == nil || m.Update.Id != st.ID {
		t.Fatalf("r2 after r1 rolled back: %v", m)
	}

	// At most 12 a minute from one relay; the next minute again.
	advance(time.Minute)
	for i := range maxUpdateReports {
		if err := report(r1, idle); err != nil {
			t.Fatalf("report %d: %v", i, err)
		}
	}
	if err := report(r1, idle); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("a 13th in a minute: %v", err)
	}
	// Another relay's own minute.
	if err := report(updateClient(t, bundles["r2"], at2), idle); err != nil {
		t.Fatalf("r2 while r1 is held back: %v", err)
	}
	advance(time.Minute)
	if err := report(r1, idle); err != nil {
		t.Fatalf("the next minute: %v", err)
	}
}

// A relay's error as the exit keeps it: redacted again, the exit's own
// name too, printable, at most 200 bytes, cut on a rune; the same text the
// same while rayd runs.
func TestCleanRelayError(t *testing.T) {
	srv, _, _, _, _ := relayNode(t, "v0.28.0")
	ctx := context.Background()
	// The relay's addresses grow as tokens: past 200 bytes, cut.
	e := strings.Repeat("8.8.4.4 ", 24) + "é"
	got := srv.cleanRelayError(ctx, e)
	if len(got) > maxUpdateError || !utf8.ValidString(got) || strings.Contains(got, "8.8.4.4") || !strings.HasPrefix(got, "<ip4:") {
		t.Fatalf("%d bytes: %q", len(got), got)
	}
	if again := srv.cleanRelayError(ctx, e); again != got {
		t.Fatalf("the same text: %q, then %q", got, again)
	}
	if got := srv.cleanRelayError(ctx, "rayspa at n.example.com: \x07 bell"); got != "rayspa at <domain>: ? bell" {
		t.Fatalf("the exit's name: %q", got)
	}
	if got := srv.cleanRelayError(ctx, strings.Repeat("ab ", 66)+"a"+"é"); len(got) != 199 {
		t.Fatalf("cut inside a rune: %d bytes", len(got))
	}
}

// One report at a time from a relay, whatever the minute allows.
func TestReportUpdateAtOnce(t *testing.T) {
	var ru relayUpdates
	now := time.Date(2026, 11, 20, 4, 0, 0, 0, time.UTC)
	done, err := ru.admit("r1", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ru.admit("r1", now); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("a second at once: %v", err)
	}
	other, err := ru.admit("r2", now)
	if err != nil {
		t.Fatalf("another relay's: %v", err)
	}
	other()
	done()
	if done, err := ru.admit("r1", now); err != nil {
		t.Fatalf("after the first: %v", err)
	} else {
		done()
	}
}

// A relay removed takes its record with it, a report under way finds no
// relay, and one added again by its name starts with none.
func TestRelayUpdateRemoved(t *testing.T) {
	srv, bundles, _, now, sock := relayNode(t, "v0.28.0", "r1")
	ctx := context.Background()
	at1, _ := serveRemoteFrom(t, srv, "198.51.100.20:40000")
	r1 := updateClient(t, bundles["r1"], at1)
	if _, err := r1.ReportUpdate(ctx, connect.NewRequest(&perimeterv1.ReportUpdateRequest{Update: &perimeterv1.RelayUpdate{Version: "v0.27.0", State: nodeupdate.Idle}})); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Store.GetSetting(ctx, relayUpdateKey+"r1"); err != nil {
		t.Fatalf("no record: %v", err)
	}
	c := NewUnixClient(sock)
	if _, err := c.RemoveRelay(ctx, connect.NewRequest(&nodev1.RemoveRelayRequest{Name: "r1"})); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Store.GetSetting(ctx, relayUpdateKey+"r1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the record outlived its relay: %v", err)
	}
	if _, err := srv.takeRelayReport(ctx, "r1", relayRecord{Reported: nodeupdate.Idle}, now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a report after the removal: %v", err)
	}
	if _, err := srv.Store.GetSetting(ctx, relayUpdateKey+"r1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a report after the removal kept")
	}
	if _, err := r1.ReportUpdate(ctx, connect.NewRequest(&perimeterv1.ReportUpdateRequest{Update: &perimeterv1.RelayUpdate{State: nodeupdate.Idle}})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("the removed relay reports: %v", err)
	}
	// One a removal left behind.
	setRecord(t, srv, "r1", relayRecord{Reported: nodeupdate.Done, Version: "v0.28.0"})
	if _, err := c.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: "r1", Address: "198.51.100.30"})); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Store.GetSetting(ctx, relayUpdateKey+"r1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a new relay with an old one's record: %v", err)
	}
}

// The phone's view of each relay (§8.2): its report on the offer, or where
// it stands with it in the queue; an update under way silent for an hour
// failed. What the queue says ends: offered only while the relay holds its
// turn, waiting until its turn comes, and a relay the queue went past with
// no word on the offer failed, no_word.
func TestRelayStatus(t *testing.T) {
	now := time.Date(2026, 11, 20, 5, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) int64 { return now.Add(-d).Unix() }
	o := &perimeterv1.RelayUpdateOffer{Id: "aa", Version: "v0.28.0", EndedAt: ago(30 * time.Minute)}
	rec := func(state, id, version, target string, remote bool) relayRecord {
		return relayRecord{Reported: state, UpdateID: id, Version: version, Target: target, Remote: remote, ChangedAt: ago(5 * time.Minute)}
	}
	plain := func(r relayRecord) relayView {
		return relayView{Name: "r1", Rec: r, Feeds: 1, ClosedAt: now.Add(-2 * time.Hour)}
	}
	// given is v given its turn for the offer at ago.
	given := func(v relayView, at time.Duration) relayView {
		v.Rec.TurnID, v.Rec.TurnAt = o.Id, ago(at)
		return v
	}
	offered := func(r relayRecord) relayView { return given(plain(r), 7*time.Minute) }
	away := func(v relayView, at time.Duration) relayView {
		v.Feeds, v.ClosedAt = 0, now.Add(-at)
		return v
	}
	silent := rec(nodeupdate.Running, "aa", "v0.27.0", "v0.28.0", true)
	silent.ChangedAt = ago(nodeupdate.Stale)
	failed := rec(nodeupdate.Failed, "aa", "v0.27.0", "v0.28.0", true)
	failed.Reason, failed.Error = nodeupdate.ReasonDownload, "neither GitHub nor a mirror answered"
	refused := rec(nodeupdate.Failed, "aa", "v0.27.0", "v0.28.0", true)
	refused.Reason = nodeupdate.ReasonVersion
	type want struct {
		state, target, id, reason string
		changed                   int64
	}
	for _, c := range []struct {
		name string
		v    relayView
		o    *perimeterv1.RelayUpdateOffer
		want want
	}{
		{"nothing offered, never a word", plain(relayRecord{}), nil, want{"unknown", "", "", "", 0}},
		{"nothing offered, its last done", plain(rec(nodeupdate.Done, "9f", "v0.27.0", "v0.27.0", true)), nil, want{"current", "", "", "", ago(5 * time.Minute)}},
		{"nothing offered, an update under way", plain(rec(nodeupdate.Running, "9f", "v0.26.0", "v0.27.0", true)), nil,
			want{nodeupdate.Running, "v0.27.0", "9f", "", ago(5 * time.Minute)}},
		{"nothing offered, silent under way", plain(silent), nil, want{nodeupdate.Failed, "v0.28.0", "aa", noWord, now.Unix()}},
		{"offered, never a word", offered(relayRecord{}), o, want{"offered", "v0.28.0", "aa", "", ago(7 * time.Minute)}},
		{"an older relay", plain(relayRecord{SeenAt: ago(time.Minute)}), o, want{"unknown", "", "", "", 0}},
		{"done", plain(rec(nodeupdate.Done, "aa", "v0.28.0", "v0.28.0", true)), o, want{nodeupdate.Done, "v0.28.0", "aa", "", ago(5 * time.Minute)}},
		{"failed", plain(failed), o, want{nodeupdate.Failed, "v0.28.0", "aa", nodeupdate.ReasonDownload, ago(5 * time.Minute)}},
		{"refused it in its turn", offered(refused), o, want{nodeupdate.Failed, "v0.28.0", "aa", nodeupdate.ReasonVersion, ago(5 * time.Minute)}},
		{"requested", offered(rec(nodeupdate.Requested, "aa", "v0.27.0", "v0.28.0", true)), o,
			want{nodeupdate.Requested, "v0.28.0", "aa", "", ago(5 * time.Minute)}},
		{"running, silent for an hour", offered(silent), o, want{nodeupdate.Failed, "v0.28.0", "aa", noWord, now.Unix()}},
		{"under way for an hour, saying other things since", func() relayView {
			v := offered(rec(nodeupdate.Running, "aa", "v0.27.0", "v0.28.0", false))
			v.Rec.UnderwayAt = ago(nodeupdate.Stale + time.Minute)
			return v
		}(), o, want{nodeupdate.Failed, "v0.28.0", "aa", noWord, ago(time.Minute)}},
		{"on it, by hand", plain(rec(nodeupdate.Idle, "", "v0.28.0", "", true)), o, want{"current", "v0.28.0", "aa", "", ago(5 * time.Minute)}},
		{"newer", plain(rec(nodeupdate.Idle, "", "v0.29.0", "", false)), o, want{"current", "v0.28.0", "aa", "", ago(5 * time.Minute)}},
		{"root has not allowed it", plain(rec(nodeupdate.Idle, "", "v0.27.0", "", false)), o, want{"off", "v0.28.0", "aa", "", ago(5 * time.Minute)}},
		{"an earlier update under way", plain(rec(nodeupdate.Running, "9f", "v0.26.0", "v0.27.0", true)), o,
			want{nodeupdate.Running, "v0.27.0", "9f", "", ago(5 * time.Minute)}},
		{"an earlier update under way, remote off since", plain(rec(nodeupdate.Running, "9f", "v0.26.0", "v0.27.0", false)), o,
			want{nodeupdate.Running, "v0.27.0", "9f", "", ago(5 * time.Minute)}},
		{"in its feed", offered(rec(nodeupdate.Idle, "", "v0.27.0", "", true)), o, want{"offered", "v0.28.0", "aa", "", ago(7 * time.Minute)}},
		{"its turn to come", plain(rec(nodeupdate.Idle, "", "v0.27.0", "", true)), o, want{"waiting", "v0.28.0", "aa", "", o.EndedAt}},
		{"failed on an earlier offer, waiting", plain(rec(nodeupdate.Failed, "9f", "v0.27.0", "v0.27.5", true)), o, want{"waiting", "v0.28.0", "aa", "", o.EndedAt}},
		{"away a while, waiting", away(plain(rec(nodeupdate.Idle, "", "v0.27.0", "", true)), 10*time.Minute), o, want{"waiting", "v0.28.0", "aa", "", o.EndedAt}},
		// The queue went past it with no word on the offer.
		{"its turn ran out", given(plain(rec(nodeupdate.Idle, "", "v0.27.0", "", true)), TurnTimeout+7*time.Minute), o,
			want{nodeupdate.Failed, "v0.28.0", "aa", noWord, ago(7 * time.Minute)}},
		{"its turn ran out, it said nothing of it", given(plain(rec(nodeupdate.RolledBack, "9f", "v0.27.0", "v0.28.0", true)), 72*time.Hour), o,
			want{nodeupdate.Failed, "v0.28.0", "aa", noWord, ago(72*time.Hour - TurnTimeout)}},
		{"away for TurnTimeout", away(plain(rec(nodeupdate.Idle, "", "v0.27.0", "", true)), TurnTimeout+time.Minute), o,
			want{nodeupdate.Failed, "v0.28.0", "aa", noWord, ago(time.Minute)}},
		// Its outcome in its turn, then idle (repaired by hand): passed when
		// it said so.
		{"its outcome in its turn, idle since", func() relayView {
			v := offered(rec(nodeupdate.Idle, "", "v0.27.0", "", true))
			v.Rec.TurnOver = true
			return v
		}(), o, want{nodeupdate.Failed, "v0.28.0", "aa", noWord, ago(5 * time.Minute)}},
	} {
		var turn relayTurn
		if c.o != nil {
			turn = relayQueue(c.o, []relayView{c.v}, now)[0]
		}
		rs := relayStatus(c.v, c.o, turn, now.Add(-time.Minute), now)
		got := want{rs.State, rs.Target, rs.UpdateId, rs.Reason, rs.ChangedAt}
		if got != c.want || rs.Name != "r1" || rs.Version != c.v.Rec.Version || rs.Remote != c.v.Rec.Remote || rs.SeenAt != now.Add(-time.Minute).Unix() {
			t.Errorf("%s: %+v, want %+v", c.name, rs, c.want)
		}
		if rs.Reason == noWord && !strings.Contains(rs.Error, "no word") {
			t.Errorf("%s: error %q", c.name, rs.Error)
		}
		if c.name == "failed" && rs.Error != failed.Error {
			t.Errorf("failed: error %q", rs.Error)
		}
	}
}

// GetUpdateStatus lists every relay by name with its update for the phone
// (§8), seen_at fresh while a feed of it is open.
func TestGetUpdateStatusRelays(t *testing.T) {
	srv, bundles, advance, now, sock := relayNode(t, "v0.28.0", "r1", "r2", "r3")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	at1, _ := serveRemoteFrom(t, srv, "198.51.100.20:40000")
	at2, _ := serveRemoteFrom(t, srv, "198.51.100.21:40000")
	c := NewUnixClient(sock)
	status := func() []*nodev1.RelayUpdateStatus {
		t.Helper()
		r, err := c.GetUpdateStatus(ctx, connect.NewRequest(&nodev1.GetUpdateStatusRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return r.Msg.Relays
	}
	states := func(rs []*nodev1.RelayUpdateStatus) []string {
		var out []string
		for _, r := range rs {
			out = append(out, r.Name+" "+r.State)
		}
		return out
	}
	// No update by request: the relays are there, unheard of.
	if got := states(status()); !slices.Equal(got, []string{"r1 unknown", "r2 unknown", "r3 unknown"}) {
		t.Fatalf("before: %v", got)
	}
	st := nodeupdate.Status{ID: "6f1c0e2a9b3d4c5e", State: nodeupdate.Done, From: "v0.27.0", To: "v0.28.0", Kind: nodeupdate.Remote, Ended: now()}
	nodeupdate.WriteStatus(srv.NodeUpdate.Status, st)
	// r1's rayd relay reports and takes the offer; r2's waits; r3 is an
	// older relay, rayspa only.
	f1 := feedMsgs(ctx, t, bundles["r1"], at1, &perimeterv1.WatchRelayRequest{Probe: true, Updates: true})
	nextMsg(t, f1, "r1")
	r1 := updateClient(t, bundles["r1"], at1)
	if _, err := r1.ReportUpdate(ctx, connect.NewRequest(&perimeterv1.ReportUpdateRequest{Update: &perimeterv1.RelayUpdate{Version: "v0.27.0", Remote: true,
		State: nodeupdate.Requested, Id: st.ID, Target: "v0.28.0"}})); err != nil {
		t.Fatal(err)
	}
	r2 := updateClient(t, bundles["r2"], at2)
	if _, err := r2.ReportUpdate(ctx, connect.NewRequest(&perimeterv1.ReportUpdateRequest{Update: &perimeterv1.RelayUpdate{Version: "v0.27.0", Remote: true,
		State: nodeupdate.Idle}})); err != nil {
		t.Fatal(err)
	}
	advance(time.Minute)
	rs := status()
	if got := states(rs); !slices.Equal(got, []string{"r1 requested", "r2 waiting", "r3 unknown"}) {
		t.Fatalf("under way: %v", got)
	}
	if rs[0].SeenAt != now().Unix() || rs[0].Target != "v0.28.0" || rs[0].UpdateId != st.ID || rs[1].SeenAt != now().Add(-time.Minute).Unix() || rs[2].SeenAt != 0 {
		t.Fatalf("under way: %v", rs)
	}
	// An hour without a word from r1.
	advance(nodeupdate.Stale)
	if rs := status(); rs[0].State != nodeupdate.Failed || rs[0].Reason != noWord {
		t.Fatalf("an hour on: %v", rs[0])
	}
}
