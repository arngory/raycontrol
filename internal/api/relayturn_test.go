package api

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/deploy"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/nodeupdate"
)

// The queue of relays' turns (spec/relay-update-remote-v1.md §3.3, §6,
// §8.2) as feeds and reports move it: turnNode does by hand what the feeds
// with updates and the reports do.

// turnNode is an exit on v0.28.0, which its last update put in, with the
// relays named.
type turnNode struct {
	t       *testing.T
	ctx     context.Context
	srv     *Server
	sock    string
	advance func(time.Duration)
	now     func() time.Time
	st      nodeupdate.Status // the last update's status
}

func newTurnNode(t *testing.T, names ...string) *turnNode {
	t.Helper()
	srv, _, advance, now, sock := relayNode(t, "v0.28.0", names...)
	n := &turnNode{t: t, ctx: context.Background(), srv: srv, sock: sock, advance: advance, now: now}
	n.status(nodeupdate.Status{ID: "6f1c0e2a9b3d4c5e", State: nodeupdate.Done, From: "v0.27.0", To: "v0.28.0", Kind: nodeupdate.Remote, Ended: now()})
	return n
}

// status writes the node's last update.
func (n *turnNode) status(st nodeupdate.Status) {
	n.t.Helper()
	if err := nodeupdate.WriteStatus(n.srv.NodeUpdate.Status, st); err != nil {
		n.t.Fatal(err)
	}
	n.st = st
}

// feed opens a feed with updates of each relay named, drop closes one:
// each moves the queue, as WatchRelay's.
func (n *turnNode) feed(names ...string) {
	for _, name := range names {
		n.srv.relayUpd.opened(name, n.now())
		n.srv.kickRelayFeeds(n.ctx)
	}
}

func (n *turnNode) drop(name string) {
	n.srv.relayUpd.closed(name, n.now())
	n.srv.kickRelayFeeds(n.ctx)
}

// report takes relay name's report as ReportUpdate does: state on update
// id, its version, remote on.
func (n *turnNode) report(name, state, version, id string) {
	n.t.Helper()
	r := relayRecord{Reported: state, Version: version, Remote: true, UpdateID: id}
	if id != "" {
		r.Target = n.st.To
	}
	n.take(name, r)
}

func (n *turnNode) take(name string, r relayRecord) {
	n.t.Helper()
	if _, err := n.srv.takeRelayReport(n.ctx, name, r, n.now()); err != nil {
		n.t.Fatal(err)
	}
	n.srv.kickRelayFeeds(n.ctx)
}

// offers are the relays whose feeds have the offer, by name: a look of
// their feeds, which gives the turn that came.
func (n *turnNode) offers() []string {
	n.t.Helper()
	m, _, err := n.srv.relayOffers(n.ctx, n.now())
	if err != nil {
		n.t.Fatal(err)
	}
	var names []string
	for name := range m {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// restart is the exit's rayd restarting: all it kept in memory goes.
func (n *turnNode) restart() {
	ru := &n.srv.relayUpd
	ru.mu.Lock()
	ru.relays, ru.started = nil, time.Time{}
	ru.mu.Unlock()
}

// states are the relays' states for the phone, "name state" each.
func (n *turnNode) states() []string {
	n.t.Helper()
	r, err := NewUnixClient(n.sock).GetUpdateStatus(n.ctx, connect.NewRequest(&nodev1.GetUpdateStatusRequest{}))
	if err != nil {
		n.t.Fatal(err)
	}
	var out []string
	for _, rs := range r.Msg.Relays {
		out = append(out, rs.Name+" "+rs.State)
	}
	return out
}

// within moves the clock a minute at a time, the feeds looking, until
// relay name has the offer, and reports how long that took; d at most.
func (n *turnNode) within(name string, d time.Duration) (time.Duration, bool) {
	for waited := time.Duration(0); waited <= d; waited += time.Minute {
		if slices.Contains(n.offers(), name) {
			return waited, true
		}
		n.advance(time.Minute)
	}
	return d, false
}

// A relay that lies holds the queue back TurnTimeout at most (§6): it is
// updating only in a turn the exit gave it. Its word on the offer's id,
// one it never had its turn for, holds nobody, nor does flipping it.
func TestRelayTurnLiar(t *testing.T) {
	// It learned the offer as a relay on the release, closed its feed and
	// says it updates, flipping the id every 19 minutes.
	n := newTurnNode(t, "r1", "r2", "r3", "r4")
	for _, name := range []string{"r1", "r2", "r3", "r4"} {
		n.report(name, nodeupdate.Idle, "v0.27.0", "")
	}
	n.feed("r1", "r2", "r3", "r4")
	if got := n.offers(); !slices.Equal(got, []string{"r1"}) {
		t.Fatalf("first: %v", got)
	}
	n.report("r2", nodeupdate.Idle, "v0.28.0", "")
	n.report("r1", nodeupdate.Done, "v0.28.0", n.st.ID)
	if got := n.offers(); !slices.Equal(got, []string{"r1", "r2", "r3"}) {
		t.Fatalf("r2 on the release: %v", got)
	}
	n.drop("r2")
	dropped := n.now()
	n.report("r2", nodeupdate.Running, "v0.27.0", n.st.ID)
	n.advance(5 * time.Minute)
	n.report("r3", nodeupdate.Done, "v0.28.0", n.st.ID)
	for step := 0; !slices.Contains(n.offers(), "r4"); step++ {
		if n.now().Sub(dropped) > TurnTimeout {
			t.Fatalf("r4 waits on r2 past TurnTimeout: %v", n.states())
		}
		n.advance(time.Minute)
		if step%19 == 0 {
			n.report("r2", nodeupdate.Running, "v0.27.0", "0123456789abcdef")
			n.report("r2", nodeupdate.Running, "v0.27.0", n.st.ID)
		}
	}

	// After a restart of the exit, with its feed open: the first by name
	// goes first, whatever the other says.
	n = newTurnNode(t, "r1", "r2")
	n.report("r1", nodeupdate.Idle, "v0.27.0", "")
	n.report("r2", nodeupdate.Running, "v0.27.0", n.st.ID)
	n.feed("r1", "r2")
	for step := range 4 {
		if got := n.offers(); !slices.Equal(got, []string{"r1"}) {
			t.Fatalf("step %d: %v", step, got)
		}
		n.advance(5 * time.Minute)
		n.report("r2", nodeupdate.Running, "v0.27.0", "0123456789abcdef")
		n.report("r2", nodeupdate.Running, "v0.27.0", n.st.ID)
	}
}

// The node updated again while a relay still updates in its turn for the
// last offer, and its rayd restarted: the turn is in the relay's record,
// so no other relay begins until it ends, or TurnTimeout after its turn
// came (§3.3, §5).
func TestRelayTurnRestart(t *testing.T) {
	n := newTurnNode(t, "r1", "r2", "r3")
	n.feed("r1", "r2", "r3")
	for _, name := range []string{"r1", "r2", "r3"} {
		n.report(name, nodeupdate.Idle, "v0.27.0", "")
	}
	n.offers()
	n.report("r1", nodeupdate.Done, "v0.28.0", n.st.ID)
	if got := n.offers(); !slices.Equal(got, []string{"r1", "r2"}) {
		t.Fatalf("r2's turn: %v", got)
	}
	given := n.now()
	n.report("r2", nodeupdate.Requested, "v0.27.0", n.st.ID)
	n.advance(time.Minute)
	n.report("r2", nodeupdate.Running, "v0.27.0", n.st.ID)
	// The node's next update: rayd stops, r2's rayd relay restarts as its
	// own update installs it.
	n.advance(time.Minute)
	n.restart()
	n.srv.Version = "v0.29.0"
	n.status(nodeupdate.Status{ID: "0a1b2c3d4e5f6071", State: nodeupdate.Done, From: "v0.28.0", To: "v0.29.0", Kind: nodeupdate.Remote, Ended: n.now()})
	n.feed("r1", "r3")
	if got := n.offers(); len(got) != 0 {
		t.Fatalf("while r2 updates to the last: %v", got)
	}
	// It never says more: the next begins TurnTimeout after r2's turn
	// came, no later.
	waited, ok := n.within("r1", TurnTimeout)
	if !ok || n.now().Sub(given) > TurnTimeout+time.Minute {
		t.Fatalf("r1 after %v: %v", waited, n.states())
	}
}

// A relay updating keeps its turn until its outcome: its new rayd relay
// says it runs the release before root's check ends (§3.3).
func TestRelayTurnOnRelease(t *testing.T) {
	n := newTurnNode(t, "r1", "r2")
	n.feed("r1", "r2")
	n.report("r1", nodeupdate.Idle, "v0.27.0", "")
	n.report("r2", nodeupdate.Idle, "v0.27.0", "")
	n.offers()
	n.report("r1", nodeupdate.Requested, "v0.27.0", n.st.ID)
	n.report("r1", nodeupdate.Running, "v0.27.0", n.st.ID)
	n.drop("r1")
	n.advance(time.Minute)
	n.feed("r1")
	n.report("r1", nodeupdate.Running, "v0.28.0", n.st.ID)
	if got := n.offers(); !slices.Equal(got, []string{"r1"}) {
		t.Fatalf("r1 not done yet: %v", got)
	}
	n.report("r1", nodeupdate.Done, "v0.28.0", n.st.ID)
	if got := n.offers(); !slices.Equal(got, []string{"r1", "r2"}) {
		t.Fatalf("r1 done: %v", got)
	}
}

// TurnTimeout is longer than the relay's update unit may run: its start,
// its stop, then ExecStopPost under the stop's limit again.
func TestRelayTurnTimeout(t *testing.T) {
	var unit string
	for _, f := range deploy.RelayPlan(deploy.DefaultBinaries).Files {
		if strings.HasSuffix(f.Path, "/"+deploy.RelayUpdateService) {
			unit = string(f.Content)
		}
	}
	limit := func(key string) time.Duration {
		t.Helper()
		m := regexp.MustCompile(`(?m)^` + key + `=(\S+)$`).FindStringSubmatch(unit)
		if m == nil {
			t.Fatalf("%s not in the unit:\n%s", key, unit)
		}
		d, err := time.ParseDuration(strings.Replace(m[1], "min", "m", 1))
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if most := limit("TimeoutStartSec") + 2*limit("TimeoutStopSec"); TurnTimeout <= most {
		t.Fatalf("TurnTimeout %v, the unit runs %v at most", TurnTimeout, most)
	}
}

// What the phone sees of the queue ends (§8.2): a relay the queue went
// past with no word on the offer, away for TurnTimeout, or silent in its
// turn, is failed (no_word), not waiting or offered for ever.
func TestRelayTurnStates(t *testing.T) {
	n := newTurnNode(t, "r1", "r2")
	setRecord(t, n.srv, "r1", relayRecord{Reported: nodeupdate.Idle, Version: "v0.27.0", Remote: true, ChangedAt: n.now().Unix()})
	n.report("r2", nodeupdate.Done, "v0.28.0", n.st.ID)
	if got := n.states(); !slices.Equal(got, []string{"r1 waiting", "r2 done"}) {
		t.Fatalf("r1 away a while: %v", got)
	}
	n.advance(TurnTimeout + time.Minute)
	n.advance(48 * time.Hour)
	if got := n.states(); !slices.Equal(got, []string{"r1 failed", "r2 done"}) {
		t.Fatalf("r1 away for two days: %v", got)
	}

	// Given its turn, it says nothing of it: an update to this release
	// rolled back there before.
	n = newTurnNode(t, "r1")
	n.feed("r1")
	n.report("r1", nodeupdate.RolledBack, "v0.27.0", "9f9f9f9f")
	n.offers()
	if got := n.states(); !slices.Equal(got, []string{"r1 offered"}) {
		t.Fatalf("its turn: %v", got)
	}
	n.advance(72 * time.Hour)
	if got := n.states(); !slices.Equal(got, []string{"r1 failed"}) {
		t.Fatalf("three days on: %v", got)
	}
}

// rayd relay's refusal of an offer before any change (failed, untouched,
// version or busy, on the offer's id) is the relay's outcome of it: the
// next relay's turn comes, and the phone shows why.
func TestRelayTurnRefused(t *testing.T) {
	n := newTurnNode(t, "r1", "r2")
	n.feed("r1", "r2")
	n.report("r1", nodeupdate.Idle, "v0.27.0", "")
	n.report("r2", nodeupdate.Idle, "v0.27.0", "")
	n.offers()
	n.take("r1", relayRecord{Reported: nodeupdate.Failed, Version: "v0.27.0", Remote: true, UpdateID: n.st.ID, Target: "v0.28.0", Reason: nodeupdate.ReasonVersion})
	if got := n.offers(); !slices.Equal(got, []string{"r2"}) {
		t.Fatalf("r1 refused: %v", got)
	}
	if got := n.states(); !slices.Equal(got, []string{"r1 failed", "r2 offered"}) {
		t.Fatalf("r1 refused: %v", got)
	}
}

// A relay that asks again for an offer whose update failed before any
// change (§3.5 step 5) updates in a later turn: nobody else begins
// meanwhile.
func TestRelayTurnRetry(t *testing.T) {
	n := newTurnNode(t, "r1", "r2", "r3")
	n.feed("r1", "r2")
	n.report("r1", nodeupdate.Idle, "v0.27.0", "")
	n.report("r2", nodeupdate.Idle, "v0.27.0", "")
	n.offers()
	n.report("r1", nodeupdate.Requested, "v0.27.0", n.st.ID)
	n.take("r1", relayRecord{Reported: nodeupdate.Failed, Version: "v0.27.0", Remote: true, UpdateID: n.st.ID, Target: "v0.28.0", Reason: nodeupdate.ReasonDownload})
	n.offers()
	n.report("r2", nodeupdate.Done, "v0.28.0", n.st.ID)
	if got := n.offers(); !slices.Equal(got, []string{"r1", "r2", "r3"}) {
		t.Fatalf("through: %v", got)
	}
	n.advance(nodeupdate.RelayRetryAfter)
	n.report("r1", nodeupdate.Requested, "v0.27.0", n.st.ID)
	// r3's rayd relay comes: it waits for r1.
	n.feed("r3")
	n.report("r3", nodeupdate.Idle, "v0.27.0", "")
	if got := n.offers(); slices.Contains(got, "r3") {
		t.Fatalf("r3 while r1 asks again: %v", got)
	}
	n.report("r1", nodeupdate.Done, "v0.28.0", n.st.ID)
	if got := n.offers(); !slices.Contains(got, "r3") {
		t.Fatalf("r1 done: %v", got)
	}
}

// Two looks at the queue at once give one turn: the turn is written
// before a feed sends the offer. A relay removed and added again by its
// name has none of the old one's turn.
func TestRelayTurnOnce(t *testing.T) {
	n := newTurnNode(t, "r1", "r2")
	n.take("r1", relayRecord{Reported: nodeupdate.Idle, Version: "v0.27.0"})
	n.report("r2", nodeupdate.Idle, "v0.27.0", "")
	n.feed("r1", "r2")
	// r2's feed looks: its turn. Before it sends, root on r1 turns remote
	// on and r1's feed looks.
	first := n.offers()
	n.report("r1", nodeupdate.Idle, "v0.27.0", "")
	second := n.offers()
	if slices.Contains(first, "r2") && slices.Contains(second, "r1") {
		t.Fatalf("two turns: %v, then %v", first, second)
	}

	n = newTurnNode(t, "r1", "r2")
	n.feed("r1")
	_, kicks := n.srv.relayUpd.changes("r1", n.now())
	m, _, err := n.srv.relayOffers(n.ctx, n.now())
	if err != nil || m["r1"] == nil {
		t.Fatalf("r1's turn: %v %v", m, err)
	}
	c := NewUnixClient(n.sock)
	if _, err := c.RemoveRelay(n.ctx, connect.NewRequest(&nodev1.RemoveRelayRequest{Name: "r1"})); err != nil {
		t.Fatal(err)
	}
	// The removed relay's feed sends the offer after it was removed.
	n.srv.relayUpd.sentOffer("r1", m["r1"], kicks, n.now())
	n.drop("r1")
	if _, err := c.AddRelay(n.ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: "r1", Address: "198.51.100.30"})); err != nil {
		t.Fatal(err)
	}
	n.feed("r2")
	n.report("r2", nodeupdate.Idle, "v0.27.0", "")
	if got := n.offers(); !slices.Equal(got, []string{"r2"}) {
		t.Fatalf("the new r1, never heard of: %v", got)
	}
}

// An update of the node that failed or rolled back since the last one
// done leaves the relays on that one's offer while the node runs its
// release (§3.3): a newer one done replaces it, and the node on another
// release drops it.
func TestRelayTurnLastOffer(t *testing.T) {
	n := newTurnNode(t, "r1", "r2")
	n.feed("r1", "r2")
	n.report("r1", nodeupdate.Idle, "v0.27.0", "")
	n.report("r2", nodeupdate.Idle, "v0.27.0", "")
	done := n.st
	offer := func() *perimeterv1.RelayUpdateOffer {
		t.Helper()
		return n.srv.relayOfferNow(n.ctx, n.now())
	}
	if o := offer(); o == nil || o.Id != done.ID {
		t.Fatalf("done: %v", o)
	}
	n.advance(time.Minute)
	n.status(nodeupdate.Status{ID: "0a1b2c3d4e5f6071", State: nodeupdate.Failed, From: "v0.28.0", To: "v0.28.1", Kind: nodeupdate.Auto,
		Untouched: true, Ended: n.now()})
	if o := offer(); o == nil || o.Id != done.ID || o.Version != "v0.28.0" || o.EndedAt != done.Ended.Unix() {
		t.Fatalf("a later update failed: %v", o)
	}
	if got := n.offers(); !slices.Equal(got, []string{"r1"}) {
		t.Fatalf("a later update failed: %v", got)
	}
	n.status(nodeupdate.Status{ID: "0a1b2c3d4e5f6072", State: nodeupdate.RolledBack, From: "v0.28.0", To: "v0.28.0", Target: "v0.28.1", Kind: nodeupdate.Remote,
		Ended: n.now()})
	if o := offer(); o == nil || o.Id != done.ID {
		t.Fatalf("a later update rolled back: %v", o)
	}
	// Another update asked for: none while it waits.
	if err := nodeupdate.WriteRequest(n.srv.NodeUpdate.Request, nodeupdate.Request{ID: "ab", Kind: nodeupdate.Remote, Version: "latest", By: "x", At: n.now()}, n.now()); err != nil {
		t.Fatal(err)
	}
	if o := offer(); o != nil {
		t.Fatalf("an update waits: %v", o)
	}
	// Rolled back by hand: none, and none again on the release.
	n.status(nodeupdate.Status{ID: "0a1b2c3d4e5f6073", State: nodeupdate.Failed, From: "v0.28.0", To: "v0.28.1", Kind: nodeupdate.Remote, Ended: n.now()})
	n.advance(nodeupdate.Stale)
	n.srv.Version = "v0.27.0"
	if o := offer(); o != nil {
		t.Fatalf("the node rolled back by hand: %v", o)
	}
	n.srv.Version = "v0.28.0"
	if o := offer(); o != nil {
		t.Fatalf("the node on the release again: %v", o)
	}
	// A newer one done.
	n.srv.Version = "v0.28.1"
	n.status(nodeupdate.Status{ID: "0a1b2c3d4e5f6074", State: nodeupdate.Done, From: "v0.28.0", To: "v0.28.1", Kind: nodeupdate.Remote, Ended: n.now()})
	n.offers()
	n.status(nodeupdate.Status{ID: "0a1b2c3d4e5f6075", State: nodeupdate.Failed, From: "v0.28.1", To: "v0.29.0", Kind: nodeupdate.Remote, Ended: n.now()})
	if o := offer(); o == nil || o.Id != "0a1b2c3d4e5f6074" || o.Version != "v0.28.1" {
		t.Fatalf("a newer one done, then one failed: %v", o)
	}
}

// A relay that keeps changing what it says fills neither the audit log nor
// the journal (§6): a change of the text alone is no line, and a relay has
// maxUpdateAudits lines an hour at most, and one that says so.
func TestRelayTurnAudit(t *testing.T) {
	srv, bundles, advance, now, _ := relayNode(t, "v0.28.0", "r1")
	ctx := context.Background()
	at1, _ := serveRemoteFrom(t, srv, "198.51.100.20:40000")
	r1 := updateClient(t, bundles["r1"], at1)
	report := func(u *perimeterv1.RelayUpdate) {
		t.Helper()
		advance(6 * time.Second) // ten a minute, within the twelve
		if _, err := r1.ReportUpdate(ctx, connect.NewRequest(&perimeterv1.ReportUpdateRequest{Update: u})); err != nil {
			t.Fatal(err)
		}
	}
	failed := func(text string) *perimeterv1.RelayUpdate {
		return &perimeterv1.RelayUpdate{Version: "v0.27.0", Remote: true, State: nodeupdate.Failed, Id: "aa", Target: "v0.28.0", Reason: "download", Error: text}
	}
	for i := range 30 {
		report(failed(strings.Repeat("x", i+1)))
	}
	if got := relayAudit(t, srv); len(got) != 1 {
		t.Fatalf("the text alone: %v", got)
	}
	start := now()
	for i := range 2 * maxUpdateAudits {
		state := nodeupdate.Requested
		if i%2 == 1 {
			state = nodeupdate.Failed
		}
		report(&perimeterv1.RelayUpdate{Version: "v0.27.0", Remote: true, State: state, Id: "aa", Target: "v0.28.0"})
	}
	got := relayAudit(t, srv)
	if len(got) != maxUpdateAudits+1 || !strings.Contains(got[len(got)-1], "muted") {
		t.Fatalf("%d lines within %v:\n%s", len(got), now().Sub(start), strings.Join(got, "\n"))
	}
	advance(time.Hour)
	report(&perimeterv1.RelayUpdate{Version: "v0.27.0", Remote: true, State: nodeupdate.Idle})
	if again := relayAudit(t, srv); len(again) != len(got)+1 || !strings.HasSuffix(again[len(again)-1], "relay.update idle v0.27.0 r1") {
		t.Fatalf("the next hour: %v", again)
	}
}
