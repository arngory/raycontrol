package traffic

import (
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

// The client's interop on v0.26.0 (traffic-limit-v1 §3.4): alice used her
// limit up and went on until the node cut her; rayctl user reset-usage
// came before the loop's next poll. What she sent between the poll that
// took her off and the cut was carried before the reset: it does not count
// in the new period (less than true, never more), and she stays back.
func TestResetUsageNotOverAgainByBytesBefore(t *testing.T) {
	n := newNode(t)
	n.user("alice", 1000, "hy")
	a := n.accountant()
	n.set("hy2:hy", "b1", "u1", 0, 0)
	a.Round(n.ctx, "", false)
	n.tick(Every)
	n.set("hy2:hy", "b1", "u1", 600, 600)
	a.Round(n.ctx, "", false)
	if u, _ := n.st.UserByName(n.ctx, "alice"); u.Active(n.now) || n.woken != 1 {
		t.Fatalf("not off: active %v, woken %d", u.Active(n.now), n.woken)
	}
	// On until the cut, five seconds later; the reset five more after it.
	n.tick(5 * time.Second)
	n.set("hy2:hy", "b1", "u1", 3000, 3000)
	n.tick(5 * time.Second)
	if _, err := n.st.SetUserTraffic(n.ctx, "alice", store.TrafficChange{ResetUsage: true}); err != nil {
		t.Fatal(err)
	}
	// The polls after: back, told once, apply woken; never off again by
	// what came before the reset, however long the loop runs (its
	// minute's write among them).
	for i := range 6 {
		n.tick(Every)
		a.Round(n.ctx, "", false)
		if u, _ := n.st.UserByName(n.ctx, "alice"); !u.Active(n.now) {
			t.Fatalf("round %d after the reset: off again, used %d", i, u.Used(n.now))
		}
	}
	n.wantUsed("alice", 0, 0)
	if got := strings.Join(n.audits(), "; "); got != "rayd user.traffic=exhausted alice; rayd user.traffic=restored alice" || n.woken != 2 {
		t.Fatalf("audits %q, woken %d", got, n.woken)
	}
	// What she sends after the reset counts.
	n.set("hy2:hy", "b1", "u1", 3100, 3200)
	n.tick(Every)
	a.Round(n.ctx, "", false)
	n.tick(time.Minute)
	a.Round(n.ctx, "", false)
	n.wantUsed("alice", 100, 200)
}

// Over the limit again after the administrator raised it, before a poll
// saw her under it: the store has it at once and apply is woken, as at any
// crossing (traffic-limit-v1 §3.1). Before, the loop still had her as over
// from before and told nobody: the store took her off at the minute's
// write, the data plane at apply's next minute, and she went on meanwhile.
func TestOverAgainAfterRaisedLimitWakes(t *testing.T) {
	n := newNode(t)
	n.user("alice", 1000, "hy")
	a := n.accountant()
	n.set("hy2:hy", "b1", "u1", 0, 0)
	a.Round(n.ctx, "", false)
	n.tick(Every)
	n.set("hy2:hy", "b1", "u1", 600, 600)
	a.Round(n.ctx, "", false) // off, woken 1
	n.tick(time.Second)
	limit := int64(2000)
	if _, err := n.st.SetUserTraffic(n.ctx, "alice", store.TrafficChange{Limit: &limit}); err != nil {
		t.Fatal(err)
	}
	// Back on the profiles, she sends more than the 800 left before the
	// loop's next poll.
	n.set("hy2:hy", "b1", "u1", 1100, 1100)
	n.tick(Every)
	a.Round(n.ctx, "", false)
	u, _ := n.st.UserByName(n.ctx, "alice")
	if u.Active(n.now) || n.woken != 2 {
		t.Fatalf("over again: active %v (used %d), woken %d, want 2", u.Active(n.now), u.Used(n.now), n.woken)
	}
	if got := strings.Join(n.audits(), "; "); got != "rayd user.traffic=exhausted alice; rayd user.traffic=exhausted alice" {
		t.Fatalf("audits %q", got)
	}
}

// Off by a lowered limit, and reset before the loop's next poll: the loop
// never had her as over, so before, that poll took her off again at once
// (written, apply woken) by what she sent before the reset, seconds after
// the subscription said she was back.
func TestResetUsageAfterLoweredLimit(t *testing.T) {
	n := newNode(t)
	n.user("alice", 1<<30, "hy")
	a := n.accountant()
	n.set("hy2:hy", "b1", "u1", 0, 0)
	a.Round(n.ctx, "", false)
	n.tick(Every)
	n.set("hy2:hy", "b1", "u1", 600, 600)
	a.Round(n.ctx, "", false)
	n.tick(time.Minute)
	a.Round(n.ctx, "", false) // the minute's write: 1200 in the store
	n.wantUsed("alice", 600, 600)
	limit := int64(1000)
	if _, err := n.st.SetUserTraffic(n.ctx, "alice", store.TrafficChange{Limit: &limit}); err != nil {
		t.Fatal(err)
	}
	// Off in the store at once (apply is woken by the API); she sends on
	// until the cut, and the administrator resets.
	n.set("hy2:hy", "b1", "u1", 1100, 1100)
	n.tick(5 * time.Second)
	if _, err := n.st.SetUserTraffic(n.ctx, "alice", store.TrafficChange{ResetUsage: true}); err != nil {
		t.Fatal(err)
	}
	woken := n.woken
	for i := range 6 {
		n.tick(Every)
		a.Round(n.ctx, "", false)
		if u, _ := n.st.UserByName(n.ctx, "alice"); !u.Active(n.now) || n.woken != woken {
			t.Fatalf("round %d after the reset: active %v (used %d), woken %d, want %d", i, u.Active(n.now), u.Used(n.now), n.woken, woken)
		}
	}
}
