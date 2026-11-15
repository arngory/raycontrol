package relayprobe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1/perimeterv1connect"
	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/spa"
)

// reports is the exit as Updates calls it: ReportUpdate, recorded, with
// the answer set.
type reports struct {
	perimeterv1connect.RelayServiceClient // the feed's calls: not made here

	mu     sync.Mutex
	got    []*perimeterv1.RelayUpdate
	answer error
}

func (e *reports) ReportUpdate(_ context.Context, req *connect.Request[perimeterv1.ReportUpdateRequest]) (*connect.Response[perimeterv1.ReportUpdateResponse], error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.got = append(e.got, req.Msg.Update)
	if e.answer != nil {
		return nil, e.answer
	}
	return connect.NewResponse(&perimeterv1.ReportUpdateResponse{}), nil
}

// relayHost is a relay's update files on temporary directories, its rayd
// relay's Updates on a clock of the test's, and root's unit as the test
// plays it.
type relayHost struct {
	t                       *testing.T
	u                       *Updates
	exit                    *reports
	request, status, policy string
	clock                   time.Time
}

func newRelayHost(t *testing.T, version string) *relayHost {
	t.Helper()
	root := t.TempDir()
	request := filepath.Join(t.TempDir(), "update-request")
	h := &relayHost{t: t, exit: &reports{}, request: request, status: filepath.Join(root, "status.json"), policy: filepath.Join(root, "policy.json"),
		clock: time.Date(2026, 11, 20, 3, 0, 0, 0, time.UTC)}
	h.restart(version)
	return h
}

// restart is a new rayd relay of version on the same files: after its own
// update, say. Its first feed is open.
func (h *relayHost) restart(version string) {
	h.u = NewUpdates(version, h.request, filepath.Dir(h.status), slog.New(slog.DiscardHandler))
	h.u.now = func() time.Time { return h.clock }
	if h.u.status != h.status || h.u.policy != h.policy {
		h.t.Fatalf("root's files at %s, %s", h.u.status, h.u.policy)
	}
	h.u.offered(true, nil)
}

func (h *relayHost) remote(on string) {
	h.t.Helper()
	if err := nodeupdate.WritePolicy(h.policy, nodeupdate.Policy{Remote: on, Auto: "off", Window: nodeupdate.DefaultWindow}); err != nil {
		h.t.Fatal(err)
	}
}

func (h *relayHost) offer(id, version string) {
	h.u.offered(false, &perimeterv1.RelayUpdateOffer{Id: id, Version: version, EndedAt: h.clock.Add(-time.Hour).Unix()})
}

func (h *relayHost) look() time.Duration { return h.u.look(context.Background(), h.exit) }

func (h *relayHost) advance(d time.Duration) { h.clock = h.clock.Add(d) }

// told is what the exit last heard, and how many reports it had.
func (h *relayHost) told() (*perimeterv1.RelayUpdate, int) {
	h.exit.mu.Lock()
	defer h.exit.mu.Unlock()
	if len(h.exit.got) == 0 {
		return &perimeterv1.RelayUpdate{}, 0
	}
	return h.exit.got[len(h.exit.got)-1], len(h.exit.got)
}

func (h *relayHost) waiting() (nodeupdate.Request, bool) { return nodeupdate.PeekRequest(h.request) }

func (h *relayHost) none(what string) {
	h.t.Helper()
	if r, ok := h.waiting(); ok {
		h.t.Fatalf("%s: a request %+v", what, r)
	}
}

func (h *relayHost) setStatus(s nodeupdate.Status) {
	h.t.Helper()
	if err := nodeupdate.WriteStatus(h.status, s); err != nil {
		h.t.Fatal(err)
	}
}

// take is root's unit taking the request, as rayctl update -request does
// (cmd/rayctl/update_request.go): running, then the request goes.
func (h *relayHost) take() nodeupdate.Status {
	h.t.Helper()
	req, ok := h.waiting()
	if !ok {
		h.t.Fatal("no request for root")
	}
	st := nodeupdate.Status{ID: req.ID, State: nodeupdate.Running, From: h.u.version, To: req.Version, Target: req.Version, Release: req.Tried(),
		By: req.By, Kind: req.Kind, Requested: req.At, Started: h.clock, Held: nodeupdate.ReadStatus(h.status).Holding()}
	h.setStatus(st)
	if err := nodeupdate.RemoveRequest(h.request); err != nil {
		h.t.Fatal(err)
	}
	return st
}

// end is the update root took ending: held when it changed the relay and
// did not hold.
func (h *relayHost) end(st nodeupdate.Status, state, reason string, untouched bool, text string) {
	h.t.Helper()
	st.State, st.Reason, st.Untouched, st.Error, st.Ended = state, reason, untouched, text, h.clock
	if state == nodeupdate.RolledBack || state == nodeupdate.Failed && !untouched {
		st.Held = nodeupdate.Hold(st.Held, st.Release)
	}
	h.setStatus(st)
}

// §3.5 in its order, on temporary directories: root's policy, a release
// newer than this relay's, none held, a failure that left the relay as it
// was tried again 6 h later, none while a request waits or an update runs,
// at most one request in 10 min and six a day; the request then goes in
// once, whole, for root to check again.
func TestOfferSteps(t *testing.T) {
	h := newRelayHost(t, "v0.28.0")
	h.offer("a1", "v0.29.0")

	// 2. Root has not allowed it (no policy: off): the exit hears so.
	h.look()
	h.none("remote off")
	if r, n := h.told(); n != 1 || r.Remote || r.State != nodeupdate.Idle || r.Version != "v0.28.0" || r.Id != "" || r.At != 0 {
		t.Fatalf("told %v (%d)", r, n)
	}
	h.remote("off")
	h.look()
	h.none("remote off")

	// 3. Not a release, no id, not newer than this relay.
	h.remote("on")
	for _, o := range [][2]string{{"a1", "latest"}, {"a1", "v0.29"}, {"a1", "v" + strings.Repeat("1", 40) + ".0.0"}, {"A1", "v0.29.0"},
		{"", "v0.29.0"}, {strings.Repeat("a", 33), "v0.29.0"}, {"a1", "v0.28.0"}, {"a1", "v0.27.9"}} {
		h.offer(o[0], o[1])
		h.look()
		h.none("offer " + o[0] + " " + o[1])
	}
	if r, _ := h.told(); !r.Remote || r.State != nodeupdate.Idle {
		t.Fatalf("told %v", r)
	}
	// A build that is no release updates by hand.
	dev := newRelayHost(t, "dev")
	dev.remote("on")
	dev.offer("a1", "v0.29.0")
	dev.look()
	dev.none("a dev build")
	if r, _ := dev.told(); r.Version != "" {
		t.Errorf("a dev build told version %q", r.Version)
	}

	// 4. Held: an update to it did not hold here before; the last status
	// rolled back, or a run of it never ended (a power cut).
	h.offer("a1", "v0.29.0")
	for _, s := range []nodeupdate.Status{
		{ID: "b2", Kind: nodeupdate.Exit, State: nodeupdate.Done, Target: "v0.28.0", Held: []string{"v0.29.0"}, Ended: h.clock},
		{ID: "a1", Kind: nodeupdate.Exit, State: nodeupdate.RolledBack, Target: "v0.29.0", Ended: h.clock},
		{ID: "a1", Kind: nodeupdate.Exit, State: nodeupdate.Failed, Reason: nodeupdate.ReasonOpen, Target: "v0.29.0", Ended: h.clock},
		{ID: "a1", Kind: nodeupdate.Exit, State: nodeupdate.Running, Target: "v0.29.0", Release: "v0.29.0", Started: h.clock.Add(-2 * time.Hour)},
	} {
		h.setStatus(s)
		h.look()
		h.none("held, " + s.State)
	}

	// 5. It failed before it changed anything (the download): again 6 h
	// after.
	h.setStatus(nodeupdate.Status{ID: "a1", Kind: nodeupdate.Exit, State: nodeupdate.Failed, Untouched: true, Reason: nodeupdate.ReasonDownload,
		Target: "v0.29.0", Ended: h.clock})
	h.look()
	h.none("untouched, at once")
	h.advance(nodeupdate.RelayRetryAfter - time.Minute)
	h.look()
	h.none("untouched, before 6 h")
	h.advance(time.Minute)

	// 6. A request waits (an earlier rayd relay's, before a restart), or
	// an update runs.
	other := nodeupdate.Request{ID: "c3", Kind: nodeupdate.Exit, Version: "v0.28.1", By: "exit", At: h.clock.Add(-time.Minute)}
	if err := nodeupdate.WriteRequest(h.request, other, h.clock); err != nil {
		t.Fatal(err)
	}
	if h.look() != lookBusy {
		t.Error("not looking every 10 s while a request waits")
	}
	if r, ok := h.waiting(); !ok || r.ID != "c3" {
		t.Fatalf("a waiting request replaced: %+v", r)
	}
	if r, _ := h.told(); r.State != nodeupdate.Requested || r.Id != "c3" || r.Target != "v0.28.1" || r.At != other.At.Unix() {
		t.Fatalf("told %v", r)
	}
	st := h.take()
	h.look()
	h.none("an update runs")
	h.end(st, nodeupdate.Done, "", false, "")

	// 8. The request, whole: the offer's id and release, the relay's clock.
	h.look()
	r, ok := h.waiting()
	if !ok || r.ID != "a1" || r.Kind != nodeupdate.Exit || r.Version != "v0.29.0" || r.By != "exit" || !r.At.Equal(h.clock) {
		t.Fatalf("request %+v", r)
	}
	if err := r.Check(nodeupdate.RelayKinds, "v0.28.0", nodeupdate.ReadStatus(h.status).Holding(), h.clock); err != nil {
		t.Fatalf("root would refuse the request: %v", err)
	}
	if told, _ := h.told(); told.State != nodeupdate.Requested || told.Id != "a1" || told.Target != "v0.29.0" || told.At != h.clock.Unix() {
		t.Fatalf("told %v", told)
	}
	// Once: the same offer again (a recount, a new feed, a restart) writes
	// nothing more, and nothing is left beside it.
	fi, _ := os.Stat(h.request)
	for i := range 3 {
		h.advance(time.Minute)
		h.u.offered(i == 1, &perimeterv1.RelayUpdateOffer{Id: "a1", Version: "v0.29.0"})
		h.look()
	}
	h.restart("v0.28.0")
	h.offer("a1", "v0.29.0")
	h.look()
	if again, _ := os.Stat(h.request); !os.SameFile(fi, again) || !again.ModTime().Equal(fi.ModTime()) {
		t.Error("the request written again")
	}
	if ents, _ := os.ReadDir(filepath.Dir(h.request)); len(ents) != 1 {
		t.Errorf("beside the request: %v", ents)
	}

}

// §3.5, step 7: an exit that names release after release that does not
// exist (each one fails to download, the relay untouched) gets a request
// at most every 10 min and six a day; a restart of rayd relay keeps the
// requests the files show.
func TestRequestLimit(t *testing.T) {
	h := newRelayHost(t, "v0.28.0")
	h.remote("on")
	first, last := h.clock, h.clock
	for i := 1; i <= requestsDaily+1; i++ {
		v := fmt.Sprintf("v0.29.%d", i)
		h.offer("a1", v)
		if i > 1 {
			h.clock = last.Add(requestGap - time.Second)
			h.look()
			h.none(fmt.Sprintf("request %d within 10 min of the last", i))
			h.clock = last.Add(requestGap)
		}
		h.look()
		if i > requestsDaily {
			h.none("a seventh request in a day")
			break
		}
		if r, ok := h.waiting(); !ok || r.Version != v {
			t.Fatalf("request %d: %+v", i, r)
		}
		// The same id as root's last status (the exit's update is the
		// same): a new request all the same.
		if r, _ := h.told(); r.State != nodeupdate.Requested || r.Target != v || r.At != h.clock.Unix() {
			t.Fatalf("request %d told %v", i, r)
		}
		last = h.clock
		if i == 2 {
			// While it waits: the request and the status before it.
			h.restart("v0.28.0")
			h.offer("a1", v)
			h.look()
		}
		h.end(h.take(), nodeupdate.Failed, nodeupdate.ReasonDownload, true, "404")
	}
	h.clock = first.Add(day - time.Second)
	h.look()
	h.none("a seventh request in a day")
	h.clock = first.Add(day)
	h.look()
	if r, ok := h.waiting(); !ok || r.Version != fmt.Sprintf("v0.29.%d", requestsDaily+1) {
		t.Fatalf("a day after the first: %+v", r)
	}
}

// Root's status is read every 10 s while a request waits or an update
// runs, every minute otherwise; the exit hears each change, a whole state,
// and with none every 10 min all the same. A request root never takes
// failed (not_taken) after an hour, and is tried again 6 h later; a run
// with no outcome for an hour failed (interrupted).
func TestUpdateReports(t *testing.T) {
	h := newRelayHost(t, "v0.28.0")
	h.remote("on")
	h.offer("a1", "v0.29.0")
	if h.look() != lookBusy {
		t.Error("not looking every 10 s while requested")
	}
	if r, n := h.told(); n != 1 || r.State != nodeupdate.Requested {
		t.Fatalf("told %v (%d)", r, n)
	}
	h.advance(lookBusy)
	h.look()
	if _, n := h.told(); n != 1 {
		t.Fatal("told again with no change")
	}
	h.advance(heartbeat)
	h.look()
	if r, n := h.told(); n != 2 || r.State != nodeupdate.Requested {
		t.Fatalf("no word in 10 min: %v (%d)", r, n)
	}

	// Root takes it; rayd relay restarts during its own update (rayspa
	// restarts, and it with it): the new one tells where it stands.
	st := h.take()
	if h.look() != lookBusy {
		t.Error("not looking every 10 s while running")
	}
	if r, _ := h.told(); r.State != nodeupdate.Running || r.Id != "a1" || r.Target != "v0.29.0" || r.At != h.clock.Unix() {
		t.Fatalf("told %v", r)
	}
	h.advance(time.Minute)
	h.restart("v0.29.0")
	h.offer("a1", "v0.29.0")
	h.look()
	_, n := h.told()
	h.end(st, nodeupdate.Done, "", false, "")
	if h.look() != lookIdle {
		t.Error("looking every 10 s once done")
	}
	r, m := h.told()
	if m != n+1 || r.State != nodeupdate.Done || r.Version != "v0.29.0" || r.Id != "a1" || r.At != h.clock.Unix() || r.Reason != "" || r.Error != "" {
		t.Fatalf("told %v (%d after %d)", r, m, n)
	}
	h.none("the release it runs")

	// Not taken (the link, too many): again at the next look, though no
	// sooner than 10 s after, whatever wakes it (a new offer, a feed).
	// Refused as it is: again once it changes, or after 10 min.
	h.end(st, nodeupdate.RolledBack, nodeupdate.ReasonCheck, false, "the check failed")
	for _, code := range []connect.Code{connect.CodeUnavailable, connect.CodeResourceExhausted, connect.CodeInvalidArgument} {
		_, n := h.told()
		h.exit.answer = connect.NewError(code, errors.New("no"))
		h.advance(lookBusy)
		h.look()
		h.look()
		h.advance(lookBusy)
		h.look()
		if _, m := h.told(); code == connect.CodeInvalidArgument && m != n+1 || code != connect.CodeInvalidArgument && m != n+2 {
			t.Errorf("%v: %d reports, then %d", code, n, m)
		}
	}
	h.exit.answer = nil
	h.advance(heartbeat)
	h.look()
	if r, _ := h.told(); r.State != nodeupdate.RolledBack || r.Reason != nodeupdate.ReasonCheck || r.Error != "the check failed" {
		t.Fatalf("told %v", r)
	}

	// Not taken within an hour: failed, root's unit did not run it. The
	// request is tried again 6 h after, if the exit still names it.
	h = newRelayHost(t, "v0.28.0")
	h.remote("on")
	h.offer("a1", "v0.29.0")
	h.look()
	asked := h.clock
	h.advance(nodeupdate.Stale - time.Second)
	h.look()
	if r, _ := h.told(); r.State != nodeupdate.Requested {
		t.Fatalf("told %v", r)
	}
	h.advance(time.Second)
	if h.look() != lookIdle {
		t.Error("looking every 10 s at a request not taken")
	}
	if r, _ := h.told(); r.State != nodeupdate.Failed || r.Reason != nodeupdate.ReasonNotTaken || r.Id != "a1" || r.Target != "v0.29.0" ||
		r.At != asked.Add(nodeupdate.Stale).Unix() || r.Error == "" {
		t.Fatalf("told %v", r)
	}
	h.advance(nodeupdate.RelayRetryAfter - time.Second)
	h.look()
	if r, _ := h.waiting(); !r.At.Equal(asked) {
		t.Fatal("asked again before 6 h")
	}
	h.advance(time.Second)
	h.look()
	if r, _ := h.waiting(); !r.At.Equal(h.clock) {
		t.Fatal("not asked again 6 h after")
	}
	if r, _ := h.told(); r.State != nodeupdate.Requested || r.At != h.clock.Unix() {
		t.Fatalf("told %v", r)
	}

	// A run with no outcome for an hour (its runner killed with no word).
	st = h.take()
	h.advance(nodeupdate.Stale)
	h.look()
	if r, _ := h.told(); r.State != nodeupdate.Failed || r.Reason != nodeupdate.ReasonInterrupted || r.At != st.Started.Add(nodeupdate.Stale).Unix() {
		t.Fatalf("told %v", r)
	}
	h.look()
	h.none("a release whose run never ended")

	// A status of another kind (none of the exit's offers): idle; what it
	// holds, carried over as root does, still counts.
	h.setStatus(nodeupdate.Status{ID: "d4", Kind: nodeupdate.Remote, State: nodeupdate.Done, Target: "v0.28.0", Ended: h.clock,
		Held: nodeupdate.ReadStatus(h.status).Holding()})
	h.look()
	if r, _ := h.told(); r.State != nodeupdate.Idle || r.Id != "" || r.At != 0 {
		t.Fatalf("told %v", r)
	}
	h.none("a release held by a status of another kind")
}

// An exit older than the method (Unimplemented) is not called again until
// the next feed, whatever changes meanwhile.
func TestUpdateUnimplemented(t *testing.T) {
	h := newRelayHost(t, "v0.28.0")
	h.exit.answer = connect.NewError(connect.CodeUnimplemented, errors.New("no such method"))
	h.look()
	h.remote("on")
	h.offer("a1", "v0.29.0")
	h.look()
	h.advance(heartbeat)
	h.look()
	if _, n := h.told(); n != 1 {
		t.Fatalf("%d calls in one feed", n)
	}
	if _, ok := h.waiting(); !ok {
		t.Fatal("no request: an older exit's silence stopped the update")
	}
	// A feed away: nothing said, nothing asked for.
	h.u.closed()
	h.look()
	h.u.offered(true, nil)
	h.look()
	if r, n := h.told(); n != 2 || r.State != nodeupdate.Requested {
		t.Fatalf("a new feed: %v (%d calls)", r, n)
	}
}

// The exit and the phone never get an address or a key out of root's
// text: the install names the exit's address and the relay's admin
// addresses. One printable line, at most 200 bytes.
func TestUpdateErrorRedacted(t *testing.T) {
	h := newRelayHost(t, "v0.28.0")
	h.remote("on")
	for _, text := range []string{
		"no perimeter from its exit 203.0.113.2 (API port 8443) within 45 s\n\tdial tcp [2001:db8:5:6::7]:8443: refused\x00",
		"SSH port [tcp/22], its admin addresses [2001:db8:1::/48 198.51.100.7/32 2001:db8::]: on the exit rayctl relay set",
		"key mlkem768x25519plus.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCd, exit at 203.0.113.2:8443",
	} {
		h.setStatus(nodeupdate.Status{ID: "a1", Kind: nodeupdate.Exit, State: nodeupdate.RolledBack, Reason: nodeupdate.ReasonInstall,
			Target: "v0.29.0", Error: text, Ended: h.clock})
		h.look()
		r, _ := h.told()
		for _, leak := range []string{"203.0.113", "2001:db8", "198.51.100", "AbCdEfGh", "\n", "\t", "\x00"} {
			if strings.Contains(r.Error, leak) {
				t.Errorf("leaked %q: %q", leak, r.Error)
			}
		}
		// Not cut: all of it was looked at.
		if len(r.Error) > 200 || strings.HasSuffix(r.Error, "…") || !utf8.ValidString(r.Error) || !strings.Contains(r.Error, "<ip") {
			t.Errorf("error %q (%d bytes)", r.Error, len(r.Error))
		}
		// The same text, the same tokens: no change to tell.
		_, n := h.told()
		h.advance(time.Minute)
		h.look()
		if _, m := h.told(); m != n {
			t.Error("the same status told again: its tokens changed")
		}
	}
	// Root cut its text (512 bytes) inside an address, which no pattern
	// knows for one then; and text past 200 bytes.
	for _, tail := range []string{"203.0.113.2 from there", "2001:db8:1:2::9 from there"} {
		long := "key " + strings.Repeat("A", 497) + " " + tail
		h.setStatus(nodeupdate.Status{ID: "a1", Kind: nodeupdate.Exit, State: nodeupdate.Failed, Untouched: true, Target: "v0.29.0", Error: long, Ended: h.clock})
		if s := nodeupdate.ReadStatus(h.status); !strings.HasSuffix(s.Error, "…") {
			t.Fatalf("root kept %q", s.Error)
		}
		h.look()
		if r, _ := h.told(); strings.Contains(r.Error, tail[:6]) || !strings.HasSuffix(r.Error, "…") || len(r.Error) > 200 {
			t.Errorf("root's cut text: %q", r.Error)
		}
	}
	h.setStatus(nodeupdate.Status{ID: "a1", Kind: nodeupdate.Exit, State: nodeupdate.Failed, Untouched: true, Target: "v0.29.0",
		Error: strings.Repeat("é ", 100), Ended: h.clock})
	h.look()
	if r, _ := h.told(); len(r.Error) > 200 || !utf8.ValidString(r.Error) || !strings.HasSuffix(r.Error, "…") {
		t.Errorf("long text: %q (%d bytes)", r.Error, len(r.Error))
	}
}

// The files as they may be found: rayd relay's directory missing (the
// exit hears why nothing moves; asked again once it is there), the
// request replaced with a link (not followed, read or written through),
// root's status a FIFO no one writes (no wait).
func TestUpdateFiles(t *testing.T) {
	h := newRelayHost(t, "v0.28.0")
	h.remote("on")
	dir := filepath.Dir(h.request)
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	h.offer("a1", "v0.29.0")
	h.look()
	r, _ := h.told()
	if r.State != nodeupdate.Failed || r.Id != "a1" || r.Target != "v0.29.0" || r.Reason != "" || !strings.Contains(r.Error, "not written") {
		t.Fatalf("told %v", r)
	}
	h.advance(time.Minute)
	h.look()
	if again, n := h.told(); n != 1 || again.At != r.At {
		t.Fatalf("told again with no change: %v (%d)", again, n)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	h.advance(time.Minute)
	h.look()
	if r, ok := h.waiting(); !ok || r.ID != "a1" {
		t.Fatal("no request once the directory is there")
	}
	if r, _ := h.told(); r.State != nodeupdate.Requested {
		t.Fatalf("told %v", r)
	}

	// A link where the request goes, to a fresh request elsewhere: not
	// one of rayd relay's, and replaced, not written through.
	h = newRelayHost(t, "v0.28.0")
	h.remote("on")
	victim := filepath.Join(t.TempDir(), "victim")
	if err := nodeupdate.WriteRequest(victim, nodeupdate.Request{ID: "e5", Kind: nodeupdate.Exit, Version: "v0.28.5", By: "exit", At: h.clock}, h.clock); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(victim)
	if err := os.Symlink(victim, h.request); err != nil {
		t.Fatal(err)
	}
	h.offer("a1", "v0.29.0")
	h.look()
	if after, _ := os.ReadFile(victim); string(after) != string(before) {
		t.Error("written through the link")
	}
	if fi, err := os.Lstat(h.request); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("the request: %v %v", fi, err)
	}
	if r, ok := h.waiting(); !ok || r.ID != "a1" {
		t.Fatalf("request %+v", r)
	}

	// Root's files as FIFOs: read at once, as none (idle, off).
	h = newRelayHost(t, "v0.28.0")
	for _, p := range []string{h.status, h.policy} {
		if err := syscall.Mkfifo(p, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h.offer("a1", "v0.29.0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.look()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a look waits on root's files")
	}
	if r, _ := h.told(); r.State != nodeupdate.Idle || r.Remote {
		t.Fatalf("told %v", r)
	}
	h.none("no policy to read")
}

// Through the feed: rayd relay's feed asks for offers; the one the exit
// sends goes to a request and the exit hears of it; an exit whose
// ReportUpdate hangs holds up neither the feed nor the devices; Watch
// ends with its context, the updates with it.
func TestUpdatesFeed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var key [spa.KeySize]byte
	key[0] = 9
	release := make(chan struct{})
	e := &exit{drop: make(chan struct{}), snap: &perimeterv1.Snapshot{},
		offer: &perimeterv1.RelayUpdateOffer{Id: "a1", Version: "v0.29.0", EndedAt: time.Now().Add(-48 * time.Hour).Unix()}}
	e.tell = func(ctx context.Context) error {
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	_, hd := perimeterv1connect.NewRelayServiceHandler(e)
	hs := httptest.NewUnstartedServer(hd)
	hs.EnableHTTP2 = true
	hs.StartTLS()
	defer hs.Close()

	root := t.TempDir()
	request := filepath.Join(t.TempDir(), "update-request")
	if err := nodeupdate.WritePolicy(filepath.Join(root, "policy.json"), nodeupdate.Policy{Remote: "on", Auto: "off", Window: nodeupdate.DefaultWindow}); err != nil {
		t.Fatal(err)
	}
	s := &Server{Name: "r1", Exit: perimeterv1connect.NewRelayServiceClient(hs.Client(), hs.URL), Log: slog.New(slog.DiscardHandler),
		Updates: NewUpdates("v0.28.0", request, root, nil)}
	s.Updates.busyLook, s.Updates.idleLook = 10*time.Millisecond, 10*time.Millisecond
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		s.Watch(ctx)
	}()
	wait := func(what string, cond func() bool) {
		t.Helper()
		for range 1000 {
			if cond() {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal(what)
	}
	wait("no request", func() bool { _, ok := nodeupdate.PeekRequest(request); return ok })
	if r, _ := nodeupdate.PeekRequest(request); r.ID != "a1" || r.Version != "v0.29.0" || r.Kind != nodeupdate.Exit {
		t.Fatalf("request %+v", r)
	}
	e.mu.Lock()
	if !e.updates || !e.probe {
		t.Error("the feed did not ask for offers")
	}
	e.mu.Unlock()

	// The exit's ReportUpdate hangs: a new feed, with a device, still
	// comes through.
	e.mu.Lock()
	e.snap = &perimeterv1.Snapshot{Devices: []*perimeterv1.Device{{Id: "dev1", Key: key[:], Allowed: []uint32{uint32(provision.RelayProbeSvc)}}}}
	close(e.drop)
	e.drop = make(chan struct{})
	e.mu.Unlock()
	wait("the feed held up by a report", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		_, ok := s.devices["dev1"]
		return ok && s.up
	})
	close(release)
	wait("no report", func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		return slices.ContainsFunc(e.told, func(r *perimeterv1.RelayUpdate) bool { return r.State == nodeupdate.Requested && r.Id == "a1" })
	})

	// An exit before the method: one call a feed, whatever changes. Root
	// takes the request, then the update is done.
	e.mu.Lock()
	e.tell = nil
	e.mu.Unlock()
	req, _ := nodeupdate.PeekRequest(request)
	st := nodeupdate.Status{ID: req.ID, State: nodeupdate.Running, Target: req.Version, Release: req.Version, By: req.By, Kind: req.Kind,
		Requested: req.At, Started: time.Now()}
	if err := nodeupdate.WriteStatus(filepath.Join(root, "status.json"), st); err != nil {
		t.Fatal(err)
	}
	if err := nodeupdate.RemoveRequest(request); err != nil {
		t.Fatal(err)
	}
	told := func(state string) func() bool {
		return func() bool {
			e.mu.Lock()
			defer e.mu.Unlock()
			return len(e.told) > 0 && e.told[len(e.told)-1].State == state
		}
	}
	calls := func() int { e.mu.Lock(); defer e.mu.Unlock(); return len(e.told) }
	wait("running not told", told(nodeupdate.Running))
	n := calls()
	st.State, st.Ended = nodeupdate.Done, time.Now()
	if err := nodeupdate.WriteStatus(filepath.Join(root, "status.json"), st); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // ten looks
	if calls() != n {
		t.Fatalf("%d calls to an exit without the method in one feed", calls()-n+1)
	}
	e.mu.Lock()
	feeds := e.feeds
	close(e.drop)
	e.drop = make(chan struct{})
	e.mu.Unlock()
	wait("done not told in the next feed", told(nodeupdate.Done))
	time.Sleep(100 * time.Millisecond)
	e.mu.Lock()
	if len(e.told) != n+1 || e.feeds != feeds+1 {
		t.Errorf("%d calls in %d feeds", len(e.told)-n, e.feeds-feeds)
	}
	e.mu.Unlock()

	cancel()
	select {
	case <-watched:
	case <-time.After(5 * time.Second):
		t.Fatal("Watch did not end with its context")
	}
	// Nobody takes a wake-up any more: the loop ended with Watch.
	select {
	case s.Updates.wake <- struct{}{}:
	default:
	}
	time.Sleep(50 * time.Millisecond)
	select {
	case s.Updates.wake <- struct{}{}:
		t.Error("the updates' loop outlived Watch")
	default:
	}
}
