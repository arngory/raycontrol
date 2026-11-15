package api

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/redact"
	"github.com/arngory/raycontrol/internal/release"
	"github.com/arngory/raycontrol/internal/store"
)

// The exit's side of the relays' updates by its word
// (spec/relay-update-remote-v1.md): once an update of its own is done, it
// names the release it runs to its relays (§3.3), one relay at a time by
// name, in the feed each already holds (WatchRelay, a feed with updates
// only), and takes what they say of it back (ReportUpdate).

// TurnTimeout is how long a relay keeps its turn once the exit gave it and
// no outcome came: longer than the relay's update unit may run (15 min to
// start, then 5 to stop and 5 for ExecStopPost: 25 min), so that a relay
// updating, whose feed drops while its rayd relay restarts, keeps it; a
// relay that never answers, or says what it likes, holds the others back
// no longer.
const TurnTimeout = 30 * time.Minute

// relayUpdateKey prefixes a relay's name in the settings table: its last
// report there and its turn (§8.3), as JSON of relayRecord. No migration:
// a rollback of the node keeps its database.
const relayUpdateKey = "relay-update/"

// Bounds of a relay's reports (§3.2, §3.6). An honest relay reports once
// per change and every 10 minutes, one call at a time.
const (
	maxUpdateReports = 12 // a minute
	maxUpdateReport  = 1 << 10
	maxUpdateError   = 200
	maxUpdateVersion = 40
	// relaySeenEvery: when a relay was last heard of goes to its record
	// this often at most; an open feed keeps it fresh in memory.
	relaySeenEvery = 10 * time.Minute
)

// noWord is the reason the exit gives an update a relay said it began and
// never said more of within nodeupdate.Stale, and an offer the queue went
// past with no word on it from the relay (§3.7, §8.2).
const noWord = "no_word"

// relayRecord is what the exit keeps of a relay's updates (§8.3): its last
// report, the fields of node.v1 RelayUpdateStatus but the state for the
// phone, which is derived when read, and the relay's own state it is
// derived from; and its turn in the queue. Times are the exit's clock,
// unix seconds.
type relayRecord struct {
	Version  string `json:"version,omitempty"`
	Remote   bool   `json:"remote,omitempty"`
	Reported string `json:"reported,omitempty"` // the relay's state (§3.4); "" no report yet
	Target   string `json:"target,omitempty"`
	UpdateID string `json:"update_id,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Error    string `json:"error,omitempty"`
	// ChangedAt is when Reported, UpdateID, Version or Remote last changed.
	ChangedAt int64 `json:"changed_at,omitempty"`
	// TurnID and TurnAt are the relay's last turn (§3.3): the offer the
	// exit gave it to take, and when. Only the exit sets them, as it gives
	// a turn (relayOffers); nothing the relay says moves them. The relay
	// counts as updating only within its turn: TurnTimeout from TurnAt.
	TurnID string `json:"turn_id,omitempty"`
	TurnAt int64  `json:"turn_at,omitempty"`
	SeenAt int64  `json:"seen_at,omitempty"`
}

// readRelayRecord is relay name's record; none (Reported "") when there is
// none, or it cannot be read.
func readRelayRecord(ctx context.Context, st *store.Store, name string) (relayRecord, error) {
	var r relayRecord
	b, err := st.GetSetting(ctx, relayUpdateKey+name)
	if errors.Is(err, store.ErrNotFound) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	if json.Unmarshal(b, &r) != nil {
		return relayRecord{}, nil
	}
	return r, nil
}

// underway: the relay's state of an update asked for and not ended.
func underway(state string) bool { return state == nodeupdate.Requested || state == nodeupdate.Running }

// ended: the relay's state of an update that has an outcome.
func ended(state string) bool {
	return state == nodeupdate.Done || state == nodeupdate.RolledBack || state == nodeupdate.Failed
}

// atLeast reports whether release v is target or newer.
func atLeast(v, target string) bool { return release.IsRelease(v) && !release.Newer(target, v) }

// validUpdateID: 1-32 lowercase hex, as a request's (nodeupdate.Request.Check).
func validUpdateID(id string) bool {
	return id != "" && len(id) <= 32 && strings.Trim(id, "0123456789abcdef") == ""
}

// relayOffer is what the exit names its relays (§3.3 points 1-3), nil for
// nothing: the last update, settled at now (st), is done, by request or by
// hand (Local) without -no-relays; it put in a release, and this rayd runs
// that release (version: one installed by hand past rayctl update since
// differs); and no update waits or runs. An update that rolled back or
// failed names nothing: the relays stay on what holds.
func relayOffer(st nodeupdate.Status, req nodeupdate.Request, waiting bool, version string, now time.Time) *perimeterv1.RelayUpdateOffer {
	switch {
	case st.State != nodeupdate.Done || st.NoRelays:
		return nil
	case st.Kind != nodeupdate.Remote && st.Kind != nodeupdate.Auto && st.Kind != nodeupdate.Local:
		return nil
	case !release.IsRelease(st.To) || st.To != version || !validUpdateID(st.ID):
		return nil
	case nodeupdate.Busy(st, req, waiting, now):
		return nil
	}
	return &perimeterv1.RelayUpdateOffer{Id: st.ID, Version: st.To, EndedAt: unixOf(st.Ended)}
}

// relayOfferNow is what the exit names its relays at now, its queue aside.
func (s *Server) relayOfferNow(now time.Time) *perimeterv1.RelayUpdateOffer {
	st, req, waiting := s.NodeUpdate.current(now)
	return relayOffer(st, req, waiting, s.Version, now)
}

// offerKey names an offer for comparison, "" none.
func offerKey(o *perimeterv1.RelayUpdateOffer) string {
	if o == nil {
		return ""
	}
	return o.Id + " " + o.Version + " " + strconv.FormatInt(o.EndedAt, 10)
}

// relayUpdates is what the exit keeps in memory of its relays' updates:
// their feeds with updates, the offer each last sent, and the wakeups of
// those feeds. The queue is worked out anew from it and the stored records
// at every look (the turns are in the records), so after a restart of the
// exit from the records alone. The zero value is ready.
type relayUpdates struct {
	mu      sync.Mutex
	started time.Time // the first look: a relay not seen since was not seen before it
	relays  map[string]*relayLive
	red     *redact.Redactor // the relays' errors, once more: one salt while rayd runs
	// turnMu holds a look at the queue that may give a turn, and a relay's
	// removal or addition, as one (§3.3): two looks never give two turns
	// at once, and none goes to a relay removed meanwhile or to a new one
	// of its name. Taken before saveMu.
	turnMu sync.Mutex
	// saveMu holds a record's read and write as one, and a relay's removal
	// with its record's: a report taken after the removal finds no relay.
	saveMu sync.Mutex
}

type relayLive struct {
	feeds    int       // feeds with updates open
	closedAt time.Time // when the last of them closed
	sent     string    // the offer its feeds last sent (offerKey)
	want     string    // the offer the last kick found for it
	kicks    uint64    // the kicks that looked at it
	wake     chan struct{}

	listening int       // feeds open, any
	seen      time.Time // when it was last heard of: a feed, a report
	seenSaved time.Time // when that last went to its record
	reporting bool      // a ReportUpdate under way
	calls     []time.Time
}

// live is relay name's, under mu.
func (ru *relayUpdates) live(name string, now time.Time) *relayLive {
	ru.start(now)
	if ru.relays == nil {
		ru.relays = map[string]*relayLive{}
	}
	l := ru.relays[name]
	if l == nil {
		l = &relayLive{}
		ru.relays[name] = l
	}
	return l
}

func (ru *relayUpdates) start(now time.Time) time.Time {
	if ru.started.IsZero() {
		ru.started = now
	}
	return ru.started
}

func (l *relayLive) wakeUp() {
	if l.wake != nil {
		close(l.wake)
		l.wake = nil
	}
}

// opened and closed count relay name's feeds with updates.
func (ru *relayUpdates) opened(name string, now time.Time) {
	ru.mu.Lock()
	defer ru.mu.Unlock()
	ru.live(name, now).feeds++
}

func (ru *relayUpdates) closed(name string, now time.Time) {
	ru.mu.Lock()
	defer ru.mu.Unlock()
	l := ru.live(name, now)
	l.feeds--
	l.closedAt = now
}

// changes is closed when the offer for relay name may no longer be what
// its feeds sent; kicks is what sentOffer takes back.
func (ru *relayUpdates) changes(name string, now time.Time) (wake <-chan struct{}, kicks uint64) {
	ru.mu.Lock()
	defer ru.mu.Unlock()
	l := ru.live(name, now)
	if l.wake == nil {
		l.wake = make(chan struct{})
	}
	return l.wake, l.kicks
}

// sentOffer records that a feed of relay name, which looked after kicks
// kicks, has o in it. A kick since that found another offer for the relay
// wakes the feed again, or it would sleep on a stale one.
func (ru *relayUpdates) sentOffer(name string, o *perimeterv1.RelayUpdateOffer, kicks uint64, now time.Time) {
	ru.mu.Lock()
	defer ru.mu.Unlock()
	l := ru.live(name, now)
	l.sent = offerKey(o)
	if l.kicks != kicks && l.want != l.sent {
		l.wakeUp()
	}
}

// relayView is a relay as the queue sees it.
type relayView struct {
	Name     string
	Rec      relayRecord // Reported "": no report ever
	Feeds    int         // feeds with updates open
	ClosedAt time.Time   // when the last closed, or the exit's first look
}

// turn is when the exit gave relay r its turn for update id, if it did.
func (r relayView) turn(id string) (time.Time, bool) {
	if id == "" || r.Rec.TurnID != id || r.Rec.TurnAt == 0 {
		return time.Time{}, false
	}
	return time.Unix(r.Rec.TurnAt, 0), true
}

// updating reports whether relay r is updating at now as the queue counts
// it (§3.3, §6): it says an update is under way, for the turn the exit
// gave it (for this offer, or for the one before: the node updated again
// meanwhile, and rayd restarted), less than TurnTimeout since the exit
// gave it. What it says of any other update, or later, holds nobody back.
func (r relayView) updating(now time.Time) bool {
	at, ok := r.turn(r.Rec.UpdateID)
	return underway(r.Rec.Reported) && ok && now.Sub(at) < TurnTimeout
}

// passed reports whether relay r is past its turn for offer o (§3.3): it
// reported an outcome of o (a refusal before any change included); or,
// unless it is updating (updating: that goes on regardless, whatever its
// version or root's switch say meanwhile), it runs o's release or newer,
// root on it does not take offers, it never reported and has no feed with
// updates (an older relay, no rayd relay) and was not given o (it may be
// updating, its report lost), it has had no such feed for TurnTimeout, or
// its turn for o began TurnTimeout ago with no outcome.
func (r relayView) passed(o *perimeterv1.RelayUpdateOffer, now time.Time) bool {
	rec, reported := r.Rec, r.Rec.Reported != ""
	given, ok := r.turn(o.Id)
	switch {
	case reported && rec.UpdateID == o.Id && ended(rec.Reported):
		return true
	case r.updating(now):
		return false
	case reported && (atLeast(rec.Version, o.Version) || !rec.Remote):
		return true
	case !reported && r.Feeds == 0 && !ok:
		return true
	case reported && r.Feeds == 0 && now.Sub(r.ClosedAt) >= TurnTimeout:
		return true
	}
	return ok && now.Sub(given) >= TurnTimeout
}

// tookLate reports whether relay r, past its turn for o, took o all the
// same: it says an update to o is under way, and said so after its turn
// for o ran out, or with no turn for o (§3.5 step 5's retry after a
// failure before any change; a relay back after its turn ran out).
func (r relayView) tookLate(o *perimeterv1.RelayUpdateOffer) bool {
	if !underway(r.Rec.Reported) || r.Rec.UpdateID != o.Id {
		return false
	}
	at, ok := r.turn(o.Id)
	return !ok || r.Rec.ChangedAt >= at.Add(TurnTimeout).Unix()
}

// passedAt is when relay r went past its turn for o with no word on it,
// and why, for the phone (§8.2).
func (r relayView) passedAt(o *perimeterv1.RelayUpdateOffer, now time.Time) (int64, string) {
	if at, ok := r.turn(o.Id); ok && now.Sub(at) >= TurnTimeout {
		return at.Add(TurnTimeout).Unix(), "no word from the relay on this update within its turn (" + TurnTimeout.String() + ")"
	}
	if r.Feeds == 0 && now.Sub(r.ClosedAt) >= TurnTimeout {
		return r.ClosedAt.Add(TurnTimeout).Unix(), "no word from the relay: its rayd relay has been away for " + TurnTimeout.String()
	}
	return now.Unix(), "no word from the relay on this update"
}

// relayTurn is where a relay stands in the queue for an offer.
type relayTurn struct {
	Passed bool // past its turn (relayView.passed)
	Busy   bool // not past it, and holding its turn or updating: the others wait
	Offer  bool // the offer goes in its feed
	Give   bool // and with it a turn, which the exit gives it now
}

// relayQueue is the queue for offer o (§3.3): the relays by name, one at a
// time. A relay's turn comes when every relay before it passed and no
// other is busy; the exit gives it then, with the offer in its feed (Give;
// never to a relay without a feed with updates). One that has its turn
// keeps it until it passes, whatever came before it since (a relay back
// after a while, a root that turned remote on), so that two never update
// at once; one updating in its turn for an earlier offer finishes that
// first. A relay on the release has the offer whenever its turn came: to
// it the offer is nothing, and taking it away from it while another
// updates would only make its feed send again. Any other relay past its
// turn (it failed, it was away, its turn ran out) has the offer only once
// the queue is through (every relay passed) and nobody updates; if it
// takes it then (tookLate), that is a later turn, given as it says so.
// views are sorted by name.
func relayQueue(o *perimeterv1.RelayUpdateOffer, views []relayView, now time.Time) []relayTurn {
	turns := make([]relayTurn, len(views))
	busy, through := 0, true
	for i, r := range views {
		t := &turns[i]
		t.Passed = r.passed(o, now)
		if t.Busy = !t.Passed && (r.Rec.TurnID == o.Id || r.updating(now)); t.Busy {
			busy++
		}
		through = through && t.Passed
	}
	before := true // every relay before this one passed
	for i, r := range views {
		t := &turns[i]
		others := busy
		if t.Busy {
			others--
		}
		switch {
		case t.Busy:
			t.Offer = r.Rec.TurnID == o.Id // its turn; or o after its update for the one before
		case !t.Passed:
			t.Offer = before && others == 0 && r.Feeds > 0
			t.Give = t.Offer
		case atLeast(r.Rec.Version, o.Version):
			t.Offer = before
		default:
			t.Offer = through && others == 0
			t.Give = t.Offer && r.Feeds > 0 && r.tookLate(o)
		}
		before = before && t.Passed
	}
	return turns
}

// relayViews are the relays as the queue sees them, by name.
func (s *Server) relayViews(ctx context.Context, now time.Time) ([]relayView, error) {
	relays, err := s.Store.ListRelays(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]relayView, 0, len(relays))
	for _, r := range relays {
		rec, err := readRelayRecord(ctx, s.Store, r.Name)
		if err != nil {
			return nil, err
		}
		views = append(views, relayView{Name: r.Name, Rec: rec})
	}
	ru := &s.relayUpd
	ru.mu.Lock()
	start := ru.start(now)
	for i := range views {
		v := &views[i]
		v.ClosedAt = start
		if l := ru.relays[v.Name]; l != nil {
			v.Feeds = l.feeds
			if !l.closedAt.IsZero() {
				v.ClosedAt = l.closedAt
			}
		}
	}
	ru.mu.Unlock()
	slices.SortFunc(views, func(a, b relayView) int { return strings.Compare(a.Name, b.Name) })
	return views, nil
}

// relayOffers is what is in each relay's feed at now, by name, and whether
// a turn was given meanwhile: the other feeds may have changed. The exit
// gives a turn here, under turnMu, and writes it in the relay's record
// before any feed sends it: two looks at once never give two, and after a
// restart of the exit the queue goes on from the records.
func (s *Server) relayOffers(ctx context.Context, now time.Time) (offers map[string]*perimeterv1.RelayUpdateOffer, gave bool, err error) {
	o := s.relayOfferNow(now)
	if o == nil {
		return nil, false, nil
	}
	ru := &s.relayUpd
	ru.turnMu.Lock()
	defer ru.turnMu.Unlock()
	// A turn given changes the queue: once more with it. No second one is
	// given then, as the first holds the others back.
	for pass := 0; ; pass++ {
		views, err := s.relayViews(ctx, now)
		if err != nil {
			return nil, gave, err
		}
		turns := relayQueue(o, views, now)
		var give []string
		for i, t := range turns {
			if t.Give && pass < 2 {
				give = append(give, views[i].Name)
			}
		}
		if len(give) == 0 {
			offers = map[string]*perimeterv1.RelayUpdateOffer{}
			for i, t := range turns {
				if t.Offer && !t.Give {
					offers[views[i].Name] = o
				}
			}
			return offers, gave, nil
		}
		for _, name := range give {
			_, _, err := s.updateRelayRecord(ctx, name, func(r *relayRecord) { r.TurnID, r.TurnAt = o.Id, now.Unix() })
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return nil, gave, err
			}
		}
		gave = true
	}
}

// kickRelayFeeds wakes the feeds with updates whose offer is no longer
// what they sent, after a change of the queue: a report, a feed with
// updates opened or closed, a turn given. Only those: a feed whose answer
// stays sleeps on. What changes with time alone (TurnTimeout, the status
// root wrote) each feed finds at its next look.
func (s *Server) kickRelayFeeds(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	now := s.NodeUpdate.now()
	offers, _, err := s.relayOffers(ctx, now)
	ru := &s.relayUpd
	ru.mu.Lock()
	defer ru.mu.Unlock()
	for name, l := range ru.relays {
		if l.feeds == 0 {
			continue
		}
		if err != nil {
			l.wakeUp() // each feed finds out for itself
			continue
		}
		l.kicks++
		if l.want = offerKey(offers[name]); l.want != l.sent {
			l.wakeUp()
		}
	}
}

// forget drops what the exit keeps in memory of a relay removed, or added
// by the name of one removed: it starts afresh. Its open feeds end at the
// removal's notify and count themselves out. Its turn is in its record,
// which goes with it.
func (ru *relayUpdates) forget(name string) {
	ru.mu.Lock()
	defer ru.mu.Unlock()
	if l := ru.relays[name]; l != nil {
		l.seen, l.seenSaved = time.Time{}, time.Time{}
	}
}

// listen counts relay name's feeds, any: while one is open the relay is
// heard of.
func (ru *relayUpdates) listen(name string, n int, now time.Time) {
	ru.mu.Lock()
	defer ru.mu.Unlock()
	l := ru.live(name, now)
	l.listening += n
	l.seen = now
}

// heard records that relay name was heard of at now, and whether its record
// is due to keep it.
func (ru *relayUpdates) heard(name string, now time.Time) (due bool) {
	ru.mu.Lock()
	defer ru.mu.Unlock()
	l := ru.live(name, now)
	l.seen = now
	if due = now.Sub(l.seenSaved) >= relaySeenEvery; due {
		l.seenSaved = now
	}
	return due
}

// relayHeard records that relay name was heard of at now (a feed's look,
// a summary report), in its record at most every relaySeenEvery.
func (s *Server) relayHeard(ctx context.Context, name string, now time.Time) {
	if !s.relayUpd.heard(name, now) {
		return
	}
	_, _, _ = s.updateRelayRecord(ctx, name, func(r *relayRecord) { r.SeenAt = now.Unix() })
}

// admit lets one ReportUpdate of relay name run at a time, and
// maxUpdateReports a minute; done ends it.
func (ru *relayUpdates) admit(name string, now time.Time) (done func(), err error) {
	ru.mu.Lock()
	defer ru.mu.Unlock()
	l := ru.live(name, now)
	if l.reporting {
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("one report at a time"))
	}
	l.calls = slices.DeleteFunc(l.calls, func(t time.Time) bool { return now.Sub(t) >= time.Minute })
	if len(l.calls) >= maxUpdateReports {
		return nil, connect.NewError(connect.CodeResourceExhausted, fmt.Errorf("at most %d reports a minute", maxUpdateReports))
	}
	l.calls, l.reporting = append(l.calls, now), true
	return func() {
		ru.mu.Lock()
		l.reporting = false
		ru.mu.Unlock()
	}, nil
}

// relayStates are the states a relay reports (§3.4); another is a change
// of the protocol.
var relayStates = []string{nodeupdate.Idle, nodeupdate.Requested, nodeupdate.Running, nodeupdate.Done, nodeupdate.RolledBack, nodeupdate.Failed}

// relayVersion: "" or vX.Y.Z, maxUpdateVersion bytes at most.
func relayVersion(v string) bool {
	return v == "" || len(v) <= maxUpdateVersion && release.IsRelease(v)
}

// checkRelayUpdate is a relay's report within its bounds (§3.6), as a
// record, its error cleaned by clean; an error says which bound it broke.
// A reason is taken by its form: a relay may be newer than its exit.
func checkRelayUpdate(m *perimeterv1.ReportUpdateRequest, clean func(string) string) (relayRecord, error) {
	u := m.GetUpdate()
	switch {
	case proto.Size(m) > maxUpdateReport:
		return relayRecord{}, fmt.Errorf("a report is at most %d bytes", maxUpdateReport)
	case u == nil:
		return relayRecord{}, errors.New("no update")
	case !relayVersion(u.Version) || !relayVersion(u.Target):
		return relayRecord{}, errors.New("version and target: vX.Y.Z or none")
	case !slices.Contains(relayStates, u.State):
		return relayRecord{}, fmt.Errorf("state: one of %s", strings.Join(relayStates, ", "))
	case u.Id != "" && !validUpdateID(u.Id):
		return relayRecord{}, errors.New("id: 1-32 hex or none")
	case !nodeupdate.ValidReason(u.Reason):
		return relayRecord{}, errors.New("reason: [a-z][a-z_]{0,31} or none")
	case len(u.Error) > maxUpdateError:
		return relayRecord{}, fmt.Errorf("error: at most %d bytes", maxUpdateError)
	}
	return relayRecord{Version: u.Version, Remote: u.Remote, Reported: u.State, Target: u.Target, UpdateID: u.Id, Reason: u.Reason,
		Error: clean(u.Error)}, nil
}

// cleanRelayError is a relay's error as the exit keeps and shows it: the
// relay redacted it, and the exit does it again (§6), with its own names
// and one salt while rayd runs, so the same text stays the same; then
// what a terminal would act on goes, and it is cut to maxUpdateError
// bytes, on a rune.
func (s *Server) cleanRelayError(ctx context.Context, e string) string {
	if e == "" {
		return ""
	}
	ru := &s.relayUpd
	ru.mu.Lock()
	red := ru.red
	ru.mu.Unlock()
	if red == nil {
		var names []string
		if h, err := node.Host(ctx, s.Store); err == nil && h != "" {
			if _, err := netip.ParseAddr(h); err != nil {
				names = append(names, h)
			}
		}
		red = redact.New(names...)
		ru.mu.Lock()
		if ru.red == nil {
			ru.red = red
		}
		red = ru.red
		ru.mu.Unlock()
	}
	e = nodeupdate.Printable(red.String(e))
	n := min(len(e), maxUpdateError)
	for n < len(e) && n > 0 && !utf8.RuneStart(e[n]) {
		n--
	}
	return e[:n]
}

// updateRelayRecord changes relay name's record with f and writes it if f
// changed it, under saveMu: nothing, and store.ErrNotFound, for a relay
// removed meanwhile.
func (s *Server) updateRelayRecord(ctx context.Context, name string, f func(*relayRecord)) (before, after relayRecord, err error) {
	ru := &s.relayUpd
	ru.saveMu.Lock()
	defer ru.saveMu.Unlock()
	if _, err := s.Store.RelayByName(ctx, name); err != nil {
		return before, after, err
	}
	if before, err = readRelayRecord(ctx, s.Store, name); err != nil {
		return before, after, err
	}
	after = before
	f(&after)
	if after == before {
		return before, after, nil
	}
	b, err := json.Marshal(after)
	if err != nil {
		return before, after, err
	}
	return before, after, s.Store.SetSetting(ctx, relayUpdateKey+name, b)
}

// takeRelayReport keeps relay name's report next, taken at now: written
// only when it says something new, or when the record is due to keep when
// the relay was last heard of. changed reports something new: the state,
// the update, the versions, root's switch, the reason or the error. The
// times are the exit's: when the state, the update, the version or the
// switch last changed. The relay's turn is the exit's: nothing it says
// moves it.
func (s *Server) takeRelayReport(ctx context.Context, name string, next relayRecord, now time.Time) (changed bool, err error) {
	at := now.Unix()
	due := s.relayUpd.heard(name, now)
	before, after, err := s.updateRelayRecord(ctx, name, func(r *relayRecord) {
		prev := *r
		next.ChangedAt, next.TurnID, next.TurnAt, next.SeenAt = prev.ChangedAt, prev.TurnID, prev.TurnAt, prev.SeenAt
		if next.Reported != prev.Reported || next.UpdateID != prev.UpdateID || next.Version != prev.Version || next.Remote != prev.Remote {
			next.ChangedAt = at
		}
		if next != prev || due {
			next.SeenAt = at
		}
		*r = next
	})
	if err != nil {
		return false, err
	}
	before.SeenAt, after.SeenAt = 0, 0
	return before != after, nil
}

// relayUpdateLine is a report as the audit log and the journal have it:
// codes and versions only, never the error, which a relay writes.
func relayUpdateLine(r relayRecord) string {
	line := "relay.update " + r.Reported + " " + cmp.Or(r.Version, "-")
	if r.Target != "" && r.Target != r.Version {
		line += " to " + r.Target
	}
	if r.Reason != "" {
		line += " (" + r.Reason + ")"
	}
	if !r.Remote {
		line += ", remote off"
	}
	return line
}

// relayStatuses are the relays' updates for the phone (§8.2), by name; none
// when the store does not answer: the node's own status matters more.
func (s *Server) relayStatuses(ctx context.Context, st nodeupdate.Status, req nodeupdate.Request, waiting bool, now time.Time) []*nodev1.RelayUpdateStatus {
	views, err := s.relayViews(ctx, now)
	if err != nil {
		return nil
	}
	o := relayOffer(st, req, waiting, s.Version, now)
	turns := make([]relayTurn, len(views))
	if o != nil {
		turns = relayQueue(o, views, now)
	}
	ru := &s.relayUpd
	ru.mu.Lock()
	seen := make([]time.Time, len(views))
	for i, v := range views {
		if l := ru.relays[v.Name]; l != nil {
			seen[i] = l.seen
			if l.listening > 0 {
				seen[i] = now
			}
		}
	}
	ru.mu.Unlock()
	out := make([]*nodev1.RelayUpdateStatus, 0, len(views))
	for i, v := range views {
		if t := time.Unix(v.Rec.SeenAt, 0); v.Rec.SeenAt != 0 && t.After(seen[i]) {
			seen[i] = t
		}
		out = append(out, relayStatus(v, o, turns[i], seen[i], now))
	}
	return out
}

// relayStatus is relay v's update as the phone sees it (§8.2): what it
// reported on the offer o, or else where it stands with it in the queue
// (t). Every state the queue gives ends: offered while the relay holds its
// turn, waiting until its turn comes, and a relay the queue went past with
// no word on o failed, no_word.
func relayStatus(v relayView, o *perimeterv1.RelayUpdateOffer, t relayTurn, seen, now time.Time) *nodev1.RelayUpdateStatus {
	rec := v.Rec
	rs := &nodev1.RelayUpdateStatus{Name: v.Name, Version: rec.Version, Remote: rec.Remote, SeenAt: unixOf(seen)}
	reported := rec.Reported != ""
	// As reported: an update under way that has been silent for Stale is
	// taken as failed, as the node's own (nodeupdate.Settled).
	asReported := func(target string) {
		rs.State, rs.Target, rs.UpdateId, rs.Reason, rs.Error, rs.ChangedAt = rec.Reported, target, rec.UpdateID, rec.Reason, rec.Error, rec.ChangedAt
		if underway(rec.Reported) && now.Sub(time.Unix(rec.ChangedAt, 0)) >= nodeupdate.Stale {
			rs.State, rs.Reason, rs.ChangedAt = nodeupdate.Failed, noWord, rec.ChangedAt+int64(nodeupdate.Stale/time.Second)
			rs.Error = "no word from the relay within " + nodeupdate.Stale.String() + " after " + rec.Reported
		}
	}
	ours := func(state string, at int64) {
		rs.State, rs.Target, rs.UpdateId, rs.ChangedAt = state, o.Version, o.Id, at
	}
	switch {
	case o == nil && !reported:
		rs.State = "unknown"
	case o == nil && underway(rec.Reported):
		asReported(rec.Target) // an update the relay took before, still under way
	case o == nil:
		rs.State, rs.ChangedAt = "current", rec.ChangedAt
	case reported && rec.UpdateID == o.Id && rec.Reported != nodeupdate.Idle:
		asReported(o.Version)
	case t.Busy && rec.TurnID == o.Id:
		ours("offered", rec.TurnAt) // its turn, no word on it yet
	case !reported:
		rs.State = "unknown"
	case atLeast(rec.Version, o.Version):
		ours("current", rec.ChangedAt)
	case underway(rec.Reported):
		asReported(rec.Target) // an earlier update, still under way
	case !rec.Remote:
		ours("off", rec.ChangedAt)
	case !t.Passed:
		ours("waiting", o.EndedAt)
	default:
		// The queue went past it with no word on o: its turn ran out, or
		// it was away.
		at, why := v.passedAt(o, now)
		ours(nodeupdate.Failed, at)
		rs.Reason, rs.Error = noWord, why
	}
	return rs
}
