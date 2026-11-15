package api

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/release"
	"github.com/arngory/raycontrol/internal/store"
)

// The exit's side of the relays' updates by its word
// (spec/relay-update-remote-v1.md): once an update of its own is done, it
// names the release it runs to its relays (§3.3), one relay at a time by
// name, in the feed each already holds (WatchRelay, a feed with updates
// only), and takes what they say of it back (ReportUpdate).

// TurnTimeout is how long a relay keeps its turn once the offer went to it
// and no outcome came: longer than the relay's update unit may run (15
// min), so that a relay updating, whose feed drops while its rayd relay
// restarts, keeps it; a relay that never answers holds the others back no
// longer.
const TurnTimeout = 20 * time.Minute

// relayUpdateKey prefixes a relay's name in the settings table: its last
// report there (§8.3), as JSON of relayRecord. No migration: a rollback of
// the node keeps its database.
const relayUpdateKey = "relay-update/"

// relayRecord is a relay's last report as the exit keeps it (§8.3): the
// fields of node.v1 RelayUpdateStatus but the state for the phone, which
// is derived when read, and the relay's own state it is derived from.
// Times are the exit's clock, unix seconds.
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
	// Since is when the relay first reported UpdateID: its turn for that
	// update began no later, whatever it reported after.
	Since  int64 `json:"since,omitempty"`
	SeenAt int64 `json:"seen_at,omitempty"`
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

// offerKey names an offer for comparison, "" none.
func offerKey(o *perimeterv1.RelayUpdateOffer) string {
	if o == nil {
		return ""
	}
	return o.Id + " " + o.Version + " " + strconv.FormatInt(o.EndedAt, 10)
}

// relayUpdates is what the exit keeps in memory of its relays' updates:
// their feeds with updates, the offer each was given, and the wakeups of
// those feeds. The queue is worked out anew from it and the stored records
// at every look, so after a restart of the exit from the records alone.
// The zero value is ready.
type relayUpdates struct {
	mu      sync.Mutex
	started time.Time // the first look: a relay not seen since was not seen before it
	relays  map[string]*relayLive
}

type relayLive struct {
	feeds     int       // feeds with updates open
	closedAt  time.Time // when the last of them closed
	offerID   string    // the offer the relay was given…
	offeredAt time.Time // …first, by its feed
	sent      string    // the offer its feeds last sent (offerKey)
	want      string    // the offer the last kick found for it
	kicks     uint64    // the kicks that looked at it
	wake      chan struct{}
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
// kicks, has of in its feed. given reports a turn the relay had not been
// given: the queue changed. A kick since that found another offer for the
// relay wakes the feed again, or it would sleep on a stale one.
func (ru *relayUpdates) sentOffer(name string, of relayOffered, kicks uint64, now time.Time) (given bool) {
	ru.mu.Lock()
	defer ru.mu.Unlock()
	l := ru.live(name, now)
	l.sent = offerKey(of.o)
	if of.turn && l.offerID != of.o.Id {
		l.offerID, l.offeredAt, given = of.o.Id, now, true
	}
	if l.kicks != kicks && l.want != l.sent {
		l.wakeUp()
	}
	return given
}

// relayView is a relay as the queue sees it.
type relayView struct {
	Name      string
	Rec       relayRecord // Reported "": no report ever
	Feeds     int         // feeds with updates open
	ClosedAt  time.Time   // when the last closed, or the exit's first look
	OfferID   string
	OfferedAt time.Time
}

// turnStart is when relay r's turn for offer o began, as far as the exit
// knows: when the offer went to it as its turn, or, after a restart of the
// exit, when it first reported on it. Neither moves with what the relay
// says after: a relay holds the others back TurnTimeout at most.
func (r relayView) turnStart(o *perimeterv1.RelayUpdateOffer) (time.Time, bool) {
	var t time.Time
	if r.OfferID == o.Id {
		t = r.OfferedAt
	}
	if r.Rec.UpdateID == o.Id && r.Rec.Since != 0 {
		if c := time.Unix(r.Rec.Since, 0); t.IsZero() || c.Before(t) {
			t = c
		}
	}
	return t, !t.IsZero()
}

// updating reports whether relay r said it is updating, at now, for offer
// o or for the turn the exit gave it before (the node updated again
// meanwhile), less than TurnTimeout since it first said so. An update it
// says it runs for any other id holds nobody back.
func (r relayView) updating(o *perimeterv1.RelayUpdateOffer, now time.Time) bool {
	id := r.Rec.UpdateID
	return underway(r.Rec.Reported) && id != "" && (id == o.Id || id == r.OfferID) && now.Sub(time.Unix(r.Rec.Since, 0)) < TurnTimeout
}

// passed reports whether relay r is past its turn for offer o (§3.3): it
// reported an outcome of o; it runs o's release or newer, or root on it
// does not take offers (unless it is updating, which goes on regardless);
// it never reported and has no feed with updates (an older relay, no rayd
// relay), unless it was given o (it may be updating, its report lost); it
// is not updating and has had no such feed for TurnTimeout; or its turn
// began TurnTimeout ago with no outcome. Updating is as updating has it:
// a last word of an update under way for any other id, or older, keeps
// nobody waiting (a relay stuck since an earlier offer, after a restart
// of the exit; one that says what it likes).
func (r relayView) passed(o *perimeterv1.RelayUpdateOffer, now time.Time) bool {
	rec, reported := r.Rec, r.Rec.Reported != ""
	switch {
	case reported && rec.UpdateID == o.Id && ended(rec.Reported):
		return true
	case reported && atLeast(rec.Version, o.Version):
		return true
	case reported && !rec.Remote && !r.updating(o, now):
		return true
	case !reported && r.Feeds == 0 && r.OfferID != o.Id:
		return true
	case reported && !r.updating(o, now) && r.Feeds == 0 && now.Sub(r.ClosedAt) > TurnTimeout:
		return true
	}
	start, ok := r.turnStart(o)
	return ok && now.Sub(start) > TurnTimeout
}

// relayTurn is where a relay stands in the queue for an offer.
type relayTurn struct {
	Passed bool // past its turn (relayView.passed)
	Busy   bool // not past it, and updating or given the offer: the others wait
	Offer  bool // the offer goes in its feed
}

// relayQueue is the queue for offer o (§3.3): the relays by name, one at a
// time. A relay gets the offer when every relay before it passed and no
// other is busy; one that has it keeps it until it passes, whatever came
// before it since (a relay back after a while, a root that turned remote
// on), so that two never update at once. A relay on the release already
// has it whenever its turn came: to it the offer is nothing, and taking it
// away from it while another updates would only make its feed send again.
// views are sorted by name.
func relayQueue(o *perimeterv1.RelayUpdateOffer, views []relayView, now time.Time) []relayTurn {
	turns := make([]relayTurn, len(views))
	busy := 0
	for i, r := range views {
		turns[i].Passed = r.passed(o, now)
		if turns[i].Busy = !turns[i].Passed && (r.OfferID == o.Id || r.updating(o, now)); turns[i].Busy {
			busy++
		}
	}
	before := true // every relay before this one passed
	for i, r := range views {
		holds := !turns[i].Passed && r.OfferID == o.Id
		others := busy
		if turns[i].Busy {
			others--
		}
		turns[i].Offer = holds || before && (atLeast(r.Rec.Version, o.Version) || others == 0)
		before = before && turns[i].Passed
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
			v.Feeds, v.OfferID, v.OfferedAt = l.feeds, l.offerID, l.offeredAt
			if !l.closedAt.IsZero() {
				v.ClosedAt = l.closedAt
			}
		}
	}
	ru.mu.Unlock()
	slices.SortFunc(views, func(a, b relayView) int { return strings.Compare(a.Name, b.Name) })
	return views, nil
}

// relayOfferNow is what the exit names its relays at now, its queue aside.
func (s *Server) relayOfferNow(now time.Time) *perimeterv1.RelayUpdateOffer {
	st, req, waiting := s.NodeUpdate.current(now)
	return relayOffer(st, req, waiting, s.Version, now)
}

// relayOffered is the offer in a relay's feed (o, nil for none), and
// whether it is the relay's turn: the relay has not passed, and the queue
// waits for it. A relay past its turn has the offer only where it is
// nothing to it or nobody else updates.
type relayOffered struct {
	o    *perimeterv1.RelayUpdateOffer
	turn bool
}

// relayOffers is what is in each relay's feed at now, by name.
func (s *Server) relayOffers(ctx context.Context, now time.Time) (map[string]relayOffered, error) {
	o := s.relayOfferNow(now)
	if o == nil {
		return nil, nil
	}
	views, err := s.relayViews(ctx, now)
	if err != nil {
		return nil, err
	}
	out := map[string]relayOffered{}
	for i, t := range relayQueue(o, views, now) {
		if t.Offer {
			out[views[i].Name] = relayOffered{o, !t.Passed}
		}
	}
	return out, nil
}

// kickRelayFeeds wakes the feeds with updates whose offer is no longer
// what they sent, after a change of the queue: a report, a feed with
// updates opened or closed, an offer given. Only those: a feed whose
// answer stays sleeps on. What changes with time alone (TurnTimeout, the
// status root wrote) each feed finds at its next look.
func (s *Server) kickRelayFeeds(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	now := s.NodeUpdate.now()
	offers, err := s.relayOffers(ctx, now)
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
		if l.want = offerKey(offers[name].o); l.want != l.sent {
			l.wakeUp()
		}
	}
}
