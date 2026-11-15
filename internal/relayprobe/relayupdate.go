package relayprobe

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1/perimeterv1connect"
	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/redact"
	"github.com/arngory/raycontrol/internal/release"
)

const (
	// lookBusy and lookIdle are how often rayd relay reads root's status
	// (spec/relay-update-remote-v1.md §3.7): while a request waits or an
	// update runs, and otherwise.
	lookBusy = 10 * time.Second
	lookIdle = time.Minute
	// heartbeat: with nothing new the exit hears the state this often all
	// the same, so that it knows when it last heard the relay.
	heartbeat = 10 * time.Minute
	// requestGap and requestsDaily bound the requests rayd relay writes
	// (§3.5, step 7): an exit that names releases that do not exist does
	// not send the relay to GitHub without end.
	requestGap    = 10 * time.Minute
	requestsDaily = 6
	day           = 24 * time.Hour
	// maxText bounds a report's error, maxVersion a version (§3.6).
	maxText    = 200
	maxVersion = 40
	// logEvery is how often, at most, the journal has a line of one cause.
	logEvery = time.Minute
)

// Updates is rayd relay's part in the relay's updates by the exit's word
// (spec/relay-update-remote-v1.md §3.5). The exit names in the feed the
// release it runs; rayd relay writes root a request for it when root's
// policy allows it and nothing else stands in the way, reads root's status
// and tells the exit where the relay stands (ReportUpdate), a whole state
// each time. It changes nothing on the host itself: root's unit checks the
// request again and does the update. It runs beside the feed, which never
// waits for it: whatever happens here (a file that cannot be read or
// written, an exit that does not answer), the devices and the probe go on.
//
// The exit is trusted to name a release and no more: only a newer one than
// this rayd relay's goes in a request, none whose update did not hold here,
// at most requestsDaily a day; the exit's clock is not used.
type Updates struct {
	version                 string // this rayd relay's: the relay's release
	request, status, policy string // nodeupdate.RelayRequestFile, StatusFile, PolicyFile
	log                     *slog.Logger
	wake                    chan struct{}

	mu    sync.Mutex
	offer offer // the one in the feed now
	feed  int   // the feeds opened so far: while up, the one open
	up    bool

	// The loop's alone.
	now                           func() time.Time
	busyLook, idleLook, heartbeat time.Duration
	// red is one redactor for the run: an address in root's text gives
	// the same token at every look, and the state does not change for it.
	red      *redact.Redactor
	sent     *perimeterv1.RelayUpdate // the state the exit last took
	sentAt   time.Time
	failedAt time.Time   // the last report not taken; zero after one that was
	muted    int         // the feed whose exit takes no reports (Unimplemented); 0: none
	asked    []time.Time // the requests written in the last day, oldest first
	seeded   bool
	// own is a failure of rayd relay's own (a request it could not write),
	// told over ownOver, the state the files said then, until they say
	// something else.
	own, ownOver *perimeterv1.RelayUpdate
	logged       *perimeterv1.RelayUpdate // the state the journal has
	decided      string                   // the offer and why it is not taken, as the journal has it
	said         map[string]time.Time     // when the journal last had each cause
}

// offer is the exit's as the feed has it, checked only when it is taken.
type offer struct {
	id, version string
	some        bool
}

// NewUpdates is the updates of a relay whose rayd relay is of version: its
// requests go to request (rayd relay's own directory,
// nodeupdate.RelayRequestFile), root's policy and status are in dir
// (nodeupdate.StatusDir).
func NewUpdates(version, request, dir string, log *slog.Logger) *Updates {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	host, _ := os.Hostname()
	return &Updates{
		version: version, request: request, log: log, wake: make(chan struct{}, 1),
		status:   filepath.Join(dir, filepath.Base(nodeupdate.StatusFile)),
		policy:   filepath.Join(dir, filepath.Base(nodeupdate.PolicyFile)),
		busyLook: lookBusy, idleLook: lookIdle, heartbeat: heartbeat, said: map[string]time.Time{},
		red: redact.New(relayNames(host, os.Getenv("RAYCONTROL_MIRRORS"))...),
	}
}

// relayNames are the relay's own names its redactor hides beside what
// redact does of itself: the host's name where it says where the relay is
// (a full one, and its domain; a single label only with a digit in it,
// relay1 or vps-1234: a plain word such as relay or debian says nothing,
// and would take that word out of every text), and the hosts of the
// mirrors set (RAYCONTROL_MIRRORS), a private one above all. The hosts of
// other links root's text names are learned from it (clean).
func relayNames(host, mirrors string) []string {
	var names []string
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	switch labels := strings.Split(host, "."); {
	case host == "" || host == "localhost":
	case len(labels) > 2:
		names = append(names, host, strings.Join(labels[len(labels)-2:], "."))
	case len(labels) == 2:
		names = append(names, host)
	case len(host) >= 4 && strings.ContainsAny(host, "0123456789"):
		names = append(names, host)
	}
	return append(names, linkHosts(mirrors)...)
}

// linkRe finds the host of a link (http, https).
var linkRe = regexp.MustCompile(`(?i)\bhttps?://([^/\s"'<>?#]+)`)

// publicHosts are the hosts a release comes from that say nothing of the
// relay: GitHub's and the default mirrors'.
var publicHosts = func() []string {
	hosts := []string{"github.com", "githubusercontent.com"}
	for _, m := range release.DefaultMirrors {
		if u, err := url.Parse(m); err == nil && u.Hostname() != "" {
			hosts = append(hosts, strings.ToLower(u.Hostname()))
		}
	}
	return hosts
}()

// linkHosts are the hosts of the links in s but the public ones and
// addresses (which redact takes out as addresses).
func linkHosts(s string) []string {
	var hosts []string
	for _, m := range linkRe.FindAllStringSubmatch(s, -1) {
		h := m[1]
		if i := strings.LastIndexByte(h, '@'); i >= 0 {
			h = h[i+1:]
		}
		if hp, _, err := net.SplitHostPort(h); err == nil {
			h = hp
		}
		h = strings.ToLower(strings.Trim(h, "[]."))
		if _, err := netip.ParseAddr(h); err == nil || h == "" || !strings.Contains(h, ".") {
			continue
		}
		public := slices.ContainsFunc(publicHosts, func(p string) bool { return h == p || strings.HasSuffix(h, "."+p) })
		if !public && !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

func (u *Updates) clock() time.Time {
	if u.now != nil {
		return u.now()
	}
	return time.Now()
}

// offered is the feed's: a message of the exit's, the first of a feed or
// not, and the offer it carries (nil: none). It does not wait for the loop.
func (u *Updates) offered(first bool, m *perimeterv1.RelayUpdateOffer) {
	if u == nil {
		return
	}
	o := offer{id: m.GetId(), version: m.GetVersion(), some: m != nil}
	u.mu.Lock()
	changed := first || o != u.offer
	if first {
		u.feed++
	}
	u.offer, u.up = o, true
	u.mu.Unlock()
	if changed {
		select {
		case u.wake <- struct{}{}:
		default:
		}
	}
}

// closed is the feed's: it ended, and what the exit offered in it goes. A
// new feed may offer something else (an exit that came back from another
// update) or nothing.
func (u *Updates) closed() {
	if u == nil {
		return
	}
	u.mu.Lock()
	u.offer, u.up = offer{}, false
	u.mu.Unlock()
}

// run looks at once, then at each new offer or feed and on its own clock,
// until ctx ends.
func (u *Updates) run(ctx context.Context, exit perimeterv1connect.RelayServiceClient) {
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-u.wake:
		case <-t.C:
		}
		t.Reset(u.look(ctx, exit))
	}
}

// look reads where the relay stands, takes the exit's offer when it is due
// and tells the exit; it returns when to look next.
func (u *Updates) look(ctx context.Context, exit perimeterv1connect.RelayServiceClient) time.Duration {
	now := u.clock()
	u.mu.Lock()
	o, feed, up := u.offer, u.feed, u.up
	u.mu.Unlock()
	st := u.read(now)
	if !u.seeded {
		u.seed(st, now)
	}
	if o.some && u.take(o, st, now) {
		st = u.read(now)
	}
	r := st.r
	switch {
	case u.own == nil:
	case proto.Equal(u.ownOver, st.r):
		r = u.own
	default:
		// The files moved on (root took a request, the policy changed):
		// they say it now.
		u.own, u.ownOver = nil, nil
	}
	u.note(r, now)
	if up && feed != u.muted && ctx.Err() == nil {
		u.tell(ctx, exit, r, feed, now)
	}
	if r.State == nodeupdate.Requested || r.State == nodeupdate.Running {
		return u.busyLook
	}
	return u.idleLook
}

// standing is where the relay stands, as the files say.
type standing struct {
	r         *perimeterv1.RelayUpdate // as the exit is told
	since     time.Time                // when r's state was reached
	untouched bool                     // r failed and left the relay as it was
	held      []string                 // releases whose update did not hold here
	busy      bool                     // a request waits, or an update runs
	asked     []time.Time              // when the requests the files show were written
}

// states are those of root's status the exit is told (§3.4).
var states = []string{nodeupdate.Running, nodeupdate.Done, nodeupdate.RolledBack, nodeupdate.Failed}

// read is the relay's standing at now: the request rayd relay wrote until
// root takes it (requested, failed with not_taken once it is too old to
// run), then root's status of it. A status of another kind than exit is
// none of the exit's offers: idle, though its held releases count.
func (u *Updates) read(now time.Time) standing {
	// The request first: root writes its status before it removes the
	// request, so a request root took is never in neither.
	req, waiting := nodeupdate.PeekRequest(u.request)
	stat := nodeupdate.ReadStatus(u.status)
	r := &perimeterv1.RelayUpdate{Version: versionOf(u.version), Remote: nodeupdate.ReadPolicy(u.policy).Remote == "on", State: nodeupdate.Idle}
	st := standing{r: r, busy: nodeupdate.Busy(stat, req, waiting, now)}
	if stat.Kind == nodeupdate.Exit && !stat.Requested.IsZero() {
		st.asked = append(st.asked, stat.Requested)
	}
	// Root copies the request's id and time into its status; the id alone
	// is the exit's update's, the same for a request asked for again.
	taken := stat.ID == req.ID && stat.Requested.Equal(req.At)
	switch {
	case waiting && !taken:
		st.asked = append(st.asked, req.At)
		r.State, r.Id, r.Target, st.since = nodeupdate.Requested, idOf(req.ID), versionOf(req.Version), req.At
		if now.Sub(req.At) >= nodeupdate.Stale {
			// Root's unit did not take it (off, or failing to start), and
			// it would refuse it now as too old. The file stays: it tells
			// a restart the same, and the next request replaces it.
			r.State, r.Reason, st.untouched, st.since = nodeupdate.Failed, nodeupdate.ReasonNotTaken, true, req.At.Add(nodeupdate.Stale)
			r.Error = "root's update unit on the relay did not take the request within " + nodeupdate.Stale.String()
		}
	case stat.Kind == nodeupdate.Exit && slices.Contains(states, stat.State):
		r.State, r.Id, r.Target, r.Unfinished = stat.State, idOf(stat.ID), versionOf(stat.Target), stat.Unfinished
		r.Reason, r.Error, st.untouched = reasonOf(stat.Reason), u.clean(stat.Error), stat.Untouched
		st.since = stat.Ended
		switch {
		case stat.State == nodeupdate.Running && now.Sub(stat.Started) >= nodeupdate.Stale:
			// Its runner died with no word (a power cut): the update was
			// cut short. As nodeupdate.Settled, which says so in the
			// node's words. This rayd relay still of the version it came
			// from (an install restarts it with the release's), it changed
			// nothing: its release is tried again later, not held for
			// good, as root's recover unit would have it (§4.3).
			r.State, r.Reason, st.since = nodeupdate.Failed, nodeupdate.ReasonInterrupted, stat.Started.Add(nodeupdate.Stale)
			r.Error = "no outcome within " + nodeupdate.Stale.String() + ": cut short (rayctl update status on the relay)"
			if isVersion(stat.From) && stat.From == u.version {
				st.untouched, stat.Untouched = true, true
			}
		case stat.State == nodeupdate.Running || st.since.IsZero():
			st.since = stat.Started
		}
	}
	st.held = stat.Holding()
	if !st.since.IsZero() {
		r.At = st.since.Unix()
	}
	return st
}

// seed takes the requests the files show (the one waiting, the one root's
// status is of) into the request limit: a restart of rayd relay (its own
// update restarts it) keeps the 10 minutes since the last one, and the
// day's count as far as the files go.
func (u *Updates) seed(st standing, now time.Time) {
	u.seeded = true
	for _, t := range st.asked {
		if d := now.Sub(t); d >= 0 && d < day && !slices.ContainsFunc(u.asked, t.Equal) {
			u.asked = append(u.asked, t)
		}
	}
	slices.SortFunc(u.asked, time.Time.Compare)
}

// mayAsk is §3.5, step 7: a request no sooner than requestGap after the
// last, and no more than requestsDaily in a day. A time ahead of now (the
// clock set back) no longer counts.
func (u *Updates) mayAsk(now time.Time) bool {
	u.asked = slices.DeleteFunc(u.asked, func(t time.Time) bool { d := now.Sub(t); return d >= day || d < 0 })
	return len(u.asked) < requestsDaily && (len(u.asked) == 0 || now.Sub(u.asked[len(u.asked)-1]) >= requestGap)
}

// Why an offer is not taken, for the journal.
var notTaken = map[string]string{
	"off":       "updates by the exit's word are off on this relay (rayctl update remote on)",
	"malformed": "no release, or no id",
	"current":   "not newer than this relay",
	"held":      "an update to it did not hold here before",
	"later":     "it failed here before it changed anything; again " + nodeupdate.RelayRetryAfter.String() + " after",
	"busy":      "an update is asked for or under way",
	"limit":     "a request at most every 10m0s and 6 a day",
}

// declines are the offers rayd relay does not take for reasons of its own
// and the code it reports each with, as an outcome on the offer's id
// (§3.5): failed, before any change. Without it the exit would see the
// offer given and no word on it, and keep the relays after this one
// waiting the whole of its turn. Remote off is told by remote itself; an
// offer that is malformed has no id to tell it on; a request waiting or
// an update under way is told by its own state, and ends in an outcome.
var declines = map[string]string{
	"current": nodeupdate.ReasonVersion, // not newer, a build that is no release, done under another id
	"held":    nodeupdate.ReasonVersion,
	"later":   nodeupdate.ReasonBusy, // RelayRetryAfter after a failure that changed nothing
	"limit":   nodeupdate.ReasonBusy,
}

// told reports whether the exit knows, without a word on it, where the
// relay stands on offer o: the files speak of its id (asked for, under
// way, an outcome); a request waits or an update runs, whose outcome is to
// come (and a run holds its own release until then, Status.Holding); or
// the relay runs o's release or a newer one, which the report says.
func told(o offer, st standing, version string) bool {
	return st.r.Id == o.id || st.busy || isVersion(version) && !release.Newer(o.version, version)
}

// decline makes the relay's word on offer o, not taken for why, an
// outcome on its id with reason's code, told over the files' state st as
// a failure of rayd relay's own is, until the files or the offer move on.
// The same decline keeps its time: the exit hears it once, and at the
// heartbeat.
func (u *Updates) decline(o offer, st standing, why, reason string, now time.Time) {
	at := now.Unix()
	if u.own != nil && u.own.Id == o.id && u.own.Target == o.version && u.own.Reason == reason {
		at = u.own.At
	}
	u.own = proto.CloneOf(st.r)
	u.own.State, u.own.Id, u.own.Target, u.own.Reason, u.own.At = nodeupdate.Failed, o.id, o.version, reason, at
	u.own.Error = "the offer not taken: " + notTaken[why]
	u.ownOver = st.r
}

// take is §3.5 for the exit's offer o, in its order; it reports whether a
// request went in. Asked again for the same release (a recount, a new
// feed, a restart of either side), it does nothing: the release runs
// already, is held, failed a while ago, or its request waits. An offer it
// declines for a reason of its own it reports as an outcome (declines).
func (u *Updates) take(o offer, st standing, now time.Time) bool {
	v := o.version
	var why string
	switch {
	case !st.r.Remote:
		why = "off"
	case !validID(o.id) || !isVersion(v):
		why = "malformed"
	case !isVersion(u.version) || !release.Newer(v, u.version) || st.r.State == nodeupdate.Done && st.r.Target == v:
		// A build that is no release updates by hand. Root's done counts
		// as well: a rayd relay the update did not restart would
		// otherwise ask for it again, and root refuse it.
		why = "current"
	case slices.Contains(st.held, v) || st.r.Target == v && (st.r.State == nodeupdate.RolledBack || st.r.State == nodeupdate.Failed && !st.untouched):
		why = "held"
	case st.r.State == nodeupdate.Failed && st.untouched && st.r.Target == v && now.Sub(st.since) < nodeupdate.RelayRetryAfter:
		why = "later"
	case st.busy:
		why = "busy"
	case !u.mayAsk(now):
		why = "limit"
	}
	if why == "" {
		req := nodeupdate.Request{ID: o.id, Kind: nodeupdate.Exit, Version: v, By: "exit", At: now.UTC()}
		err := nodeupdate.WriteRequest(u.request, req, now)
		switch {
		case errors.Is(err, nodeupdate.ErrWaiting):
			why = "busy"
		case err != nil:
			// Said to the exit, so that the phone shows why the relay
			// does not move; tried again at the next look.
			if u.own == nil || u.own.Id != o.id || u.own.Target != v || u.own.Reason != "" {
				u.own = proto.CloneOf(st.r)
				u.own.State, u.own.Id, u.own.Target, u.own.Reason, u.own.At = nodeupdate.Failed, o.id, v, "", now.Unix()
				u.own.Error = u.clean("the update request not written: " + err.Error())
			}
			u.ownOver = st.r
			u.say("write", now, slog.LevelWarn, "relay update: the request not written", "version", v, "id", o.id, "err", err)
			return false
		default:
			u.asked = append(u.asked, now)
			u.own, u.ownOver, u.decided = nil, nil, ""
			u.log.Info("relay update requested", "version", v, "id", o.id, "running", u.version)
			return true
		}
	}
	if key := o.id + " " + v + " " + why; key != u.decided {
		u.decided = key
		level := slog.LevelInfo
		if why == "current" {
			level = slog.LevelDebug // the steady state once the relay updated
		}
		if why == "malformed" || why == "off" {
			// The offer's fields unchecked (off: before any check): none
			// of them goes in the journal.
			u.say(why, now, level, "relay update: the exit's offer not taken", "why", notTaken[why])
		} else {
			u.say(why, now, level, "relay update: the exit's offer not taken", "version", v, "id", o.id, "why", notTaken[why])
		}
	}
	switch reason, ok := declines[why]; {
	case ok && !told(o, st, u.version):
		u.decline(o, st, why, reason, now)
	case u.own != nil && (u.own.Id != o.id || u.own.Target != v):
		u.own, u.ownOver = nil, nil // of an offer gone
	}
	return false
}

// note puts a new state in the journal: the state, the offer's id and
// version, the reason's code, never root's text (§6).
func (u *Updates) note(r *perimeterv1.RelayUpdate, now time.Time) {
	l := u.logged
	if l != nil && l.State == r.State && l.Id == r.Id && l.Target == r.Target && l.Reason == r.Reason {
		return
	}
	u.logged = r
	if l == nil && r.State == nodeupdate.Idle {
		return
	}
	u.say("state "+r.State, now, slog.LevelInfo, "relay update", "state", r.State, "id", r.Id, "target", r.Target, "reason", r.Reason)
}

// tell gives the exit r when it changed, or heartbeat after the last one
// the exit took. Not taken (the link, Unavailable, ResourceExhausted):
// again at the next look, though no sooner than busyLook after, whatever
// woke the loop (one at a time and at most six a minute: the exit takes
// twelve). An exit without the method (older than this relay) is not
// asked again in this feed.
func (u *Updates) tell(ctx context.Context, exit perimeterv1connect.RelayServiceClient, r *perimeterv1.RelayUpdate, feed int, now time.Time) {
	if u.sent != nil && proto.Equal(u.sent, r) && now.Sub(u.sentAt) < u.heartbeat {
		return
	}
	if d := now.Sub(u.failedAt); !u.failedAt.IsZero() && d >= 0 && d < u.busyLook {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, ReportTimeout)
	_, err := exit.ReportUpdate(rctx, connect.NewRequest(&perimeterv1.ReportUpdateRequest{Update: r}))
	cancel()
	u.failedAt = time.Time{}
	switch code := connect.CodeOf(err); {
	case err == nil:
		u.sent, u.sentAt = r, now
	case ctx.Err() != nil:
	case code == connect.CodeUnimplemented:
		u.muted = feed
		u.say("unimplemented", now, slog.LevelInfo, "relay update: the exit takes no reports (older than this relay); quiet until its next feed")
	case code == connect.CodeInvalidArgument:
		// This state as it is will not do for this exit: again once it
		// changes, or at the heartbeat, not at every look.
		u.sent, u.sentAt = r, now
		u.say("refused", now, slog.LevelWarn, "relay update: the exit refused the report", "state", r.State)
	default:
		u.failedAt = now
		// The code only: the error's text names the exit's address.
		u.say("report "+code.String(), now, slog.LevelWarn, "relay update: report not taken", "code", code)
	}
}

// say logs a line of cause, unless one went in less than logEvery ago.
func (u *Updates) say(cause string, now time.Time, level slog.Level, msg string, args ...any) {
	if t, ok := u.said[cause]; ok && now.Sub(t) < logEvery && now.Sub(t) >= 0 {
		return
	}
	u.said[cause] = now
	u.log.Log(context.Background(), level, msg, args...)
}

// clean is a status's text as the exit may have it (§6): no addresses,
// keys or identifiers (internal/redact), one printable line, at most 200
// bytes. The text of a relay's install names the exit's address and the
// relay's admin addresses; it stays whole in root's status and the unit's
// journal, on the relay.
func (u *Updates) clean(s string) string {
	if s == "" {
		return ""
	}
	// Root cut it (nodeupdate keeps 512 bytes): its last word may be part
	// of an address, which redact would not know for one.
	cut := strings.HasSuffix(s, "…")
	if cut {
		s = strings.TrimSuffix(s, "…")
		s = s[:max(strings.LastIndexFunc(s, unicode.IsSpace), 0)]
	}
	// A mirror's host (set in the update unit's environment, which rayd
	// relay does not see) is named in a link of the download's error, and
	// bare beside it ("lookup mirror.example: no such host"): taken from
	// the links, it goes wherever it is.
	u.red.Add(linkHosts(s)...)
	s = u.red.String(nodeupdate.Printable(strings.Join(strings.Fields(s), " ")))
	if cut {
		s = strings.TrimSpace(s + " …")
	}
	return clipText(s, maxText)
}

// clipText cuts s to at most n bytes, on a rune boundary, saying so.
func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	const more = "…"
	n -= len(more)
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + more
}

// validID reports whether s names an update as a request does: 1-32
// lowercase hex.
func validID(s string) bool {
	return s != "" && len(s) <= 32 && strings.Trim(s, "0123456789abcdef") == ""
}

func idOf(s string) string {
	if validID(s) {
		return s
	}
	return ""
}

func isVersion(v string) bool { return len(v) <= maxVersion && release.IsRelease(v) }

func versionOf(v string) string {
	if isVersion(v) {
		return v
	}
	return ""
}

func reasonOf(s string) string {
	if nodeupdate.ValidReason(s) {
		return s
	}
	return ""
}
