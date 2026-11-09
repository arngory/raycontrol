// Package traffic counts each user's bytes for the traffic limit
// (docs/spec/traffic-limit-v1.md §2.4): rayd reads the counters of the
// processes that carry users (Xray's inner and REALITY, niko-server's
// Hysteria2, rayd naive) every 15 s, keeps what it last read from each
// (marks, by name), and adds what grew since to the users' periods. A user
// who reaches the limit is taken off every profile (store.User.Active):
// the loop writes at once and wakes apply.
//
// Counters only, by name: nothing of destinations. The log says only that
// a user reached the limit or came back, by number.
package traffic

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// The loop's times (owner's decision 5): a poll every Every, a write every
// WriteEvery at most, unless a user crosses the limit or a period resets.
const (
	Every      = 15 * time.Second
	WriteEvery = time.Minute
	first      = 5 * time.Second
	stopWait   = 5 * time.Second
)

// youngSlack: a process whose start (Xray's) is at least this long after
// a user's limit was set carries none of the user's bytes from before.
const youngSlack = time.Second

// Source is a process that counts a service's users.
type Source struct {
	Key     string // "xray:<service>", "hy2:<service>", "naive:<service>"
	Service string
	Read    func(ctx context.Context, now time.Time) (Reading, error)
	// Counts reports whether a user's bytes may count here: the user has
	// the service (for inner, a service behind it). A process cannot add
	// bytes to a user it does not carry.
	Counts func(u store.User) bool
}

// Processes are the sources of a node: each enabled Xray, Hysteria2 and
// naive service, read at its socket under paths.
func Processes(paths render.Paths) func(services []store.Service) []Source {
	return func(services []store.Service) []Source {
		byID := map[int64]store.Service{}
		for _, svc := range services {
			byID[svc.ID] = svc
		}
		has := func(id int64) func(store.User) bool {
			return func(u store.User) bool { return slices.Contains(u.Services, id) }
		}
		var out []Source
		for _, svc := range services {
			if !svc.Enabled {
				continue
			}
			name := svc.Name
			switch {
			case svc.Kind == "inner":
				out = append(out, Source{Key: "xray:" + name, Service: name,
					Read: func(ctx context.Context, now time.Time) (Reading, error) {
						return ReadXray(ctx, paths.APISocket(name))
					},
					Counts: func(u store.User) bool {
						return slices.ContainsFunc(u.Services, func(id int64) bool { return provision.NeedsInner(byID[id].Kind) })
					}})
			case svc.Kind == "reality":
				out = append(out, Source{Key: "xray:" + name, Service: name,
					Read: func(ctx context.Context, now time.Time) (Reading, error) {
						return ReadXray(ctx, paths.APISocket(name))
					},
					Counts: has(svc.ID)})
			case render.IsHysteria(svc.Kind), svc.Kind == "naive":
				prefix := "hy2:"
				if svc.Kind == "naive" {
					prefix = "naive:"
				}
				out = append(out, Source{Key: prefix + name, Service: name,
					Read: func(ctx context.Context, _ time.Time) (Reading, error) {
						return ReadLine(ctx, paths.StatsSocket(name))
					},
					Counts: has(svc.ID)})
			}
		}
		return out
	}
}

// Accountant is the loop's state: what it read from each process since
// its last write, and the users' bytes not yet written. It is ahead of the
// store by the polls since the last write; a crash loses those, and the
// next poll counts them again from the marks in the store, once.
type Accountant struct {
	Store   *store.Store
	Sources func(services []store.Service) []Source
	Health  *health.Board
	Log     *slog.Logger
	// Notify wakes apply: a user crossed the limit, one way or the other.
	Notify func()
	// Now is time.Now when nil (tests).
	Now func() time.Time

	mu      sync.Mutex
	loaded  bool
	sources map[string]*sourceState
	pending map[int64]*pendingBytes
	over    map[int64]bool // users over the limit, as last seen
	written time.Time
}

type sourceState struct {
	boot   string
	polled time.Time // whole seconds, as the store keeps it and counted_from
	marks  map[string]store.TrafficCounter
	fresh  bool // polled since the last write
	// Xray's uptime and the monotonic time of the read, kept in memory
	// only: set once this rayd has read the process (mono).
	uptime, monoAt time.Duration
	mono           bool
}

// sameRun reports whether a reading comes from the run of the process the
// state was taken from. Xray (a reading with a start): its uptime grew at
// least by the monotonic time between the two reads, less bootSlack; with
// no reading of this rayd's yet, by the wall time since the stored poll;
// with no poll stored, its start is the stored one within bootSlack. A
// step of the wall clock between two reads of one rayd changes nothing.
// The others: the same boot.
func sameRun(prev *sourceState, r Reading, now time.Time) bool {
	switch {
	case prev == nil:
		return false
	case r.Start.IsZero():
		return prev.boot == r.Boot
	case prev.mono:
		return r.Uptime+bootSlack >= prev.uptime+(r.Mono-prev.monoAt)
	case !prev.polled.IsZero():
		return strings.HasPrefix(prev.boot, xrayBoot) && r.Uptime+bootSlack >= now.Sub(prev.polled)
	}
	return SameBoot(prev.boot, r.Boot)
}

type pendingBytes struct {
	start    time.Time // the period they count in
	up, down int64
}

func (a *Accountant) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Accountant) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Run polls every Every until ctx ends, then polls once more and writes
// (rayd stops): the bytes since the last write are not lost to a stop.
func (a *Accountant) Run(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(first):
	}
	t := time.NewTicker(Every)
	defer t.Stop()
	for {
		a.Round(ctx, "", false)
		select {
		case <-ctx.Done():
			final, cancel := context.WithTimeout(context.WithoutCancel(ctx), stopWait)
			a.Round(final, "", true)
			cancel()
			return
		case <-t.C:
		}
	}
}

// Flush polls a service's process and writes at once, before rayd
// restarts it (internal/live): its counters start again, and what they
// held since the last poll would be lost. A process never read is left
// alone: there is nothing of it to keep yet.
func (a *Accountant) Flush(ctx context.Context, service string) {
	a.mu.Lock()
	known := false
	// Before the first round too: the store's marks of the run before.
	if users, err := a.Store.ListUsers(ctx); err == nil && a.load(ctx, users) == nil {
		for key := range a.sources {
			_, name, _ := strings.Cut(key, ":")
			known = known || name == service
		}
	}
	a.mu.Unlock()
	if known {
		a.Round(ctx, service, true)
	}
}

// load reads the store's marks and the users' state once.
func (a *Accountant) load(ctx context.Context, users []store.User) error {
	if a.loaded {
		return nil
	}
	srcs, err := a.Store.TrafficSources(ctx)
	if err != nil {
		return err
	}
	a.sources = map[string]*sourceState{}
	for key, s := range srcs {
		a.sources[key] = &sourceState{boot: s.Boot, polled: s.Polled, marks: s.Marks}
	}
	a.pending = map[int64]*pendingBytes{}
	// Over as the store has it, before any reset: a period that reset
	// while rayd was down is told (restored) at the first poll.
	a.over = map[int64]bool{}
	for _, u := range users {
		if u.Limited() && u.TrafficUp+u.TrafficDown >= *u.TrafficLimit {
			a.over[u.ID] = true
		}
	}
	a.loaded = true
	return nil
}

// Round is one poll: of every source, or only the service's (Flush); force
// writes whatever comes of it.
func (a *Accountant) Round(ctx context.Context, only string, force bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	// No limit, and nothing kept of one: one query and done (most nodes,
	// every 15 s).
	if a.loaded && len(a.sources) == 0 && len(a.pending) == 0 {
		limits, err := a.Store.HasTrafficLimits(ctx)
		if err != nil {
			a.Health.Done("traffic", err)
			return
		}
		if !limits {
			a.over = map[int64]bool{}
			a.Health.Retain("traffic", nil)
			return
		}
	}
	users, err := a.Store.ListUsers(ctx)
	if err == nil {
		err = a.load(ctx, users)
	}
	var services []store.Service
	if err == nil {
		services, err = a.Store.ListServices(ctx)
	}
	if err != nil {
		a.Health.Done("traffic", err)
		return
	}
	limited := map[int64]store.User{}
	for _, u := range users {
		if u.Limited() {
			limited[u.ID] = u
		}
	}
	if len(limited) == 0 {
		// Nothing counts: no process is read, the store keeps no marks.
		if len(a.sources) > 0 || len(a.pending) > 0 {
			if err := a.Store.ClearTraffic(ctx); err != nil {
				a.Health.Done("traffic", err)
				return
			}
		}
		a.sources, a.pending, a.over = map[string]*sourceState{}, map[int64]*pendingBytes{}, map[int64]bool{}
		a.Health.Retain("traffic", nil) // the loop and its sources
		return
	}

	// A period that reset since its count was written: the reset is
	// written now, and its bytes until this poll go with the old period
	// (the poll's share after the reset too: the count is less than true,
	// never more).
	var w store.TrafficWrite
	resetting := map[int64]bool{}
	for id, u := range limited {
		if u.TrafficStart.IsZero() {
			// A limit without its count (the store makes both at once):
			// counted from now, from the next poll.
			w.Start = append(w.Start, id)
			delete(limited, id)
			continue
		}
		if due, last := u.ResetDue(now); due {
			w.Resets = append(w.Resets, store.TrafficReset{UserID: id, From: u.TrafficStart, To: last})
			resetting[id] = true
			delete(a.pending, id)
		}
	}

	sources := a.Sources(services)
	// All read at once: a process that does not answer holds the round
	// (and a Flush waiting for it, and so apply) readWait at most, however
	// many there are. The readings are taken in order, under the lock.
	type result struct {
		r    Reading
		err  error
		read bool
	}
	results := make([]result, len(sources))
	var wg sync.WaitGroup
	for i, src := range sources {
		if only != "" && src.Service != only {
			continue
		}
		wg.Go(func() {
			r, err := src.Read(ctx, now)
			results[i] = result{r, err, true}
		})
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	var keep []string
	for i, src := range sources {
		keep = append(keep, src.Service)
		r, err := results[i].r, results[i].err
		if !results[i].read {
			continue
		}
		if notRunning(err) {
			// No socket, or no one at it: the process does not run (a
			// service waiting for its site's certificate, one stopped).
			// It carries nothing, so nothing goes uncounted; its marks
			// stay for when it is back with the same run.
			a.Health.Report("traffic "+src.Service, "not running", nil)
			continue
		}
		if err != nil {
			a.Health.Report("traffic "+src.Service, "", err)
			continue
		}
		for id, d := range a.take(src, r, limited, now) {
			if resetting[id] || (d.Up == 0 && d.Down == 0) {
				continue
			}
			start := limited[id].PeriodStart(now)
			p := a.pending[id]
			if p == nil || !p.start.Equal(start) {
				// A period moved (rayctl user reset-usage) since: the bytes
				// before would be dropped by the write anyway.
				p = &pendingBytes{start: start}
				a.pending[id] = p
			}
			p.up, p.down = addCapped(p.up, d.Up), addCapped(p.down, d.Down)
		}
		a.Health.Report("traffic "+src.Service, "", nil)
	}
	if only == "" {
		// A source no longer there (its service deleted, disabled): its
		// marks go.
		for key := range a.sources {
			if !slices.ContainsFunc(sources, func(s Source) bool { return s.Key == key }) {
				w.Drop = append(w.Drop, key)
				delete(a.sources, key)
			}
		}
		a.Health.Retain("traffic ", keep)
	}

	// Who is over the limit now: the store's count, a reset read as zero,
	// with the bytes not written yet.
	var exhausted, restored []store.User
	for id, u := range limited {
		used := u.Used(now)
		if p := a.pending[id]; p != nil {
			used = addCapped(used, addCapped(p.up, p.down))
		}
		over := used >= *u.TrafficLimit
		switch {
		case over && !a.over[id]:
			exhausted = append(exhausted, u)
		case !over && a.over[id]:
			restored = append(restored, u)
		}
	}
	for id := range a.over {
		if _, ok := limited[id]; !ok {
			delete(a.over, id) // its limit or the user went: nothing to tell
		}
	}

	fresh := slices.ContainsFunc(slices.Collect(maps.Values(a.sources)), func(s *sourceState) bool { return s.fresh })
	if force || len(exhausted) > 0 || len(w.Resets) > 0 || len(w.Drop) > 0 || len(w.Start) > 0 || (fresh && now.Sub(a.written) >= WriteEvery) {
		if err := a.write(ctx, w, now); err != nil {
			// Nothing is told until the store has it: the users stay as
			// they are, and the next round tries again.
			a.Health.Done("traffic", err)
			return
		}
		a.Health.Done("traffic", nil)
	}
	for _, u := range exhausted {
		a.over[u.ID] = true
		a.tell(ctx, u, "exhausted")
	}
	for _, u := range restored {
		delete(a.over, u.ID)
		a.tell(ctx, u, "restored")
	}
	if len(exhausted)+len(restored) > 0 && a.Notify != nil {
		a.Notify()
	}
}

// tell audits a crossing, actor rayd, and logs it by the user's number
// only (docs/09-observability.md §1).
func (a *Accountant) tell(ctx context.Context, u store.User, what string) {
	if err := a.Store.Audit(ctx, "rayd", "user.traffic="+what, u.Name, "ok"); err != nil {
		a.log().Warn("audit", "err", err)
	}
	if what == "exhausted" {
		a.log().Info("traffic limit reached: the user is off the profiles until the period resets or the limit is raised", "user", u.ID)
	} else {
		a.log().Info("traffic limit: the user is back on the profiles", "user", u.ID)
	}
}

// write writes the resets, the bytes and the marks of the sources polled
// since the last write in one transaction.
func (a *Accountant) write(ctx context.Context, w store.TrafficWrite, now time.Time) error {
	for id, p := range a.pending {
		w.Adds = append(w.Adds, store.TrafficAdd{UserID: id, Start: p.start, Up: p.up, Down: p.down})
	}
	w.Sources = map[string]store.TrafficSource{}
	for key, s := range a.sources {
		if s.fresh {
			w.Sources[key] = store.TrafficSource{Boot: s.boot, Polled: s.polled, Marks: s.marks}
		}
	}
	if err := a.Store.WriteTraffic(ctx, w); err != nil {
		return err
	}
	a.pending = map[int64]*pendingBytes{}
	for _, s := range a.sources {
		s.fresh = false
	}
	a.written = now
	return nil
}

// take reads a source's counters against its marks: the bytes each user
// gained since the last poll, and the new marks. For each name of a user
// with a limit (store.TrafficNames):
//   - a user whose limit was set after the source's last poll is counted
//     from this one (the mark is the value), unless the process started
//     after the limit (Xray says when): all its counters are since then;
//   - else, the same run of the process and a value not below the mark:
//     the difference; a new run, a value below the mark (a counter that
//     went back) or a name new to the process: the whole value.
//
// Names of other users, or of none, are not kept. A user the source does
// not carry is marked but not counted.
func (a *Accountant) take(src Source, r Reading, limited map[int64]store.User, now time.Time) map[int64]store.TrafficCounter {
	var polled time.Time
	var marks map[string]store.TrafficCounter
	boot := r.Boot
	prev := a.sources[src.Key]
	same := sameRun(prev, r, now)
	if prev != nil {
		polled, marks = prev.polled, prev.marks
		if same {
			boot = prev.boot // one run: its first reading names it
		}
	}
	// The poll's time in whole seconds, as counted_from: a limit set in
	// the same second as this poll, after it, must not read as set before.
	next := &sourceState{boot: boot, polled: now.Truncate(time.Second), marks: map[string]store.TrafficCounter{}, fresh: true,
		uptime: r.Uptime, monoAt: r.Mono, mono: !r.Start.IsZero()}
	out := map[int64]store.TrafficCounter{}
	for name, v := range r.Users {
		id, ok := store.TrafficUser(name)
		u, lim := limited[id]
		if !ok || !lim {
			continue
		}
		v = store.TrafficCounter{Up: max(v.Up, 0), Down: max(v.Down, 0)}
		next.marks[name] = v
		tracked := u.TrafficCountedFrom.Before(polled)
		young := !r.Start.IsZero() && !r.Start.Before(u.TrafficCountedFrom.Add(youngSlack))
		if !tracked && !young {
			continue // counted from this poll on
		}
		d := v
		if m, ok := marks[name]; tracked && same && ok {
			if v.Up >= m.Up {
				d.Up = v.Up - m.Up
			}
			if v.Down >= m.Down {
				d.Down = v.Down - m.Down
			}
		}
		if !src.Counts(u) {
			continue
		}
		c := out[id]
		c.Up, c.Down = addCapped(c.Up, d.Up), addCapped(c.Down, d.Down)
		out[id] = c
	}
	a.sources[src.Key] = next
	return out
}

// notRunning reports whether a read failed for want of the process: its
// socket is not there, or nothing listens on it.
func notRunning(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)
}

// addCapped adds two counts (neither below zero) without wrapping: counts
// from a process are not trusted.
func addCapped(a, b int64) int64 {
	const most = int64(1) << 62
	a, b = min(max(a, 0), most), min(max(b, 0), most)
	if a > most-b {
		return most
	}
	return a + b
}
