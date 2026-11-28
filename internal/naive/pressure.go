package naive

import (
	"cmp"
	"context"
	"io"
	"log/slog"
	"maps"
	"math"
	"net"
	"runtime/metrics"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/arngory/raycontrol/internal/memlimit"
	"github.com/arngory/raycontrol/internal/site"
)

// The memory of TCP tunnels (docs/spec/memory-v1.md §5). HTTP/2 puts what a
// client uploads into the stream's buffer whether the handler reads it or
// not, up to the stream's window, and QUIC holds it in its packets: a
// tunnel whose destination does not take the upload holds that much of the
// process, and so does a stream still waiting for its dial. Every TCP
// tunnel is charged, from its admission to its end:
//
//   - tunnelCost (F), what an idle tunnel holds: copy buffers, goroutines,
//     the stream's state;
//   - and, while it is pending (admitted, its copy not started) or its
//     upload's write to the destination is blocked, its window part (W):
//     HTTP/2's stream window, all of a connection's within the connection
//     window; HTTP/3's h3Packets times the stream's window within the
//     connection's (as far as AllowH3Window let it grow), all of a
//     connection's within h3Packets times the connection's window;
//   - over HTTP/3, a connection with an upload of the user's not ended is
//     the user's for its window at least (groupState.charge): QUIC keeps
//     what comes out of order until the gap is filled, unseen;
//   - a stream blocked on its download to the client holds no more of the
//     process: what it holds is the destination socket's kernel memory
//     (SO_MEMINFO), read only when a round of evictions ranks it.
//
// Two marks:
//
//  1. at the budget B (MemoryBudget) or under pressure, a new CONNECT of a
//     user whose charge is its fair share or more (B over the users with a
//     tunnel, memShares of them at least) is refused 429, and HTTP/3
//     connections' windows grow no more. Nothing is cut: it bounds
//     admission, not memory;
//  2. under pressure (a heap and sockets near the Go limit or the cgroup's
//     throttle, or the charge at 1.5 B) the scanner resets the streams that
//     hold memory and do not move, those of the users over their share
//     first (evict). A stream that is neither pending nor in a write is
//     never reset, an idle SSH session or websocket stays, but for an
//     HTTP/3 one of a user over its share whose upload's read has waited
//     long, the last resort (classReading).
const (
	// tunnelCost (F) is what an idle TCP tunnel holds of the heap and the
	// stacks, measured by TestTunnelCost on loopback (Go 1.27, amd64, 200
	// tunnels, the client in another process): HTTP/2 90-91 KiB, HTTP/3
	// 80-81 KiB a tunnel, its two 32 KiB copy buffers among them; rounded
	// up.
	tunnelCost = 96 << 10
	// quic-go's windows (h3serve leaves them as they are): a stream's at
	// most, a connection's to start with and at most.
	h3StreamWindowMax = 6 << 20
	h3ConnWindow      = 768 << 10
	h3ConnWindowMax   = 15 << 20
	// h3Packets: quic-go holds a STREAM frame of 128 bytes or more in a
	// packet buffer of its own, up to 11 times a window
	// (niko-server's hymem.go).
	h3Packets = 11
	// memShares: the fair share is B over this many users at least.
	memShares = 8
	// evictRound bounds the streams one round resets (K).
	evictRound = 64
	// memEvery is the scanner's tick.
	memEvery = time.Second
	// memWarnEvery bounds the warnings of refusals and evictions.
	memWarnEvery = time.Minute
)

// evictGrace: a stream blocked this long is stuck rather than slow, as a
// UoT stream silent that long is quiet (quietAfter). Tests shorten it.
var evictGrace = quietAfter

// The marks of pressure (percent): on at the first, off at the second.
const (
	liveOn, liveOff                         = 85, 70   // live heap, stacks, sockets of the Go limit
	goalOn, goalOff                         = 95, 85   // the heap's goal, stacks, sockets of the throttle
	chargeOn, chargeOff                     = 150, 125 // the charge of B
	triggerLive, triggerGoal, triggerCharge = 0, 1, 2
)

// MemoryBudget is naive's budget for its tunnels in a process of memory l:
// half the base of its cgroup's limit (memlimit.Limits.Base, the less of
// memory.high and 15/16 of memory.max), no floor; without one an eighth
// of the host's memory, 32 MiB to 2 GiB.
func MemoryBudget(l memlimit.Limits) int64 {
	if b := l.Base(); b > 0 {
		return b / 2
	}
	return min(max(l.MemTotal/8, 32<<20), 2<<30)
}

// memSignals are what the scanner weighs: the runtime's live heap, its
// goal, the goroutines' stacks, its memory limit (0: none) and its GC
// cycles; the cgroup's socket buffers (memory.stat's sock) and where the
// kernel throttles it (memlimit.Limits.Throttle, 0: no limit).
type memSignals struct {
	live, goal, stacks, limit int64
	cycles                    uint64
	sock, throttle            int64
}

// MemoryStats are the tunnels' charge and what it did since the process
// started, as the stats socket gives them (TrafficSnapshot.Memory):
// counts only.
type MemoryStats struct {
	Budget   int64 `json:"budget"`   // B, bytes
	Charge   int64 `json:"charge"`   // the TCP tunnels' charge now, bytes
	Pressure bool  `json:"pressure"` // the second mark is on
	Refused  int64 `json:"refused"`  // CONNECTs refused 429 at the budget
	Evicted  int64 `json:"evicted"`  // tunnels reset under pressure
}

// tunnels are a server's TCP tunnels and their charge (Server.tunnels
// sets the budget and the readers at first use).
type tunnels struct {
	mu     sync.Mutex
	budget int64
	all    map[*tunnelMem]bool
	users  map[string]*memUser
	groups map[groupKey]*memGroup     // of streams on a known connection
	byConn map[any]map[*memGroup]bool // HTTP/3's groups by connection
	grants map[any]int64              // HTTP/3 connections' window growth granted
	charge int64                      // all users'

	pressure         atomic.Bool
	refused, evicted atomic.Int64
	read             func() memSignals

	// The scanner's own (one goroutine): the triggers' state; after a
	// round of the heap's, the wait for a GC (heapWait: gcAt once the
	// round's tunnels have gone, at the next look) and what that round saw
	// of the heap and reckoned to free; the warning's; the candidates'
	// slice, used again.
	on        [3]bool
	heapWait  bool
	gcSet     bool
	gcAt      uint64
	heapSeen  [2]int64 // the live heap and the goal, stacks with each, less sockets
	heapFreed int64
	warnAt    time.Time
	warned    [2]int64 // refused, evicted at the last warning
	warnLog   *slog.Logger
	cands     []memCand
}

type memUser struct {
	charge  int64
	streams int
}

// groupKey is a user's streams on one connection: their window parts are
// within the connection's window.
type groupKey struct {
	user string
	conn any
}

type memGroup struct {
	key       groupKey
	user      *memUser
	h3        bool
	streams   int
	counted   int   // streams with their window part
	uploading int   // streams whose upload has not ended
	w         int64 // the group's window part as charged
}

// tunnelMem is one TCP tunnel in the registry. up and down are when its
// write to the destination and to the client began (mono), 0 out of one;
// rd when its read of the client's upload began, over HTTP/3 only: the
// tunnel's own goroutines set them, two stores a write or a read, no lock.
type tunnelMem struct {
	up, down, rd atomic.Int64

	// Under tunnels.mu.
	g         *memGroup
	cancel    context.CancelCauseFunc
	at        int64 // admitted (mono)
	out       net.Conn
	pend      bool // admitted, its copy not started
	count     bool // its window part counted
	uploading bool // its upload has not ended
	gone      bool // evicted, or ended: charges nothing
}

// tunnels is the server's registry, its budget from s.Memory (the
// process's limits when nil) at first use.
func (s *Server) tunnels() *tunnels {
	s.memOnce.Do(func() {
		t := &s.mem
		l := s.Memory
		if l == nil {
			r := memlimit.Read(memlimit.System)
			l = &r
		}
		if t.budget == 0 {
			t.budget = MemoryBudget(*l)
		}
		if t.read == nil {
			t.read = runtimeSignals(*l)
		}
		t.warnLog = s.Log
	})
	return &s.mem
}

// shareLocked is a user's fair share of the budget.
func (t *tunnels) shareLocked() int64 {
	return t.budget / int64(max(memShares, len(t.users)))
}

// groupState is what a group's window part is reckoned from.
type groupState struct {
	h3                 bool
	counted, uploading int64
	w, limit, win      int64
}

// charge is the group's window part: its counted streams' within the cap;
// over HTTP/3 the connection's window at least while an upload of the
// group's has not ended. QUIC keeps what comes out of order in its packets
// until the gap is filled, unseen by the handler, which waits in its read
// meanwhile: a connection holds up to its window so.
func (g groupState) charge() int64 {
	n := min(g.limit, g.counted*g.w)
	if g.h3 && g.uploading > 0 {
		n = max(n, g.win)
	}
	return n
}

// stateLocked is g's as it is now: HTTP/2's stream window, all of a
// connection's within its window; HTTP/3's h3Packets times the stream's
// window within the connection's (as far as AllowH3Window let it grow), all
// of a connection's within h3Packets times its window.
func (t *tunnels) stateLocked(g *memGroup) groupState {
	gs := groupState{h3: g.h3, counted: int64(g.counted), uploading: int64(g.uploading)}
	if !g.h3 {
		gs.w, gs.limit = site.StreamWindow, site.ConnWindow
		return gs
	}
	gs.win = h3ConnWindow
	if g.key.conn != nil {
		gs.win = min(gs.win+t.grants[g.key.conn], h3ConnWindowMax)
	}
	gs.w, gs.limit = h3Packets*min(h3StreamWindowMax, gs.win), h3Packets*gs.win
	return gs
}

// recountLocked sets g's window part anew.
func (t *tunnels) recountLocked(g *memGroup) {
	n := t.stateLocked(g).charge()
	t.addLocked(g.user, n-g.w)
	g.w = n
}

func (t *tunnels) addLocked(u *memUser, n int64) {
	u.charge += n
	t.charge += n
}

// admit registers a TCP tunnel of user on conn (nil: none known), pending,
// unless the charge is at the budget, or there is pressure, and the
// user's is at its fair share: then nil, the refusal counted. The check
// and the charge are one step under the lock: a burst of CONNECTs is
// weighed one by one, each charged.
func (t *tunnels) admit(user string, conn any, h3 bool, cancel context.CancelCauseFunc) *tunnelMem {
	t.mu.Lock()
	defer t.mu.Unlock()
	u := t.users[user]
	if (t.charge >= t.budget || t.pressure.Load()) && u != nil && u.charge >= t.shareLocked() {
		t.refused.Add(1)
		return nil
	}
	if t.users == nil {
		t.all, t.users, t.groups = map[*tunnelMem]bool{}, map[string]*memUser{}, map[groupKey]*memGroup{}
		t.byConn = map[any]map[*memGroup]bool{}
	}
	if u == nil {
		u = &memUser{}
		t.users[user] = u
	}
	var g *memGroup
	if conn != nil {
		g = t.groups[groupKey{user, conn}]
	}
	if g == nil {
		g = &memGroup{key: groupKey{user, conn}, user: u, h3: h3}
		if conn != nil {
			t.groups[g.key] = g
			if h3 {
				if t.byConn[conn] == nil {
					t.byConn[conn] = map[*memGroup]bool{}
				}
				t.byConn[conn][g] = true
			}
		}
	}
	tm := &tunnelMem{g: g, cancel: cancel, at: mono(), pend: true, count: true, uploading: true}
	t.all[tm] = true
	u.streams++
	g.streams++
	g.counted++
	g.uploading++
	t.addLocked(u, tunnelCost)
	t.recountLocked(g)
	return tm
}

// run notes that the tunnel's copy starts, to out: it is no longer
// pending.
func (t *tunnels) run(tm *tunnelMem, out net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	tm.out, tm.pend = out, false
	t.setCountLocked(tm, tm.up.Load() != 0)
}

// uploaded notes that the tunnel's upload ended.
func (t *tunnels) uploaded(tm *tunnelMem) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.endUploadLocked(tm)
}

func (t *tunnels) endUploadLocked(tm *tunnelMem) {
	if tm.gone || !tm.uploading {
		return
	}
	tm.uploading = false
	tm.g.uploading--
	t.recountLocked(tm.g)
}

func (t *tunnels) setCountLocked(tm *tunnelMem, count bool) {
	if tm.gone || tm.count == count {
		return
	}
	tm.count = count
	if count {
		tm.g.counted++
	} else {
		tm.g.counted--
	}
	t.recountLocked(tm.g)
}

// leave takes the tunnel out at its end.
func (t *tunnels) leave(tm *tunnelMem) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dropLocked(tm)
	delete(t.all, tm)
	g := tm.g
	if g.streams--; g.streams == 0 && t.groups[g.key] == g {
		delete(t.groups, g.key)
		if gs := t.byConn[g.key.conn]; gs != nil {
			delete(gs, g)
			if len(gs) == 0 {
				delete(t.byConn, g.key.conn)
			}
		}
	}
	if g.user.streams--; g.user.streams == 0 {
		delete(t.users, g.key.user)
	}
	tm.out = nil
}

// dropLocked takes the tunnel's charge off, once.
func (t *tunnels) dropLocked(tm *tunnelMem) {
	if tm.gone {
		return
	}
	t.setCountLocked(tm, false)
	t.endUploadLocked(tm)
	tm.gone = true
	t.addLocked(tm.g.user, -tunnelCost)
}

// grow is HTTP/3's window hook (Server.AllowH3Window): a connection's
// window grows while the charge is under the budget and there is no
// pressure, and what it grew by sizes its streams' window parts at once.
// Its record goes when done does.
func (t *tunnels) grow(conn any, done <-chan struct{}, delta uint64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if conn == nil || t.charge >= t.budget || t.pressure.Load() {
		return false
	}
	if t.grants == nil {
		t.grants = map[any]int64{}
	}
	had, ok := t.grants[conn]
	if !ok {
		go func() {
			<-done
			t.mu.Lock()
			defer t.mu.Unlock()
			delete(t.grants, conn)
		}()
	}
	t.grants[conn] = min(had+int64(min(delta, h3ConnWindowMax)), h3ConnWindowMax)
	for g := range t.byConn[conn] {
		t.recountLocked(g)
	}
	return true
}

func (t *tunnels) stats() MemoryStats {
	t.mu.Lock()
	charge := t.charge
	t.mu.Unlock()
	return MemoryStats{Budget: t.budget, Charge: charge, Pressure: t.pressure.Load(), Refused: t.refused.Load(), Evicted: t.evicted.Load()}
}

// memCand is a stream a round may reset, as the scan saw it.
type memCand struct {
	tm        *tunnelMem
	user      string
	class     int   // classStuck, classPending, classSlow, classReading
	since     int64 // blocked, admitted or reading since (mono)
	down      bool  // only its download blocked: its socket's memory ranks it
	counted   bool  // its window part counted
	uploading bool
	held      int64 // its socket's memory (SO_MEMINFO), when down
	out       net.Conn
	g         *memGroup
}

const (
	classStuck   = iota // blocked evictGrace or longer
	classPending        // admitted, its copy not started
	classSlow           // blocked less than evictGrace
	// classReading: over HTTP/3, neither pending nor blocked, its read of
	// the upload waiting evictGrace or longer: what came out of order may
	// be in QUIC's packets (groupState.charge).
	classReading
	classes
)

// memSnapshot is what a round weighs: the streams it may reset, the
// users' charges, the charge, the share and the groups.
type memSnapshot struct {
	cands  []memCand
	users  map[string]int64
	charge int64
	share  int64
	groups map[*memGroup]*groupState
}

// scan counts every stream's window part anew from its state, in one pass
// under the lock reading atomics only, and gives what a round weighs when
// collect says one may come (the streams only then).
func (t *tunnels) scan(collect func(charge int64) bool) memSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	snap := memSnapshot{charge: t.charge, share: t.shareLocked()}
	want := collect(t.charge)
	now, grace := mono(), int64(evictGrace)
	cands := t.cands[:0]
	for tm := range t.all {
		if tm.gone {
			continue
		}
		up := tm.up.Load()
		t.setCountLocked(tm, tm.pend || up != 0)
		if !want {
			continue
		}
		c := memCand{tm: tm, user: tm.g.key.user, g: tm.g, out: tm.out, counted: tm.count, uploading: tm.uploading}
		down, rd := tm.down.Load(), tm.rd.Load()
		switch since := min(nonzero(up), nonzero(down)); {
		case tm.pend:
			c.class, c.since = classPending, tm.at
		case since != math.MaxInt64:
			c.since, c.down = since, up == 0
			c.class = classSlow
			if now-since >= grace {
				c.class = classStuck
			}
		case tm.g.h3 && tm.uploading && rd != 0 && now-rd >= grace:
			c.class, c.since = classReading, rd
		default:
			continue // idle: never reset
		}
		cands = append(cands, c)
	}
	t.cands = cands
	snap.charge = t.charge
	if !want {
		return snap
	}
	snap.cands = cands
	snap.users = make(map[string]int64, len(t.users))
	for name, u := range t.users {
		snap.users[name] = u.charge
	}
	snap.groups = map[*memGroup]*groupState{}
	for i := range cands {
		if g := cands[i].g; snap.groups[g] == nil {
			gs := t.stateLocked(g)
			snap.groups[g] = &gs
		}
	}
	return snap
}

// snapshot is scan with the streams, whatever the readings.
func (t *tunnels) snapshot() memSnapshot {
	return t.scan(func(int64) bool { return true })
}

func nonzero(v int64) int64 {
	if v == 0 {
		return math.MaxInt64
	}
	return v
}

// tick is one look of the scanner: the triggers, and under pressure a
// round of resets.
func (t *tunnels) tick() {
	sig := t.read()
	budget := t.budget
	// The three triggers (spec/memory-v1.md §5): the live heap, stacks and
	// sockets against the Go limit; the heap's goal (within the limit),
	// stacks and sockets against the cgroup's throttle; the charge against
	// the budget. Each on at its first mark, off at its second.
	heapLive := sig.live + sig.stacks
	heapGoal := sig.goal
	if sig.limit > 0 {
		heapGoal = min(heapGoal, sig.limit)
	}
	heapGoal += sig.stacks
	over := func(v, of, on int64) bool { return of > 0 && v*100 >= of*on }
	snap := t.scan(func(charge int64) bool {
		return t.pressure.Load() || over(heapLive+sig.sock, sig.limit, liveOn) || over(heapGoal+sig.sock, sig.throttle, goalOn) ||
			over(charge, budget, chargeOn)
	})
	var need [3]int64
	mark := func(i int, v, of, on, off int64) {
		switch {
		case of <= 0:
			t.on[i] = false
			return
		case v*100 >= of*on:
			t.on[i] = true
		case v*100 <= of*off:
			t.on[i] = false
		}
		need[i] = v - of*on/100
	}
	mark(triggerLive, heapLive+sig.sock, sig.limit, liveOn, liveOff)
	mark(triggerGoal, heapGoal+sig.sock, sig.throttle, goalOn, goalOff)
	mark(triggerCharge, snap.charge, budget, chargeOn, chargeOff)
	t.pressure.Store(t.on[triggerLive] || t.on[triggerGoal] || t.on[triggerCharge])
	// After a round of the heap's what it freed shows only once a GC has
	// run past the tunnels' end: two cycles from the look after the round
	// (by then the reset tunnels have gone, a write that stood within its
	// second). Meanwhile the heap is taken as that round saw it, less what
	// it reckoned to free, and only the sockets' growth since brings a round.
	// The charge's rounds do not wait.
	heap := max(need[triggerLive], need[triggerGoal], 0)
	waiting := t.heapWait
	if waiting {
		if !t.gcSet {
			t.gcAt, t.gcSet = sig.cycles, true
		}
		if sig.cycles >= t.gcAt+2 {
			waiting, t.heapWait = false, false
		} else {
			var l, g int64
			if sig.limit > 0 {
				l = t.heapSeen[0] + sig.sock - t.heapFreed - sig.limit*liveOn/100
			}
			if sig.throttle > 0 {
				g = t.heapSeen[1] + sig.sock - t.heapFreed - sig.throttle*goalOn/100
			}
			heap = min(heap, max(l, g, 0))
		}
	}
	if want := max(heap, need[triggerCharge]); want > 0 && len(snap.cands) > 0 {
		list, freed := pick(snap, want)
		t.evict(list)
		if heap > 0 {
			if waiting {
				t.heapFreed += freed
			} else {
				t.heapSeen, t.heapFreed = [2]int64{heapLive, heapGoal}, freed
			}
			t.heapWait, t.gcSet = true, false
		}
	}
	t.warn(snap.charge, budget)
}

// pick chooses the streams to reset, at most evictRound, until what they
// are reckoned to free (their charge, and a download's socket memory)
// reaches want, and says what that is. The users over their fair share
// come first, the largest first; of a user, the streams blocked evictGrace
// or longer, the longest first; then its pending ones and those blocked
// less, only from a user at twice its share or more, or once no user over
// its share has a stream blocked that long. Once none of theirs is pending
// or blocked, their HTTP/3 streams whose upload's read has waited
// evictGrace or longer (classReading), the longest first: the one exception
// to an idle stream never reset. Then the users under their share, while
// want is not met, only their streams blocked evictGrace or longer. A
// download's are ranked by their socket's memory, after the streams that
// hold their window part.
func pick(snap memSnapshot, want int64) ([]*tunnelMem, int64) {
	eff := maps.Clone(snap.users)
	for i := range snap.cands {
		c := &snap.cands[i]
		if c.down && c.out != nil {
			c.held = connMemory(c.out)
			eff[c.user] += c.held
		}
	}
	byUser := map[string]*[classes][]*memCand{}
	for i := range snap.cands {
		c := &snap.cands[i]
		if byUser[c.user] == nil {
			byUser[c.user] = new([classes][]*memCand)
		}
		byUser[c.user][c.class] = append(byUser[c.user][c.class], c)
	}
	var over, under []string
	for name := range byUser {
		if eff[name] > snap.share {
			over = append(over, name)
		} else {
			under = append(under, name)
		}
	}
	largest := func(a, b string) int { return cmp.Compare(eff[b], eff[a]) }
	slices.SortFunc(over, largest)
	slices.SortFunc(under, largest)
	for _, classes := range byUser {
		for _, list := range classes {
			slices.SortFunc(list, func(a, b *memCand) int {
				switch {
				case a.down != b.down: // the window's holders first
					if a.down {
						return 1
					}
					return -1
				case a.down && a.held != b.held:
					return cmp.Compare(b.held, a.held)
				}
				return cmp.Compare(a.since, b.since)
			})
		}
	}
	var out []*tunnelMem
	var freed int64
	taken := map[*memCand]bool{}
	full := func() bool { return len(out) >= evictRound || freed >= want }
	take := func(list []*memCand) {
		for _, c := range list {
			if full() {
				return
			}
			if taken[c] {
				continue
			}
			taken[c] = true
			out = append(out, c.tm)
			// Its window part: what the group's comes down by.
			g := snap.groups[c.g]
			before := g.charge()
			if c.counted {
				g.counted--
			}
			if c.uploading {
				g.uploading--
			}
			freed += tunnelCost + c.held + before - g.charge()
		}
	}
	for _, name := range over {
		take(byUser[name][classStuck])
		if eff[name] >= 2*snap.share {
			take(byUser[name][classPending])
			take(byUser[name][classSlow])
		}
	}
	for _, name := range over {
		take(byUser[name][classPending])
		take(byUser[name][classSlow])
	}
	var reading []*memCand
	for _, name := range over {
		reading = append(reading, byUser[name][classReading]...)
	}
	slices.SortFunc(reading, func(a, b *memCand) int { return cmp.Compare(a.since, b.since) })
	take(reading)
	for _, name := range under {
		take(byUser[name][classStuck])
	}
	return out, freed
}

// evict resets the streams: their charge goes at once, and their tunnels
// end with errEvicted, a reset to the client (Server.tunnel).
func (t *tunnels) evict(list []*tunnelMem) {
	if len(list) == 0 {
		return
	}
	var cancels []context.CancelCauseFunc
	t.mu.Lock()
	for _, tm := range list {
		if tm.gone {
			continue
		}
		t.dropLocked(tm)
		t.evicted.Add(1)
		cancels = append(cancels, tm.cancel)
	}
	t.mu.Unlock()
	for _, cancel := range cancels {
		cancel(errEvicted)
	}
}

// warn says, at most once in memWarnEvery, how many CONNECTs were refused
// at the budget and how many tunnels reset under pressure since it last
// did, when any were: counts only, nobody and nowhere.
func (t *tunnels) warn(charge, budget int64) {
	refused, evicted := t.refused.Load(), t.evicted.Load()
	if t.warnLog == nil || refused == t.warned[0] && evicted == t.warned[1] || time.Since(t.warnAt) < memWarnEvery {
		return
	}
	t.warnLog.Warn("naive: TCP tunnels at the memory budget", "refused", refused-t.warned[0], "evicted", evicted-t.warned[1],
		"charge_mib", charge>>20, "budget_mib", budget>>20, "pressure", t.pressure.Load())
	t.warnAt, t.warned = time.Now(), [2]int64{refused, evicted}
}

// connMemory is what the kernel holds for a destination's socket
// (SO_MEMINFO); 0 when it cannot be read, or off Linux.
func connMemory(c net.Conn) int64 {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return 0
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return 0
	}
	var n int64
	if rc.Control(func(fd uintptr) { n, err = sockMemory(fd) }) != nil || err != nil {
		return 0
	}
	return n
}

// runtimeSignals reads the runtime's metrics and the cgroup's sock for a
// process of memory l.
func runtimeSignals(l memlimit.Limits) func() memSignals {
	stat := memlimit.StatFile(memlimit.System)
	throttle := l.Throttle()
	samples := []metrics.Sample{{Name: "/gc/heap/live:bytes"}, {Name: "/gc/heap/goal:bytes"},
		{Name: "/memory/classes/heap/stacks:bytes"}, {Name: "/gc/gomemlimit:bytes"}, {Name: "/gc/cycles/total:gc-cycles"}}
	var mu sync.Mutex
	return func() memSignals {
		mu.Lock()
		defer mu.Unlock()
		metrics.Read(samples)
		v := func(i int) int64 {
			if samples[i].Value.Kind() != metrics.KindUint64 {
				return 0
			}
			return int64(min(samples[i].Value.Uint64(), math.MaxInt64))
		}
		sig := memSignals{live: v(0), goal: v(1), stacks: v(2), limit: v(3), throttle: throttle}
		if sig.limit == math.MaxInt64 {
			sig.limit = 0 // no Go limit
		}
		if samples[4].Value.Kind() == metrics.KindUint64 {
			sig.cycles = samples[4].Value.Uint64()
		}
		if stat != "" {
			sig.sock, _ = memlimit.Sock(stat)
		}
		return sig
	}
}

// AllowH3Window is the HTTP/3 server's window hook (h3serve.Options.Window
// in cmd/rayd): a connection's receive window grows only while the
// tunnels' charge is under the budget and there is no pressure. conn is
// the connection, as H3Conn gives it to a request.
func (s *Server) AllowH3Window(conn any, done <-chan struct{}, delta uint64) bool {
	return s.tunnels().grow(conn, done, delta)
}

// MemoryStats are the tunnels' charge and what it did, for the stats
// socket.
func (s *Server) MemoryStats() MemoryStats { return s.tunnels().stats() }

// WatchMemory runs the tunnels' scanner every memEvery until ctx ends: the
// pressure, and the resets under it (spec/memory-v1.md §5).
func (s *Server) WatchMemory(ctx context.Context) {
	t := s.tunnels()
	tk := time.NewTicker(memEvery)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			t.tick()
		}
	}
}

// stampReader notes when each read began in since, and 0 once it is done.
type stampReader struct {
	r     io.Reader
	since *atomic.Int64
}

func (s stampReader) Read(b []byte) (int, error) {
	s.since.Store(mono())
	n, err := s.r.Read(b)
	s.since.Store(0)
	return n, err
}

// stampWriter notes when each write began in since, and 0 once it is
// done: a write in progress is a tunnel blocked that long.
type stampWriter struct {
	w     io.Writer
	since *atomic.Int64
}

func (s stampWriter) Write(b []byte) (int, error) {
	s.since.Store(mono())
	n, err := s.w.Write(b)
	s.since.Store(0)
	return n, err
}
