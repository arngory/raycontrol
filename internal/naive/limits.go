package naive

import (
	"context"
	"errors"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// The per-user connection limits (spec/conn-limit-v1.md §2, §3.1, §5): one
// set per user in the process, by the user's base name (u5 for u5 and the
// names of its credentials: rotation does not multiply them). They count
// what the kernel will hold: every TCP attempt, failed dials, UDP pairs
// even after their stream, name lookups. A user's tokens outlive their last
// connection until they have refilled: closing gives none back.
//
// rayctl conn-limit off turns the TCP limits and the pairs off (the file
// -conn-limit names); UoT's stream and destination limits stay, as they
// were before.
const (
	tcpPerUser          = 1024
	tcpRate, tcpBurst   = 30, 600
	tcpWait             = 500 * time.Millisecond // less than the first SYN retry (1 s)
	failRate, failBurst = 5, 100
	// failDebt bounds the debt: as many failures as dials in flight.
	failDebt = tcpPerUser

	// UoT: a new stream past uotPerUser takes the place of the quietest,
	// one silent both ways this long.
	quietAfter = 10 * time.Second

	// Pairs (local port, destination) of UDP as conntrack keeps them: 30 s
	// after the last packet sent without an answer, 120 s after the last
	// packet either way with one; in a live stream and after it.
	pairsPerUser   = 1024
	pairAnswered   = 120 * time.Second
	pairUnanswered = 30 * time.Second
	// ageEvery: a user's pairs are aged this often at most.
	ageEvery = time.Second
	// The process's ceiling of pairs: a quarter of nf_conntrack_max, read
	// again every ceilingEvery; defaultCeiling where it cannot be read.
	ceilingEvery   = time.Minute
	defaultCeiling = 65536 / 4

	// Name lookups (misses of the process's cache), TCP and UDP together;
	// with the limits off, UoT's alone and its burst as before.
	lookupRate, lookupBurst, lookupBurstOff = 20, 100, 50
)

// The kinds of refusals (§2), counted by name since the process started.
const (
	refusedTCP     = "tcp"     // TCP at once
	refusedRate    = "rate"    // TCP attempts
	refusedFailed  = "failed"  // failed dials in debt
	refusedUDP     = "udp"     // UoT streams, none quiet to give way
	refusedEvicted = "evicted" // a quiet UoT stream gave way
	refusedDest    = "dest"    // new UDP destinations
	refusedLive    = "live"    // UDP pairs
	refusedLookup  = "lookup"  // name lookups
)

// errEvicted ends a quiet UoT stream for a new one of the same user.
var errEvicted = errors.New("naive: a quiet stream gave way to a new one")

// limits are a process's per-user limits. The zero value is ready, limits
// on.
type limits struct {
	mu    sync.Mutex
	now   func() time.Time // time.Now when nil (tests: a fake clock)
	sleep func(ctx context.Context, d time.Duration) error
	off   atomic.Bool

	users   map[string]*limUser
	total   int // UoT streams of the service
	swept   time.Time
	refused map[string]map[string]int64

	// ctMax reads nf_conntrack_max (the file when nil).
	ctMax       func() (uint64, error)
	ceiling     int
	ceilingAt   time.Time
	pairs       int // counted pairs of all users
	withPairs   int // users with pairs counted: the fair share's divisor
	agedAll     time.Time
	lookupBurst float64 // tests
}

type limUser struct {
	streams int
	slots   map[*uotSlot]bool
	tcp     int
	// attempts, failures (in debt below zero), new UDP destinations,
	// lookups.
	attempts, failed, peers, lookups bucket
	journal                          []int64 // the ends of ended streams' pairs (monoAt)
	pairs                            int     // counted: live streams' and the journal's
	aged                             time.Time
}

// uotSlot is a UoT stream's place: its user, its end, and the stream once
// it runs (its pairs).
type uotSlot struct {
	user    string
	cancel  context.CancelCauseFunc
	last    atomic.Int64 // mono: the last packet either way
	evicted bool         // under limits.mu: it gave way, its place is free
	stream  *uotStream   // under limits.mu
	pairs   int          // counted for it, under limits.mu
}

func (l *limits) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

func (l *limits) wait(ctx context.Context, d time.Duration) error {
	if l.sleep != nil {
		return l.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (l *limits) lookupRoom() float64 {
	switch {
	case l.lookupBurst > 0:
		return l.lookupBurst
	case l.off.Load():
		return lookupBurstOff
	}
	return lookupBurst
}

// userLocked is a user's state, made at first sight with full buckets.
func (l *limits) userLocked(name string, now time.Time) *limUser {
	if now.Sub(l.swept) > 10*time.Second {
		l.sweepLocked(now)
	}
	u := l.users[name]
	if u == nil {
		if l.users == nil {
			l.users = map[string]*limUser{}
		}
		u = &limUser{attempts: bucket{tcpBurst, now}, failed: bucket{failBurst, now}, peers: bucket{uotPeerBurst, now},
			lookups: bucket{l.lookupRoom(), now}}
		l.users[name] = u
	}
	return u
}

// sweepLocked forgets the users with nothing open, nothing owed and full
// buckets, after aging their journals.
func (l *limits) sweepLocked(now time.Time) {
	l.swept = now
	for k, u := range l.users {
		l.ageLocked(u, now, true)
		if u.streams == 0 && u.tcp == 0 && u.pairs == 0 && u.attempts.full(now, tcpRate, tcpBurst) &&
			u.failed.full(now, failRate, failBurst) && u.peers.full(now, uotPeerRate, uotPeerBurst) &&
			u.lookups.full(now, lookupRate, l.lookupRoom()) {
			delete(l.users, k)
		}
	}
}

// refuseLocked counts a refusal of the user's.
func (l *limits) refuseLocked(user, kind string) {
	if l.refused == nil {
		l.refused = map[string]map[string]int64{}
	}
	if l.refused[user] == nil {
		l.refused[user] = map[string]int64{}
	}
	l.refused[user][kind]++
}

func (l *limits) refuse(user, kind string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refuseLocked(user, kind)
}

// Refused are the refusals by base name (u<id>) and kind since the process
// started; names that are no user's number (a password without a name)
// are left out. Reading resets nothing.
func (l *limits) Refused() map[string]map[string]int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string]map[string]int64, len(l.refused))
	for name, kinds := range l.refused {
		if !userNumber(name) {
			continue
		}
		k := make(map[string]int64, len(kinds))
		for kind, n := range kinds {
			k[kind] = n
		}
		out[name] = k
	}
	return out
}

// userNumber reports whether a name is u<id>.
func userNumber(name string) bool {
	id, ok := strings.CutPrefix(name, "u")
	_, err := strconv.ParseUint(id, 10, 63)
	return ok && err == nil && id != "" && id[0] != '+'
}

// tcpStart takes a place among the user's TCP connections and a token for
// its first attempt, waiting tcpWait at most and no longer than ctx, and
// checks the debt of failed dials. done gives the place back; kind says
// why not ("" with done when admitted). With the limits off, all pass.
func (l *limits) tcpStart(ctx context.Context, user string) (done func(), kind string) {
	if l.off.Load() {
		return func() {}, ""
	}
	l.mu.Lock()
	u := l.userLocked(user, l.clock())
	if u.tcp >= tcpPerUser {
		l.refuseLocked(user, refusedTCP)
		l.mu.Unlock()
		return nil, refusedTCP
	}
	u.tcp++
	l.mu.Unlock()
	var once sync.Once
	done = func() {
		once.Do(func() {
			l.mu.Lock()
			u.tcp--
			l.mu.Unlock()
		})
	}
	if !l.waitAttempt(ctx, user, u) {
		done()
		return nil, refusedRate
	}
	l.mu.Lock()
	debt := u.failed.level(l.clock(), failRate, failBurst) < 0
	if debt {
		l.refuseLocked(user, refusedFailed)
	}
	l.mu.Unlock()
	if debt {
		done()
		return nil, refusedFailed
	}
	return done, ""
}

// waitAttempt takes an attempt token, waiting for one up to tcpWait while
// ctx lasts; a refusal is counted.
func (l *limits) waitAttempt(ctx context.Context, user string, u *limUser) bool {
	start := l.clock()
	for {
		l.mu.Lock()
		now := l.clock()
		if u.attempts.take(now, tcpRate, tcpBurst) {
			l.mu.Unlock()
			return true
		}
		// Until the next token comes.
		// A millisecond at least: a float's dust must not spin the loop.
		need := max(time.Millisecond, time.Duration((1-u.attempts.tokens)/tcpRate*float64(time.Second)))
		if now.Add(need).Sub(start) > tcpWait || ctx.Err() != nil {
			l.refuseLocked(user, refusedRate)
			l.mu.Unlock()
			return false
		}
		l.mu.Unlock()
		if l.wait(ctx, need) != nil {
			l.refuse(user, refusedRate)
			return false
		}
	}
}

// attempt takes a token for one more attempt of a dial (the next address
// of a name), without waiting.
func (l *limits) attempt(user string) bool {
	if l.off.Load() {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	u := l.userLocked(user, l.clock())
	if !u.attempts.take(l.clock(), tcpRate, tcpBurst) {
		l.refuseLocked(user, refusedRate)
		return false
	}
	return true
}

// failedDial charges a dial that sent a SYN and got no connection: a
// timeout, ECONNREFUSED, EHOSTUNREACH. ENETUNREACH and EPERM did not send
// one (no route, or the guard refused it), nor did a dial its caller gave
// up: not charged.
func (l *limits) failedDial(user string, err error) {
	if err == nil || l.off.Load() || !chargeable(err) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	u := l.userLocked(user, l.clock())
	u.failed.charge(l.clock(), failRate, failBurst, failDebt)
}

// chargeable reports whether a dial's error means a SYN went and nothing
// came of it.
func chargeable(err error) bool {
	switch {
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EPERM), errors.Is(err, context.Canceled):
		return false
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.EHOSTUNREACH):
		return true
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// lookup takes a token for a name lookup the cache missed.
func (l *limits) lookup(user string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	u := l.userLocked(user, l.clock())
	if !u.lookups.take(l.clock(), lookupRate, l.lookupRoom()) {
		l.refuseLocked(user, refusedLookup)
		return false
	}
	return true
}

// uotTake gives a UoT stream its place: at the user's limit (limits on),
// the quietest stream silent quietAfter gives way. nil and why when there
// is none.
func (l *limits) uotTake(user string, cancel context.CancelCauseFunc) (*uotSlot, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	u := l.userLocked(user, now)
	if l.total >= uotPerService {
		l.refuseLocked(user, refusedUDP)
		return nil, refusedUDP
	}
	if u.streams >= uotPerUser {
		var quiet *uotSlot
		if !l.off.Load() {
			m := mono()
			for s := range u.slots {
				if s.evicted || time.Duration(m-s.last.Load()) < quietAfter {
					continue
				}
				if quiet == nil || s.last.Load() < quiet.last.Load() {
					quiet = s
				}
			}
		}
		if quiet == nil {
			l.refuseLocked(user, refusedUDP)
			return nil, refusedUDP
		}
		quiet.evicted = true
		quiet.cancel(errEvicted)
		u.streams--
		l.total--
		delete(u.slots, quiet)
		l.refuseLocked(user, refusedEvicted)
	}
	s := &uotSlot{user: user, cancel: cancel}
	s.last.Store(mono())
	if u.slots == nil {
		u.slots = map[*uotSlot]bool{}
	}
	u.slots[s] = true
	u.streams++
	l.total++
	return s, ""
}

// uotRun ties a slot to its stream: its pairs count from now on.
func (l *limits) uotRun(s *uotSlot, st *uotStream) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s.stream = st
}

// uotPut gives a stream's place back (unless it gave way already) and
// moves its pairs to the user's journal, to live out their time there.
func (l *limits) uotPut(s *uotSlot) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	u := l.userLocked(s.user, now)
	if !s.evicted {
		u.streams--
		l.total--
		delete(u.slots, s)
	}
	s.evicted = true
	if s.stream != nil && !l.off.Load() {
		u.journal = append(u.journal, s.stream.ends()...)
	}
	s.stream = nil
	l.recountLocked(u, now)
}

// newPair admits a stream's new pair (a destination it has not sent to):
// within the user's pairs, the process's ceiling, and a token for a new
// destination. A refusal is counted.
func (l *limits) newPair(s *uotSlot) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	u := l.userLocked(s.user, now)
	if !l.off.Load() {
		l.ageLocked(u, now, false)
		if u.pairs >= pairsPerUser {
			l.refuseLocked(s.user, refusedLive)
			return false
		}
		if c := l.ceilingLocked(now); l.pairs >= c {
			// Every user's pairs aged first: the count may be behind.
			if now.Sub(l.agedAll) >= ageEvery {
				l.agedAll = now
				for _, x := range l.users {
					l.ageLocked(x, now, true)
				}
			}
			if l.pairs >= c && u.pairs > c/max(1, l.withPairs) {
				l.refuseLocked(s.user, refusedLive)
				return false
			}
		}
	}
	if !u.peers.take(now, uotPeerRate, uotPeerBurst) {
		l.refuseLocked(s.user, refusedDest)
		return false
	}
	if !l.off.Load() {
		s.pairs++
		l.setPairsLocked(u, u.pairs+1)
	}
	return true
}

// setPairsLocked sets a user's count of pairs, and the process's counts:
// its pairs, and how many users have some (the fair share of the ceiling
// is the ceiling over them; counted as it goes, not by walking the users
// at each new pair).
func (l *limits) setPairsLocked(u *limUser, n int) {
	switch {
	case u.pairs == 0 && n > 0:
		l.withPairs++
	case u.pairs > 0 && n == 0:
		l.withPairs--
	}
	l.pairs += n - u.pairs
	u.pairs = n
}

// ceilingLocked is the process's ceiling of pairs: a quarter of the live
// nf_conntrack_max, read again every ceilingEvery.
func (l *limits) ceilingLocked(now time.Time) int {
	if l.ceiling > 0 && now.Sub(l.ceilingAt) < ceilingEvery {
		return l.ceiling
	}
	l.ceilingAt = now
	read := l.ctMax
	if read == nil {
		read = conntrackMax
	}
	if v, err := read(); err == nil && v >= 4 {
		l.ceiling = int(min(v/4, 1<<30))
	} else {
		l.ceiling = defaultCeiling
	}
	return l.ceiling
}

// conntrackMax reads nf_conntrack_max (readable under
// ProtectKernelTunables).
func conntrackMax() (uint64, error) {
	b, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_max")
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
}

// ageLocked ages a user's pairs once in ageEvery (always with force): the
// live streams' and the journal's, and sets the counts anew.
func (l *limits) ageLocked(u *limUser, now time.Time, force bool) {
	if !force && now.Sub(u.aged) < ageEvery {
		return
	}
	l.recountLocked(u, now)
}

// recountLocked counts a user's pairs from the streams and the journal.
func (l *limits) recountLocked(u *limUser, now time.Time) {
	u.aged = now
	m := monoAt(now)
	u.journal = slices.DeleteFunc(u.journal, func(end int64) bool { return m >= end })
	n := len(u.journal)
	for s := range u.slots {
		s.pairs = 0
		if s.stream != nil {
			s.pairs = s.stream.age(now)
		}
		n += s.pairs
	}
	if l.off.Load() {
		n = 0
	}
	l.setPairsLocked(u, n)
}

// Refused are the refusals of the connection limits by base name and kind
// (limits.Refused), for the stats socket.
func (s *Server) Refused() map[string]map[string]int64 { return s.lim.Refused() }

// ConnLimitOn reports whether the per-user limits are on.
func (s *Server) ConnLimitOn() bool { return !s.lim.off.Load() }

// SetConnLimit turns the per-user limits on or off; what is open stays.
func (s *Server) SetConnLimit(on bool) { s.lim.off.Store(!on) }

// WatchConnLimit reads the switch file (render.NaiveConnLimit) now and
// every reloadEvery until ctx ends: "off" turns the limits off, anything
// else, or no file, on. A change is logged, without a restart.
func (s *Server) WatchConnLimit(ctx context.Context, path string) {
	read := func() {
		b, err := os.ReadFile(path) //nolint:gosec // G304: the unit's own file
		on := err != nil || strings.TrimSpace(string(b)) != "off"
		if on != s.ConnLimitOn() {
			s.SetConnLimit(on)
			if s.Log != nil {
				s.Log.Info("naive: per-user connection limits", "on", on)
			}
		}
	}
	read()
	t := time.NewTicker(reloadEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			read()
		}
	}
}

// bucket is a token bucket: rate tokens a second, up to burst.
type bucket struct {
	tokens float64
	at     time.Time
}

// level is the tokens now, refilled.
func (b *bucket) level(now time.Time, rate, burst float64) float64 {
	b.tokens = min(burst, b.tokens+now.Sub(b.at).Seconds()*rate)
	b.at = now
	return b.tokens
}

func (b *bucket) full(now time.Time, rate, burst float64) bool {
	return b.tokens+now.Sub(b.at).Seconds()*rate >= burst
}

func (b *bucket) take(now time.Time, rate, burst float64) bool {
	if b.level(now, rate, burst) < 1 {
		return false
	}
	b.tokens--
	return true
}

// charge takes a token in debt: down to -debt.
func (b *bucket) charge(now time.Time, rate, burst, debt float64) {
	b.tokens = max(-debt, b.level(now, rate, burst)-1)
}
