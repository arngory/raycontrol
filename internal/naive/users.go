package naive

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Users are the accepted passwords, as SHA-256 hashes in a JSON file that
// rayd rewrites when credentials rotate and users come and go:
// {"<hash>": "<name>"}, the name the bytes of that password count under
// (u<id>-<fingerprint>, the credential's own name for its whole life;
// u<id>, u<id>-n and u<id>-p from rayd before v0.23.0;
// docs/spec/traffic-limit-v1.md §2.3). rayd
// before v0.22.0 wrote a list of the hashes, read too: no name, nothing
// counted. The file is read again when it changes, without a restart; a
// hash it no longer has, or gives another name, loses its live streams:
// CONNECT tunnels, UDP over TCP and ICMP (§3.2), as niko-server's
// Hysteria2 does on a reload.
//
// The counters are by name, up (sent to the destinations) and down
// (received from them), since the process started; a name gone from the
// file keeps them while it has streams and staleAfter after the last one
// (prune): nothing of destinations, addresses or times. Neither they
// nor destinations go to the log.
type Users struct {
	Path string
	// Refused gives the refusals of the connection limits by base name and
	// kind (Server.Refused), for the stats socket; nil: none.
	Refused func() map[string]map[string]int64

	every   time.Duration // reloadEvery when 0 (tests make it short)
	mu      sync.Mutex
	checked time.Time
	file    os.FileInfo
	loaded  bool
	byHash  map[[32]byte]string
	live    map[[32]byte]map[*session]bool
	traffic map[string]*Traffic
	boot    string
	stale   time.Duration // staleAfter when 0 (tests make it short)
}

// staleAfter is how long the counters of a name gone from the file stay
// readable once its last stream has ended: rayd reads them every 15 s, so
// it has their last bytes long before (traffic-limit-v1 §2.3). Without
// it every credential rotation would leave a name for good, and a process
// running for months would answer with more names than rayd reads.
const staleAfter = 5 * time.Minute

// reloadEvery is how often the file is looked at: by Watch, and by a
// request when Watch does not run.
const reloadEvery = 5 * time.Second

// errRevoked ends the streams of a password the users file no longer has.
var errRevoked = errors.New("naive: the user is no longer in the users file")

// HashPassword is how the users file names a password.
func HashPassword(p string) string {
	sum := sha256.Sum256([]byte(p))
	return hex.EncodeToString(sum[:])
}

// Traffic are a name's bytes at the destinations' side. Nil counts for
// nobody. streams and gone (under Users.mu) tell when the counters of a
// name the file no longer has may go: none of its streams left, and gone
// staleAfter ago.
type Traffic struct {
	upN, downN atomic.Int64
	streams    int
	gone       time.Time
}

func (t *Traffic) addUp(n int) {
	if t != nil && n > 0 {
		t.upN.Add(int64(n))
	}
}

func (t *Traffic) addDown(n int) {
	if t != nil && n > 0 {
		t.downN.Add(int64(n))
	}
}

func (t *Traffic) up() *atomic.Int64 {
	if t == nil {
		return nil
	}
	return &t.upN
}

func (t *Traffic) down() *atomic.Int64 {
	if t == nil {
		return nil
	}
	return &t.downN
}

// countWriter counts what is written through it (nil: nothing).
type countWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c countWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	if c.n != nil && n > 0 {
		c.n.Add(int64(n))
	}
	return n, err
}

// countReader counts what is read through it (nil: nothing).
type countReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c countReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	if c.n != nil && n > 0 {
		c.n.Add(int64(n))
	}
	return n, err
}

// session is a live stream of a password: cancel ends it.
type session struct{ cancel context.CancelCauseFunc }

// admitted is an authenticated stream: its user (the password's hash),
// the counters of the name, a context that ends when the password leaves
// the users file, and leave, which takes the stream out when it ends.
type admitted struct {
	user [32]byte
	// key is whose limits it takes (spec/conn-limit-v1.md §2): the base
	// name, u5 for u5 and its credentials' names; a password without a
	// name is its own user.
	key     string
	traffic *Traffic
	ctx     context.Context
	leave   func()
}

// Accepts reports whether the password is a current credential.
func (u *Users) Accepts(password string) bool {
	if password == "" {
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.maybeReload()
	_, ok := u.byHash[sha256.Sum256([]byte(password))]
	return ok
}

// admit lets a stream with this password in, under the same lock as a
// reload: either it is in before the reload and its context ends there,
// or it comes after and finds the password gone.
func (u *Users) admit(parent context.Context, password string) (admitted, bool) {
	if password == "" {
		return admitted{}, false
	}
	hash := sha256.Sum256([]byte(password))
	u.mu.Lock()
	defer u.mu.Unlock()
	u.maybeReload()
	name, ok := u.byHash[hash]
	if !ok {
		return admitted{}, false
	}
	ctx, cancel := context.WithCancelCause(parent)
	s := &session{cancel: cancel}
	if u.live == nil {
		u.live = map[[32]byte]map[*session]bool{}
	}
	if u.live[hash] == nil {
		u.live[hash] = map[*session]bool{}
	}
	u.live[hash][s] = true
	t := u.trafficOf(name)
	if t != nil {
		t.streams++
	}
	leave := func() {
		cancel(nil)
		u.mu.Lock()
		defer u.mu.Unlock()
		delete(u.live[hash], s)
		if len(u.live[hash]) == 0 {
			delete(u.live, hash)
		}
		if t != nil {
			t.streams--
		}
	}
	key := baseName(name)
	if name == "" {
		key = "#" + hex.EncodeToString(hash[:8])
	}
	return admitted{user: hash, key: key, traffic: t, ctx: ctx, leave: leave}, true
}

// trafficOf is a name's counters, made at first sight and kept until the
// process ends; nil for no name. Under u.mu.
func (u *Users) trafficOf(name string) *Traffic {
	if name == "" {
		return nil
	}
	if u.traffic == nil {
		u.traffic = map[string]*Traffic{}
	}
	t := u.traffic[name]
	if t == nil {
		t = new(Traffic)
		u.traffic[name] = t
	}
	return t
}

// maybeReload reads the file again when it was last looked at reloadEvery
// ago, or never. Under u.mu.
func (u *Users) maybeReload() {
	if u.loaded && time.Since(u.checked) < u.period() {
		return
	}
	u.reload()
}

func (u *Users) period() time.Duration {
	if u.every > 0 {
		return u.every
	}
	return reloadEvery
}

// reload reads the file if it changed (another file in its place, or
// another time), takes the new table and ends the streams of the
// passwords it no longer has under the same name. A file that cannot be
// read leaves the table as it was. Under u.mu.
func (u *Users) reload() {
	u.checked = time.Now()
	defer u.prune(u.checked)
	st, err := os.Stat(u.Path)
	if err != nil {
		return
	}
	if u.loaded && os.SameFile(st, u.file) && st.ModTime().Equal(u.file.ModTime()) && st.Size() == u.file.Size() {
		return
	}
	next, err := readUsers(u.Path)
	if err != nil {
		return
	}
	for hash, ss := range u.live {
		// A password that stays with its user keeps its streams: a
		// credential keeps its name through a switch, and a name that
		// changes but stays the user's is the same user's (u5-<fingerprint>
		// becoming u5 when a rollback brings back a rayd before v0.23.0,
		// whose names go by the role and move at a switch: u5-n becomes u5,
		// u5 becomes u5-p). Its streams count on under the name they came in
		// with.
		if name, ok := next[hash]; ok && baseName(name) == baseName(u.byHash[hash]) {
			continue
		}
		for s := range ss {
			s.cancel(errRevoked)
		}
		delete(u.live, hash)
	}
	u.byHash, u.file, u.loaded = next, st, true
	for _, name := range next {
		u.trafficOf(name) // listed from the start, as niko-server's
	}
}

// prune drops the counters of the names the file no longer has, their
// last stream ended staleAfter ago or more. A name back in the file is
// kept. Under u.mu.
func (u *Users) prune(now time.Time) {
	if !u.loaded {
		return
	}
	in := make(map[string]bool, len(u.byHash))
	for _, name := range u.byHash {
		in[name] = true
	}
	stale := u.stale
	if stale <= 0 {
		stale = staleAfter
	}
	for name, t := range u.traffic {
		switch {
		case in[name] || t.streams > 0:
			t.gone = time.Time{}
		case t.gone.IsZero():
			t.gone = now
		case now.Sub(t.gone) >= stale:
			delete(u.traffic, name)
		}
	}
}

// baseName is the user a name stands for: u5 for u5 and for the names of
// its credentials, u5-<fingerprint> (rayd v0.23.0), and u5-n and u5-p (by
// the role, before).
func baseName(name string) string {
	b, _, _ := strings.Cut(name, "-")
	return b
}

// Watch reads the file every reloadEvery until ctx ends, so that a user
// who leaves it loses the live streams within that, without a request.
func (u *Users) Watch(ctx context.Context) {
	t := time.NewTicker(u.period())
	defer t.Stop()
	for {
		u.mu.Lock()
		u.reload()
		u.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// maxUsersFile bounds the users file: 4096 users with three credentials
// each take ~1.2 MiB.
const maxUsersFile = 8 << 20

// readUsers reads the users file: an object of hash to name, or the list
// of hashes rayd wrote before v0.22.0 (names "").
func readUsers(path string) (map[[32]byte]string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the unit's own file
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxUsersFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxUsersFile {
		return nil, errors.New("naive: the users file is too large")
	}
	byHash := map[string]string{}
	if err := json.Unmarshal(b, &byHash); err != nil {
		var list []string
		if json.Unmarshal(b, &list) != nil {
			return nil, err
		}
		for _, h := range list {
			byHash[h] = ""
		}
	}
	out := make(map[[32]byte]string, len(byHash))
	for h, name := range byHash {
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != 32 {
			return nil, errors.New("naive: bad hash in the users file")
		}
		out[[32]byte(raw)] = name
	}
	return out, nil
}

// TrafficSnapshot is the stats socket's answer to "traffic": each name's
// bytes since the process started, as niko-server's Hysteria2 backends
// give them (v0.15.0) and rayd reads them. Boot is random at each start:
// a new one means the counters began again.
type TrafficSnapshot struct {
	V     int                    `json:"v"`
	Boot  string                 `json:"boot"`
	Users map[string]UserTraffic `json:"users"`
	// Limit are the connection limits' refusals by base name (u5) and kind
	// since the start (spec/conn-limit-v1.md §2), only names with some: a
	// field rayd before v0.24.0 does not read.
	Limit map[string]map[string]int64 `json:"limit,omitempty"`
}

// UserTraffic are a name's bytes at the destinations' side.
type UserTraffic struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// Snapshot returns the counters; reading resets nothing.
func (u *Users) Snapshot() TrafficSnapshot {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.boot == "" {
		var b [8]byte
		_, _ = rand.Read(b[:])
		u.boot = hex.EncodeToString(b[:])
	}
	s := TrafficSnapshot{V: 1, Boot: u.boot, Users: make(map[string]UserTraffic, len(u.traffic))}
	for name, t := range u.traffic {
		s.Users[name] = UserTraffic{Up: t.upN.Load(), Down: t.downN.Load()}
	}
	if u.Refused != nil {
		if r := u.Refused(); len(r) > 0 {
			s.Limit = r
		}
	}
	return s
}

// ServeStats answers on a unix socket at path until ctx ends, as
// niko-server's Hysteria2 stats socket: one line in, "traffic" gets the
// Snapshot as one JSON line, anything else nothing; then the connection
// closes. The socket is 0660 in the service's runtime directory, which
// rayd's group may pass through.
func (u *Users) ServeStats(ctx context.Context, path string, log *slog.Logger) error {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o660); err != nil { //nolint:gosec // G302: rayd connects through the service's group
		_ = ln.Close()
		return err
	}
	u.Snapshot() // the boot is made now: the process's start
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				log.Warn("naive: stats socket", "err", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			go u.answer(c)
		}
	}()
	return nil
}

func (u *Users) answer(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(io.LimitReader(c, 192)).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "traffic" {
		return
	}
	_ = json.NewEncoder(c).Encode(u.Snapshot())
}
