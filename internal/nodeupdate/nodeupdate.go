// Package nodeupdate is what an update the node asks for itself goes
// through (docs/spec/node-update-v1.md): an admin's request over the API
// (remote) or rayd's own for a patch release (auto). rayd runs without
// privileges: it writes a request, a root unit (raycontrol-update.path)
// sees it and runs rayctl update -request, which checks it again against
// root's own policy file, updates as rayctl update does (signed releases
// only) and writes the outcome to a status file rayd reads.
package nodeupdate

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/arngory/raycontrol/internal/release"
)

const (
	// RequestFile is rayd's: in its state directory, watched by
	// raycontrol-update.path.
	RequestFile = "/var/lib/raycontrol/update-request"
	// StatusDir is root's (0755): rayd reads what is in it, nobody but
	// root writes it.
	StatusDir  = "/var/lib/raycontrol-update"
	StatusFile = StatusDir + "/status.json"
	// PolicyFile is root's (rayctl update remote|auto): rayd cannot turn
	// an update on that root left off.
	PolicyFile = StatusDir + "/policy.json"
	// ResultFile is where the runner has the update's outcome written
	// (ResultEnv).
	ResultFile = StatusDir + "/result.json"
	// ResultEnv names the file the rayctl doing an update writes its
	// Result to. Frozen (docs/RELEASE.md): the rayctl of a newer release
	// writes it for the runner of an older one.
	ResultEnv = "RAYCONTROL_UPDATE_RESULT"
	// PathUnit and ServiceUnit run the requests (deploy.Plan).
	PathUnit    = "raycontrol-update.path"
	ServiceUnit = "raycontrol-update.service"

	// DefaultWindow is the auto update's window when none is set.
	DefaultWindow = "03:00-05:00"
	// MinWindow: a shorter window could pass between two looks of rayd.
	MinWindow = 30 * time.Minute
	// Spread: in the window each node asks at a moment of its own, this
	// long at most after it saw the window open.
	Spread = 30 * time.Minute

	// Stale: a request or a run older than this is taken as dead (a node
	// that went down in the middle); the unit's own limit is 50 min.
	Stale = time.Hour
	// RetryAfter: an auto update that failed before it changed the node
	// (the download, say) is asked for again this much later.
	RetryAfter = 24 * time.Hour

	maxFile   = 4 << 10  // a request, the policy
	maxStatus = 16 << 10 // the status, the result
	maxField  = 128
	maxError  = 512
	maxHeld   = 8
)

// Kinds of request.
const (
	Remote = "remote"
	Auto   = "auto"
)

// States of an update.
const (
	Idle       = "idle"
	Requested  = "requested"
	Running    = "running"
	Done       = "done"
	RolledBack = "rolled_back" // the update failed and the previous version runs
	Failed     = "failed"      // refused, or failed without a rollback
)

// ErrWaiting: a request waits already.
var ErrWaiting = errors.New("an update is requested already")

// Request is an update asked for.
type Request struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`    // Remote or Auto
	Version string `json:"version"` // "latest" or vX.Y.Z
	// Release is what latest was as rayd saw it, for latest: the release
	// the auto update then leaves alone if this update does not hold and
	// says nothing (only rayd's own auto update follows it).
	Release string    `json:"release,omitempty"`
	By      string    `json:"by"` // who: "alice/phone (remote)", "auto"
	At      time.Time `json:"at"`
}

// Status is an update's outcome, or its progress.
type Status struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	From      string `json:"from"`
	To        string `json:"to"`                // the version asked for until it ran, then the node's
	Target    string `json:"target"`            // the version asked for
	Release   string `json:"release,omitempty"` // the release it went for, once known
	By        string `json:"by"`
	Kind      string `json:"kind"`
	Error     string `json:"error,omitempty"`
	Untouched bool   `json:"untouched,omitempty"` // failed before anything on the node changed
	// Held are releases whose update rolled back or broke on the way: the
	// auto update leaves them alone. Each status carries them over.
	Held      []string  `json:"held,omitempty"`
	Requested time.Time `json:"requested"`
	Started   time.Time `json:"started"`
	Ended     time.Time `json:"ended"`
}

// Policy is root's: what rayd may ask for.
type Policy struct {
	Remote string `json:"remote"` // "on": admins may update the node over the API
	Auto   string `json:"auto"`   // "patch": rayd updates to patch releases in the window
	Window string `json:"window"` // HH:MM-HH:MM, the node's local time
}

// Result is how an update ended, written by the rayctl that did it to the
// file ResultEnv names. Frozen with ResultEnv.
type Result struct {
	State     string `json:"state"`             // Done, RolledBack or Failed
	Version   string `json:"version,omitempty"` // the node's version after it, when known
	Release   string `json:"release,omitempty"` // the release it went for, once known
	Error     string `json:"error,omitempty"`
	Untouched bool   `json:"untouched,omitempty"` // failed before anything on the node changed
}

// NewID names a request.
func NewID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ValidVersion reports whether v is one a request may name: "latest" or a
// release.
func ValidVersion(v string) bool { return v == "latest" || release.IsRelease(v) }

// Check is a request as the root side takes it at now: well formed and
// fresh, its kind allowed, never back.
func (r Request) Check(installed string, now time.Time) error {
	switch {
	case r.ID == "" || len(r.ID) > 32 || strings.Trim(r.ID, "0123456789abcdef") != "":
		return errors.New("the request has no id")
	case r.Kind != Remote && r.Kind != Auto:
		return fmt.Errorf("a request of kind %q", Printable(r.Kind))
	case !ValidVersion(r.Version):
		return fmt.Errorf("version %q: latest or vX.Y.Z", Printable(r.Version))
	case r.Release != "" && !release.IsRelease(r.Release):
		return fmt.Errorf("release %q: vX.Y.Z", Printable(r.Release))
	case r.By == "" || len(r.By) > maxField || Printable(r.By) != r.By:
		return fmt.Errorf("the request names no one who asked (%q)", Printable(r.By))
	case now.Sub(r.At) > Stale || r.At.Sub(now) > time.Minute:
		return fmt.Errorf("the request is from %s: too old to run now", r.At.UTC().Format(time.RFC3339))
	case r.Version != "latest" && !release.Newer(r.Version, installed):
		return fmt.Errorf("%s is not newer than %s: an update by request never goes back", r.Version, installed)
	case r.Kind == Auto && (r.Version == "latest" || !Patch(r.Version, installed)):
		return fmt.Errorf("an auto update takes patch releases of %s only, not %s", installed, r.Version)
	}
	return nil
}

// Allows reports why p does not let r run at now, nil when it does: a
// remote request while root has remote updates on, an auto one while auto
// is on and in the window (a few minutes' grace for a request written at
// its end).
func (p Policy) Allows(r Request, now time.Time) error {
	switch {
	case r.Kind == Remote && p.Remote != "on":
		return errors.New("remote updates are off on this node (rayctl update remote on)")
	case r.Kind == Auto && p.Auto != "patch":
		return errors.New("auto updates are off on this node (rayctl update auto patch)")
	case r.Kind == Auto && !InWindow(now, p.Window) && !InWindow(now.Add(-5*time.Minute), p.Window):
		return fmt.Errorf("an auto update outside the window %s", p.Window)
	}
	return nil
}

// WriteRequest is rayd's: the request in place at once (a temporary file
// linked in), for the path unit to see, unless one waits already
// (ErrWaiting); a stale one is replaced.
func WriteRequest(path string, r Request, now time.Time) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp, err := writeTemp(path, b, 0o640)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	if err := os.Link(tmp, path); !errors.Is(err, os.ErrExist) {
		return err
	}
	if w, ok := PeekRequest(path); ok && now.Sub(w.At) < Stale {
		return ErrWaiting
	}
	return os.Rename(tmp, path)
}

// ReadRequest is root's: the request, read without following a link (the
// directory is rayd's). ok is false when there is none; with ok and an
// error there is something the path unit sees but no request.
func ReadRequest(path string) (r Request, ok bool, err error) {
	b, err := readNoFollow(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, false, nil
	}
	if err != nil {
		return r, true, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, true, fmt.Errorf("the request: %w", err)
	}
	return r, true, nil
}

// RemoveRequest is root's: whatever is at path goes, a directory too (no
// link followed), so that the path unit does not fire again.
func RemoveRequest(path string) error { return os.RemoveAll(path) }

// PeekRequest is rayd's: the request waiting, if any.
func PeekRequest(path string) (Request, bool) {
	var r Request
	b, err := readNoFollow(path)
	if err != nil || json.Unmarshal(b, &r) != nil {
		return r, false
	}
	return r, true
}

// WriteStatus is root's, in its own directory. Fields are made printable
// and cut, so that ReadStatus takes the file back whatever they held.
func WriteStatus(path string, s Status) error {
	for _, f := range []*string{&s.ID, &s.State, &s.From, &s.To, &s.Target, &s.Release, &s.By, &s.Kind} {
		*f = clip(Printable(*f), maxField)
	}
	s.Error = clip(Printable(s.Error), maxError)
	s.Held = slices.DeleteFunc(slices.Clone(s.Held), func(v string) bool { return !release.IsRelease(v) || len(v) > maxField })
	if len(s.Held) > maxHeld {
		s.Held = s.Held[len(s.Held)-maxHeld:]
	}
	b, err := marshal(s)
	if err != nil {
		return err
	}
	return writeRoot(path, b)
}

// Tried is the release r goes for, as far as it is known before it runs.
func (r Request) Tried() string {
	if r.Version != "latest" && release.IsRelease(r.Version) {
		return r.Version
	}
	if release.IsRelease(r.Release) {
		return r.Release
	}
	return ""
}

// Holding is what s holds, and its own release when it is a run that
// never ended (a power cut: no word, no stop hook): what the next status
// carries over.
func (s Status) Holding() []string {
	if s.State == Running {
		return Hold(s.Held, s.Release)
	}
	return s.Held
}

// Hold adds release v to held: the auto update leaves it alone.
func Hold(held []string, v string) []string {
	if !release.IsRelease(v) || slices.Contains(held, v) {
		return held
	}
	return append(slices.Clone(held), v)
}

// ReadStatus is the last status, Idle when there is none.
func ReadStatus(path string) Status {
	var s Status
	b, err := readLimit(path, maxStatus)
	if err != nil || json.Unmarshal(b, &s) != nil || s.State == "" {
		return Status{State: Idle}
	}
	return s
}

// Settled is s as it stands at now: a run with no outcome after Stale
// (its runner killed with no word: a power cut) failed.
func Settled(s Status, now time.Time) Status {
	if s.State == Running && now.Sub(s.Started) >= Stale {
		s.State = Failed
		s.Error = "interrupted: no outcome within " + Stale.String() + " (journalctl -u " + ServiceUnit + ")"
	}
	return s
}

// Busy reports whether an update is waiting or under way, and not stale.
func Busy(s Status, req Request, waiting bool, now time.Time) bool {
	if waiting && now.Sub(req.At) < Stale {
		return true
	}
	return Settled(s, now).State == Running
}

// DefaultPolicy is the policy of a node whose root set none: all off.
func DefaultPolicy() Policy { return Policy{Remote: "off", Auto: "off", Window: DefaultWindow} }

// Check reports a policy root may not set.
func (p Policy) Check() error {
	switch {
	case p.Remote != "on" && p.Remote != "off":
		return fmt.Errorf("remote %q: on or off", p.Remote)
	case p.Auto != "patch" && p.Auto != "off":
		return fmt.Errorf("auto %q: off or patch", p.Auto)
	}
	_, _, err := ParseWindow(p.Window)
	return err
}

// ReadPolicy is root's policy; all off when there is none, or it cannot be
// read.
func ReadPolicy(path string) Policy {
	var p Policy
	b, err := readNoFollow(path)
	if err != nil || json.Unmarshal(b, &p) != nil || p.Check() != nil {
		return DefaultPolicy()
	}
	return p
}

// WritePolicy is root's.
func WritePolicy(path string, p Policy) error {
	if err := p.Check(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writeRoot(path, append(b, '\n'))
}

// WriteResult is the updating rayctl's, to the file ResultEnv names.
func WriteResult(path string, r Result) error {
	r.Version, r.Release, r.Error = clip(Printable(r.Version), maxField), clip(Printable(r.Release), maxField), clip(Printable(r.Error), maxError)
	b, err := marshal(r)
	if err != nil {
		return err
	}
	return writeAtomic(path, b, 0o600)
}

// ReadResult is the runner's: the outcome the update wrote, if it did.
func ReadResult(path string) (Result, bool) {
	var r Result
	b, err := readLimit(path, maxStatus)
	if err != nil || json.Unmarshal(b, &r) != nil {
		return r, false
	}
	switch r.State {
	case Done, RolledBack, Failed:
		return r, true
	}
	return r, false
}

// marshal is v as one line of JSON, with no HTML escapes: printable
// fields grow by their quotes and backslashes at most.
func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	err := enc.Encode(v)
	return b.Bytes(), err
}

// Printable is s with what a terminal or a journal would act on (control
// characters, invalid UTF-8) shown as '?'.
func Printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			return '?'
		}
		return r
	}, s)
}

// clip cuts s to at most n bytes, on a rune boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

func writeRoot(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // G301: rayd reads the status and the policy
		return err
	}
	return writeAtomic(path, b, 0o644)
}

func writeTemp(path string, b []byte, mode os.FileMode) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(mode)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

func writeAtomic(path string, b []byte, mode os.FileMode) error {
	tmp, err := writeTemp(path, b, mode)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil { // replaces a link, does not follow it
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func readNoFollow(path string) ([]byte, error) { return readLimit(path, maxFile) }

func readLimit(path string, limit int) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: fixed paths
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err == nil && len(b) > limit {
		err = fmt.Errorf("%s: larger than %d bytes", path, limit)
	}
	return b, err
}

// Patch reports whether release a is a newer patch release of b: the same
// major and minor version.
func Patch(a, b string) bool {
	if !release.IsRelease(a) || !release.IsRelease(b) || !release.Newer(a, b) {
		return false
	}
	ma, mb := strings.Split(a, "."), strings.Split(b, ".")
	return ma[0] == mb[0] && ma[1] == mb[1]
}

var windowRe = regexp.MustCompile(`^([01]\d|2[0-3]):([0-5]\d)-([01]\d|2[0-3]):([0-5]\d)$`)

// ParseWindow reads "HH:MM-HH:MM" (the node's local time; it may run past
// midnight) as minutes of the day; it is MinWindow long at least.
func ParseWindow(w string) (from, to int, err error) {
	m := windowRe.FindStringSubmatch(w)
	if m == nil {
		return 0, 0, fmt.Errorf("window %q: HH:MM-HH:MM", w)
	}
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	from, to = n(m[1])*60+n(m[2]), n(m[3])*60+n(m[4])
	if time.Duration((to-from+24*60)%(24*60))*time.Minute < MinWindow {
		return 0, 0, fmt.Errorf("window %q: shorter than %v", w, MinWindow)
	}
	return from, to, nil
}

// Left is how long the window still runs at t (in t's location: its
// clock, daylight saving time included), 0 when t is outside it.
func Left(t time.Time, w string) time.Duration {
	from, to, err := ParseWindow(w)
	if err != nil {
		return 0
	}
	y, m, d := t.Date()
	at := func(day, min int) time.Time { return time.Date(y, m, d+day, min/60, min%60, 0, 0, t.Location()) }
	// The window that holds t, if any, opened today or yesterday. One
	// that falls into the hour the clock skips is empty that day.
	for _, day := range []int{0, -1} {
		start, end := at(day, from), at(day, to)
		if to <= from { // past midnight
			end = at(day+1, to)
		}
		if !t.Before(start) && t.Before(end) {
			return end.Sub(t)
		}
	}
	return 0
}

// InWindow reports whether t (in its own location) falls in the window.
func InWindow(t time.Time, w string) bool { return Left(t, w) > 0 }
