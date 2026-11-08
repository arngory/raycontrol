// Package nodeupdate is what an update the node asks for itself goes
// through (docs/spec/node-update-v1.md): an admin's request over the API
// (remote) or rayd's own for a patch release (auto). rayd runs without
// privileges: it writes a request, a root unit (raycontrol-update.path)
// sees it and runs rayctl update -request, which checks it again, updates
// as rayctl update does (signed releases only) and writes the outcome to a
// status file rayd reads.
package nodeupdate

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/arngory/raycontrol/internal/release"
)

const (
	// RequestFile is rayd's: in its state directory, watched by
	// raycontrol-update.path.
	RequestFile = "/var/lib/raycontrol/update-request"
	// StatusDir is the update unit's (root, 0755): rayd reads the status,
	// nobody but root writes it.
	StatusDir  = "/var/lib/raycontrol-update"
	StatusFile = StatusDir + "/status.json"
	// PathUnit and ServiceUnit run the requests (deploy.Plan).
	PathUnit    = "raycontrol-update.path"
	ServiceUnit = "raycontrol-update.service"

	// Settings in the node's database (rayctl update remote|auto).
	SettingRemote = "update_remote" // "on": admins may update the node over the API
	SettingAuto   = "update_auto"   // "patch": rayd updates to patch releases in the window
	SettingWindow = "update_window" // "HH:MM-HH:MM", the node's local time
	// DefaultWindow is the auto update's window when none is set.
	DefaultWindow = "03:00-05:00"

	// Stale: a request or a run older than this is taken as dead (a node
	// that went down in the middle).
	Stale = 2 * time.Hour

	maxFile = 4 << 10
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

// Request is an update asked for.
type Request struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"`    // Remote or Auto
	Version string    `json:"version"` // "latest" or vX.Y.Z
	By      string    `json:"by"`      // who: "alice/phone (remote)", "auto"
	At      time.Time `json:"at"`
}

// Status is an update's outcome, or its progress.
type Status struct {
	ID        string    `json:"id"`
	State     string    `json:"state"`
	From      string    `json:"from"`
	To        string    `json:"to"`     // the version asked for until it ran, then the node's
	Target    string    `json:"target"` // the version asked for
	By        string    `json:"by"`
	Kind      string    `json:"kind"`
	Error     string    `json:"error,omitempty"`
	Requested time.Time `json:"requested"`
	Started   time.Time `json:"started"`
	Ended     time.Time `json:"ended"`
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

// Check is a request as the root side takes it: well formed, its kind
// allowed, never back.
func (r Request) Check(installed string) error {
	switch {
	case r.ID == "" || len(r.ID) > 32 || strings.Trim(r.ID, "0123456789abcdef") != "":
		return errors.New("the request has no id")
	case r.Kind != Remote && r.Kind != Auto:
		return fmt.Errorf("a request of kind %q", r.Kind)
	case !ValidVersion(r.Version):
		return fmt.Errorf("version %q: latest or vX.Y.Z", r.Version)
	case r.Version != "latest" && !release.Newer(r.Version, installed):
		return fmt.Errorf("%s is not newer than %s: an update by request never goes back", r.Version, installed)
	case r.Kind == Auto && (r.Version == "latest" || !Patch(r.Version, installed)):
		return fmt.Errorf("an auto update takes patch releases of %s only, not %s", installed, r.Version)
	}
	return nil
}

// WriteRequest is rayd's: the request in place at once (a temporary file
// renamed over), for the path unit to see.
func WriteRequest(path string, r Request) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return writeAtomic(path, b, 0o640)
}

// TakeRequest is root's: the request, read without following a link (the
// directory is rayd's) and removed, so that the path unit does not fire
// again. ok is false when there is none.
func TakeRequest(path string) (r Request, ok bool, err error) {
	b, err := readNoFollow(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, false, nil
	}
	_ = os.Remove(path)
	if err != nil {
		return r, true, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, true, fmt.Errorf("the request: %w", err)
	}
	return r, true, nil
}

// PeekRequest is rayd's: the request waiting, if any.
func PeekRequest(path string) (Request, bool) {
	var r Request
	b, err := readNoFollow(path)
	if err != nil || json.Unmarshal(b, &r) != nil {
		return r, false
	}
	return r, true
}

// WriteStatus is root's, in its own directory.
func WriteStatus(path string, s Status) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // G301: rayd reads the status
		return err
	}
	return writeAtomic(path, append(b, '\n'), 0o644)
}

// ReadStatus is the last status, Idle when there is none.
func ReadStatus(path string) Status {
	var s Status
	b, err := readNoFollow(path)
	if err != nil || json.Unmarshal(b, &s) != nil || s.State == "" {
		return Status{State: Idle}
	}
	return s
}

// Busy reports whether an update is waiting or under way, and not stale.
func Busy(s Status, req Request, waiting bool, now time.Time) bool {
	if waiting && now.Sub(req.At) < Stale {
		return true
	}
	return s.State == Running && now.Sub(s.Started) < Stale
}

func writeAtomic(path string, b []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(mode)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path) // replaces a link, does not follow it
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

func readNoFollow(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: fixed paths
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err == nil && len(b) > maxFile {
		err = fmt.Errorf("%s: larger than %d bytes", path, maxFile)
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
// midnight) as minutes of the day.
func ParseWindow(w string) (from, to int, err error) {
	m := windowRe.FindStringSubmatch(w)
	if m == nil {
		return 0, 0, fmt.Errorf("window %q: HH:MM-HH:MM", w)
	}
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	from, to = n(m[1])*60+n(m[2]), n(m[3])*60+n(m[4])
	if from == to {
		return 0, 0, fmt.Errorf("window %q: empty", w)
	}
	return from, to, nil
}

// InWindow reports whether t (in its own location) falls in the window.
func InWindow(t time.Time, w string) bool {
	from, to, err := ParseWindow(w)
	if err != nil {
		return false
	}
	m := t.Hour()*60 + t.Minute()
	if from < to {
		return m >= from && m < to
	}
	return m >= from || m < to
}
