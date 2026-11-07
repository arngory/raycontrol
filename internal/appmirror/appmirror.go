// Package appmirror keeps the client's latest verified releases on the
// node and serves them to its devices (spec/app-update-v1.md): where GitHub
// does not answer, a client without its VPN still learns of a new version
// from the subscription and downloads it from the node. Trust does not
// change: the client checks the minisign signature with its own key, as
// for GitHub; the node checks it too before it serves anything.
package appmirror

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/arngory/raycontrol/internal/release"
	"github.com/arngory/raycontrol/internal/store"
)

const (
	// App is the one client served: Niko, from Repo.
	App  = "niko"
	Repo = "arngory/niko"
	// PubKey signs the client's SHA256SUMS (D5D2D2E799D74D8D, the
	// client's niko-update.pub); the trusted comment is "niko <tag>".
	PubKey = "RWSNTdeZ59LS1bdwyf4iRzgIdSmDfFWw9yWiy6Qy/eAfBNj5gLnEwmRl"
	// Path is where the files are served, on the subscription's port.
	Path = "/app/v1/"
	// DefaultDir is under rayd's state directory.
	DefaultDir = "/var/lib/raycontrol/app"

	// Interval between checks, with up to Jitter more.
	Interval = 6 * time.Hour
	Jitter   = 30 * time.Minute
	// MaxFile and MaxRelease bound what a release may take on the disk.
	MaxFile    = 200 << 20
	MaxRelease = 600 << 20
	// MinFree is the room rayctl app-mirror on asks for.
	MinFree = 1 << 30
	// PerNode downloads at once; a device has one.
	PerNode = 16
	// Stall ends a download that takes no byte for so long.
	Stall = 60 * time.Second
	// RetryAfter is what a client over a limit waits, in seconds.
	RetryAfter = 10

	settingEnabled = "app_mirror"
	sumsName       = "SHA256SUMS"
	sigName        = "SHA256SUMS.minisig"
	manifestName   = "release.json"
	maxSums        = 64 << 10
	maxSig         = 4 << 10
)

// File is a file of a release as the node holds it.
type File struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Release is a release the node holds whole and verified.
type Release struct {
	Tag        string    `json:"tag"`
	Prerelease bool      `json:"prerelease"`
	Files      []File    `json:"files"` // SHA256SUMS, its signature, then what it lists
	Verified   time.Time `json:"verified"`
}

// Bytes is the size of all its files.
func (r Release) Bytes() int64 {
	var n int64
	for _, f := range r.Files {
		n += f.Size
	}
	return n
}

func (r Release) file(name string) (File, bool) {
	i := slices.IndexFunc(r.Files, func(f File) bool { return f.Name == name })
	if i < 0 {
		return File{}, false
	}
	return r.Files[i], true
}

// Hint is the subscription's field (app-update-v1 §1).
type Hint struct {
	Niko []HintRelease `json:"niko"`
}

// HintRelease is a release in the hint.
type HintRelease struct {
	Tag        string `json:"tag"`
	Prerelease bool   `json:"prerelease"`
}

// Status is what rayctl app-mirror shows.
type Status struct {
	Enabled  bool
	Releases []Release
	Checked  time.Time
	Err      string
}

// Mirror holds the releases and serves them.
type Mirror struct {
	Store  *store.Store
	Dir    string       // DefaultDir when empty
	API    string       // https://api.github.com when empty (a test seam)
	HTTP   *http.Client // with timeouts when nil
	PubKey string       // PubKey when empty (a test seam)
	Log    *slog.Logger

	mu      sync.Mutex
	held    []Release // the stable first, then a newer pre-release
	checked time.Time
	lastErr string
	kick    chan struct{}

	dl     sync.Mutex
	active map[string]bool // a device's download
	total  int
}

func (m *Mirror) dir() string {
	if m.Dir != "" {
		return m.Dir
	}
	return DefaultDir
}

func (m *Mirror) appDir() string { return filepath.Join(m.dir(), App) }

func (m *Mirror) pubKey() string {
	if m.PubKey != "" {
		return m.PubKey
	}
	return PubKey
}

func (m *Mirror) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Enabled says whether the administrator turned the mirror on.
func Enabled(ctx context.Context, st *store.Store) bool {
	v, err := st.GetSetting(ctx, settingEnabled)
	return err == nil && string(v) == "on"
}

// SetEnabled turns the mirror on, with MinFree in its directory, or off;
// rayd's loop follows (Kick), and drops the files when it is off.
func (m *Mirror) SetEnabled(ctx context.Context, on bool) error {
	if !on {
		return m.Store.SetSetting(ctx, settingEnabled, []byte("off"))
	}
	free, err := freeBytes(m.dir())
	if err != nil {
		return err
	}
	if free < MinFree {
		return fmt.Errorf("%w: %d MiB free in %s, the mirror wants %d MiB (two releases of ~110 MB, and room to fetch the next)",
			store.ErrInvalid, free>>20, m.dir(), MinFree>>20)
	}
	return m.Store.SetSetting(ctx, settingEnabled, []byte("on"))
}

// freeBytes is the room for rayd under dir (or its nearest existing
// parent: the directory comes with the first release).
func freeBytes(dir string) (uint64, error) {
	for {
		var st unix.Statfs_t
		err := unix.Statfs(dir, &st)
		if err == nil {
			return st.Bavail * uint64(st.Bsize), nil
		}
		parent := filepath.Dir(dir)
		if !errors.Is(err, unix.ENOENT) || parent == dir {
			return 0, fmt.Errorf("free space in %s: %w", dir, err)
		}
		dir = parent
	}
}

// Kick makes the loop check at once (the administrator turned it on or
// off).
func (m *Mirror) Kick() {
	m.mu.Lock()
	k := m.kick
	m.mu.Unlock()
	if k != nil {
		select {
		case k <- struct{}{}:
		default:
		}
	}
}

// Status reports the mirror.
func (m *Mirror) Status(ctx context.Context) Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Status{Enabled: Enabled(ctx, m.Store), Releases: slices.Clone(m.held), Checked: m.checked, Err: m.lastErr}
}

// Hint is the subscription's field: nil when the mirror is off or holds
// nothing yet.
func (m *Mirror) Hint(ctx context.Context) *Hint {
	if m == nil || !Enabled(ctx, m.Store) {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.held) == 0 {
		return nil
	}
	h := &Hint{}
	for _, r := range m.held {
		h.Niko = append(h.Niko, HintRelease{Tag: r.Tag, Prerelease: r.Prerelease})
	}
	return h
}

func (m *Mirror) heldRelease(tag string) (Release, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := slices.IndexFunc(m.held, func(r Release) bool { return r.Tag == tag })
	if i < 0 {
		return Release{}, false
	}
	return m.held[i], true
}

// Run keeps the mirror while ctx lasts: a check at once and every
// Interval (with jitter) while it is on, the files dropped when it is off.
func (m *Mirror) Run(ctx context.Context, jitter func() time.Duration) {
	m.mu.Lock()
	if m.kick == nil {
		m.kick = make(chan struct{}, 1)
	}
	kick := m.kick
	m.mu.Unlock()
	m.load()
	for {
		wait := time.Hour // off: look again now and then (and on a kick)
		if Enabled(ctx, m.Store) {
			if err := m.Sync(ctx); err != nil {
				m.log().Warn("client releases not mirrored", "err", err)
			}
			wait = Interval
			if jitter != nil {
				wait += jitter()
			}
		} else {
			m.clear()
		}
		select {
		case <-ctx.Done():
			return
		case <-kick:
		case <-time.After(wait):
		}
	}
}

// load takes the releases a previous rayd left whole and verified.
func (m *Mirror) load() {
	entries, err := os.ReadDir(m.appDir())
	if err != nil {
		return
	}
	var held []Release
	for _, e := range entries {
		dir := filepath.Join(m.appDir(), e.Name())
		r, err := m.check(dir)
		if err != nil {
			m.log().Info("a mirrored release dropped", "dir", dir, "err", err)
			_ = os.RemoveAll(dir)
			continue
		}
		held = append(held, r)
	}
	held = pick(held)
	m.mu.Lock()
	m.held = held
	m.mu.Unlock()
	m.prune(held)
}

// check reads a release's directory: its manifest, its files by size, and
// the signature of its SHA256SUMS again (cheap; the files are rayd's).
func (m *Mirror) check(dir string) (Release, error) {
	var r Release
	b, err := os.ReadFile(filepath.Join(dir, manifestName)) //nolint:gosec // G304: rayd's own directory
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, err
	}
	if !validTag(r.Tag) || filepath.Base(dir) != r.Tag {
		return r, fmt.Errorf("tag %q", r.Tag)
	}
	if len(r.Files) < 3 || r.Files[0].Name != sumsName || r.Files[1].Name != sigName {
		return r, errors.New("files")
	}
	for _, f := range r.Files {
		if !validName(f.Name) {
			return r, fmt.Errorf("file %q", f.Name)
		}
		st, err := os.Stat(filepath.Join(dir, f.Name))
		if err != nil || st.Size() != f.Size {
			return r, fmt.Errorf("file %s", f.Name)
		}
	}
	sums, err := os.ReadFile(filepath.Join(dir, sumsName)) //nolint:gosec // G304: rayd's own directory
	if err != nil {
		return r, err
	}
	sig, err := os.ReadFile(filepath.Join(dir, sigName)) //nolint:gosec // G304: rayd's own directory
	if err != nil {
		return r, err
	}
	if err := m.verify(r.Tag, sums, sig); err != nil {
		return r, err
	}
	return r, nil
}

// verify checks a release's SHA256SUMS: the signature and its trusted
// comment, "niko <tag>".
func (m *Mirror) verify(tag string, sums, sig []byte) error {
	trusted, err := release.Verify(sums, sig, m.pubKey())
	if err != nil {
		return err
	}
	if trusted != App+" "+tag {
		return fmt.Errorf("trusted comment %q, want %q", trusted, App+" "+tag)
	}
	return nil
}

// clear drops what the mirror holds (it was turned off).
func (m *Mirror) clear() {
	m.mu.Lock()
	had := len(m.held) > 0
	m.held = nil
	m.lastErr = ""
	m.mu.Unlock()
	if had {
		m.log().Info("client releases no longer mirrored")
	}
	_ = os.RemoveAll(m.appDir())
}

// prune removes the directories of releases not held, and what a fetch
// left behind.
func (m *Mirror) prune(held []Release) {
	entries, err := os.ReadDir(m.appDir())
	if err != nil {
		return
	}
	for _, e := range entries {
		if !slices.ContainsFunc(held, func(r Release) bool { return r.Tag == e.Name() }) {
			_ = os.RemoveAll(filepath.Join(m.appDir(), e.Name()))
		}
	}
}

// pick keeps the newest stable release and the newest pre-release newer
// than it (app-update-v1 §1), the stable first.
func pick(rs []Release) []Release {
	var stable, pre *Release
	for i := range rs {
		r := &rs[i]
		if r.Prerelease {
			if pre == nil || semverCompare(r.Tag, pre.Tag) > 0 {
				pre = r
			}
		} else if stable == nil || semverCompare(r.Tag, stable.Tag) > 0 {
			stable = r
		}
	}
	var out []Release
	if stable != nil {
		out = append(out, *stable)
	}
	if pre != nil && (stable == nil || semverCompare(pre.Tag, stable.Tag) > 0) {
		out = append(out, *pre)
	}
	return out
}
