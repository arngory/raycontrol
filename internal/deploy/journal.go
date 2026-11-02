package deploy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// JournalDir keeps what raycontrol changed on the host, so that rayctl
// uninstall can put everything back (docs/08-decisions.md, R4-2). Root
// only; it lives apart from the state directory, which rayd owns.
const JournalDir = "/var/lib/raycontrol-install"

// Change kinds, in the order uninstall does NOT follow: it reverts them
// last first, grouped by kind (see Uninstall).
const (
	ChangeFile    = "file"    // Path created (Backup "") or replaced (Backup holds the original)
	ChangeDir     = "dir"     // Path created; removed if empty
	ChangeState   = "state"   // Path created; removed with its contents
	ChangeSymlink = "symlink" // Path pointed to Target before
	ChangeGroup   = "group"   // Name created
	ChangeUser    = "user"    // Name created
	ChangeUnit    = "unit"    // Name enabled
	ChangeSysctl  = "sysctl"  // Name had Value before
	ChangeBinary  = "binary"  // Path installed
	ChangePackage = "package" // Name installed with the manager in Value
)

// Change is one entry of the journal.
type Change struct {
	Kind   string      `json:"kind"`
	Path   string      `json:"path,omitempty"`
	Name   string      `json:"name,omitempty"`
	Backup string      `json:"backup,omitempty"` // file name in the journal's backup directory
	Mode   fs.FileMode `json:"mode,omitempty"`   // of the replaced file
	Target string      `json:"target,omitempty"`
	Value  string      `json:"value,omitempty"`
}

func (c Change) key() string { return c.Kind + "\x00" + c.Path + "\x00" + c.Name }

// Journal is the list of changes, saved after every new entry: a change is
// recorded before it is made, so an interrupted install can be undone too.
type Journal struct {
	root    string // test seam: prefixes every path
	mu      sync.Mutex
	Changes []Change `json:"changes"`
}

func (j *Journal) dir() string  { return filepath.Join(j.root, JournalDir) }
func (j *Journal) file() string { return filepath.Join(j.dir(), "journal.json") }

// OpenJournal loads the journal (empty if there is none yet).
func OpenJournal(root string) (*Journal, error) {
	j := &Journal{root: root}
	b, err := os.ReadFile(j.file())
	if errors.Is(err, fs.ErrNotExist) {
		return j, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, j); err != nil {
		return nil, fmt.Errorf("journal %s: %w", j.file(), err)
	}
	return j, nil
}

// Exists reports whether a journal has been saved.
func (j *Journal) Exists() bool {
	_, err := os.Stat(j.file())
	return err == nil
}

// Has reports whether a change of this kind for this path or name is
// recorded: only the first one counts, it holds the original state.
func (j *Journal) Has(kind, path, name string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	k := Change{Kind: kind, Path: path, Name: name}.key()
	for _, c := range j.Changes {
		if c.key() == k {
			return true
		}
	}
	return false
}

// Record adds a change unless one for the same kind and key is there. It
// first merges what another instance (another rayctl run, or a nested one)
// saved meanwhile: the first record of a path holds its original state and
// must never be lost to a stale copy.
func (j *Journal) Record(c Change) error {
	if j == nil {
		return nil
	}
	if err := j.merge(); err != nil {
		return err
	}
	if j.Has(c.Kind, c.Path, c.Name) {
		return nil
	}
	j.mu.Lock()
	j.Changes = append(j.Changes, c)
	j.mu.Unlock()
	return j.save()
}

// merge adds the saved changes this instance does not know, keeping the
// saved order first.
func (j *Journal) merge() error {
	disk, err := OpenJournal(j.root)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	known := map[string]bool{}
	for _, c := range disk.Changes {
		known[c.key()] = true
	}
	merged := disk.Changes
	for _, c := range j.Changes {
		if !known[c.key()] {
			merged = append(merged, c)
		}
	}
	j.Changes = merged
	return nil
}

func (j *Journal) save() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := os.MkdirAll(j.dir(), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	tmp := j.file() + ".new"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, j.file())
}

// RecordFile notes the state of a file before raycontrol writes it: absent
// (with the directories it will create), or present, then copied aside.
func (j *Journal) RecordFile(path string) error {
	if j == nil {
		return nil
	}
	if err := j.merge(); err != nil {
		return err
	}
	if j.Has(ChangeFile, path, "") {
		return nil
	}
	real := filepath.Join(j.root, path)
	st, err := os.Lstat(real)
	if errors.Is(err, fs.ErrNotExist) {
		if err := j.recordDirs(filepath.Dir(path)); err != nil {
			return err
		}
		return j.Record(Change{Kind: ChangeFile, Path: path})
	}
	if err != nil {
		return err
	}
	b, err := os.ReadFile(real) //nolint:gosec // G304: a path raycontrol is about to write
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(path))
	backup := hex.EncodeToString(sum[:8])
	if err := os.MkdirAll(filepath.Join(j.dir(), "backup"), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(j.dir(), "backup", backup), b, 0o600); err != nil {
		return err
	}
	return j.Record(Change{Kind: ChangeFile, Path: path, Backup: backup, Mode: st.Mode().Perm()})
}

// recordDirs notes the directories up to dir that do not exist yet, the
// outermost first.
func (j *Journal) recordDirs(dir string) error {
	var missing []string
	for d := dir; d != "/" && d != "."; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(j.root, d)); err == nil {
			break
		}
		missing = append(missing, d)
	}
	for i := len(missing) - 1; i >= 0; i-- {
		if err := j.Record(Change{Kind: ChangeDir, Path: missing[i]}); err != nil {
			return err
		}
	}
	return nil
}

// Remove deletes the journal and its backups (the last step of uninstall).
func (j *Journal) Remove() error { return os.RemoveAll(j.dir()) }

// backup returns the saved original of a replaced file.
func (j *Journal) backup(c Change) ([]byte, error) {
	return os.ReadFile(filepath.Join(j.dir(), "backup", c.Backup))
}
