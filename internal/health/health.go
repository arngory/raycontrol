// Package health keeps, for each of rayd's loops (applying the rendered
// files, certificates, DNS records, rotations), when it last succeeded and
// when it last failed, with that error (O-2). rayctl status and the metrics
// show it: a node that stopped applying or renewing is visible before its
// clients notice.
package health

import (
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Loop is one loop's record.
type Loop struct {
	Name    string
	Runs    uint64
	Errors  uint64
	LastOK  time.Time // zero: never
	LastErr time.Time // zero: never
	Err     string    // the last error, on one line
	failing bool      // the last round failed
}

// Board collects the loops. The zero value is ready; a nil Board ignores
// everything.
type Board struct {
	Now func() time.Time // time.Now when nil

	mu    sync.Mutex
	loops map[string]*Loop
}

// Done records a round of the loop name: a success when err is nil.
func (b *Board) Done(name string, err error) {
	if b == nil {
		return
	}
	now := time.Now()
	if b.Now != nil {
		now = b.Now()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.loops == nil {
		b.loops = map[string]*Loop{}
	}
	l := b.loops[name]
	if l == nil {
		l = &Loop{Name: name}
		b.loops[name] = l
	}
	l.Runs++
	l.failing = err != nil
	if err != nil {
		l.Errors++
		// Joined errors (render.ServiceErrors) come on several lines; status
		// and the log show one.
		l.LastErr, l.Err = now, strings.Join(strings.Fields(strings.ReplaceAll(err.Error(), "\n", " ; ")), " ")
		return
	}
	l.LastOK = now
}

// Retain forgets the loops named prefix+<name> for every name not in keep:
// a deleted site or service no longer shows as failing.
func (b *Board) Retain(prefix string, keep []string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for name := range b.loops {
		if rest, ok := strings.CutPrefix(name, prefix); ok && !slices.Contains(keep, rest) {
			delete(b.loops, name)
		}
	}
}

// Loops returns the records by name.
func (b *Board) Loops() []Loop {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Loop, 0, len(b.loops))
	for _, l := range b.loops {
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Failing reports whether the loop's last round failed (two rounds in the
// same second tell nothing by their times).
func (l Loop) Failing() bool { return l.failing }
