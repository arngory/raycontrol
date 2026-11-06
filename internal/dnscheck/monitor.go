package dnscheck

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// Monitor runs the checks of a node: the periodic ones and an operator's
// (rayctl dns check -now). Callers that ask while a check with the same
// resolvers runs share it, and an operator's check comes at most once per
// Gap: the node must not become a source of load on the resolvers.
type Monitor struct {
	Checker *Checker
	// Targets are the zones to check now (provision.DNSCheckTargets).
	Targets func(context.Context) ([]Zone, error)
	// Resolvers are those of the periodic check.
	Resolvers []Resolver
	// Gap is the least time between two forced checks; 30 s when zero.
	Gap time.Duration
	// Done receives every full check with Resolvers (the health board);
	// it runs before the callers get the report.
	Done func(Report)
	// Base bounds the checks, which outlive the callers that started them
	// (rayd's context); context.Background() when nil.
	Base context.Context

	mu      sync.Mutex
	last    *Report            // the last full check with Resolvers
	custom  map[string]*Report // the last of other resolvers, maxCustom at most
	order   []string           // custom's keys, oldest first
	running map[string]*monitorRun
	forced  time.Time // when the last forced check started
	next    time.Time // the next periodic check
}

// maxCustom: the reports of other sets of resolvers a Monitor keeps.
const maxCustom = 8

type monitorRun struct {
	done chan struct{}
	rep  Report
	err  error
}

// TooSoon is a forced check asked within Gap of the previous one, when
// that one has no report to give instead.
type TooSoon struct{ Gap, Wait time.Duration }

func (e TooSoon) Error() string {
	return fmt.Sprintf("one check per %v: the next in %v", e.Gap, e.Wait.Round(time.Second))
}

// RunOptions say what to check.
type RunOptions struct {
	Resolvers  []Resolver // nil: the Monitor's
	Forced     bool       // an operator's check: at most once per Gap
	ParentOnly bool       // the parents only (after a change of zones)
}

// Last is the last full check with the periodic resolvers.
func (m *Monitor) Last() (Report, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.last == nil {
		return Report{}, false
	}
	return *m.last, true
}

// SetNext records when the next periodic check is due (shown with the
// last report); zero: none.
func (m *Monitor) SetNext(t time.Time) {
	m.mu.Lock()
	m.next = t
	m.mu.Unlock()
}

// Next is when the next periodic check is due; zero: none.
func (m *Monitor) Next() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.next
}

// Run checks the zones, or joins a check of the same kind in progress, and
// returns its report. A forced check within Gap of the last forced one
// gets that one's report, Limited, or TooSoon when there is none.
func (m *Monitor) Run(ctx context.Context, o RunOptions) (Report, error) {
	periodic := o.Resolvers == nil || resolversKey(o.Resolvers) == resolversKey(m.Resolvers)
	resolvers := o.Resolvers
	if periodic {
		resolvers = m.Resolvers
	}
	key := resolversKey(resolvers)
	if o.ParentOnly {
		key = "parents"
	}
	m.mu.Lock()
	if r := m.running[key]; r != nil {
		m.mu.Unlock()
		return wait(ctx, r)
	}
	if o.Forced {
		gap := m.Gap
		if gap <= 0 {
			gap = 30 * time.Second
		}
		if since := time.Since(m.forced); since < gap {
			last := m.custom[key]
			if periodic {
				last = m.last
			}
			m.mu.Unlock()
			if last == nil {
				return Report{}, TooSoon{Gap: gap, Wait: gap - since}
			}
			rep := *last
			rep.Limited = true
			return rep, nil
		}
		m.forced = time.Now()
	}
	if m.running == nil {
		m.running = map[string]*monitorRun{}
	}
	r := &monitorRun{done: make(chan struct{})}
	m.running[key] = r
	m.mu.Unlock()

	base := m.Base
	if base == nil {
		base = context.Background()
	}
	go func() {
		defer close(r.done)
		zones, err := m.Targets(base)
		if err != nil {
			r.err = err
		} else {
			r.rep = m.Checker.Check(base, zones, resolvers, o.ParentOnly)
		}
		m.mu.Lock()
		delete(m.running, key)
		if err == nil && !o.ParentOnly {
			rep := r.rep
			if periodic {
				m.last = &rep
			} else {
				if m.custom == nil {
					m.custom = map[string]*Report{}
				}
				if _, ok := m.custom[key]; !ok {
					// A few sets of resolvers kept, the oldest go (each
					// asked set was kept for good).
					if len(m.order) >= maxCustom {
						delete(m.custom, m.order[0])
						m.order = m.order[1:]
					}
					m.order = append(m.order, key)
				}
				m.custom[key] = &rep
			}
		}
		m.mu.Unlock()
		if err == nil && !o.ParentOnly && periodic && m.Done != nil {
			m.Done(r.rep)
		}
	}()
	return wait(ctx, r)
}

func wait(ctx context.Context, r *monitorRun) (Report, error) {
	select {
	case <-r.done:
		return r.rep, r.err
	case <-ctx.Done():
		return Report{}, ctx.Err()
	}
}

// resolversKey names a set of resolvers.
func resolversKey(rs []Resolver) string {
	keys := make([]string, 0, len(rs))
	for _, r := range rs {
		keys = append(keys, r.Net+":"+r.Addr.String())
	}
	slices.Sort(keys)
	return strings.Join(keys, ",")
}
