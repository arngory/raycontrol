// Package stats keeps the last two hours of the node's counters, a sample a
// minute, so that rayctl stats can say what changed in a window, an hour by
// default (spec/stats-v1.md). The samples are what rayctl metrics shows,
// with the services as kind#n and the zones as numbers, and the host's CPU,
// memory, network and disk: no names, addresses, domains or keys. Memory
// only: a restart of rayd starts it again.
package stats

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"
)

// Point is one series of a sample: a metric, its labels as name, value
// pairs, and its value. A name ending in _total is a counter.
type Point struct {
	Name   string
	Labels []string
	Value  float64
}

// Key is the series' identity within a sample.
func (p Point) Key() string {
	var b strings.Builder
	b.WriteString(p.Name)
	for i := 0; i+1 < len(p.Labels); i += 2 {
		b.WriteByte(0)
		b.WriteString(p.Labels[i])
		b.WriteByte('=')
		b.WriteString(p.Labels[i+1])
	}
	return b.String()
}

// Counter reports whether the series counts up (its name ends in _total).
func (p Point) Counter() bool { return strings.HasSuffix(p.Name, "_total") }

// meta is a series' name and labels, and its key: the one string the
// samples share.
type meta struct {
	key    string
	name   string
	labels []string
}

// Sample is the node at one moment.
type Sample struct {
	At     time.Time
	Values map[string]float64 // by Point.Key
	Host   Host
}

// Sampler takes a sample every Every and keeps those of the last Keep.
type Sampler struct {
	// Collect returns the series of the moment (api.Server.StatsPoints).
	Collect func(ctx context.Context, now time.Time) ([]Point, error)
	// ReadHost reads the host's counters (ReadHost on Linux); nil: none.
	ReadHost func() Host
	Every    time.Duration // a minute when zero
	Keep     time.Duration // MaxWindow and two samples when zero
	Now      func() time.Time
	Log      *slog.Logger

	mu      sync.Mutex
	samples []Sample
	series  map[string]*meta // the name and labels of every key kept
	started time.Time
}

// MaxWindow is the longest window a report covers; MinWindow the shortest.
// SampleTimeout bounds one sample.
const (
	MaxWindow     = 2 * time.Hour
	MinWindow     = 5 * time.Minute
	SampleTimeout = 30 * time.Second
)

func (s *Sampler) every() time.Duration {
	if s.Every > 0 {
		return s.Every
	}
	return time.Minute
}

func (s *Sampler) keep() time.Duration {
	if s.Keep > 0 {
		return s.Keep
	}
	return MaxWindow + 2*s.every()
}

func (s *Sampler) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Start marks when the samples begin; Run calls it, tests may too.
func (s *Sampler) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started.IsZero() {
		s.started = s.now()
	}
}

// Run samples until ctx ends: at once, then every Every.
func (s *Sampler) Run(ctx context.Context) {
	s.Start()
	t := time.NewTicker(s.every())
	defer t.Stop()
	for {
		if err := s.Take(ctx); err != nil && ctx.Err() == nil && s.Log != nil {
			s.Log.Warn("stats: sample not taken", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Take adds a sample of now and drops those older than Keep, and the keys
// no sample holds any more.
func (s *Sampler) Take(ctx context.Context) error {
	sm, err := s.sample(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.samples = append(s.samples, sm)
	cut := sm.At.Add(-s.keep())
	i := 0
	for i < len(s.samples)-1 && s.samples[i].At.Before(cut) {
		i++
	}
	if i > 0 {
		s.samples = slices.Delete(s.samples, 0, i)
		for k := range s.series {
			held := false
			for _, old := range s.samples {
				if _, ok := old.Values[k]; ok {
					held = true
					break
				}
			}
			if !held {
				delete(s.series, k)
			}
		}
	}
	return nil
}

// sample reads the series and the host now. A key already held is shared,
// so that two hours of samples hold each key's string once.
func (s *Sampler) sample(ctx context.Context) (Sample, error) {
	now := s.now()
	// A sample is a few queries and the stats sockets (each with its own
	// deadline): never longer than this, so that a stuck read costs one
	// minute's sample, not the sampler.
	ctx, cancel := context.WithTimeout(ctx, SampleTimeout)
	defer cancel()
	points, err := s.Collect(ctx, now)
	if err != nil {
		return Sample{}, err
	}
	sm := Sample{At: now, Values: make(map[string]float64, len(points))}
	s.mu.Lock()
	if s.series == nil {
		s.series = map[string]*meta{}
	}
	for _, p := range points {
		k := p.Key()
		m, ok := s.series[k]
		if !ok {
			m = &meta{key: k, name: p.Name, labels: slices.Clone(p.Labels)}
			s.series[k] = m
		}
		sm.Values[m.key] += p.Value
	}
	s.mu.Unlock()
	if s.ReadHost != nil {
		sm.Host = s.ReadHost()
	}
	return sm, nil
}
