package store

import (
	"context"
	"strconv"
	"time"
)

// The debug window (rayctl debug, docs/09-observability.md §3): until this
// time rayd, rayspa and niko-server log at debug level. Client
// addresses then reach the journal, so the window always ends by itself.
const settingDebugUntil = "debug_until"

// MaxDebug is the longest debug window.
const MaxDebug = 24 * time.Hour

// DebugUntil returns the end of the debug window, zero if none was set.
func (s *Store) DebugUntil(ctx context.Context) time.Time {
	v, err := s.GetSetting(ctx, settingDebugUntil)
	if err != nil {
		return time.Time{}
	}
	n, err := strconv.ParseInt(string(v), 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}
	}
	return time.Unix(n, 0)
}

// SetDebugUntil opens the debug window until t, or closes it (zero t).
func (s *Store) SetDebugUntil(ctx context.Context, t time.Time) error {
	if t.IsZero() {
		return s.DeleteSetting(ctx, settingDebugUntil)
	}
	return s.SetSetting(ctx, settingDebugUntil, []byte(strconv.FormatInt(t.Unix(), 10)))
}
