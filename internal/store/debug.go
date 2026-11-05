package store

import (
	"context"
	"crypto/rand"
	"fmt"
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

// settingDNSProbeKey is the node's key of dnsprobe-v1 (docs/spec/
// dnsprobe-v1.md): 32 bytes, made once, sent to users with a DNS tunnel.
const settingDNSProbeKey = "dns_probe_key"

// DNSProbeKey returns the node's dnsprobe-v1 key, making it the first
// time. Two callers at once get the same key: the first insert wins.
func (s *Store) DNSProbeKey(ctx context.Context) ([]byte, error) {
	if v, err := s.GetSetting(ctx, settingDNSProbeKey); err == nil && len(v) == 32 {
		return v, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING`,
		settingDNSProbeKey, key); err != nil {
		return nil, err
	}
	v, err := s.GetSetting(ctx, settingDNSProbeKey)
	if err != nil {
		return nil, err
	}
	if len(v) != 32 {
		return nil, fmt.Errorf("%w: dns_probe_key of %d bytes", ErrInvalid, len(v))
	}
	return v, nil
}
