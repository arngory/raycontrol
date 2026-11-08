package main

import (
	"context"
	"log/slog"
	mrand "math/rand/v2"
	"sync/atomic"
	"time"

	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/release"
	"github.com/arngory/raycontrol/internal/store"
)

// autoCheck is how often the auto update asks GitHub for the latest
// release, give or take 10 %.
const autoCheck = 6 * time.Hour

// autoUpdate is the node's own update to a patch release
// (spec/node-update-v1.md §4), while root has it on (rayctl update auto
// patch): it asks for the latest release every ~6 h, and once in the
// window, at a moment of its own (nodes in one zone do not all update at
// its start), writes a request for a newer patch release of this minor
// version; root's unit does the update. A version whose update failed is
// not asked for again: a newer one, or root, moves on. seen keeps the
// latest release for GetUpdateStatus.
func autoUpdate(ctx context.Context, st *store.Store, running string, latest func(context.Context) (string, error),
	seen *atomic.Value, requestFile, statusFile string, now func() time.Time, tick time.Duration, hb *health.Board, log *slog.Logger) {
	var (
		last    string
		checked time.Time
		due     time.Time // the moment in this window, once in it
	)
	for {
		on := setting(ctx, st, nodeupdate.SettingAuto, "off") == "patch"
		switch {
		case !on:
			hb.Retain("auto-update", nil)
			due = time.Time{}
		case !release.IsRelease(running):
			hb.Report("auto-update", "on, but this build is no release ("+running+"): it updates by hand", nil)
		default:
			if checked.IsZero() || now().Sub(checked) > jitter(autoCheck, 10) {
				cctx, cancel := context.WithTimeout(ctx, time.Minute)
				v, err := latest(cctx)
				cancel()
				checked = now()
				if err != nil {
					hb.Report("auto-update", "patch: the latest release not known: "+err.Error(), nil)
				} else {
					last = v
					seen.Store(v)
				}
			}
			window := setting(ctx, st, nodeupdate.SettingWindow, nodeupdate.DefaultWindow)
			t := now()
			stat := nodeupdate.ReadStatus(statusFile)
			req, waiting := nodeupdate.PeekRequest(requestFile)
			switch {
			case last == "" || !nodeupdate.Patch(last, running):
				hb.Report("auto-update", "patch, window "+window+": up to date ("+running+")", nil)
				due = time.Time{}
			case stat.Target == last && (stat.State == nodeupdate.Failed || stat.State == nodeupdate.RolledBack):
				hb.Report("auto-update", "patch: the update to "+last+" failed ("+stat.Error+"); not again by itself", nil)
			case !nodeupdate.InWindow(t, window):
				hb.Report("auto-update", "patch: "+last+" waits for the window "+window, nil)
				due = time.Time{}
			case nodeupdate.Busy(stat, req, waiting, t):
				hb.Report("auto-update", "patch: an update is under way", nil)
			case due.IsZero():
				due = t.Add(time.Duration(mrand.Int64N(int64(30 * time.Minute)))) //nolint:gosec // a moment, not a secret
				hb.Report("auto-update", "patch: "+last+" at "+due.Format("15:04"), nil)
			case !t.Before(due):
				r := nodeupdate.Request{ID: nodeupdate.NewID(), Kind: nodeupdate.Auto, Version: last, By: "auto", At: t.UTC()}
				if err := nodeupdate.WriteRequest(requestFile, r); err != nil {
					hb.Report("auto-update", "patch: the request for "+last+" not written", err)
				} else {
					log.Info("auto update requested", "version", last, "running", running)
					_ = st.Audit(ctx, "auto", "update.start "+last, "node", "ok")
					hb.Report("auto-update", "patch: "+last+" requested", nil)
				}
				due = time.Time{}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(tick):
		}
	}
}

func setting(ctx context.Context, st *store.Store, key, def string) string {
	v, err := st.GetSetting(ctx, key)
	if err != nil || len(v) == 0 {
		return def
	}
	return string(v)
}
