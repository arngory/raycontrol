package main

import (
	"context"
	"errors"
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

// autoUpdater is the node's own update to a patch release
// (spec/node-update-v1.md §1), while root's policy has it on (rayctl update
// auto patch): it asks for the latest release every ~6 h, and once in the
// window, at a moment of its own (nodes in one zone do not all update at
// its start) still in it, writes a request for a newer patch release of
// this minor version; root's unit does the update. A version whose update
// failed is not asked for again, but for a failure that left the node as
// it was (the download, say), a day later; a newer one, or root, moves on.
type autoUpdater struct {
	st      *store.Store
	running string
	latest  func(context.Context) (string, error)
	seen    *atomic.Value // the latest release, for GetUpdateStatus

	request, status, policy string // nodeupdate.RequestFile, StatusFile, PolicyFile
	now                     func() time.Time
	tick                    time.Duration
	hb                      *health.Board
	log                     *slog.Logger
}

func (a *autoUpdater) run(ctx context.Context) {
	var (
		last    string
		checked time.Time
		due     time.Time // the moment in this window, once in it
	)
	for {
		p := nodeupdate.ReadPolicy(a.policy)
		t := a.now()
		switch {
		case p.Auto != "patch":
			a.hb.Retain("auto-update", nil)
			due = time.Time{}
		case !release.IsRelease(a.running):
			a.hb.Report("auto-update", "on, but this build is no release ("+a.running+"): it updates by hand", nil)
		default:
			if checked.IsZero() || t.Sub(checked) > jitter(autoCheck, 10) {
				cctx, cancel := context.WithTimeout(ctx, time.Minute)
				v, err := a.latest(cctx)
				cancel()
				checked = t
				if err != nil {
					a.hb.Report("auto-update", "patch: the latest release not known: "+err.Error(), nil)
				} else {
					last = v
					a.seen.Store(v)
				}
			}
			stat := nodeupdate.Settled(nodeupdate.ReadStatus(a.status), t)
			req, waiting := nodeupdate.PeekRequest(a.request)
			switch {
			case last == "" || !nodeupdate.Patch(last, a.running):
				a.hb.Report("auto-update", "patch, window "+p.Window+": up to date ("+a.running+")", nil)
				due = time.Time{}
			case stat.Target == last && gaveUp(stat, t):
				a.hb.Report("auto-update", "patch: the update to "+last+" failed ("+stat.Error+"); not again by itself", nil)
			case !nodeupdate.InWindow(t, p.Window):
				a.hb.Report("auto-update", "patch: "+last+" waits for the window "+p.Window, nil)
				due = time.Time{}
			case nodeupdate.Busy(stat, req, waiting, t):
				a.hb.Report("auto-update", "patch: an update is under way", nil)
			case due.IsZero():
				due = t
				if span := min(nodeupdate.Spread, nodeupdate.Left(t, p.Window)-time.Minute); span > 0 {
					due = t.Add(time.Duration(mrand.Int64N(int64(span)))) //nolint:gosec // a moment, not a secret
				}
				a.hb.Report("auto-update", "patch: "+last+" at "+due.Format("15:04"), nil)
			case !t.Before(due):
				r := nodeupdate.Request{ID: nodeupdate.NewID(), Kind: nodeupdate.Auto, Version: last, By: "auto", At: t.UTC()}
				switch err := nodeupdate.WriteRequest(a.request, r, t); {
				case errors.Is(err, nodeupdate.ErrWaiting):
					a.hb.Report("auto-update", "patch: an update is under way", nil)
				case err != nil:
					a.hb.Report("auto-update", "patch: the request for "+last+" not written", err)
				default:
					a.log.Info("auto update requested", "version", last, "running", a.running)
					_ = a.st.Audit(ctx, "auto", "update.start "+last, "node", "ok")
					a.hb.Report("auto-update", "patch: "+last+" requested", nil)
				}
				due = time.Time{}
			}
		}
		// Waiting for the moment, not a whole tick past it: the window
		// may close in between.
		wait := a.tick
		if !due.IsZero() {
			wait = min(wait, max(due.Sub(t), time.Second))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// gaveUp reports whether the auto update leaves the version of s alone:
// its update rolled back, or failed; one that failed before it changed
// anything on the node is tried again after nodeupdate.RetryAfter.
func gaveUp(s nodeupdate.Status, now time.Time) bool {
	switch s.State {
	case nodeupdate.RolledBack:
		return true
	case nodeupdate.Failed:
		return !s.Untouched || now.Sub(s.Ended) < nodeupdate.RetryAfter
	}
	return false
}
