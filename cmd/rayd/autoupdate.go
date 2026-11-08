package main

import (
	"context"
	"errors"
	"log/slog"
	mrand "math/rand/v2"
	"slices"
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

// autoState is what the loop keeps from one look to the next.
type autoState struct {
	last    string // the latest release seen
	lerr    error  // why last is not known
	checked time.Time
	due     time.Time // the moment in this window, once in it
}

func (a *autoUpdater) run(ctx context.Context) {
	var s autoState
	for {
		t := a.now()
		soon := a.step(ctx, &s, t)
		select {
		case <-ctx.Done():
			return
		case <-time.After(nextWait(a.tick, s.due, t, soon)):
		}
	}
}

// step is one look at t; soon reports that it waits for its moment.
func (a *autoUpdater) step(ctx context.Context, s *autoState, t time.Time) (soon bool) {
	p := nodeupdate.ReadPolicy(a.policy)
	switch {
	case p.Auto != "patch":
		a.hb.Retain("auto-update", nil)
		s.due = time.Time{}
	case !release.IsRelease(a.running):
		a.hb.Report("auto-update", "on, but this build is no release ("+a.running+"): it updates by hand", nil)
	default:
		if s.checked.IsZero() || t.Sub(s.checked) > jitter(autoCheck, 10) {
			cctx, cancel := context.WithTimeout(ctx, time.Minute)
			v, err := a.latest(cctx)
			cancel()
			s.checked, s.lerr = t, err
			if err == nil {
				s.last = v
				a.seen.Store(v)
			}
		}
		// The request first: root writes the status before it
		// removes the request.
		req, waiting := nodeupdate.PeekRequest(a.request)
		stat := nodeupdate.Settled(nodeupdate.ReadStatus(a.status), t)
		switch {
		case s.last == "" && s.lerr != nil:
			a.hb.Report("auto-update", "patch: the latest release not known: "+s.lerr.Error(), nil)
			s.due = time.Time{}
		case s.last == "" || !nodeupdate.Patch(s.last, a.running):
			a.hb.Report("auto-update", "patch, window "+p.Window+": up to date ("+a.running+")", nil)
			s.due = time.Time{}
		case gaveUp(stat, s.last, t):
			a.hb.Report("auto-update", "patch: the update to "+s.last+" did not hold; not again by itself (rayctl update status)", nil)
			s.due = time.Time{}
		case !nodeupdate.InWindow(t, p.Window):
			a.hb.Report("auto-update", "patch: "+s.last+" waits for the window "+p.Window, nil)
			s.due = time.Time{}
		case nodeupdate.Busy(stat, req, waiting, t):
			a.hb.Report("auto-update", "patch: an update is under way", nil)
			s.due = time.Time{}
		case s.due.IsZero():
			s.due, soon = t, true
			if span := min(nodeupdate.Spread, nodeupdate.Left(t, p.Window)-time.Minute); span > 0 {
				s.due = t.Add(time.Duration(mrand.Int64N(int64(span)))) //nolint:gosec // a moment, not a secret
			}
			a.hb.Report("auto-update", "patch: "+s.last+" at "+s.due.Format("15:04"), nil)
		case t.Before(s.due):
			soon = true
		default:
			r := nodeupdate.Request{ID: nodeupdate.NewID(), Kind: nodeupdate.Auto, Version: s.last, By: "auto", At: t.UTC()}
			switch err := nodeupdate.WriteRequest(a.request, r, t); {
			case errors.Is(err, nodeupdate.ErrWaiting):
				a.hb.Report("auto-update", "patch: an update is under way", nil)
			case err != nil:
				a.hb.Report("auto-update", "patch: the request for "+s.last+" not written", err)
			default:
				a.log.Info("auto update requested", "version", s.last, "running", a.running)
				_ = a.st.Audit(ctx, "auto", "update.start "+s.last, "node", "ok")
				a.hb.Report("auto-update", "patch: "+s.last+" requested", nil)
			}
			s.due = time.Time{}
		}
	}
	return soon
}

// nextWait is how long the loop sleeps: a tick, or until the moment it
// waits for, not a whole tick past it (the window may close in between).
func nextWait(tick time.Duration, due, now time.Time, soon bool) time.Duration {
	if !soon {
		return tick
	}
	return min(tick, max(due.Sub(now), time.Second))
}

// gaveUp reports whether the auto update leaves release v alone: an update
// to it rolled back or broke on the way (held, whatever came since), or it
// is the one that just failed before it changed anything on the node, tried
// again after nodeupdate.RetryAfter.
func gaveUp(s nodeupdate.Status, v string, now time.Time) bool {
	if slices.Contains(s.Held, v) {
		return true
	}
	if s.Release != v && s.Target != v {
		return false
	}
	switch s.State {
	case nodeupdate.RolledBack:
		return true
	case nodeupdate.Failed:
		return !s.Untouched || now.Sub(s.Ended) < nodeupdate.RetryAfter
	}
	return false
}
