// Package live keeps the data plane in step with the node state while rayd
// runs: it rewrites rendered files, syncs inner users through the Xray API
// and restarts processes whose configs changed.
package live

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/xrayapi"
)

// InnerAPI is the part of the Xray API live needs.
type InnerAPI interface {
	SyncVLESS(ctx context.Context, tag, flow string, want map[string]string) (added, removed int, err error)
}

// Applier renders and applies.
type Applier struct {
	Store *store.Store
	Paths render.Paths
	Log   *slog.Logger
	// Restart runs systemctl verb ("try-restart" or "restart") on a unit;
	// nil uses systemctl (allowed for the rayd user by the raycontrol polkit
	// rule).
	Restart func(ctx context.Context, verb, unit string) error
	// Inner returns an API client for an inner API socket; nil dials Xray.
	Inner func(socket string) InnerAPI
	// Report, if set, gets the outcome of every Apply in Run (O-2).
	Report func(error)
	// BeforeRestart, if set, runs before a service's process is restarted:
	// the traffic loop reads its counters, which start again with it
	// (traffic-limit-v1 §2.4).
	BeforeRestart func(ctx context.Context, service string)
	// SyncTimeout bounds each Xray API call that syncs an inbound's users
	// (0: DefaultSyncTimeout): a process that stopped answering would
	// otherwise hold the apply loop, and every later change, for good. A
	// call that runs out restarts the process as any failed sync does.
	SyncTimeout time.Duration

	skipped []string // the waiting services last logged
}

// DefaultSyncTimeout is SyncTimeout's default: a sync of thousands of
// users over the local socket takes well under a second.
const DefaultSyncTimeout = 30 * time.Second

// syncVLESS is api.SyncVLESS within SyncTimeout.
func (a *Applier) syncVLESS(ctx context.Context, api InnerAPI, tag, flow string, want map[string]string) (int, int, error) {
	ctx, cancel := context.WithTimeout(ctx, cmp.Or(a.SyncTimeout, DefaultSyncTimeout))
	defer cancel()
	return api.SyncVLESS(ctx, tag, flow, want)
}

func (a *Applier) restart(ctx context.Context, verb, unit string) error {
	if a.Restart != nil {
		return a.Restart(ctx, verb, unit)
	}
	out, err := exec.CommandContext(ctx, "systemctl", verb, unit).CombinedOutput() //nolint:gosec // G204: verb is one of two constants
	if err != nil {
		return fmt.Errorf("systemctl %s %s: %w: %s", verb, unit, err, bytes.TrimSpace(out))
	}
	return nil
}

func (a *Applier) inner(socket string) InnerAPI {
	if a.Inner != nil {
		return a.Inner(socket)
	}
	return xrayapi.Dial(socket)
}

// Apply renders everything once. A service whose files cannot be written
// is skipped (and not restarted); the others go on, and the errors come back
// joined.
func (a *Applier) Apply(ctx context.Context) error {
	m, err := render.CollectForRender(ctx, a.Store)
	if err != nil {
		return err
	}
	// A service that cannot be rendered keeps its files and its process;
	// the others are applied (Q-1).
	files, skipped, rerr := render.Render(m, a.Paths)
	if rerr != nil && !render.Partial(rerr) {
		return rerr
	}
	var errs []error
	if rerr != nil {
		errs = append(errs, rerr)
	}
	// Waiting services are logged when the list changes, not on every apply.
	if !slices.Equal(skipped, a.skipped) {
		for _, s := range skipped {
			a.Log.Info("service not rendered yet", "service", s)
		}
		a.skipped = skipped
	}

	// Service users traverse this directory to their own subdirectory.
	if err := os.MkdirAll(a.Paths.Rendered, 0o711); err != nil { //nolint:gosec // G301: traversal only, the subdirectories are 0750
		return err
	}
	if err := os.Chmod(a.Paths.Rendered, 0o711); err != nil { //nolint:gosec // G302: as above
		return err
	}

	type change struct {
		old, new []byte
		reload   bool // the process reads it again by itself
	}
	changed := map[string][]change{} // service -> changed files
	failed := map[string]bool{}
	for _, f := range files {
		if failed[f.Service] {
			continue
		}
		old, err := os.ReadFile(f.Path)
		if err == nil && bytes.Equal(old, f.Content) {
			// Same content, but the group may have appeared since the file was
			// written (rayctl apply creates it): fix group and mode, and
			// restart the process that could not read the file.
			fixed, err := fixMeta(f)
			switch {
			case err != nil:
				failed[f.Service] = true
				errs = append(errs, fmt.Errorf("service %s: %s: %w", f.Service, f.Path, err))
			case fixed && f.Refresh:
				// A broken service's users: reread, never a restart (Q-1).
				changed[f.Service] = append(changed[f.Service], change{old, f.Content, true})
			case fixed:
				changed[f.Service] = append(changed[f.Service], change{nil, f.Content, false})
			}
			continue
		}
		if errors.Is(err, os.ErrNotExist) && f.Refresh {
			continue // a broken service's users: only replaced, never made (Q-1)
		}
		if err == nil || errors.Is(err, os.ErrNotExist) {
			err = writeFile(f)
		}
		if err != nil {
			// E.g. the service group exists but rayd is not in it yet: rayctl
			// apply restarts rayd with its new groups.
			failed[f.Service] = true
			errs = append(errs, fmt.Errorf("service %s: %s: %w", f.Service, f.Path, err))
			continue
		}
		changed[f.Service] = append(changed[f.Service], change{old, f.Content, f.Reload && old != nil})
	}

	for service, cs := range changed {
		if failed[service] {
			continue
		}
		unit := render.UnitName(service)
		if !slices.ContainsFunc(cs, func(c change) bool { return !c.reload }) {
			a.Log.Info("reloaded without a restart", "service", service)
			continue
		}
		if svc, ok := xrayService(m, service); ok && len(cs) == 1 && cs[0].old != nil && sameExceptClients(cs[0].old, cs[0].new) {
			_, want := render.XrayUsers(m, svc)
			api := a.inner(a.Paths.APISocket(service))
			flow := ""
			if svc.Kind == "reality" {
				flow = render.RealityFlow
			}
			// The same users on every inbound: REALITY's previous keys have
			// one of their own for a while (R4-19).
			var added, removed int
			var err error
			for _, tag := range render.XrayTags(svc) {
				a1, r1, e := a.syncVLESS(ctx, api, tag, flow, want)
				added, removed, err = added+a1, removed+r1, errors.Join(err, e)
			}
			if err == nil {
				a.Log.Info("xray users synced", "service", service, "added", added, "removed", removed)
				continue
			}
			a.Log.Warn("xray API sync failed, restarting", "service", service, "err", err)
		}
		// Files that were not there before: the unit waited for them
		// (ConditionPathExists) and starts now. Otherwise only a running
		// process restarts, so a unit stopped on purpose stays stopped.
		verb := "try-restart"
		if slices.ContainsFunc(cs, func(c change) bool { return c.old == nil }) {
			verb = "restart"
		}
		if a.BeforeRestart != nil {
			a.BeforeRestart(ctx, service)
		}
		if err := a.restart(ctx, verb, unit); err != nil {
			a.Log.Warn("restart failed (is the node deployed? run rayctl apply)", "unit", unit, "err", err)
		} else {
			a.Log.Info("restarted after config change", "unit", unit)
		}
	}
	return errors.Join(errs...)
}

// xrayService finds the Xray service (inner, REALITY) of that name.
func xrayService(m render.Model, service string) (render.Service, bool) {
	for _, s := range m.Services {
		if s.Name == service && render.IsXray(s.Kind) {
			return s, true
		}
	}
	return render.Service{}, false
}

// sameExceptClients reports whether two Xray configs differ only in the
// users of the inbound.
func sameExceptClients(a, b []byte) bool {
	strip := func(raw []byte) ([]byte, bool) {
		var cfg map[string]any
		if json.Unmarshal(raw, &cfg) != nil {
			return nil, false
		}
		ins, _ := cfg["inbounds"].([]any)
		for _, in := range ins {
			if m, ok := in.(map[string]any); ok {
				if s, ok := m["settings"].(map[string]any); ok {
					delete(s, "clients")
				}
			}
		}
		out, err := json.Marshal(cfg)
		return out, err == nil
	}
	x, ok1 := strip(a)
	y, ok2 := strip(b)
	return ok1 && ok2 && bytes.Equal(x, y)
}

// fixMeta gives an existing file and its directory the group (once it
// exists) and the file its mode, and reports whether it changed anything.
func fixMeta(f render.File) (bool, error) {
	fixed := false
	if f.Group != "" {
		g, err := user.LookupGroup(f.Group)
		if err != nil {
			return false, nil // not deployed yet
		}
		gid, _ := strconv.Atoi(g.Gid)
		for _, p := range []string{filepath.Dir(f.Path), f.Path} {
			st, err := os.Stat(p)
			if err != nil {
				return fixed, err
			}
			if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Gid) != gid {
				if err := os.Chown(p, -1, gid); err != nil {
					return fixed, err
				}
				fixed = true
			}
		}
	}
	st, err := os.Stat(f.Path)
	if err != nil {
		return fixed, err
	}
	if st.Mode().Perm() != os.FileMode(f.Mode).Perm() {
		if err := os.Chmod(f.Path, os.FileMode(f.Mode)); err != nil {
			return fixed, err
		}
		fixed = true
	}
	return fixed, nil
}

// writeFile writes atomically with the file's mode and group. The group is
// set only if it exists (it does once the node is deployed).
func writeFile(f render.File) error {
	dir := filepath.Dir(f.Path)
	gid := -1
	if f.Group != "" {
		if g, err := user.LookupGroup(f.Group); err == nil {
			gid, _ = strconv.Atoi(g.Gid)
		}
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if gid >= 0 {
		// The directory must let the group in; the files decide the rest.
		if err := os.Chown(dir, -1, gid); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(f.Content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if gid >= 0 {
		if err := os.Chown(tmp.Name(), -1, gid); err != nil {
			return err
		}
	}
	if err := os.Chmod(tmp.Name(), os.FileMode(f.Mode)); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.Path)
}

// Run applies now, after every change signalled on changes and every minute
// (users expire without a change).
func (a *Applier) Run(ctx context.Context, changes func() <-chan struct{}) {
	for {
		// Taken before Apply: a change during Apply wakes the next round.
		wake := changes()
		err := a.Apply(ctx)
		if ctx.Err() != nil {
			return
		}
		if a.Report != nil {
			a.Report(err)
		}
		if err != nil {
			a.Log.Error("apply", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
			// Let a burst of changes settle.
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
		case <-time.After(time.Minute):
		}
	}
}
