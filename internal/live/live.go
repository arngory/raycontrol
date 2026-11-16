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
	"maps"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/arngory/raycontrol/internal/deploy"
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
	// Pending is the directory of the restarts owed (owe); empty: "restarts"
	// beside the rendered directory, in rayd's state directory.
	Pending string
	// FrontUnit is the front's installed unit file (systemd); empty: none
	// to read (the supervisor copies in what its own plan names). A
	// hy2-obfs whose password it does not copy in yet is kept off the
	// front until rayctl apply (render.Model.FrontCopies).
	FrontUnit string

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
		if bytes.Contains(out, []byte("not found")) || bytes.Contains(out, []byte("not loaded")) {
			err = errors.Join(errNoUnit, err)
		}
		return fmt.Errorf("systemctl %s %s: %w: %s", verb, unit, err, bytes.TrimSpace(out))
	}
	return nil
}

// errNoUnit: the unit is not installed (the node is not deployed yet, or
// the service is new and rayctl apply has not run). No process runs with
// the files of before, and rayctl apply starts the unit with the ones
// there: nothing is owed.
var errNoUnit = errors.New("no such unit")

// A restart owed to a service is written down before the file that calls
// for it changes, and struck only when systemctl has done it. Without the
// record a restart that did not happen was lost for good: rayd stopped or
// killed between the write and systemctl, or systemctl failing, and every
// later apply found the files equal to what it would write and restarted
// nothing. After a switch of a site's key that left naive, the site and
// the Hysteria2 backends on the old key while subscriptions pinned the new
// one (spec/cert-pin-v1.md §6).
//
// One file a service, named by it, holding the verb. rayd's own directory:
// nobody else writes there.

// frontCopies is what the front's installed unit copies in, as
// render.Model.FrontCopies has it: nil (all) without FrontUnit or without
// the unit, which rayctl apply then writes with every one the render names.
func (a *Applier) frontCopies() func(string) bool {
	if a.FrontUnit == "" {
		return nil
	}
	b, err := os.ReadFile(a.FrontUnit)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			a.Log.Warn("the front's unit cannot be read; its routes as rendered", "err", err)
		}
		return nil
	}
	copies := deploy.UnitCopies(b)
	return func(path string) bool { return copies[path] }
}

func (a *Applier) pendingDir() string {
	if a.Pending != "" {
		return a.Pending
	}
	return filepath.Join(filepath.Dir(a.Paths.Rendered), "restarts")
}

// owed reads the restarts written down and not done: service to verb.
func (a *Applier) owed() map[string]string {
	out := map[string]string{}
	entries, err := os.ReadDir(a.pendingDir())
	if err != nil {
		return out
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(a.pendingDir(), e.Name()))
		if err != nil || e.IsDir() {
			continue
		}
		verb := "try-restart"
		if string(bytes.TrimSpace(b)) == "restart" {
			verb = "restart"
		}
		out[e.Name()] = verb
	}
	return out
}

// owe writes down that service's unit needs verb; "restart" (the unit
// waited for a file) stays over "try-restart".
func (a *Applier) owe(service, verb string, have map[string]string) error {
	if have[service] == verb || have[service] == "restart" {
		return nil
	}
	if err := os.MkdirAll(a.pendingDir(), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(a.pendingDir(), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(verb + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(a.pendingDir(), service)); err != nil {
		return err
	}
	have[service] = verb
	return nil
}

// settle strikes a restart done, or found unnecessary.
func (a *Applier) settle(service string, have map[string]string) {
	if _, ok := have[service]; !ok {
		return
	}
	if err := os.Remove(filepath.Join(a.pendingDir(), service)); err != nil && !errors.Is(err, os.ErrNotExist) {
		a.Log.Warn("a restart done stays written down; it will be made once more", "service", service, "err", err)
		return
	}
	delete(have, service)
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
	m.FrontCopies = a.frontCopies()
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
		rereads  bool // a file the process rereads and none of its units waits for
	}
	changed := map[string][]change{} // service -> changed files
	failed := map[string]bool{}
	// The restarts owed from before this apply, and those it writes down.
	owed := a.owed()
	before := maps.Clone(owed)
	rendered := map[string]bool{}
	wrote := map[string]bool{}
	for _, f := range files {
		rendered[f.Service] = true
		if failed[f.Service] {
			continue
		}
		// A certificate chain is reread too (spec/cert-pin-v1.md §6), but
		// its unit waits for it: new, it starts the unit (File.Needed).
		rereads := f.Reload && !f.Needed
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
			case fixed && f.AtStart:
				// Read at the process's next start: no restart for it.
			case fixed && f.Refresh:
				// A broken service's users: reread, never a restart (Q-1).
				changed[f.Service] = append(changed[f.Service], change{old, f.Content, true, rereads})
			case fixed:
				changed[f.Service] = append(changed[f.Service], change{nil, f.Content, false, rereads})
				// After the fact: whether the group was missing shows only
				// in fixing it. rayctl apply, which makes the groups, starts
				// the units itself.
				verb := "try-restart"
				if !rereads {
					verb = "restart"
				}
				if err := a.owe(f.Service, verb, owed); err != nil {
					a.Log.Warn("restart not written down", "service", f.Service, "err", err)
				}
			}
			continue
		}
		if errors.Is(err, os.ErrNotExist) && f.Refresh {
			continue // a broken service's users: only replaced, never made (Q-1)
		}
		if err == nil || errors.Is(err, os.ErrNotExist) {
			// A change the process does not take by itself: its restart is
			// written down first. A file that cannot be written down is
			// not written either: the next apply finds the change again.
			// Nor one it takes at its next start, whenever that is.
			if f.AtStart {
				err = nil
			} else if !f.Reload || old == nil {
				verb := "try-restart"
				if old == nil && !rereads {
					verb = "restart"
				}
				err = a.owe(f.Service, verb, owed)
			} else {
				err = nil
			}
			switch {
			case err == nil && f.Pair != "":
				// A key and its chain, the key's restart written down
				// first: the chain then needs no change of its own. The
				// key renamed and the chain not: its restart stays owed.
				var first bool
				first, err = writePair(f, files)
				wrote[f.Service] = wrote[f.Service] || first
			case err == nil:
				err = writeFile(f)
			}
		}
		if err != nil {
			// E.g. the service group exists but rayd is not in it yet: rayctl
			// apply restarts rayd with its new groups.
			failed[f.Service] = true
			errs = append(errs, fmt.Errorf("service %s: %s: %w", f.Service, f.Path, err))
			// Nothing of the service changed: nothing is owed for it.
			if _, was := before[f.Service]; !was && !wrote[f.Service] {
				a.settle(f.Service, owed)
			}
			continue
		}
		wrote[f.Service] = true
		if f.AtStart {
			continue // nothing to restart, nothing reloaded
		}
		changed[f.Service] = append(changed[f.Service], change{old, f.Content, f.Reload && old != nil, rereads})
	}
	// No front's config from Render: the front carries nothing now (its
	// last service deleted, disabled, waiting for a certificate, or not
	// rendering: the front leaves that out too, render.ServiceErrors). The
	// one of before goes: the front's unit waits for it only, and is
	// planned for what this render wrote, not for it (deploy, the
	// salamander passwords it copies in). Left there, it started the front
	// at the next apply, update or boot with backends that are gone, one
	// password missing: niko-server exited, again every 2 s.
	frontGone := !slices.ContainsFunc(files, func(f render.File) bool { return f.Path == a.Paths.FrontConfig() })
	if frontGone {
		if err := a.dropFrontConfig(owed, before); err != nil {
			failed["front"] = true
			errs = append(errs, fmt.Errorf("service front: %s: %w", a.Paths.FrontConfig(), err))
		}
	}

	// What to restart: the services whose files changed, and those owed a
	// restart from an apply that did not get to it.
	todo := map[string]string{}
	for service, cs := range changed {
		if failed[service] {
			continue
		}
		_, late := before[service]
		if !slices.ContainsFunc(cs, func(c change) bool { return !c.reload }) {
			a.Log.Info("reloaded without a restart", "service", service)
			continue
		}
		// Not for a service owed a restart from before: its process has
		// more to take than the users.
		if svc, ok := xrayService(m, service); ok && !late && len(cs) == 1 && cs[0].old != nil && sameExceptClients(cs[0].old, cs[0].new) {
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
				a.settle(service, owed)
				continue
			}
			a.Log.Warn("xray API sync failed, restarting", "service", service, "err", err)
		}
		// Files that were not there before: the unit waited for them
		// (ConditionPathExists) and starts now. Otherwise only a running
		// process restarts, so a unit stopped on purpose stays stopped. A
		// new file the process rereads (the conn-limit switch) gates no
		// unit: it starts nothing.
		verb := "try-restart"
		if slices.ContainsFunc(cs, func(c change) bool { return c.old == nil && !c.rereads }) {
			verb = "restart"
		}
		todo[service] = verb
	}
	for service, verb := range owed {
		switch {
		case !rendered[service] && (service != "front" || !frontGone):
			// The service is gone or off: its unit must not be started for
			// a file it once waited for. The front without its config is
			// owed its stop: a restart cannot start it.
			a.settle(service, owed)
		case failed[service]:
			// Half-written: the next apply.
		case verb == "restart" || todo[service] == "":
			todo[service] = verb
		}
	}
	for _, service := range slices.Sorted(maps.Keys(todo)) {
		verb, unit := todo[service], render.UnitName(service)
		if a.BeforeRestart != nil {
			a.BeforeRestart(ctx, service)
		}
		_, late := before[service]
		switch err := a.restart(ctx, verb, unit); {
		case err == nil:
			a.settle(service, owed)
			a.Log.Info("restarted after config change", "unit", unit, "late", late)
		case errors.Is(err, errNoUnit):
			a.settle(service, owed)
			a.Log.Warn("restart failed (is the node deployed? run rayctl apply)", "unit", unit, "err", err)
		default:
			// The process runs with the files of before, a key among them
			// maybe: said through the apply's error, so that rayctl status
			// shows it, and made again at every apply until it works.
			a.Log.Warn("restart failed; it stays owed and is made again at the next apply", "unit", unit, "err", err)
			errs = append(errs, fmt.Errorf("service %s: %s of %s failed, its process runs with the files of before: %w", service, verb, unit, err))
		}
	}
	return errors.Join(errs...)
}

// dropFrontConfig removes the front's config, which this render did not
// make. Its stop is written down first, as a restart is before the file
// that calls for it changes: try-restart stops a running front, whose
// unit's condition then fails. The probe key stays: the unit copies it in
// as long as there is no config (deploy, TestProbeKeyBeforeDNSTT), and
// Render writes it again with the next one.
func (a *Applier) dropFrontConfig(owed, before map[string]string) error {
	config := a.Paths.FrontConfig()
	if _, err := os.Lstat(config); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := a.owe("front", "try-restart", owed); err != nil {
		return err // not removed either: the next apply finds it again
	}
	if err := os.Remove(config); err != nil && !errors.Is(err, os.ErrNotExist) {
		// Still there: a restart would start the front on it.
		if _, was := before["front"]; !was {
			a.settle("front", owed)
		}
		return err
	}
	a.Log.Info("the front carries no service: its config removed, the front stops", "path", config)
	return nil
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
	tmp, err := stageFile(f)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	return os.Rename(tmp, f.Path)
}

// writePair writes f and, if its content changed, the file of f.Pair in
// files: both staged first, then renamed back to back, f first. A key and
// its chain: a full disk or a failed write leaves both as they were, and
// only a stop between the renames leaves the new key with the old chain,
// which the running process, holding the old key, does not see as a
// change.
func writePair(f render.File, files []render.File) (wroteF bool, err error) {
	i := slices.IndexFunc(files, func(p render.File) bool { return p.Path == f.Pair })
	var pair *render.File
	if i >= 0 {
		if old, err := os.ReadFile(files[i].Path); err != nil || !bytes.Equal(old, files[i].Content) {
			pair = &files[i]
		}
	}
	tmp, err := stageFile(f)
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp)
	var tmpPair string
	if pair != nil {
		if tmpPair, err = stageFile(*pair); err != nil {
			return false, err
		}
		defer os.Remove(tmpPair)
	}
	if err := os.Rename(tmp, f.Path); err != nil {
		return false, err
	}
	if pair == nil {
		return true, nil
	}
	return true, renamePair(tmpPair, pair.Path)
}

// renamePair is the second rename of writePair (tests: one that fails).
var renamePair = os.Rename

// stageFile writes f's content to a temporary file beside it, with its
// mode and group, and returns its path; the caller renames or removes it.
func stageFile(f render.File) (string, error) {
	dir := filepath.Dir(f.Path)
	gid := -1
	if f.Group != "" {
		if g, err := user.LookupGroup(f.Group); err == nil {
			gid, _ = strconv.Atoi(g.Gid)
		}
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	if gid >= 0 {
		// The directory must let the group in; the files decide the rest.
		if err := os.Chown(dir, -1, gid); err != nil {
			return "", err
		}
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return "", err
	}
	_, err = tmp.Write(f.Content)
	err = errors.Join(err, tmp.Close())
	if err == nil && gid >= 0 {
		err = os.Chown(tmp.Name(), -1, gid)
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), os.FileMode(f.Mode))
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
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
