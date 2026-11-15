package main

import (
	"cmp"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/nodeupdate"
)

// fakeRunner is a relay's runner on a test's own directories: the request
// in rayd relay's, the status and the policy in root's, the update's mark
// in the copy's; the rollback, the install lock and the system's state
// given.
type fakeRunner struct {
	t        *testing.T
	dir      string
	q        requests
	ops      relayOps
	stopping bool
	rolled   int          // rollbacks run
	back     func() error // the rollback; nil: it puts the relay back (the mark goes)
	onFree   func()       // the install lock waited for
	locked   error        // the update lock not taken
	relayVer string       // the relay's version as its rayd says
	onLock   func()       // the update lock waited for
	// signalled: the unit was told to stop (its runner caught the signal).
	signalled bool
}

func newFakeRunner(t *testing.T) *fakeRunner {
	t.Helper()
	saved := version
	t.Cleanup(func() { version = saved })
	version = "v0.27.0"
	f := &fakeRunner{t: t, dir: t.TempDir(), relayVer: "v0.27.0"}
	for _, d := range []string{"rayd-relay", "status", "previous"} {
		if err := os.MkdirAll(filepath.Join(f.dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.ops = relayOps{dir: filepath.Join(f.dir, "previous")}
	f.q = requests{request: filepath.Join(f.dir, "rayd-relay", "update-request"), status: filepath.Join(f.dir, "status", "status.json"),
		policy: filepath.Join(f.dir, "status", "policy.json"), result: filepath.Join(f.dir, "status", "result.json"),
		ready: func() error { return nil }, nodeVersion: func() string { return f.relayVer },
		kinds: nodeupdate.RelayKinds, target: relayTarget, lock: func(stop func() bool) error {
			if f.onLock != nil {
				f.onLock()
			}
			if stop != nil && stop() {
				return errLockWaitStopped
			}
			return f.locked
		}}
	f.q.relay = &relayRunner{
		mark:     f.ops.readMark,
		stopping: func() bool { return f.stopping },
		free: func() {
			if f.onFree != nil {
				f.onFree()
			}
		},
		rollback: func() (string, error) {
			f.rolled++
			if f.back != nil {
				if err := f.back(); err != nil {
					return err.Error(), err
				}
			}
			f.ops.unmark()
			return "", nil
		},
		signals: func() (func() bool, func()) { return func() bool { return f.signalled }, func() {} },
		lock:    func() error { return f.locked },
	}
	f.policy("on")
	return f
}

func (f *fakeRunner) policy(remote string) {
	f.t.Helper()
	if err := nodeupdate.WritePolicy(f.q.policy, nodeupdate.Policy{Remote: remote, Auto: "off", Window: nodeupdate.DefaultWindow}); err != nil {
		f.t.Fatal(err)
	}
}

// request is rayd relay's, for the release the exit names.
func (f *fakeRunner) request(v string) nodeupdate.Request {
	f.t.Helper()
	r := nodeupdate.Request{ID: nodeupdate.NewID(), Kind: nodeupdate.Exit, Version: v, By: "exit", At: time.Now().UTC()}
	if err := nodeupdate.WriteRequest(f.q.request, r, time.Now()); err != nil {
		f.t.Fatal(err)
	}
	return r
}

// rayctl is the installed rayctl, a script: it records how it was run.
func (f *fakeRunner) rayctl(script string) {
	p := filepath.Join(f.dir, "rayctl")
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho \"$@\" > "+f.at("args")+"\nenv > "+f.at("env")+"\n"+script+"\n"), 0o755); err != nil {
		f.t.Fatal(err)
	}
	f.q.rayctl = p
}

func (f *fakeRunner) at(p string) string { return filepath.Join(f.dir, p) }

func (f *fakeRunner) mark(m relayMark) {
	f.t.Helper()
	if err := f.ops.mark(m); err != nil {
		f.t.Fatal(err)
	}
}

// markScript is a shell line that leaves the exit's mark of an update to v.
func (f *fakeRunner) markScript(by, v string) string {
	return `printf '{"state":"updating","from":"v0.27.0","to":"` + v + `","by":"` + by + `"}' > ` + filepath.Join(f.ops.dir, relayMarkFile)
}

// run is rayctl update -request on the relay: the request is gone after
// it, whatever it was, and the result file too.
func (f *fakeRunner) run() (nodeupdate.Status, error) {
	f.t.Helper()
	var err error
	_, _ = captureStdout(f.t, func() error { err = f.q.take(); return nil })
	if _, serr := os.Lstat(f.q.request); !os.IsNotExist(serr) {
		f.t.Fatal("the request stays: the path unit would fire again")
	}
	if _, serr := os.Stat(f.q.result); !os.IsNotExist(serr) {
		f.t.Fatal("the result stays")
	}
	return nodeupdate.ReadStatus(f.q.status), err
}

// rayctl update -request on a relay refuses, the relay untouched and the
// installed rayctl not run, what root does not take: remote off, a request
// too old, a version not strictly newer, held or below the relay's floor,
// latest, a node's kind, something that is no request (a link rayd relay
// planted, a directory), and a request while the update lock is held (a
// manual update). The status says so, with the request's id and time
// (rayd relay knows its request taken by them), and the code of the place.
func TestRelayRequestRefused(t *testing.T) {
	for name, c := range map[string]struct {
		set    func(*fakeRunner) nodeupdate.Request
		reason string
	}{
		"remote off": {func(f *fakeRunner) nodeupdate.Request { f.policy("off"); return f.request("v0.27.1") }, nodeupdate.ReasonPolicy},
		"no policy":  {func(f *fakeRunner) nodeupdate.Request { os.Remove(f.q.policy); return f.request("v0.27.1") }, nodeupdate.ReasonPolicy},
		"the same":   {func(f *fakeRunner) nodeupdate.Request { return f.request("v0.27.0") }, nodeupdate.ReasonVersion},
		"older":      {func(f *fakeRunner) nodeupdate.Request { return f.request("v0.26.3") }, nodeupdate.ReasonVersion},
		"latest":     {func(f *fakeRunner) nodeupdate.Request { return f.request("latest") }, nodeupdate.ReasonVersion},
		"update lock": {func(f *fakeRunner) nodeupdate.Request {
			f.locked = errors.New("another update is running")
			return f.request("v0.27.1")
		}, nodeupdate.ReasonBusy},
		"a node's kind": {func(f *fakeRunner) nodeupdate.Request {
			r := nodeupdate.Request{ID: nodeupdate.NewID(), Kind: nodeupdate.Remote, Version: "v0.27.1", By: "exit", At: time.Now().UTC()}
			nodeupdate.WriteRequest(f.q.request, r, time.Now())
			return r
		}, ""},
		"too old": {func(f *fakeRunner) nodeupdate.Request {
			r := nodeupdate.Request{ID: nodeupdate.NewID(), Kind: nodeupdate.Exit, Version: "v0.27.1", By: "exit", At: time.Now().Add(-2 * time.Hour).UTC()}
			nodeupdate.WriteRequest(f.q.request, r, time.Now())
			return r
		}, nodeupdate.ReasonStale},
		"held": {func(f *fakeRunner) nodeupdate.Request {
			nodeupdate.WriteStatus(f.q.status, nodeupdate.Status{ID: "0a", State: nodeupdate.RolledBack, Kind: nodeupdate.Exit, Held: []string{"v0.27.1"}})
			return f.request("v0.27.1")
		}, nodeupdate.ReasonVersion},
		// A dev build takes any release as newer: the relay's floor holds.
		"below the floor": {func(f *fakeRunner) nodeupdate.Request { version = "dev"; return f.request("v0.25.1") }, nodeupdate.ReasonVersion},
	} {
		f := newFakeRunner(t)
		f.rayctl(`exit 9`)
		r := c.set(f)
		st, err := f.run()
		if err == nil || st.State != nodeupdate.Failed || !st.Untouched || st.Reason != c.reason || st.ID != r.ID || !st.Requested.Equal(r.At) ||
			st.Kind != r.Kind || st.Error == "" || st.Error != nodeupdate.Printable(st.Error) {
			t.Errorf("%s: %v, status %+v", name, err, st)
		}
		if _, err := os.Stat(f.at("args")); err == nil {
			t.Errorf("%s: the update ran", name)
		}
		if name == "held" && !slices.Equal(st.Held, []string{"v0.27.1"}) {
			t.Errorf("held: what was held is forgotten: %v", st.Held)
		}
	}

	// A link rayd relay put there: not followed, and it goes (the file it
	// points to stays); a directory goes too.
	f := newFakeRunner(t)
	f.rayctl(`exit 9`)
	secret := filepath.Join(t.TempDir(), "shadow")
	os.WriteFile(secret, []byte(`{"id":"0a","kind":"exit","version":"v0.27.1","by":"exit"}`), 0o600)
	os.Symlink(secret, f.q.request)
	if st, err := f.run(); err == nil || st.State != nodeupdate.Failed || !st.Untouched {
		t.Errorf("a link: %v %+v", err, st)
	}
	if _, err := os.Stat(secret); err != nil {
		t.Errorf("the link's target: %v", err)
	}
	os.MkdirAll(filepath.Join(f.q.request, "x"), 0o700)
	if st, err := f.run(); err == nil || st.State != nodeupdate.Failed {
		t.Errorf("a directory: %v %+v", err, st)
	}
	// No request: nothing, no status.
	f = newFakeRunner(t)
	if st, err := f.run(); err != nil || st.State != nodeupdate.Idle {
		t.Errorf("no request: %v %+v", err, st)
	}
	// An update by hand that did not end: the relay's rayctl refuses
	// (unfinished), and the status says root must act; nothing rolls it
	// back for the person who ran it.
	f = newFakeRunner(t)
	f.mark(relayMark{State: "updating", From: "v0.26.3", To: "v0.27.0"})
	f.rayctl(`echo '{"state":"failed","version":"v0.27.0","error":"an update of this relay was interrupted","untouched":true,"reason":"unfinished"}' > "$RAYCONTROL_UPDATE_RESULT"; exit 1`)
	f.request("v0.27.1")
	if st, _ := f.run(); st.State != nodeupdate.Failed || st.Reason != nodeupdate.ReasonUnfinished || !st.Unfinished || !st.Untouched || f.rolled != 0 {
		t.Errorf("a mark by hand: %+v, rolled back %d", st, f.rolled)
	}
	// Refused before the update with the mark there: said too.
	f.policy("off")
	f.request("v0.27.1")
	if st, _ := f.run(); st.Reason != nodeupdate.ReasonPolicy || !st.Unfinished {
		t.Errorf("refused, a mark there: %+v", st)
	}
}

// The update itself: the installed rayctl, told to write its outcome,
// once the status says running and the request is gone; its outcome in
// the status with its code; a version that did not hold is held.
func TestRelayRequestRun(t *testing.T) {
	f := newFakeRunner(t)
	f.rayctl(`grep -q '"running"' ` + f.q.status + ` && [ ! -e ` + f.q.request + ` ] || exit 3
echo '{"state":"done","version":"v0.27.1","release":"v0.27.1"}' > "$RAYCONTROL_UPDATE_RESULT"`)
	r := f.request("v0.27.1")
	st, err := f.run()
	args, _ := os.ReadFile(f.at("args"))
	env, _ := os.ReadFile(f.at("env"))
	if err != nil || st.State != nodeupdate.Done || st.From != "v0.27.0" || st.To != "v0.27.1" || st.Kind != nodeupdate.Exit || st.By != "exit" ||
		st.ID != r.ID || !st.Requested.Equal(r.At) || st.Reason != "" || st.Unfinished || len(st.Held) != 0 ||
		strings.TrimSpace(string(args)) != "update -yes -version v0.27.1" || !strings.Contains(string(env), nodeupdate.ResultEnv+"="+f.q.result) {
		t.Fatalf("done: %v %+v %q", err, st, args)
	}
	for name, c := range map[string]struct {
		script string
		want   nodeupdate.Status
		held   bool
	}{
		"rolled back": {`echo '{"state":"rolled_back","version":"v0.27.0","release":"v0.27.1","error":"rayspa is inactive/dead","reason":"check"}' > "$RAYCONTROL_UPDATE_RESULT"; exit 1`,
			nodeupdate.Status{State: nodeupdate.RolledBack, To: "v0.27.0", Reason: nodeupdate.ReasonCheck, Error: "rayspa is inactive/dead"}, true},
		"not downloaded": {`echo '{"state":"failed","version":"v0.27.0","error":"downloading SHA256SUMS: timeout","untouched":true,"reason":"download"}' > "$RAYCONTROL_UPDATE_RESULT"; exit 1`,
			nodeupdate.Status{State: nodeupdate.Failed, To: "v0.27.0", Reason: nodeupdate.ReasonDownload, Untouched: true, Error: "downloading SHA256SUMS: timeout"}, false},
		// No outcome and no mark, the relay where it was: it died before
		// its first change; what it said last, interrupted, untouched,
		// and tried again later (TestRelayRequestCutShort).
		"died": {`echo "rayctl: SHA256SUMS: downloading" >&2; exit 1`,
			nodeupdate.Status{State: nodeupdate.Failed, To: "v0.27.0", Reason: nodeupdate.ReasonInterrupted, Untouched: true, Error: "SHA256SUMS: downloading"}, false},
		// An older runner's way: rolled back, by its words.
		"its words": {`echo "rayctl: update failed, the previous version runs again: rayspa is inactive/dead" >&2; exit 1`,
			nodeupdate.Status{State: nodeupdate.RolledBack, To: "v0.27.0", Reason: nodeupdate.ReasonInterrupted, Error: "update failed, the previous version runs again: rayspa is inactive/dead"}, true},
	} {
		f := newFakeRunner(t)
		f.rayctl(c.script)
		f.request("v0.27.1")
		st, _ := f.run()
		got := nodeupdate.Status{State: st.State, To: st.To, Reason: st.Reason, Untouched: st.Untouched, Error: st.Error}
		if got.State != c.want.State || got.To != c.want.To || got.Reason != c.want.Reason || got.Untouched != c.want.Untouched ||
			got.Error != c.want.Error || slices.Contains(st.Held, "v0.27.1") != c.held || st.Release != "v0.27.1" || f.rolled != 0 || st.Unfinished {
			t.Errorf("%s: %+v, rolled back %d", name, st, f.rolled)
		}
	}
}

// A relay's update that ended with no outcome and left the exit's mark
// (killed: kill -9, out of memory) is rolled back by the runner itself,
// once, after the install it ran has ended; not as the system shuts down
// (no unit would start: the recover unit does it after the boot), and
// not one by hand. A rollback that does not bring the relay back leaves
// it open, and the status says root must act.
func TestRelayRequestKilled(t *testing.T) {
	killed := func(f *fakeRunner, by string) {
		f.rayctl(f.markScript(by, "v0.27.1") + "\nkill -9 $$")
	}
	f := newFakeRunner(t)
	killed(f, markByExit)
	f.relayVer = "v0.27.0"
	freed := 0
	f.onFree = func() { freed++ }
	f.request("v0.27.1")
	st, err := f.run()
	if err == nil || st.State != nodeupdate.RolledBack || st.Reason != nodeupdate.ReasonInterrupted || st.To != "v0.27.0" || st.Unfinished ||
		!slices.Contains(st.Held, "v0.27.1") || f.rolled != 1 || freed == 0 || !strings.Contains(st.Error, "rolled back by its runner") {
		t.Errorf("killed: %v %+v, rolled back %d, waited %d", err, st, f.rolled, freed)
	}

	// The release's rayctl it was handed to went on (its parent killed)
	// and ended once the install lock was free: its outcome, no rollback.
	f = newFakeRunner(t)
	killed(f, markByExit)
	f.onFree = func() {
		os.WriteFile(f.q.result, []byte(`{"state":"done","version":"v0.27.1","release":"v0.27.1"}`), 0o600)
		f.ops.unmark()
	}
	f.request("v0.27.1")
	if st, _ := f.run(); st.State != nodeupdate.Done || st.To != "v0.27.1" || f.rolled != 0 || st.Unfinished {
		t.Errorf("an outcome after the lock: %+v, rolled back %d", st, f.rolled)
	}

	// The rollback left the host open.
	f = newFakeRunner(t)
	killed(f, markByExit)
	f.back = func() error {
		f.mark(relayMark{State: "open", From: "v0.27.0", To: "v0.27.1", By: markByExit})
		return errors.New("the previous relay did not come back either")
	}
	f.request("v0.27.1")
	if st, _ := f.run(); st.State != nodeupdate.Failed || st.Reason != nodeupdate.ReasonOpen || !st.Unfinished || f.rolled != 1 ||
		!strings.Contains(st.Error, "did not bring the relay back") {
		t.Errorf("open: %+v", st)
	}
	// The rollback refused (another install, SSH): interrupted, unfinished.
	f = newFakeRunner(t)
	killed(f, markByExit)
	f.back = func() error { return errors.New("another rayctl install -relay is running on this host") }
	f.request("v0.27.1")
	if st, _ := f.run(); st.State != nodeupdate.Failed || st.Reason != nodeupdate.ReasonInterrupted || !st.Unfinished || f.rolled != 1 {
		t.Errorf("refused: %+v", st)
	}
	// The system shuts down: no rollback now.
	f = newFakeRunner(t)
	killed(f, markByExit)
	f.stopping = true
	f.request("v0.27.1")
	if st, _ := f.run(); st.State != nodeupdate.Failed || st.Reason != nodeupdate.ReasonInterrupted || !st.Unfinished || f.rolled != 0 ||
		!strings.Contains(st.Error, "the recover unit") {
		t.Errorf("shutting down: %+v, rolled back %d", st, f.rolled)
	}
	// A mark by hand: nothing.
	f = newFakeRunner(t)
	killed(f, "")
	f.request("v0.27.1")
	if st, _ := f.run(); st.State != nodeupdate.Failed || !st.Unfinished || f.rolled != 0 {
		t.Errorf("a mark by hand: %+v, rolled back %d", st, f.rolled)
	}
}

// The unit stopped before the update changed anything (its timeout during
// a download GitHub throttles, systemctl stop): the update that died of
// the signal, with no outcome and no mark, left the relay as it was. Its
// release is not held, or rayd relay would never ask for it again: failed,
// interrupted, untouched, tried again later (spec §7). The runner takes
// the signal from its start: told to stop while it waits for the lock, or
// before the update began, it begins none. Died after a change (the relay
// on another version, or it said it failed after one), the release is
// held as before.
func TestRelayRequestCutShort(t *testing.T) {
	for name, c := range map[string]struct {
		script    string
		set       func(*fakeRunner)
		untouched bool
		ran       bool
	}{
		"killed downloading":                    {script: `echo 'downloading SHA256SUMS'; kill -TERM $$`, untouched: true, ran: true},
		"killed, moved on":                      {script: `kill -TERM $$`, set: func(f *fakeRunner) { f.relayVer = "v0.27.1" }, ran: true},
		"killed, said it failed after a change": {script: `echo 'update failed: the relay install: boom'; kill -9 $$`, ran: true},
		"stopped before the update began": {script: `exit 9`, set: func(f *fakeRunner) {
			f.q.ready = func() error { f.signalled = true; return nil }
		}, untouched: true},
		"stopped waiting for the lock": {script: `exit 9`, set: func(f *fakeRunner) {
			f.locked = errors.New("another update is running")
			f.onLock = func() { f.signalled = true }
		}, untouched: true},
	} {
		f := newFakeRunner(t)
		f.rayctl(c.script)
		if c.set != nil {
			c.set(f)
		}
		f.request("v0.27.1")
		st, err := f.run()
		_, ran := os.Stat(f.at("args"))
		if err == nil || st.State != nodeupdate.Failed || st.Reason != nodeupdate.ReasonInterrupted || st.Untouched != c.untouched ||
			slices.Contains(st.Held, "v0.27.1") == c.untouched || f.rolled != 0 || (ran == nil) != c.ran || st.Error == "" {
			t.Errorf("%s: %v %+v, rolled back %d, ran %v", name, err, st, f.rolled, ran == nil)
		}
		if !c.ran && !strings.Contains(st.Error, "nothing changed") {
			t.Errorf("%s: %q", name, st.Error)
		}
	}

	// The real signals: SIGTERM to the runner while it waits for the lock
	// (were it not caught there, this test's process would die), then to
	// the update and the runner at once, as the unit's stop sends it.
	f := newFakeRunner(t)
	f.q.relay.signals = catchSignals
	f.rayctl(`exit 9`)
	f.locked = errors.New("another update is running")
	f.onLock = func() {
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		time.Sleep(200 * time.Millisecond)
	}
	f.request("v0.27.1")
	if st, err := f.run(); err == nil || st.State != nodeupdate.Failed || st.Reason != nodeupdate.ReasonInterrupted || !st.Untouched || len(st.Held) != 0 {
		t.Errorf("SIGTERM waiting for the lock: %v %+v", err, st)
	}
	f = newFakeRunner(t)
	f.q.relay.signals = catchSignals
	f.rayctl(`echo 'downloading SHA256SUMS'; kill -TERM $PPID $$`)
	f.request("v0.27.1")
	if st, err := f.run(); err == nil || st.State != nodeupdate.Failed || st.Reason != nodeupdate.ReasonInterrupted || !st.Untouched || len(st.Held) != 0 {
		t.Errorf("SIGTERM to the unit while it downloads: %v %+v", err, st)
	}
}

// rayctl update -request-ended, the unit's ExecStopPost: a runner killed
// past the unit's TimeoutStopSec leaves the status running. Failed,
// interrupted; with the exit's mark, rolled back as the runner would have
// (not as the system shuts down); nothing when the runner wrote how it
// ended.
func TestRelayRequestEnded(t *testing.T) {
	t.Setenv("SERVICE_RESULT", "timeout")
	running := func(f *fakeRunner) {
		nodeupdate.WriteStatus(f.q.status, nodeupdate.Status{ID: "0a", State: nodeupdate.Running, From: "v0.27.0", To: "v0.27.1", Target: "v0.27.1",
			Release: "v0.27.1", By: "exit", Kind: nodeupdate.Exit, Started: time.Now()})
	}
	f := newFakeRunner(t)
	running(f)
	f.mark(relayMark{State: "updating", From: "v0.27.0", To: "v0.27.1", By: markByExit})
	_, err := captureStdout(t, f.q.ended)
	st := nodeupdate.ReadStatus(f.q.status)
	if err != nil || st.State != nodeupdate.RolledBack || st.Reason != nodeupdate.ReasonInterrupted || st.ID != "0a" || f.rolled != 1 || st.Unfinished ||
		!strings.Contains(st.Error, "interrupted (timeout)") || !slices.Contains(st.Held, "v0.27.1") || st.Ended.IsZero() {
		t.Errorf("with the exit's mark: %v %+v, rolled back %d", err, st, f.rolled)
	}
	// Ended already: nothing again.
	if _, err := captureStdout(t, f.q.ended); err != nil || f.rolled != 1 {
		t.Errorf("again: %v, rolled back %d", err, f.rolled)
	}
	// No mark of the exit's (it goes in before the first change) and the
	// relay where it was: nothing changed, untouched, its release not held
	// but tried again later. On another version, or the exit's mark left
	// as the system shuts down, held.
	for name, c := range map[string]struct {
		set       func(*fakeRunner)
		untouched bool
	}{
		"no mark":           {func(*fakeRunner) {}, true},
		"by hand":           {func(f *fakeRunner) { f.mark(relayMark{State: "updating", From: "v0.27.0", To: "v0.27.1"}) }, true},
		"no mark, moved on": {func(f *fakeRunner) { f.relayVer = "v0.27.1" }, false},
		"no mark, not told": {func(f *fakeRunner) { f.relayVer = "" }, false},
		"stopping":          {func(f *fakeRunner) { f.stopping = true; f.mark(relayMark{State: "updating", By: markByExit}) }, false},
		"not mine":          {},
		"no running":        {},
	} {
		f := newFakeRunner(t)
		if c.set == nil {
			nodeupdate.WriteStatus(f.q.status, nodeupdate.Status{ID: "0a", State: nodeupdate.Done, Kind: nodeupdate.Exit})
			f.mark(relayMark{State: "updating", By: markByExit})
			captureStdout(t, f.q.ended)
			if st := nodeupdate.ReadStatus(f.q.status); st.State != nodeupdate.Done || f.rolled != 0 {
				t.Errorf("%s: %+v, rolled back %d", name, st, f.rolled)
			}
			continue
		}
		running(f)
		c.set(f)
		captureStdout(t, f.q.ended)
		_, marked := f.ops.readMark()
		if st := nodeupdate.ReadStatus(f.q.status); st.State != nodeupdate.Failed || st.Reason != nodeupdate.ReasonInterrupted || f.rolled != 0 ||
			st.Unfinished != marked || st.Untouched != c.untouched || slices.Contains(st.Held, "v0.27.1") == c.untouched ||
			c.untouched && st.To != "v0.27.0" {
			t.Errorf("%s: %+v, rolled back %d", name, st, f.rolled)
		}
	}
	// The runner alone was killed: the outcome the update wrote (rolled
	// back by the release's rayctl, done), not interrupted, no rollback
	// again.
	for name, c := range map[string]struct {
		result string
		want   nodeupdate.Status
		held   bool
	}{
		"rolled back": {`{"state":"rolled_back","version":"v0.27.0","release":"v0.27.1","error":"rayspa is inactive/dead","reason":"check"}`,
			nodeupdate.Status{State: nodeupdate.RolledBack, To: "v0.27.0", Reason: nodeupdate.ReasonCheck, Error: "rayspa is inactive/dead"}, true},
		"done": {`{"state":"done","version":"v0.27.1","release":"v0.27.1"}`,
			nodeupdate.Status{State: nodeupdate.Done, To: "v0.27.1"}, false},
		"stopped first": {`{"state":"failed","version":"v0.27.0","error":"stopped before any change","untouched":true,"reason":"interrupted"}`,
			nodeupdate.Status{State: nodeupdate.Failed, To: "v0.27.0", Reason: nodeupdate.ReasonInterrupted, Error: "stopped before any change", Untouched: true}, false},
	} {
		f := newFakeRunner(t)
		running(f)
		if err := os.WriteFile(f.q.result, []byte(c.result), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := captureStdout(t, f.q.ended)
		st := nodeupdate.ReadStatus(f.q.status)
		got := nodeupdate.Status{State: st.State, To: st.To, Reason: st.Reason, Error: st.Error, Untouched: st.Untouched}
		if err != nil || got.State != c.want.State || got.To != c.want.To || got.Reason != c.want.Reason || got.Error != c.want.Error ||
			got.Untouched != c.want.Untouched || slices.Contains(st.Held, "v0.27.1") != c.held || f.rolled != 0 || st.Ended.IsZero() || st.ID != "0a" {
			t.Errorf("a result, %s: %v %+v, rolled back %d", name, err, st, f.rolled)
		}
		if _, err := os.Stat(f.q.result); !os.IsNotExist(err) {
			t.Errorf("a result, %s: the result stays", name)
		}
	}
	// A node's: as ever, no rollback of its own.
	node := filepath.Join(t.TempDir(), "status.json")
	nodeupdate.WriteStatus(node, nodeupdate.Status{ID: "0a", State: nodeupdate.Running, Release: "v0.27.1"})
	q := nodeRequests()
	q.status = node
	if err := q.ended(); err != nil || nodeupdate.ReadStatus(node).State != nodeupdate.Failed {
		t.Errorf("a node's: %v %+v", err, nodeupdate.ReadStatus(node))
	}
}

// rayctl update -request-recover, once a boot while the mark is there: an
// update by the exit's word that a shutdown or a power cut ended halfway
// is rolled back and its status says so; a mark by hand, or none, is left
// alone.
func TestRelayRequestRecover(t *testing.T) {
	f := newFakeRunner(t)
	if _, err := captureStdout(t, f.q.recover); err != nil || f.rolled != 0 {
		t.Errorf("no mark: %v, rolled back %d", err, f.rolled)
	}
	f.mark(relayMark{State: "updating", From: "v0.27.0", To: "v0.27.1"})
	if _, err := captureStdout(t, f.q.recover); err != nil || f.rolled != 0 {
		t.Errorf("by hand: %v, rolled back %d", err, f.rolled)
	}
	if _, marked := f.ops.readMark(); !marked {
		t.Error("the mark by hand went")
	}

	// The last status, running at the power cut: rolled back, interrupted.
	f = newFakeRunner(t)
	nodeupdate.WriteStatus(f.q.status, nodeupdate.Status{ID: "0a", State: nodeupdate.Running, From: "v0.27.0", To: "v0.27.1", Target: "v0.27.1",
		Release: "v0.27.1", By: "exit", Kind: nodeupdate.Exit, Held: []string{"v0.26.9"}})
	f.mark(relayMark{State: "open", From: "v0.27.0", To: "v0.27.1", By: markByExit})
	if _, err := captureStdout(t, f.q.recover); err != nil {
		t.Fatal(err)
	}
	st := nodeupdate.ReadStatus(f.q.status)
	if st.ID != "0a" || st.State != nodeupdate.RolledBack || st.Reason != nodeupdate.ReasonInterrupted || st.Unfinished || f.rolled != 1 ||
		!slices.Equal(st.Held, []string{"v0.26.9", "v0.27.1"}) || st.To != "v0.27.0" {
		t.Errorf("recovered: %+v, rolled back %d", st, f.rolled)
	}
	// The rollback leaves it open: said, and the unit fails.
	f = newFakeRunner(t)
	nodeupdate.WriteStatus(f.q.status, nodeupdate.Status{ID: "0b", State: nodeupdate.Done, Kind: nodeupdate.Exit, Release: "v0.26.9"})
	f.mark(relayMark{State: "open", From: "v0.27.0", To: "v0.27.1", By: markByExit})
	f.back = func() error { return errors.New("the previous relay did not come back either") }
	if _, err := captureStdout(t, f.q.recover); err == nil {
		t.Error("a recovery that failed did not say so")
	}
	st = nodeupdate.ReadStatus(f.q.status)
	if st.ID == "0b" || st.State != nodeupdate.Failed || st.Reason != nodeupdate.ReasonOpen || !st.Unfinished || st.Kind != nodeupdate.Exit ||
		st.Target != "v0.27.1" {
		t.Errorf("not recovered, another update's status last: %+v", st)
	}
	// The update lock held (root updating by hand): refused, nothing done.
	f = newFakeRunner(t)
	f.mark(relayMark{State: "updating", From: "v0.27.0", To: "v0.27.1", By: markByExit})
	f.locked = errors.New("another update is running")
	if _, err := captureStdout(t, f.q.recover); err == nil || f.rolled != 0 {
		t.Errorf("locked: %v, rolled back %d", err, f.rolled)
	}
	// On a node: nothing.
	if _, err := captureStdout(t, nodeRequests().recover); err != nil {
		t.Error(err)
	}
}

// A power cut before the update's first change leaves root's status
// running and no mark (it goes in before the first change): at the boot
// the recover unit settles it, failed, interrupted, and with the relay on
// the version it came from untouched, its release not held but tried
// again later (spec §4.3); on another version, held. An outcome the update
// wrote before the cut is taken. And a runner that finds such a status
// left (the recover unit did not run) does not hold its release either.
func TestRelayRequestPowerCutFirst(t *testing.T) {
	running := func(f *fakeRunner) {
		nodeupdate.WriteStatus(f.q.status, nodeupdate.Status{ID: "0a", State: nodeupdate.Running, From: "v0.27.0", To: "v0.27.1", Target: "v0.27.1",
			Release: "v0.27.1", By: "exit", Kind: nodeupdate.Exit, Held: []string{"v0.26.9"}, Started: time.Now().Add(-time.Hour)})
	}
	for name, c := range map[string]struct {
		set       func(*fakeRunner)
		state     string
		untouched bool
		held      bool
	}{
		"on its version": {func(*fakeRunner) {}, nodeupdate.Failed, true, false},
		"moved on":       {func(f *fakeRunner) { f.relayVer = "v0.27.1" }, nodeupdate.Failed, false, true},
		"its outcome written": {func(f *fakeRunner) {
			os.WriteFile(f.q.result, []byte(`{"state":"done","version":"v0.27.1","release":"v0.27.1"}`), 0o600)
		}, nodeupdate.Done, false, false},
	} {
		f := newFakeRunner(t)
		running(f)
		c.set(f)
		if _, err := captureStdout(t, f.q.recover); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		st := nodeupdate.ReadStatus(f.q.status)
		if st.ID != "0a" || st.State != c.state || c.state == nodeupdate.Failed && st.Reason != nodeupdate.ReasonInterrupted || st.Untouched != c.untouched ||
			slices.Contains(st.Held, "v0.27.1") != c.held || !slices.Contains(st.Held, "v0.26.9") || f.rolled != 0 || st.Ended.IsZero() || st.Unfinished {
			t.Errorf("%s: %+v, rolled back %d", name, st, f.rolled)
		}
		if _, err := os.Stat(f.q.result); !os.IsNotExist(err) {
			t.Errorf("%s: the result stays", name)
		}
	}
	// Nothing to settle: a status that ended, of another kind, none.
	for name, st := range map[string]nodeupdate.Status{
		"ended":           {ID: "0a", State: nodeupdate.Done, Kind: nodeupdate.Exit, Release: "v0.27.1"},
		"another kind":    {ID: "0a", State: nodeupdate.Running, Kind: nodeupdate.Local, Release: "v0.27.1"},
		"no status, none": {},
	} {
		f := newFakeRunner(t)
		f.locked = errors.New("the lock is not for this")
		if st.State != "" {
			nodeupdate.WriteStatus(f.q.status, st)
		}
		if _, err := captureStdout(t, f.q.recover); err != nil || nodeupdate.ReadStatus(f.q.status).State != cmp.Or(st.State, nodeupdate.Idle) {
			t.Errorf("%s: %v %+v", name, err, nodeupdate.ReadStatus(f.q.status))
		}
	}
	// The update lock held (root updating by hand): refused, nothing done.
	f := newFakeRunner(t)
	running(f)
	f.locked = errors.New("another update is running")
	if _, err := captureStdout(t, f.q.recover); err == nil || nodeupdate.ReadStatus(f.q.status).State != nodeupdate.Running {
		t.Errorf("locked: %v %+v", err, nodeupdate.ReadStatus(f.q.status))
	}

	// The recover unit did not run (remote turned off and on since): the
	// next request for the release runs.
	f = newFakeRunner(t)
	running(f)
	f.rayctl(`echo '{"state":"done","version":"v0.27.1","release":"v0.27.1"}' > "$RAYCONTROL_UPDATE_RESULT"`)
	f.request("v0.27.1")
	if st, err := f.run(); err != nil || st.State != nodeupdate.Done || !slices.Equal(st.Held, []string{"v0.26.9"}) {
		t.Errorf("asked again: %v %+v", err, st)
	}
	// Moved on, or the exit's mark there: held as before.
	for name, set := range map[string]func(*fakeRunner){
		"moved on": func(f *fakeRunner) { f.relayVer = "v0.27.1" },
		"the exit's mark": func(f *fakeRunner) {
			f.mark(relayMark{State: "updating", From: "v0.27.0", To: "v0.27.1", By: markByExit})
		},
	} {
		f := newFakeRunner(t)
		running(f)
		set(f)
		f.rayctl(`exit 9`)
		f.request("v0.27.1")
		if st, _ := f.run(); st.State != nodeupdate.Failed || st.Reason != nodeupdate.ReasonVersion || !slices.Contains(st.Held, "v0.27.1") {
			t.Errorf("%s: %+v", name, st)
		}
	}
}

// A relay's runner waits for the lock a fifth of its unit's time at most:
// the download, the install and a rollback need the rest (spec §4.2).
func TestRelayLockWait(t *testing.T) {
	var limit time.Duration
	for _, f := range deploy.RelayPlan(deploy.DefaultBinaries).Files {
		if strings.HasSuffix(f.Path, "/"+deploy.RelayUpdateService) {
			for _, l := range strings.Split(string(f.Content), "\n") {
				if v, ok := strings.CutPrefix(l, "TimeoutStartSec="); ok {
					limit, _ = time.ParseDuration(strings.TrimSuffix(v, "in"))
				}
			}
		}
	}
	if limit == 0 || relayLockWait*5 > limit {
		t.Errorf("the lock waited for %v of the unit's %v", relayLockWait, limit)
	}
}

// The runner of each host: a relay's takes the exit's requests from rayd
// relay's directory only, a node's the node's; a node's request that does
// not get the lock stays for the path unit to run again, untouched.
func TestHostRunners(t *testing.T) {
	r, n := relayRequests(), nodeRequests()
	if r.request != nodeupdate.RelayRequestFile || !slices.Equal(r.kinds, nodeupdate.RelayKinds) || r.relay == nil || r.target == nil ||
		r.status != nodeupdate.StatusFile || r.policy != nodeupdate.PolicyFile {
		t.Errorf("a relay's: %+v", r)
	}
	if n.request != nodeupdate.RequestFile || !slices.Equal(n.kinds, nodeupdate.NodeKinds) || n.relay != nil || n.target != nil {
		t.Errorf("a node's: %+v", n)
	}
	dir := t.TempDir()
	n.request, n.status = filepath.Join(dir, "update-request"), filepath.Join(dir, "status.json")
	n.lock = func(func() bool) error { return errors.New("another update is running") }
	nodeupdate.WriteRequest(n.request, nodeupdate.Request{ID: "0a", Kind: nodeupdate.Remote, Version: "latest", By: "alice", At: time.Now()}, time.Now())
	if err := n.take(); err == nil {
		t.Fatal("taken without the lock")
	}
	if _, err := os.Stat(n.request); err != nil || nodeupdate.ReadStatus(n.status).State != nodeupdate.Idle {
		t.Errorf("a node's request without the lock: %v %+v", err, nodeupdate.ReadStatus(n.status))
	}
}
