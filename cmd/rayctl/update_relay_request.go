package main

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/release"
)

// Root on a relay (spec/relay-update-remote-v1.md §4.2-§4.3): rayd relay,
// unprivileged, writes a request for the release the exit names in its
// own state directory; the relay's path unit starts rayctl update
// -request, which checks it again as a node's runner does (requests.run)
// and updates the relay as by hand. What a relay adds: only the exit's
// kind of request, never below the release that brought the relay's
// update (relayTarget); a busy lock refuses rather than waits again; and
// an update that ended with no outcome is rolled back by root itself, by
// the runner, by the unit's ExecStopPost or by the recover unit at boot,
// since no one is there in an SSH session to do it. Only an update the
// mark says is the exit's (relayMark.By): one by hand a person ran, and
// was told what to do.

// relayRunner is what a relay's runner does beside a node's, with the
// host's operations given so that a test can follow it.
type relayRunner struct {
	mark     func() (relayMark, bool) // the mark of an update of the relay that did not end
	stopping func() bool              // the system shuts down: no unit starts now
	free     func()                   // waits for the relay install's lock to be free
	rollback func() (string, error)   // rayctl update -rollback -yes; why it failed
	signals  func() (caught func() bool, stop func())
	lock     func() error // the update lock for the recover unit
}

// relayLockWait is how long a relay's runner waits for a manual update or
// rollback to let the update lock go: of its unit's 15 minutes
// (TimeoutStartSec), the download needs most of the rest, and the install
// with a rollback after it up to about 4.
const relayLockWait = 3 * time.Minute

// relayFailedLine is what a relay's update prints once it failed after a
// change (relayUpdate.run), before it rolls the relay back.
const relayFailedLine = "update failed:"

// hostRequests is where this host's requests are: a relay's or the node's.
func hostRequests() requests {
	if host, _ := updateHost(deploy.DB, deploy.RelayBundle, relayUnitFile); host == relayHost {
		return relayRequests()
	}
	return nodeRequests()
}

// relayRequests is the runner on a relay: the request in rayd relay's
// directory, the status and policy where a node has them.
func relayRequests() requests {
	q := requests{request: nodeupdate.RelayRequestFile, status: nodeupdate.StatusFile, policy: nodeupdate.PolicyFile, result: nodeupdate.ResultFile,
		rayctl: "/usr/local/bin/rayctl", ready: func() error { return nil }, nodeVersion: raydVersion,
		kinds: nodeupdate.RelayKinds, target: relayTarget,
		lock: func(stop func() bool) error {
			return takeUpdateLockUnless("update by the exit's word", relayLockWait, stop)
		}}
	ops := relayOps{dir: previousDir}
	q.relay = &relayRunner{
		mark:     ops.readMark,
		stopping: systemStopping,
		// The install a killed update ran goes on; up to its own bound.
		free:     func() { waitLockFree(relayInstallLock, 5*time.Minute, time.Second) },
		rollback: func() (string, error) { return runRollback(q.rayctl) },
		signals:  catchSignals,
		lock:     func() error { return takeUpdateLock("recovery of an update by the exit's word", 2*time.Minute) },
	}
	return q
}

// relayStatusGroup is the group that reads a relay's status beside root:
// rayd relay's (Group=rayd, deploy.RelayPlan). A test's own.
var relayStatusGroup = "rayd"

// writeRelayStatus writes a relay's status, 0640 of relayStatusGroup:
// rayd relay reads it, nobody else on the relay does (its error is root's
// whole text, the relay's admin addresses and its exit's among it); root's
// alone (0600) when there is no such group, and then no rayd relay either.
func writeRelayStatus(path string, st nodeupdate.Status) error {
	gid := -1
	if g, err := user.LookupGroup(relayStatusGroup); err == nil {
		if n, err := strconv.Atoi(g.Gid); err == nil {
			gid = n
		}
	}
	return nodeupdate.WriteStatusFor(path, st, gid)
}

// writeStatus writes q's status: a relay's as writeRelayStatus, a node's
// for everyone (its rayd reads it).
func (q requests) writeStatus(st nodeupdate.Status) error {
	if q.relay != nil {
		return writeRelayStatus(q.status, st)
	}
	return nodeupdate.WriteStatus(q.status, st)
}

// unfinished says whether an update of the relay did not end: its mark is
// in root's directory, which rayd relay cannot read, and root on the relay
// must act. Never on a node.
func (q requests) unfinished() bool {
	if q.relay == nil {
		return false
	}
	_, marked := q.relay.mark()
	return marked
}

// outcome is what the update wrote of how it ended. On a relay, with none
// and the update's mark left, the release's rayctl it went to may go on
// (the rayctl that handed it over was killed), holding the relay install's
// lock: its end first.
func (q requests) outcome() (nodeupdate.Result, bool) {
	res, ok := nodeupdate.ReadResult(q.result)
	if ok || q.relay == nil {
		return res, ok
	}
	if m, marked := q.relay.mark(); marked && m.By == markByExit {
		q.relay.free()
		return nodeupdate.ReadResult(q.result)
	}
	return res, false
}

// cutShort is a relay's update that ended with no outcome (killed: kill
// -9, out of memory, the unit's timeout or stop before it took the
// signal), st as the runner read its exit and last lines; failedAfter:
// they said it failed after a change. Interrupted; and if it left its
// mark, the exit's, the relay is rolled back here, once, unless the
// system shuts down (no unit would start: the recover unit does it after
// the boot). With no such mark (it goes in before the first change) and
// the relay still on the version it came from, it changed nothing:
// untouched, and its release is not held but tried again later
// (spec/relay-update-remote-v1.md §7), as after a download that failed.
func (r *relayRunner) cutShort(st *nodeupdate.Status, version func() string, failedAfter bool) {
	st.Reason = nodeupdate.ReasonInterrupted
	if !r.exitMarked() {
		st.Untouched = st.State == nodeupdate.Failed && !failedAfter && untouchedSince(st.From, version())
		return
	}
	if r.stopping() {
		st.Error = "the update ended with no outcome (" + st.Error + ") as the system shuts down: the recover unit rolls the relay back after the boot"
		return
	}
	r.free()
	r.rolledBack(st, "the update ended with no outcome ("+st.Error+")", "by its runner")
	st.To = version()
}

// exitMarked reports whether the mark of an update by the exit's word is
// left: one that changed the relay and did not end.
func (r *relayRunner) exitMarked() bool {
	m, marked := r.mark()
	return marked && m.By == markByExit
}

// untouchedSince reports whether a relay whose update left no mark of the
// exit's, from version from, is still on it as its rayd says (now): a
// release, the same. Anything else (another version, none told) may be
// what the update left.
func untouchedSince(from, now string) bool { return release.IsRelease(from) && now == from }

// held is what q's last status holds, carried over into the next
// (Status.Holding). On a relay, a run by the exit's word that never ended
// (a power cut, the recover unit not run since), with no mark of the
// exit's left and the relay on the version it came from, changed nothing
// (the mark goes in before the first change): its release is not held,
// or the relay would never take it again (spec/relay-update-remote-v1.md
// §4.3).
func (q requests) held() []string {
	st := nodeupdate.ReadStatus(q.status)
	if q.relay != nil && st.Kind == nodeupdate.Exit && st.State == nodeupdate.Running && !q.relay.exitMarked() && untouchedSince(st.From, q.nodeVersion()) {
		st.Untouched = true
	}
	return st.Holding()
}

// unended settles st, a run root's status still has running though its
// runner is gone (cut says how), from what the run left: the outcome the
// update wrote, if it did; else failed, interrupted, and, with no mark of
// the exit's (it goes in before the first change) and the relay on the
// version it came from, untouched, its release not held but tried again
// later (cutShort). exits reports the exit's mark left: the relay is to be
// rolled back.
func (q requests) unended(st *nodeupdate.Status, cut string) (exits bool) {
	st.Ended = time.Now().UTC()
	if res, ok := nodeupdate.ReadResult(q.result); ok {
		q.settle(st, res)
		st.Held, st.Unfinished = holdIfBroke(*st), q.unfinished()
		_ = os.Remove(q.result)
		return false
	}
	st.State, st.Reason, st.Error = nodeupdate.Failed, nodeupdate.ReasonInterrupted, cut
	exits = q.relay.exitMarked()
	if v := q.nodeVersion(); !exits && untouchedSince(st.From, v) {
		st.Untouched, st.To = true, v
	}
	st.Held, st.Unfinished = holdIfBroke(*st), q.unfinished()
	return exits
}

// rolledBack runs the rollback and says in st how it went: rolled back
// (interrupted), or not, open when the host was left open.
func (r *relayRunner) rolledBack(st *nodeupdate.Status, what, by string) {
	why, err := r.rollback()
	m, marked := r.mark()
	switch {
	case err == nil && !marked:
		st.State, st.Reason = nodeupdate.RolledBack, nodeupdate.ReasonInterrupted
		st.Error = what + ": rolled back " + by
	case marked && m.State == "open":
		st.State, st.Reason = nodeupdate.Failed, nodeupdate.ReasonOpen
		st.Error = what + ", and its rollback " + by + " did not bring the relay back: " + why
	default:
		st.State, st.Reason = nodeupdate.Failed, nodeupdate.ReasonInterrupted
		st.Error = what + ", and its rollback " + by + " failed: " + cmp.Or(why, "the update's mark stays")
	}
}

// ended is rayctl update -request-ended, the update unit's ExecStopPost:
// a runner that did not get to write how the update ended (killed past
// the unit's TimeoutStopSec) leaves it running. On a relay, the outcome
// the update wrote, if it did (the runner alone was killed); else failed,
// interrupted, and rolled back if the update left the exit's mark, as the
// runner would have, unless the system shuts down. With no such mark and
// the relay on the version it came from, nothing changed (cutShort).
func (q requests) ended() error {
	if q.relay == nil {
		return markInterrupted(q.status)
	}
	st := nodeupdate.ReadStatus(q.status)
	if st.State != nodeupdate.Running {
		return nil // the runner wrote how it ended
	}
	cut := "interrupted (" + cmp.Or(os.Getenv("SERVICE_RESULT"), "killed") + ")"
	exits := q.unended(&st, cut+": journalctl -u "+deploy.RelayUpdateService)
	// Failed first: the rollback may itself be cut short.
	if err := q.writeStatus(st); err != nil {
		return err
	}
	if !exits {
		return nil
	}
	if q.relay.stopping() {
		fmt.Println("the system shuts down: the recover unit rolls the relay back after the boot")
		return nil
	}
	q.relay.free()
	q.relay.rolledBack(&st, "the update was "+cut, "by the unit's stop")
	st.Ended, st.To, st.Unfinished = time.Now().UTC(), q.nodeVersion(), q.unfinished()
	return q.writeStatus(st)
}

// recover is rayctl update -request-recover, the relay's recover unit, once
// a boot while the mark or root's status is there: an update by the exit's
// word that a shutdown or a power cut ended halfway is rolled back, its
// status says so; one they ended before its first change, with no mark
// yet, is settled (recoverCut). A mark by hand stays for the person who
// ran it.
func (q requests) recover() error {
	if q.relay == nil {
		fmt.Println("nothing to recover: this host is no relay")
		return nil
	}
	m, marked := q.relay.mark()
	switch {
	case !marked:
		return q.recoverCut()
	case m.By != markByExit:
		fmt.Println("an update or rollback of this relay by hand did not end: it is root's to recover (rayctl update status says how)")
		return nil
	}
	if err := q.relay.lock(); err != nil {
		return err
	}
	now := time.Now().UTC()
	// The status of the update that left the mark, if it is the last one;
	// else one of its own.
	st := nodeupdate.ReadStatus(q.status)
	if st.Kind != nodeupdate.Exit || st.Release != m.To {
		st = nodeupdate.Status{ID: nodeupdate.NewID(), From: m.From, To: m.To, Target: m.To, Release: m.To, By: markByExit, Kind: nodeupdate.Exit,
			Requested: now, Started: now, Held: st.Holding()}
	}
	q.relay.free()
	q.relay.rolledBack(&st, "the update of the relay did not end (a shutdown, a power cut)", "at the boot")
	st.Ended, st.To, st.Untouched, st.Unfinished = now, q.nodeVersion(), false, q.unfinished()
	st.Held = nodeupdate.Hold(st.Held, st.Release)
	if err := q.writeStatus(st); err != nil {
		return err
	}
	if st.State != nodeupdate.RolledBack {
		return errors.New(st.Error)
	}
	return nil
}

// recoverCut is the recover unit with no mark: root's status says a run by
// the exit's word is under way, and none can be at the boot (the update
// unit starts after this one). A shutdown or a power cut ended it before
// its first change, the mark not yet in, or after its last, the mark gone
// and the outcome not yet in the status. Settled as the unit's stop would
// have (unended), with nothing to roll back: on the version it came from,
// failed, interrupted and untouched, its release not held but tried again
// later; else what the update wrote, or failed and held. Left running,
// rayd relay would take it as cut short after a change and decline the
// release as held for good, and root refuse it (spec §4.3).
func (q requests) recoverCut() error {
	running := func(st nodeupdate.Status) bool { return st.Kind == nodeupdate.Exit && st.State == nodeupdate.Running }
	if !running(nodeupdate.ReadStatus(q.status)) {
		fmt.Println("no update of the relay to recover")
		return nil
	}
	if err := q.relay.lock(); err != nil {
		return err
	}
	st := nodeupdate.ReadStatus(q.status)
	if !running(st) {
		fmt.Println("no update of the relay to recover")
		return nil
	}
	q.unended(&st, "the update did not end (a shutdown, a power cut) and left no mark: journalctl -u "+deploy.RelayUpdateService)
	if err := q.writeStatus(st); err != nil {
		return err
	}
	switch {
	case st.State != nodeupdate.Failed:
		fmt.Printf("the update of the relay to %s ended before the boot: %s\n", st.Release, st.State)
	case st.Untouched:
		fmt.Printf("the update of the relay to %s was cut short before its first change: nothing changed, it is tried again later\n", st.Release)
	default:
		fmt.Printf("the update of the relay to %s was cut short, and the relay is not on %s: rayctl update status\n", st.Release, st.From)
	}
	return nil
}

// runRollback is rayctl update -rollback -yes on this relay, by the rayctl
// installed: the one a person would run, which knows the state the update
// left. Why it failed is its last words.
func runRollback(rayctl string) (string, error) {
	tail := &tailWriter{max: 40}
	cmd := exec.Command(rayctl, "update", "-rollback", "-yes") //nolint:gosec // G204: the installed rayctl
	cmd.Stdout, cmd.Stderr = io.MultiWriter(os.Stdout, tail), io.MultiWriter(os.Stderr, tail)
	// Its status is the runner's to write, of the update it rolls back.
	cmd.Env = append(os.Environ(), rollbackByRunnerEnv+"=1")
	if err := cmd.Run(); err != nil {
		return tail.reason(err), err
	}
	return "", nil
}

// systemStopping reports whether the system shuts down: systemd then
// starts no unit, and a rollback would leave the host open.
func systemStopping() bool {
	out, _ := exec.Command("systemctl", "is-system-running").Output()
	return strings.TrimSpace(string(out)) == "stopping"
}

// waitLockFree waits, up to limit, for the install lock at path to be
// free: nothing is rolled back under an install that goes on.
func waitLockFree(path string, limit, every time.Duration) {
	deadline := time.Now().Add(limit)
	for {
		f, err := takeInstallLock(path)
		if err == nil {
			_ = f.Close()
			return
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(every)
	}
}
