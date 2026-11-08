package main

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/deploy"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/nodeupdate"
)

// requests is where rayctl update -request finds what it runs; the node's
// is nodeRequests.
type requests struct {
	request, status, policy, result string
	rayctl                          string       // the installed rayctl: it does the update
	ready                           func() error // whether the node can be updated
	nodeVersion                     func() string
}

func nodeRequests() requests {
	return requests{request: nodeupdate.RequestFile, status: nodeupdate.StatusFile, policy: nodeupdate.PolicyFile, result: nodeupdate.ResultFile,
		rayctl: "/usr/local/bin/rayctl", ready: func() error { return updatable(deploy.DB, deploy.RelayBundle) }, nodeVersion: raydVersion}
}

// run is an update the node asked for (spec/node-update-v1.md §3): the
// root unit raycontrol-update.service starts it when rayd has written a
// request. rayd being the unprivileged side, the request is checked again
// here: well formed and fresh, never back, auto only a patch, and its kind
// allowed by root's own policy file, which rayd cannot write. Its status
// is written before the request goes, so that rayd never sees neither.
// The update itself is rayctl update's, by the rayctl installed (which
// hands it to the release's own); the outcome it writes
// (nodeupdate.ResultEnv) goes to the status file rayd reads.
func (q requests) run() error {
	now := time.Now()
	r, ok, err := nodeupdate.ReadRequest(q.request)
	if !ok {
		fmt.Println("no update request")
		return nil
	}
	// The releases the auto update leaves alone go on from status to status.
	st := nodeupdate.Status{ID: r.ID, From: version, To: r.Version, Target: r.Version, Release: r.Tried(), By: r.By, Kind: r.Kind,
		Requested: r.At, Started: now.UTC(), Held: nodeupdate.ReadStatus(q.status).Holding()}
	if err == nil {
		err = r.Check(version, now)
	}
	if err == nil {
		err = nodeupdate.ReadPolicy(q.policy).Allows(r, now)
	}
	if err == nil {
		err = q.ready()
	}
	if err != nil {
		st.State, st.Error, st.Ended, st.Untouched = nodeupdate.Failed, err.Error(), now.UTC(), true
	} else {
		st.State = nodeupdate.Running
	}
	werr := nodeupdate.WriteStatus(q.status, st)
	if rerr := nodeupdate.RemoveRequest(q.request); werr == nil {
		werr = rerr
	}
	if err != nil {
		return errors.Join(err, werr)
	}
	if werr != nil {
		return werr
	}
	fmt.Printf("update to %s asked for by %s (%s)\n", r.Version, r.By, r.Kind)

	_ = os.Remove(q.result)
	tail := &tailWriter{max: 40}
	cmd := exec.Command(q.rayctl, "update", "-yes", "-version", r.Version) //nolint:gosec // G204: the installed rayctl
	cmd.Stdout, cmd.Stderr = io.MultiWriter(os.Stdout, tail), io.MultiWriter(os.Stderr, tail)
	cmd.Env = append(os.Environ(), nodeupdate.ResultEnv+"="+q.result)
	runErr := cmd.Run()
	st.Ended = time.Now().UTC()
	if res, ok := nodeupdate.ReadResult(q.result); ok {
		st.State, st.Error, st.Untouched = res.State, res.Error, res.Untouched
		st.To, st.Release = cmp.Or(res.Version, q.nodeVersion()), cmp.Or(res.Release, st.Release)
	} else {
		// No word from the update (a rayctl that died): its exit and its
		// last lines.
		switch {
		case runErr == nil:
			st.State = nodeupdate.Done
		case tail.has("the previous version runs again"):
			st.State, st.Error = nodeupdate.RolledBack, tail.reason(runErr)
		default:
			st.State, st.Error = nodeupdate.Failed, tail.reason(runErr)
		}
		st.To = q.nodeVersion()
		// The release verified, if it said: rayd's hint for latest may be
		// hours old.
		st.Release = cmp.Or(tail.verified(), st.Release)
	}
	if st.State == nodeupdate.RolledBack || (st.State == nodeupdate.Failed && !st.Untouched) {
		st.Held = nodeupdate.Hold(st.Held, st.Release)
	}
	_ = os.Remove(q.result)
	if err := nodeupdate.WriteStatus(q.status, st); err != nil {
		return errors.Join(runErr, err)
	}
	return runErr
}

// raydVersion is the version of the rayd installed, "" when it does not
// say.
func raydVersion() string {
	out, err := exec.Command(deploy.DefaultBinaries.Rayd, "version").Output() //nolint:gosec // G204: a fixed path
	v := strings.TrimSpace(string(out))
	if err != nil || len(v) > 40 || nodeupdate.Printable(v) != v {
		return ""
	}
	return v
}

// markInterrupted is the update unit's ExecStopPost: an update whose
// runner did not get to write how it ended (killed by the unit's timeout,
// a shutdown) failed.
func markInterrupted(statusFile string) error {
	st := nodeupdate.ReadStatus(statusFile)
	if st.State != nodeupdate.Running {
		return nil
	}
	st.State, st.Ended = nodeupdate.Failed, time.Now().UTC()
	st.Error = "interrupted (" + cmp.Or(os.Getenv("SERVICE_RESULT"), "killed") + "): journalctl -u " + nodeupdate.ServiceUnit
	st.Held = nodeupdate.Hold(st.Held, st.Release)
	return nodeupdate.WriteStatus(statusFile, st)
}

// tailWriter keeps the last lines written, and the release an update said
// it verified.
type tailWriter struct {
	mu      sync.Mutex
	max     int
	lines   []string
	part    []byte
	release string
}

// verifiedLine is what rayctl update prints once it verified a release
// it hands over (handoff).
var verifiedLine = regexp.MustCompile(`^release (v\d+\.\d+\.\d+) verified`)

func (t *tailWriter) verified() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.release
}

func (t *tailWriter) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.part = append(t.part, p...)
	for {
		i := bytes.IndexByte(t.part, '\n')
		if i < 0 {
			break
		}
		line := string(t.part[:i])
		if m := verifiedLine.FindStringSubmatch(line); m != nil && t.release == "" {
			t.release = m[1]
		}
		t.lines = append(t.lines, line)
		t.part = t.part[i+1:]
		if len(t.lines) > t.max {
			t.lines = t.lines[len(t.lines)-t.max:]
		}
	}
	return len(p), nil
}

func (t *tailWriter) has(s string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, l := range t.lines {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// reason is what an admin reads of a failed update: the cause the update
// printed ("update failed: …"), else its last line.
func (t *tailWriter) reason(err error) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := len(t.lines) - 1; i >= 0; i-- {
		if r, ok := strings.CutPrefix(strings.TrimSpace(t.lines[i]), "update failed:"); ok {
			return strings.TrimSpace(r)
		}
	}
	for i := len(t.lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(strings.TrimPrefix(t.lines[i], "rayctl:")); l != "" {
			return l
		}
	}
	return err.Error()
}

// updatePolicy is rayctl update remote|auto|status. The policy is a file
// of root's (nodeupdate.PolicyFile) that rayd reads and cannot change.
func (c *cli) updatePolicy(ctx context.Context, args []string) error {
	return c.updatePolicyAt(ctx, args, nodeupdate.PolicyFile, "/etc/systemd/system/"+nodeupdate.PathUnit, needRoot)
}

func (c *cli) updatePolicyAt(ctx context.Context, args []string, policyFile, unit string, root func() error) error {
	if args[0] == "status" {
		if len(args) != 1 {
			return errUsage
		}
		return c.updateStatus(ctx)
	}
	p := nodeupdate.ReadPolicy(policyFile)
	switch args[0] {
	case "remote":
		if len(args) != 2 || (args[1] != "on" && args[1] != "off") {
			return errUsage
		}
		p.Remote = args[1]
	case "auto":
		fs := flag.NewFlagSet("update auto", flag.ContinueOnError)
		window := fs.String("window", "", "HH:MM-HH:MM in the node's time, 30 min at least (default "+nodeupdate.DefaultWindow+")")
		if len(args) < 2 || (args[1] != "off" && args[1] != "patch") || fs.Parse(args[2:]) != nil || fs.NArg() != 0 {
			return errUsage
		}
		p.Auto = args[1]
		if *window != "" {
			p.Window = *window
		}
	default:
		return errUsage
	}
	if err := root(); err != nil {
		return err
	}
	if err := nodeupdate.WritePolicy(policyFile, p); err != nil {
		return err
	}
	switch {
	case args[0] == "remote" && p.Remote == "on":
		fmt.Println("admin devices may now update this node to a signed release newer than it (rayctl update remote off)")
	case args[0] == "auto" && p.Auto == "patch":
		fmt.Printf("rayd checks GitHub for releases every ~6 h and updates to a newer patch release of this minor version in the window %s, node time (rayctl update status)\n", p.Window)
	}
	if _, err := os.Stat(unit); err != nil && (p.Remote == "on" || p.Auto == "patch") {
		fmt.Println("the update unit is not installed yet: rayctl apply")
	}
	return nil
}

func (c *cli) updateStatus(ctx context.Context) error {
	r, err := c.c.GetUpdateStatus(ctx, connect.NewRequest(&nodev1.GetUpdateStatusRequest{}))
	if err != nil {
		return err
	}
	m := r.Msg
	if c.json {
		return c.print(m, nil)
	}
	// What rayd says, shown as text: no control characters reach the
	// terminal.
	p := nodeupdate.Printable
	fmt.Printf("installed  %s\n", p(m.Installed))
	if m.Latest != "" {
		fmt.Printf("latest     %s\n", p(m.Latest))
	}
	fmt.Printf("remote     %s\nauto       %s (window %s, %s)\n", p(m.Remote), p(m.Auto), p(m.Window), p(m.Timezone))
	if len(m.Held) > 0 {
		fmt.Printf("held       %s (did not hold: the auto update leaves them; rayctl update -version V by hand)\n", p(strings.Join(m.Held, ", ")))
	}
	s := m.Status
	if s == nil || s.State == nodeupdate.Idle {
		fmt.Println("last       none")
		return nil
	}
	line := fmt.Sprintf("last       %s: %s → %s, by %s", p(s.State), p(s.From), p(cmp.Or(s.To, "?")), p(s.By))
	if s.EndedAt != 0 {
		line += ", " + time.Unix(s.EndedAt, 0).UTC().Format(time.RFC3339)
	} else if s.RequestedAt != 0 {
		line += ", asked " + time.Unix(s.RequestedAt, 0).UTC().Format(time.RFC3339)
	}
	fmt.Println(line)
	if s.Error != "" {
		fmt.Printf("error      %s\n", p(s.Error))
	}
	return nil
}
