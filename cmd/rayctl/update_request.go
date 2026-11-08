package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/nodeupdate"
)

// updateRequest runs an update the node asked for (spec/node-update-v1.md
// §3): the root unit raycontrol-update.service starts it when rayd has
// written a request. The request is checked again here, rayd being the
// unprivileged side: well formed, signed releases only, never back, and
// its kind allowed by the policy now. The update itself is rayctl update's,
// by the rayctl installed (which hands it to the release's own); its
// outcome goes to the status file rayd reads.
func (c *cli) updateRequest(ctx context.Context, requestFile, statusFile, rayctl string) error {
	r, ok, err := nodeupdate.TakeRequest(requestFile)
	if !ok {
		fmt.Println("no update request")
		return nil
	}
	st := nodeupdate.Status{ID: r.ID, From: version, To: r.Version, Target: r.Version, By: r.By, Kind: r.Kind, Requested: r.At, Started: time.Now().UTC()}
	refuse := func(err error) error {
		st.State, st.Error, st.Ended = nodeupdate.Failed, err.Error(), time.Now().UTC()
		if werr := nodeupdate.WriteStatus(statusFile, st); werr != nil {
			return errors.Join(err, werr)
		}
		return err
	}
	if err != nil {
		return refuse(err)
	}
	if err := r.Check(version); err != nil {
		return refuse(err)
	}
	// The policy as rayd has it now: a request written before root turned
	// it off does not run.
	pol, err := c.c.GetUpdateStatus(ctx, connect.NewRequest(&nodev1.GetUpdateStatusRequest{}))
	if err != nil {
		return refuse(fmt.Errorf("rayd: %w", err))
	}
	switch {
	case r.Kind == nodeupdate.Remote && pol.Msg.Remote != "on":
		return refuse(errors.New("remote updates are off on this node"))
	case r.Kind == nodeupdate.Auto && pol.Msg.Auto != "patch":
		return refuse(errors.New("auto updates are off on this node"))
	}
	st.State = nodeupdate.Running
	if err := nodeupdate.WriteStatus(statusFile, st); err != nil {
		return err
	}
	fmt.Printf("update to %s asked for by %s (%s)\n", r.Version, r.By, r.Kind)
	tail := &tailWriter{max: 40}
	cmd := exec.Command(rayctl, "update", "-yes", "-version", r.Version) //nolint:gosec // G204: the installed rayctl
	cmd.Stdout, cmd.Stderr = io.MultiWriter(os.Stdout, tail), io.MultiWriter(os.Stderr, tail)
	cmd.Env = os.Environ()
	runErr := cmd.Run()
	st.Ended = time.Now().UTC()
	if v := c.nodeVersion(ctx); v != "" {
		st.To = v
	}
	switch {
	case runErr == nil:
		st.State = nodeupdate.Done
	case tail.has("the previous version runs again"):
		st.State, st.Error = nodeupdate.RolledBack, tail.reason(runErr)
	default:
		st.State, st.Error = nodeupdate.Failed, tail.reason(runErr)
	}
	if err := nodeupdate.WriteStatus(statusFile, st); err != nil {
		return errors.Join(runErr, err)
	}
	return runErr
}

// nodeVersion is the version rayd reports once it answers again, "" if it
// does not within a minute.
func (c *cli) nodeVersion(ctx context.Context) string {
	for range 60 {
		st, err := c.c.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{}))
		if err == nil {
			return st.Msg.Version
		}
		select {
		case <-ctx.Done():
			return ""
		case <-time.After(time.Second):
		}
	}
	return ""
}

// tailWriter keeps the last lines written.
type tailWriter struct {
	mu    sync.Mutex
	max   int
	lines []string
	part  []byte
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
		t.lines = append(t.lines, string(t.part[:i]))
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

// updatePolicy is rayctl update remote|auto|status.
func (c *cli) updatePolicy(ctx context.Context, args []string) error {
	switch args[0] {
	case "status":
		return c.updateStatus(ctx)
	case "remote":
		if len(args) != 2 || (args[1] != "on" && args[1] != "off") {
			return errUsage
		}
		if _, err := c.c.SetUpdatePolicy(ctx, connect.NewRequest(&nodev1.SetUpdatePolicyRequest{Remote: args[1]})); err != nil {
			return err
		}
		if args[1] == "on" {
			fmt.Println("admin devices may now update this node to a signed release, not an older one (rayctl update remote off)")
		}
		return nil
	case "auto":
		fs := flag.NewFlagSet("update auto", flag.ContinueOnError)
		window := fs.String("window", "", "HH:MM-HH:MM in the node's time (default "+nodeupdate.DefaultWindow+")")
		if len(args) < 2 || (args[1] != "off" && args[1] != "patch") || fs.Parse(args[2:]) != nil || fs.NArg() != 0 {
			return errUsage
		}
		if _, err := c.c.SetUpdatePolicy(ctx, connect.NewRequest(&nodev1.SetUpdatePolicyRequest{Auto: args[1], Window: *window})); err != nil {
			return err
		}
		if args[1] == "patch" {
			fmt.Println("rayd checks GitHub for releases every ~6 h and updates to a newer patch release of this minor version in the window (rayctl update status)")
		}
		return nil
	}
	return errUsage
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
	fmt.Printf("installed  %s\n", m.Installed)
	if m.Latest != "" {
		fmt.Printf("latest     %s\n", m.Latest)
	}
	fmt.Printf("remote     %s\nauto       %s (window %s, %s)\n", m.Remote, m.Auto, m.Window, m.Timezone)
	s := m.Status
	if s == nil || s.State == nodeupdate.Idle {
		fmt.Println("last       none")
		return nil
	}
	line := fmt.Sprintf("last       %s: %s → %s, by %s", s.State, s.From, s.To, s.By)
	if s.EndedAt != 0 {
		line += ", " + time.Unix(s.EndedAt, 0).UTC().Format(time.RFC3339)
	} else if s.RequestedAt != 0 {
		line += ", asked " + time.Unix(s.RequestedAt, 0).UTC().Format(time.RFC3339)
	}
	fmt.Println(line)
	if s.Error != "" {
		fmt.Printf("error      %s\n", s.Error)
	}
	return nil
}
