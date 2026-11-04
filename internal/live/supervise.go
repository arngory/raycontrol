package live

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/arngory/raycontrol/internal/deploy"
)

// Supervisor runs the data plane as child processes of rayd, where there
// is no systemd: tests and containers (rayd serve -supervise). It follows
// the same plan rayctl apply installs as units, without their users,
// groups and sandbox: every process runs as rayd does. Set it as the
// Applier's Restart.
type Supervisor struct {
	// Plan is the current deployment: read again after a Restart and
	// every replanEvery.
	Plan func(ctx context.Context) (deploy.Plan, error)
	Log  *slog.Logger
	// Output receives the processes' output, each line after its unit's
	// name (default: standard error).
	Output io.Writer

	mu      sync.Mutex
	procs   map[string]*child
	restart map[string]bool
	wake    chan struct{}
	outMu   sync.Mutex
}

type child struct {
	spec   deploy.Process
	cmd    *exec.Cmd     // nil: the start failed
	done   chan struct{} // closed when the process has exited
	exited time.Time     // set before done is closed
	failed time.Time     // when the start failed
	ending atomic.Bool   // stopped on purpose
}

// retry is when the process may start again (RestartSec).
func (c *child) retry() time.Time {
	if c.cmd == nil {
		return c.failed.Add(restartDelay)
	}
	return c.exited.Add(restartDelay)
}

// restartDelay is the pause before a process that exited is started again,
// as RestartSec in the units.
const restartDelay = 2 * time.Second

// replanEvery catches services that left without a Restart (disabled).
const replanEvery = 30 * time.Second

func (s *Supervisor) init() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.procs == nil {
		s.procs = map[string]*child{}
		s.restart = map[string]bool{}
		s.wake = make(chan struct{}, 1)
	}
}

// Restart restarts a unit's process, or starts it: the Applier calls it
// after a config change (verb: restart or try-restart, both the same here).
func (s *Supervisor) Restart(_ context.Context, _, unit string) error {
	s.init()
	s.mu.Lock()
	s.restart[unit] = true
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}

// Run keeps the plan's processes running until ctx ends, then stops them.
func (s *Supervisor) Run(ctx context.Context) {
	s.init()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var plan deploy.Plan
	var planned time.Time
	replan := true
	for {
		if replan || time.Since(planned) >= replanEvery {
			p, err := s.Plan(ctx)
			if err != nil {
				if ctx.Err() == nil {
					s.Log.Error("supervise: plan", "err", err)
				}
			} else {
				plan, planned = p, time.Now()
			}
		}
		if !planned.IsZero() {
			s.round(plan)
		}
		replan = false
		select {
		case <-ctx.Done():
			s.stopAll()
			return
		case <-s.wake:
			replan = true
		case <-t.C: // restarts after RestartSec
		}
	}
}

func (s *Supervisor) round(plan deploy.Plan) {
	for _, d := range plan.Dirs {
		if err := os.MkdirAll(d, 0o750); err != nil {
			s.Log.Error("supervise: directory", "dir", d, "err", err)
		}
	}
	s.mu.Lock()
	restart := s.restart
	s.restart = map[string]bool{}
	s.mu.Unlock()

	// Gone from the plan, or started differently: stop.
	want := map[string]deploy.Process{}
	for _, p := range plan.Processes {
		want[p.Unit] = p
	}
	for unit, c := range s.procs {
		p, ok := want[unit]
		if !ok || !slices.Equal(p.Args, c.spec.Args) || p.Dir != c.spec.Dir || !slices.Equal(p.Copies, c.spec.Copies) {
			s.stop(c)
			delete(s.procs, unit)
		}
	}
	now := time.Now()
	for _, p := range plan.Processes {
		c := s.procs[p.Unit]
		if c != nil && restart[p.Unit] {
			s.stop(c)
		} else if c != nil && (c.running() || now.Before(c.retry())) {
			continue
		}
		if p.Needs != "" {
			if _, err := os.Stat(p.Needs); err != nil {
				continue // ConditionPathExists: rayd starts it once it is there
			}
		}
		nc, err := s.start(p)
		if err != nil {
			s.Log.Error("supervise: start", "unit", p.Unit, "err", err)
			nc = &child{spec: p, failed: now}
		} else {
			s.Log.Info("supervise: started", "unit", p.Unit, "pid", nc.cmd.Process.Pid)
		}
		s.procs[p.Unit] = nc
	}
}

func (c *child) running() bool {
	if c.cmd == nil {
		return false
	}
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

// start prepares the runtime directory and the credentials as systemd
// does (RuntimeDirectory, ExecStartPre=+install), then starts the process.
func (s *Supervisor) start(p deploy.Process) (*child, error) {
	if len(p.Args) == 0 {
		return nil, errors.New("no command")
	}
	if p.Dir != "" {
		// Removed at stop by systemd: no stale sockets.
		if err := os.RemoveAll(p.Dir); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(p.Dir, 0o750); err != nil {
			return nil, err
		}
	}
	for _, c := range p.Copies {
		if err := copyFile(c[0], c[1]); err != nil {
			return nil, fmt.Errorf("credential %s: %w", c[1], err)
		}
	}
	cmd := exec.Command(p.Args[0], p.Args[1:]...) //nolint:gosec // G204: the deployment plan's own command
	out := s.lines(p.Unit)
	cmd.Stdout, cmd.Stderr = out, out
	cmd.SysProcAttr = procAttr()
	if err := cmd.Start(); err != nil {
		_ = out.Close()
		return nil, err
	}
	c := &child{spec: p, cmd: cmd, done: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		_ = out.Close()
		c.exited = time.Now()
		close(c.done)
		if !c.ending.Load() {
			s.Log.Warn("supervise: exited", "unit", p.Unit, "err", err)
		}
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}()
	return c, nil
}

func (s *Supervisor) stop(c *child) {
	if !c.running() {
		return
	}
	c.ending.Store(true)
	_ = c.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		_ = c.cmd.Process.Kill()
		<-c.done
	}
	s.Log.Info("supervise: stopped", "unit", c.spec.Unit)
}

func (s *Supervisor) stopAll() {
	// All at once: each may take its time to close.
	var wg sync.WaitGroup
	for unit, c := range s.procs {
		wg.Add(1)
		go func() { defer wg.Done(); s.stop(c) }()
		delete(s.procs, unit)
	}
	wg.Wait()
}

// lines passes a process's output on, line by line, after its unit name.
func (s *Supervisor) lines(unit string) io.WriteCloser {
	w := s.Output
	if w == nil {
		w = os.Stderr
	}
	r, pw := io.Pipe()
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			s.outMu.Lock()
			fmt.Fprintf(w, "%s: %s\n", unit, sc.Bytes())
			s.outMu.Unlock()
		}
		_, _ = io.Copy(io.Discard, r)
	}()
	return pw
}

// copyFile copies a credential, readable by its owner only.
func copyFile(from, to string) error {
	b, err := os.ReadFile(from) //nolint:gosec // G304: the deployment plan's own path
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o750); err != nil {
		return err
	}
	_ = os.Remove(to) // 0400: not writable in place
	return os.WriteFile(to, b, 0o400)
}
