package live

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/deploy"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestSupervisor(t *testing.T) {
	dir := t.TempDir()
	run := filepath.Join(dir, "run")
	secret := filepath.Join(dir, "secret")
	os.WriteFile(secret, []byte("s3"), 0o600)
	needs := filepath.Join(dir, "rendered.json")
	// Each process writes its pid and the credential it found, then waits.
	proc := func(name string) deploy.Process {
		d := filepath.Join(run, name)
		return deploy.Process{Unit: "niko-" + name + ".service", Dir: d,
			Args:   []string{"/bin/sh", "-c", `echo "$$ $(cat ` + d + `/secret)" > ` + d + `.pid; echo started ` + name + `; exec sleep 60`},
			Copies: [][2]string{{secret, filepath.Join(d, "secret")}}}
	}
	var mu sync.Mutex
	plan := deploy.Plan{Processes: []deploy.Process{proc("a"), proc("b")}, Dirs: []string{filepath.Join(run, "a-api")}}
	plan.Processes[1].Needs = needs
	var out syncBuffer
	s := &Supervisor{Log: slog.New(slog.NewTextHandler(&out, nil)), Output: &out,
		Plan: func(context.Context) (deploy.Plan, error) {
			mu.Lock()
			defer mu.Unlock()
			return plan, nil
		}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	pidOf := func(name string, not int) int {
		t.Helper()
		for range 100 {
			b, _ := os.ReadFile(filepath.Join(run, name+".pid"))
			if f := strings.Fields(string(b)); len(f) == 2 {
				pid, _ := strconv.Atoi(f[0])
				if pid != not {
					if f[1] != "s3" {
						t.Fatalf("%s found credential %q", name, f[1])
					}
					return pid
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("%s did not start (again)\n%s", name, out.String())
		return 0
	}
	a := pidOf("a", 0)
	if _, err := os.Stat(filepath.Join(run, "a-api")); err != nil {
		t.Fatal("shared directory not made")
	}
	if fi, err := os.Stat(filepath.Join(run, "a", "secret")); err != nil || fi.Mode().Perm() != 0o400 {
		t.Fatalf("credential copy: %v %v", fi, err)
	}
	// b waits for its file (ConditionPathExists).
	time.Sleep(300 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(run, "b.pid")); err == nil {
		t.Fatal("b started before its file")
	}
	os.WriteFile(needs, []byte("{}"), 0o644)
	pidOf("b", 0)

	// Killed: started again after RestartSec.
	if p, err := os.FindProcess(a); err == nil {
		p.Kill()
	}
	a2 := pidOf("a", a)
	// Restart (a config change): a new process at once.
	s.Restart(ctx, "try-restart", "niko-a.service")
	a3 := pidOf("a", a2)
	// Gone from the plan: stopped.
	mu.Lock()
	plan.Processes = plan.Processes[1:]
	mu.Unlock()
	s.Restart(ctx, "restart", "niko-b.service")
	for range 100 {
		if !processAlive(a3) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if processAlive(a3) {
		t.Fatal("a still runs after it left the plan")
	}
	cancel()
	<-done
	if !strings.Contains(out.String(), "niko-b.service: started b") {
		t.Errorf("output not passed on:\n%s", out.String())
	}
}

func processAlive(pid int) bool {
	_, err := os.Stat("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return false
	}
	b, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	// A zombie (Z) has exited.
	f := strings.Fields(string(b))
	return len(f) > 2 && f[2] != "Z"
}
