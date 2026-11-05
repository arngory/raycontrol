package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The SSH session's address comes from the nearest process that has it,
// and counts only below sshd: not from tmux, screen or a variable set by
// hand.
func TestSSHClient(t *testing.T) {
	env := func(kv ...string) func(string) string {
		return func(k string) string {
			for i := 0; i+1 < len(kv); i += 2 {
				if kv[i] == k {
					return kv[i+1]
				}
			}
			return ""
		}
	}
	none := env()
	sess := env("SSH_CONNECTION", "203.0.113.9 50000 198.51.100.1 2200")
	want := session{"203.0.113.9", 2200}
	long := map[int]proc{}
	for pid := 10; pid < 60; pid++ {
		long[pid] = proc{"bash", pid + 1, sess}
	}
	long[60] = proc{"sshd", 1, none}
	for name, c := range map[string]struct {
		procs map[int]proc
		want  session
	}{
		"direct": {map[int]proc{
			10: {"rayctl", 9, sess}, 9: {"bash", 8, sess}, 8: {"sshd-session", 7, none}, 7: {"sshd", 1, none},
		}, want},
		"through sudo": {map[int]proc{
			10: {"rayctl", 9, none}, 9: {"sudo", 8, sess}, 8: {"bash", 7, sess}, 7: {"sshd", 1, none},
		}, want},
		"sudo -i": {map[int]proc{
			10: {"rayctl", 9, none}, 9: {"bash", 8, none}, 8: {"sudo", 7, sess}, 7: {"bash", 6, sess}, 6: {"sshd-session", 1, none},
		}, want},
		"su -, doas": {map[int]proc{
			10: {"rayctl", 9, none}, 9: {"bash", 8, none}, 8: {"su", 7, sess}, 7: {"doas", 6, sess}, 6: {"bash", 5, sess}, 5: {"sshd-auth", 1, none},
		}, want},
		"SSH_CLIENT, an older sshd": {map[int]proc{
			10: {"rayctl", 9, env("SSH_CLIENT", "2001:db8::9 50000 22")}, 9: {"sshd", 1, none},
		}, session{"2001:db8::9", 22}},
		"the nearest session": {map[int]proc{
			10: {"rayctl", 9, env("SSH_CONNECTION", "192.0.2.1 1 2 3")}, 9: {"sshd-session", 8, none},
			8: {"bash", 7, sess}, 7: {"sshd", 1, none},
		}, session{"192.0.2.1", 3}},
		"tmux": {map[int]proc{
			10: {"rayctl", 9, sess}, 9: {"bash", 8, sess}, 8: {"tmux: server", 1, sess},
		}, session{}},
		"by hand on the console": {map[int]proc{
			10: {"rayctl", 9, sess}, 9: {"login", 1, none},
		}, session{}},
		"a process gone": {map[int]proc{10: {"rayctl", 9, sess}}, session{}},
		"no session":     {map[int]proc{10: {"rayctl", 9, none}, 9: {"sshd", 1, none}}, session{}},
		"too far up":     {long, session{}},
	} {
		got := sshSessionIn(10, func(pid int) (proc, bool) {
			p, ok := c.procs[pid]
			return p, ok
		})
		if got != c.want {
			t.Errorf("%s: %+v, want %+v", name, got, c.want)
		}
	}
}

// readProc reads a parent's name and environment, which sudo does not pass
// on.
func TestReadProc(t *testing.T) {
	if os.Getenv("RAYCTL_SSH_STAGE") == "child" {
		self, ok := readProc(os.Getpid())
		parent, ok2 := readProc(os.Getppid())
		fmt.Printf("ok=%v ppid=%v own=%q parent=%q\n", ok && ok2, self.ppid == os.Getppid(),
			self.env("SSH_CONNECTION"), parent.env("SSH_CONNECTION"))
		return
	}
	if os.Getenv("RAYCTL_SSH_STAGE") == "parent" {
		cmd := exec.Command(os.Args[0], "-test.run", "^TestReadProc$")
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(kv, "SSH_") && !strings.HasPrefix(kv, "RAYCTL_SSH_STAGE=") {
				cmd.Env = append(cmd.Env, kv)
			}
		}
		cmd.Env = append(cmd.Env, "RAYCTL_SSH_STAGE=child")
		out, err := cmd.CombinedOutput()
		fmt.Print(string(out))
		if err != nil {
			os.Exit(1)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestReadProc$", "-test.v")
	cmd.Env = append(os.Environ(), "RAYCTL_SSH_STAGE=parent", "SSH_CONNECTION=203.0.113.9 50000 198.51.100.1 22")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), `ok=true ppid=true own="" parent="203.0.113.9 50000 198.51.100.1 22"`) {
		t.Fatalf("%v\n%s", err, out)
	}
	if p, ok := readProc(os.Getpid()); !ok || !strings.HasPrefix(p.comm, "rayctl") {
		t.Fatalf("own name %q", p.comm)
	}
}
