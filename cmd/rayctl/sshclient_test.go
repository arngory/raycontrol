package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Under sudo the SSH session's variables are gone from rayctl's own
// environment; sshClient finds them in a parent's.
func TestSSHClientThroughParent(t *testing.T) {
	switch os.Getenv("RAYCTL_SSH_STAGE") {
	case "parent": // has the session, starts a child without it, like sudo
		cmd := exec.Command(os.Args[0], "-test.run", "TestSSHClientThroughParent")
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
	case "child":
		fmt.Printf("client=%q\n", sshClient())
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "TestSSHClientThroughParent", "-test.v")
	cmd.Env = append(os.Environ(), "RAYCTL_SSH_STAGE=parent", "SSH_CONNECTION=203.0.113.9 50000 198.51.100.1 22")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), `client="203.0.113.9"`) {
		t.Fatalf("%v\n%s", err, out)
	}
}
