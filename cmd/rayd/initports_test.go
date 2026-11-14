package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// rayd init -ports keeps clear of sshd's ports on its own path too:
// -ssh-ports as rayctl install passes them, or sshd -T; an sshd that
// cannot say refuses -ports instead of taking it unchecked.
func TestInitSSHPorts(t *testing.T) {
	if ps, err := initSSHPorts("2222"); err != nil || !slices.Equal(ps, []uint16{2222}) {
		t.Fatalf("given: %v %v", ps, err)
	}
	if ps, err := initSSHPorts("none"); err != nil || ps != nil {
		t.Fatalf("none: %v %v", ps, err)
	}
	dir := t.TempDir()
	sshd := filepath.Join(dir, "sshd")
	t.Setenv("PATH", dir)
	if err := os.WriteFile(sshd, []byte("#!/bin/sh\necho 'port 22'\necho 'listenaddress 0.0.0.0:2200'\n"), 0o755); err != nil { //nolint:gosec // G306: an executable
		t.Fatal(err)
	}
	if ps, err := initSSHPorts(""); err != nil || !slices.Equal(ps, []uint16{2200}) {
		t.Fatalf("sshd -T: %v %v", ps, err)
	}
	if err := os.WriteFile(sshd, []byte("#!/bin/sh\necho 'sshd: no hostkeys available -- exiting.' >&2\nexit 1\n"), 0o755); err != nil { //nolint:gosec // G306: an executable
		t.Fatal(err)
	}
	if _, err := initSSHPorts(""); err == nil || !strings.Contains(err.Error(), "-ssh-ports") {
		t.Fatalf("sshd -T failing: %v", err)
	}
}
