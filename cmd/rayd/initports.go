package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/arngory/raycontrol/internal/provision"
)

// initSSHPorts are the ports -ports keeps clear of: -ssh-ports as given,
// or sshd -T's. Without sshd there are none; with an sshd that cannot say
// (sshd -T needs root, and rayd init runs as rayd), -ports is refused
// rather than taken unchecked: a chosen range over sshd's port would give
// SSH's port to SPA or a service.
func initSSHPorts(flag string) ([]uint16, error) {
	if flag != "" {
		return provision.ParseSSHPorts(flag)
	}
	bin, err := exec.LookPath("sshd")
	if err != nil {
		bin = "/usr/sbin/sshd"
	}
	if _, err := os.Stat(bin); err != nil {
		return nil, nil // no sshd: no port of its to keep clear
	}
	out, err := exec.Command(bin, "-T").Output() //nolint:gosec // G204: the host's sshd
	if err != nil {
		return nil, fmt.Errorf("-ports: sshd's ports are not known (sshd -T: %w; it needs root): pass them with -ssh-ports N[,N...], "+
			"or -ssh-ports none if sshd does not listen here", err)
	}
	return provision.SSHDPorts(string(out))
}
