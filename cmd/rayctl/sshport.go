package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/hostcheck"
	"github.com/arngory/raycontrol/internal/store"
)

// The install reads sshd's port once and makes it the ssh service's; the
// perimeter admits SSH on the ports of the enabled ssh services only. An
// operator who later moves sshd to another port (Port in sshd_config) is
// shut out once sshd restarts on it. rayd does not follow sshd by itself
// (a wrong read would open or close a port): rayctl check and status say
// when the two differ, and what brings them in line.

// sshAdmitted are the TCP ports the perimeter admits SSH on, as rayd has
// its services: those of the enabled ssh services, each with their names.
func sshAdmitted(services []*nodev1.Service) map[int][]string {
	out := map[int][]string{}
	for _, s := range services {
		if !s.Enabled || s.Kind != "ssh" {
			continue
		}
		ports, err := store.Service{Name: s.Name, Kind: s.Kind, Settings: s.SettingsJson}.Ports()
		if err != nil {
			continue
		}
		for _, p := range ports {
			if p.Proto == "tcp" {
				out[int(p.Num)] = append(out[int(p.Num)], s.Name)
			}
		}
	}
	return out
}

// sshPortResult compares sshd's configured ports with those the perimeter
// admits. A port sshd has and the perimeter does not is a warning, with the
// commands that admit it; one the perimeter admits where sshd is not (the
// old port, kept through a move) is only said.
func sshPortResult(sshd []int, admitted map[int][]string) hostcheck.Result {
	res := hostcheck.Result{Level: hostcheck.Advised, Name: "ssh port", OK: true}
	ports := slices.Sorted(maps.Keys(admitted))
	var missing, dead []int
	for _, p := range sshd {
		if admitted[p] == nil {
			missing = append(missing, p)
		}
	}
	for _, p := range ports {
		if !slices.Contains(sshd, p) {
			dead = append(dead, p)
		}
	}
	list := func(ps []int) string {
		s := make([]string, len(ps))
		for i, p := range ps {
			s[i] = strconv.Itoa(p)
		}
		return strings.Join(s, ", ")
	}
	var names []string
	for _, p := range ports {
		names = append(names, fmt.Sprintf("%d (%s)", p, strings.Join(admitted[p], ", ")))
	}
	admits := "admits SSH on " + strings.Join(names, ", ")
	if len(names) == 0 {
		admits = "admits SSH on no port: no ssh service is enabled"
	}
	if len(missing) == 0 {
		res.Detail = "sshd's port " + list(sshd) + ": the perimeter " + admits
		if len(dead) > 0 {
			res.Detail += "; sshd is not configured for " + list(dead) + " (a service for an old port can go: rayctl service del NAME)"
		}
		return res
	}
	res.OK = false
	res.Detail = "sshd is configured for " + list(missing) + ", which the perimeter does not admit (it " + admits + ")"
	if len(missing) == len(sshd) {
		res.Detail += ": once sshd runs as configured, SSH from the admin addresses and after a knock is closed to everyone"
	}
	p := missing[0]
	res.Fix = fmt.Sprintf("rayctl service add ssh ssh-%d -settings '{\"ports\":[\"tcp/%d\"]}', give it to the users who knock for SSH "+
		"(rayctl user services emergency ssh,ssh-%d: the list whole), then rayctl apply; keep the old port in sshd until a new "+
		"session on %d gets in (docs/10-quickstart-debian13.md §7); or put sshd back on %s", p, p, p, p, cmpPorts(ports))
	return res
}

// cmpPorts names the admitted ports for the way back.
func cmpPorts(ports []int) string {
	if len(ports) == 0 {
		return "its port (no ssh service is enabled: rayctl service list)"
	}
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, " or ")
}

// sshPortResults is sshPortResult for this node: rayd's services and sshd
// -T, which needs root. None before the install (rayd does not answer), or
// on a relay (no rayd API).
func (c *cli) sshPortResults(ctx context.Context) []hostcheck.Result {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	r, err := c.c.ListServices(ctx, connect.NewRequest(&nodev1.ListServicesRequest{}))
	if err != nil {
		return nil
	}
	bin := sshdBinary()
	sshd, err := sshdPortsOf(bin)
	switch {
	case err != nil && noOpenSSH(bin, err):
		// Nothing to compare, and nothing wrong: status says nothing,
		// check one line.
		return []hostcheck.Result{{Level: hostcheck.Advised, Name: "ssh port", OK: true,
			Detail: "no OpenSSH sshd here (sshd -T cannot be run, or the sshd is another server): its ports are not compared with the perimeter's"}}
	case err != nil && os.Geteuid() != 0:
		return []hostcheck.Result{{Level: hostcheck.Advised, Name: "ssh port", OK: true,
			Detail: "sshd's ports are read with sshd -T, which needs root: run rayctl check as root to compare them with the perimeter's"}}
	case err != nil:
		return []hostcheck.Result{{Level: hostcheck.Advised, Name: "ssh port", OK: false, Detail: err.Error(),
			Fix: "sshd -T must read its configuration: fix it before sshd restarts"}}
	}
	res := sshPortResult(sshd, sshAdmitted(r.Msg.Services))
	res.Detail += sshSocketNote(sshSocketLinks)
	return []hostcheck.Result{res}
}

// noOpenSSH reports whether sshd -T of bin failed for want of OpenSSH's
// sshd: no such program, or another server under its name (Dropbear's
// compatibility link, a stub). OpenSSH's sshd names itself in its answer
// to -V, and an older one, which does not know -V, in the usage it prints
// then. An OpenSSH sshd whose configuration does not read is not this.
func noOpenSSH(bin string, err error) bool {
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
		return true
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return false
	}
	out, _ := exec.Command(bin, "-V").CombinedOutput() //nolint:gosec // G204: the host's sshd
	return !strings.Contains(string(out), "OpenSSH")
}

// sshSocketLinks are where an enabled socket unit of sshd links, Debian's
// and Ubuntu's name and that of others.
var sshSocketLinks = []string{
	"/etc/systemd/system/sockets.target.wants/ssh.socket",
	"/etc/systemd/system/sockets.target.wants/sshd.socket",
}

// sshSocketNote is what to add when sshd is started by an enabled socket
// unit: then the unit's ListenStream is where SSH is taken, which sshd -T
// does not show and this check does not read.
func sshSocketNote(links []string) string {
	for _, l := range links {
		if _, err := os.Lstat(l); err == nil {
			return "; " + filepath.Base(l) + " is enabled: SSH is taken on its ListenStream ports, which this check does not read " +
				"(systemctl cat " + filepath.Base(l) + ")"
		}
	}
	return ""
}
