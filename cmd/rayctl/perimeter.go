package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/arngory/raycontrol/internal/api"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/hostcheck"
	"github.com/arngory/raycontrol/internal/perimeter"
)

// perimeterHost is what perimeterResult asks of the host; tests replace it.
type perimeterHost struct {
	unitFile string               // rayspa's unit: no file, no perimeter to check
	state    func() string        // systemctl is-active rayspa.service
	input    func() (bool, error) // the table's input chain is in the kernel
	euid     func() int           // os.Geteuid when nil
	look     func(string) error   // the nft binary is there
	// show is systemctl show of rayspa.service: ActiveState, MainPID and
	// StatusText (rayspa's STATUS); nil, or an error: not known.
	show func() (map[string]string, error)
}

// showRayspa is systemctl show of rayspa.service, the properties
// ownTable reads.
func showRayspa() (map[string]string, error) {
	out, err := exec.Command("systemctl", "show", "-p", "ActiveState,MainPID,StatusText", "rayspa.service").Output()
	st := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			st[k] = strings.TrimSpace(v)
		}
	}
	return st, err
}

// tableOwn is what rayspa's STATUS says of its table.
type tableOwn int

const (
	// ownUnknown: a STATUS that names no process (a rayspa before it did,
	// or none yet): only the kernel's table can be looked at.
	ownUnknown tableOwn = iota
	// ownUp: the running rayspa (its pid, MainPID) has its table in with
	// a snapshot of rayd's.
	ownUp
	// ownNot: the running rayspa says its table is not in, not whole, or
	// not from rayd yet; or the STATUS is another process's.
	ownNot
)

// ownTable reads rayspa's STATUS (cmd/rayspa, stateNow.status): "perimeter
// up: rayd's snapshot; rayspa V, pid N" from the process systemd runs now
// is the one state that a table an earlier rayspa left cannot give. An
// older rayspa's STATUS (no pid) is ownUnknown.
func ownTable(st map[string]string) (tableOwn, string) {
	text := st["StatusText"]
	i := strings.LastIndex(text, ", pid ")
	if i < 0 || !strings.Contains(text, "; rayspa ") {
		return ownUnknown, text
	}
	if pid := text[i+len(", pid "):]; pid != st["MainPID"] || pid == "0" {
		return ownNot, text + " (from pid " + pid + ", not the running " + st["MainPID"] + ")"
	}
	if strings.HasPrefix(text, "perimeter up: rayd's snapshot;") {
		return ownUp, text
	}
	return ownNot, text
}

// rayspaUpdated is the update's check of the perimeter after rayspa's
// restart (rayctl update, restartNode): the new rayspa has its own table
// in, with the new rayd's snapshot (it starts after rayd). A rayspa whose
// STATUS names no process (a rollback to a version before it) is checked
// as before: running, and a table in the kernel.
func rayspaUpdated(show func() (map[string]string, error), table func() error) error {
	st, err := show()
	if err != nil {
		return fmt.Errorf("systemctl show rayspa: %w", err)
	}
	if st["ActiveState"] != "active" {
		return fmt.Errorf("rayspa.service is %s", st["ActiveState"])
	}
	switch own, text := ownTable(st); own {
	case ownUp:
		return nil
	case ownNot:
		return fmt.Errorf("rayspa: %s", text)
	}
	if err := table(); err != nil {
		return fmt.Errorf("no table inet %s: %w", perimeter.Table, err)
	}
	return nil
}

var defaultPerimeterHost = perimeterHost{
	unitFile: "/etc/systemd/system/rayspa.service",
	state: func() string {
		out, _ := exec.Command("systemctl", "is-active", "rayspa.service").Output()
		return strings.TrimSpace(string(out))
	},
	input: func() (bool, error) {
		// The input chain, not the table: a relay holds its forwarding
		// with a table that has none until its first snapshot (R4-40).
		err := exec.Command("nft", "list", "chain", "inet", perimeter.Table, "input").Run() //nolint:gosec // G204: fixed arguments
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return false, nil
		}
		return err == nil, err
	},
	look: func(name string) error { _, err := exec.LookPath(name); return err },
	show: showRayspa,
}

// perimeterResult says whether the perimeter is up (docs/08-decisions.md,
// R4-40): rayspa's table in the kernel, rayspa running. None before the
// install, and none for anyone but root, who alone may read the table.
// Without the table the host is open: that is a failure as loud as the
// output gets, rayctl status's FAILED. With the table and no rayspa the
// host stays closed as rayspa left it, and no knock is answered.
func perimeterResult(h perimeterHost) []hostcheck.Result {
	if _, err := os.Stat(h.unitFile); err != nil {
		return nil
	}
	euid := h.euid
	if euid == nil {
		euid = os.Geteuid
	}
	if euid() != 0 {
		return []hostcheck.Result{{Level: hostcheck.Advised, Name: "perimeter", OK: true,
			Detail: "the perimeter's table is read with nft, which needs root: run as root to know whether it is in"}}
	}
	res := hostcheck.Result{Level: hostcheck.Advised, Name: "perimeter", OK: true}
	if err := h.look("nft"); err != nil {
		res.OK, res.Detail, res.Fix = false, "nft is not installed: rayspa cannot have its table in, the host is open", "install nftables, then systemctl restart rayspa"
		return []hostcheck.Result{res}
	}
	state := h.state()
	in, err := h.input()
	switch {
	case err != nil:
		res.OK, res.Detail = false, "the perimeter's table cannot be read: "+err.Error()
	case !in:
		res.OK = false
		res.Detail = "perimeter down: the host is open (no table inet " + perimeter.Table + " with its input chain; rayspa.service is " + state + ")"
		res.Fix = "systemctl restart rayspa; journalctl -u rayspa -b -p warning says why it is not in; from the console, rayctl status again"
	case state != "active":
		res.OK = false
		res.Detail = "rayspa.service is " + state + ": its table stays in force as it left it (closed), but no knock is answered " +
			"and no change of the node reaches it"
		res.Fix = "systemctl start rayspa; journalctl -u rayspa -b -p warning says why it stopped"
	default:
		res.Detail = "rayspa runs, its table is in"
		if h.show == nil {
			break
		}
		st, err := h.show()
		if err != nil {
			break
		}
		// The table in the kernel may be an earlier rayspa's (frozen: its
		// slots stop, no knock is answered after one), or this one's
		// behind its snapshot: rayspa's STATUS says (R4-40).
		switch own, text := ownTable(st); own {
		case ownUp:
			res.Detail = "rayspa runs, its table is in with rayd's snapshot"
		case ownNot:
			res.OK = false
			res.Detail = "a table is in, but rayspa says: " + text
			res.Fix = "journalctl -u rayspa -b -p warning says why its own table is not in; systemctl restart rayspa"
		}
	}
	return []hostcheck.Result{res}
}

// egressStatusLine is the egress policy in rayctl status. On a node of
// rayd serve -supervise (docs/18-platforms-and-hosts.md) there is no
// perimeter unless one was started by hand, and the policy's local part
// never covers rayd's UID, as which the data plane runs there: what is set
// is not what the kernel does, and the line says so.
func egressStatusLine(e *nodev1.Egress, supervised bool) string {
	if !supervised {
		return egressLine(e)
	}
	line := "set: " + strings.TrimSuffix(egressLine(e), " (rayctl egress)")
	if e.GetLocal() {
		line += "; local networks: not in the kernel here (rayd serve -supervise: the data plane runs as rayd, " +
			"which the local part does not cover), only the processes' own checks (Xray's routing, naive's and niko-server's)"
	}
	if e.GetSmtp() || e.GetBittorrent() {
		line += "; smtp and bittorrent: only where a rayspa runs, which -supervise does not start"
	}
	return line + " (rayctl egress)"
}

// perimeterLoopState is loopState, but for rayd's perimeter loop when
// rayspa follows the feed and reports nothing of its table (a rayspa
// older than rayd): "unknown", not "ok" (R4-40).
func perimeterLoopState(l *nodev1.LoopHealth, now time.Time) string {
	s := loopState(l, now)
	if rest, ok := strings.CutPrefix(l.Detail, api.RayspaUnknown); ok && l.Name == api.RayspaLoop && strings.HasPrefix(s, "ok ") {
		return "unknown " + strings.TrimSuffix(strings.TrimPrefix(s, "ok "), ": "+l.Detail) + ": " + rest
	}
	return s
}

// perimeterLine is perimeterResult in rayctl status: FAILED when the host
// is open, WARNING otherwise when not ok.
func perimeterLine(r hostcheck.Result) string {
	switch {
	case r.OK:
		return "ok: " + r.Detail
	case strings.HasPrefix(r.Detail, "perimeter down") || strings.HasPrefix(r.Detail, "nft is not installed"):
		return "FAILED " + r.Detail + ": " + r.Fix
	}
	return "WARNING " + r.Detail + ": " + r.Fix
}
