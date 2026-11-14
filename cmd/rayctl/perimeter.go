package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"

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
	}
	return []hostcheck.Result{res}
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
