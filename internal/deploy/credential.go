package deploy

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/arngory/raycontrol/internal/render"
)

// CredentialCommand is rayd's command that copies a credential in for a
// service, run by systemd as root before the service starts
// (ExecStartPre=+): CopyCredential. Not install(1): it follows links, and
// the files and directories it would read are rayd's
// (spec/apply-plan-v1.md §5, §6 decision 3).
const CredentialCommand = "credential"

// MaxCredential bounds a credential: keys and passwords are a few hundred
// bytes, a relay's bundle a few kilobytes.
const MaxCredential = 1 << 20

// The owners of the files credentials are copied from: rendered files are
// rayd's (it writes them), the relay's bundle root's.
const (
	renderedOwner = "rayd"
	bundleOwner   = "root"
)

// copyIn is the unit line that copies the credential src in for user
// before the start: rayd's credential command, as root. anchor is a
// directory rayd cannot change, src a file below it (no link is followed
// from anchor down), owner the user src must belong to.
func copyIn(rayd, anchor, owner, user, src, dst string) string {
	rel, err := filepath.Rel(anchor, src)
	if err != nil {
		rel = src
	}
	return "ExecStartPre=+" + rayd + " " + CredentialCommand + " " + anchor + " " + rel + " " + owner + " " + user + " " + dst
}

// renderedAnchor is the directory a rendered credential is opened from:
// above rayd's StateDirectory (Paths.Rendered is in it), which is rayd's,
// so rayd could turn rendered/ itself into a link.
func renderedAnchor(p render.Paths) string { return path.Dir(path.Dir(p.Rendered)) }

// copyOf reads a copyIn line back: the source and the destination
// (Process.Copies).
func copyOf(line string) (src, dst string, ok bool) {
	f := strings.Fields(line)
	if len(f) != 7 || !strings.HasPrefix(f[0], "+") || f[1] != CredentialCommand {
		return "", "", false
	}
	return path.Join(f[2], f[3]), f[6], true
}

// UnitCopies is what a unit file copies in before its start: the
// destinations of its credential lines (copyIn). rayd reads the front's
// installed unit with it: a password its config would name that the unit
// does not copy in yet (a hy2-obfs added since the last rayctl apply)
// would keep the whole front from starting (live.Applier.FrontUnit).
func UnitCopies(unit []byte) map[string]bool {
	out := map[string]bool{}
	for line := range strings.Lines(string(unit)) {
		v, ok := strings.CutPrefix(strings.TrimSpace(line), "ExecStartPre=")
		if !ok {
			continue
		}
		if _, dst, ok := copyOf(v); ok {
			out[dst] = true
		}
	}
	return out
}
