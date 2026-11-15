package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/release"
)

// updateOpts are rayctl update's flags that choose and stage a release, a
// node's and a relay's alike.
type updateOpts struct {
	want, from, local            string
	check, yes, force, noHandoff bool
	host                         string // what the handoff says it updates: "node" when empty, or "relay"
}

// releaseBase is where releases are downloaded from: github.com when
// empty (a test seam, release.Fetcher.Base).
var releaseBase string

// staged is how stageRelease ended: the version it staged, or that the
// update ends here (done): nothing newer, -check, or handed over to the
// release's own rayctl (handed, whose error is the update's).
type staged struct {
	version      string
	done, handed bool
}

// reasonErr is an update's error with the code of where it failed
// (nodeupdate.Reason*, spec/relay-update-remote-v1.md §3.6): the outcome
// an update by request writes carries it (writeResult), for a relay's
// exit to show; a person reads the text, which is err's.
type reasonErr struct {
	reason string
	err    error
}

func (e reasonErr) Error() string { return e.err.Error() }
func (e reasonErr) Unwrap() error { return e.err }

// withReason is err with the code of where it failed, nil for nil.
func withReason(reason string, err error) error {
	if err == nil {
		return nil
	}
	return reasonErr{reason, err}
}

// reasonOf is the code err carries: the outermost one (a rollback that
// did not bring the relay back is open, whatever failed first), or
// nodeupdate's for a request refused; "" when none.
func reasonOf(err error) string {
	if r := (reasonErr{}); errors.As(err, &r) {
		return r.reason
	}
	return nodeupdate.ReasonOf(err)
}

// fetchReason is err, of a release that was not staged, with its code: a
// release that does not verify (a signature, the version it signs, the
// archive's checksum), or one that could not be had.
func fetchReason(err error) error {
	if errors.Is(err, release.ErrUnverified) {
		return withReason(nodeupdate.ReasonSignature, err)
	}
	return withReason(nodeupdate.ReasonDownload, err)
}

// newStage is the update's staging directory, root's, beside the install
// journal.
func newStage() (string, error) {
	if err := os.MkdirAll(deploy.JournalDir, 0o700); err != nil {
		return "", err
	}
	return os.MkdirTemp(deploy.JournalDir, "update-")
}

// stageRelease picks the release an update installs and puts its files in
// stage, the same for a node and a relay: a release downloaded or from
// -from, verified with the pinned key (SHA256SUMS and its signature, the
// version from the signature), never back unless named, -check only says,
// and a newer release goes to its own rayctl (handoff). bins are the
// binaries -local takes. first runs once the target is known, before
// anything changes and before the handoff (with -check too): what refuses
// that target, or warns of it.
func (c *cli) stageRelease(ctx context.Context, o updateOpts, stage, installed string, bins map[string]string, first func(to string) error) (staged, error) {
	var s staged
	first = c.targetsFirst(ctx, first) // REALITY targets the data plane does not reach (R4-38)
	if o.local != "" {
		for name := range bins {
			if b, err := os.ReadFile(filepath.Join(o.local, name)); err == nil { //nolint:gosec // G304: the operator's directory
				if err := os.WriteFile(filepath.Join(stage, name), b, 0o755); err != nil { //nolint:gosec // G306: executables
					return s, err
				}
			}
		}
		s.version = "local"
		fmt.Println("binaries from", o.local, "without verification (test mode)")
		err := first(s.version)
		s.done = err != nil || o.check
		return s, err
	}
	var (
		r   release.Release
		err error
	)
	arch := runtime.GOARCH
	if o.from != "" {
		r, err = release.Local(o.from, arch, releaseKey)
	} else {
		f := &release.Fetcher{Base: releaseBase, Mirrors: mirrors(), Log: func(format string, a ...any) { fmt.Printf(format+"\n", a...) }}
		v := o.want
		// Which release latest is first, from its signed SHA256SUMS: no
		// archive downloaded for nothing.
		if v == "latest" && !o.force {
			if l, lerr := f.Latest(ctx, releaseKey); lerr == nil {
				// Unless latest is a patch release of this one, a patch
				// release may be out beside it: after a new minor version,
				// and after a latest that is not newer (GitHub's latest may
				// be a backport of an older minor version; one request when
				// latest is this version: release.Fetcher.NewestPatch).
				p := ""
				if release.IsRelease(installed) && !nodeupdate.Patch(l, installed) && (o.check || !release.Newer(l, installed)) {
					p, _ = f.NewestPatch(ctx, releaseKey, installed, l)
				}
				switch {
				case p != "" && !release.Newer(l, installed):
					// The newest release there is for this node.
					fmt.Printf("release %s, a patch release of %s, is out; GitHub's latest, %s, is not newer\n", p, installed, l)
					if o.check {
						fmt.Printf("installed %s, release %s available: rayctl update\n", installed, p)
						s.done = true
						return s, first(p)
					}
					l = p
				case l == installed:
					fmt.Printf("raycontrol %s is installed, the newest release\n", installed)
					s.done = true
					return s, nil
				case release.Newer(installed, l):
					return s, withReason(nodeupdate.ReasonVersion,
						fmt.Errorf("installed %s is newer than the latest release %s; rayctl update -version %s goes back", installed, l, l))
				case o.check:
					fmt.Printf("installed %s, release %s available: rayctl update\n", installed, l)
					if p != "" {
						fmt.Printf("release %s, the newest patch release of %s, available: rayctl update -version %s\n", p, installed, p)
					}
					s.done = true
					return s, first(l)
				}
				v = l
			}
		}
		r, err = f.Fetch(ctx, v, arch, releaseKey)
	}
	if err != nil {
		return s, fetchReason(err)
	}
	s.version = r.Version
	switch {
	case s.version == installed && !o.force:
		fmt.Printf("raycontrol %s is installed, the newest release\n", installed)
		s.done = true
		return s, nil
	case release.Newer(installed, s.version) && o.want == "latest" && !o.force:
		return s, withReason(nodeupdate.ReasonVersion,
			fmt.Errorf("installed %s is newer than the latest release %s; rayctl update -version %s goes back", installed, s.version, s.version))
	}
	if o.check {
		fmt.Printf("installed %s, release %s available: rayctl update\n", installed, s.version)
		s.done = true
		return s, first(s.version)
	}
	if err := first(s.version); err != nil {
		return s, err
	}
	// A newer release updates the host with its own rayctl. Going back, or
	// the same version again, stays with this one: it knows the newer state
	// of the host.
	if handsOff(o.noHandoff, s.version, installed) {
		h, herr := handoff(r, stage, installed, o.host, o.yes, o.force)
		if h {
			s.done, s.handed = true, true
			return s, herr
		}
		fmt.Printf("the release's rayctl does not run here (%v): this rayctl updates instead\n", herr)
	}
	if _, err := release.Extract(r.Archive, stage); err != nil {
		return s, err
	}
	if b, err := os.ReadFile(filepath.Join(stage, "VERSIONS")); err == nil { //nolint:gosec // G304: our staging directory
		fmt.Print(string(b))
	}
	return s, nil
}
