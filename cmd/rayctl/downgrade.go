package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/release"
	"github.com/arngory/raycontrol/internal/store"
)

// nodeEnv is what an update and a rollback touch on the node besides the
// release's files: rayd's database, systemctl, and the install of the
// binaries. localNode is the node's own; tests take theirs.
type nodeEnv struct {
	db        string
	systemctl func(args ...string) error
	install   func(stage string) error
}

var localNode = nodeEnv{
	db:        deploy.DB,
	systemctl: func(args ...string) error { return run("systemctl", args...) },
	install:   installBinaries,
}

// beforeOverlap reports whether target, the version whose binaries go in,
// has a rayd before overlapSince: a release older, or a build that is no
// release (dev, -local), taken for one.
func beforeOverlap(target string) bool {
	if release.IsRelease(target) && !release.Newer(overlapSince, target) {
		return false
	}
	return true
}

// rollbackRenewsOverlap reports whether binaries of target going in over
// the node give new credentials to the users whose rotation a revocation
// with overlap began (store.RenewOverlapRotations, R4-43): a rayd before
// overlapSince (beforeOverlap) on a node without a period (rot, the
// schedule rayd stored at its start: the flags it runs with, not those of
// a unit changed since) runs no rotation loop, and would never switch the
// rotation nor drop the previous secret. With a period its loop finishes
// them.
func rollbackRenewsOverlap(target string, rot store.Rotation) bool {
	return beforeOverlap(target) && rot.Period <= 0
}

// renewForOlder runs before binaries of target go in over the node, a
// rollback's or an update's going back (update -version, -from, -local):
// when they are of a rayd before overlapSince on a node without a period
// (rollbackRenewsOverlap), the users whose rotation a revocation with
// overlap began get new credentials (store.RenewOverlapRotations, audit
// user.renew:<op> by actor), on root's copy of the database with rayd
// stopped, then the copy back. Nothing is read for a target of
// overlapSince or later. stopped: rayd is stopped already (the caller
// starts it again on an error); else it is stopped here, only when a copy
// taken first has someone to renew (stoppedHere), and on an error after
// the stop started again, the error saying so. It returns the users
// renewed. On an error the database is as it was.
func (n nodeEnv) renewForOlder(ctx context.Context, target string, stopped bool, actor, op string) (users []string, stoppedHere bool, err error) {
	if !beforeOverlap(target) {
		return nil, false, nil
	}
	if stopped {
		users, err = n.renewCopy(ctx, target, actor, op, true)
		return users, false, err
	}
	// Whether there is anyone, on a copy, before rayd stops.
	if users, err = n.renewCopy(ctx, target, actor, op, false); err != nil {
		return nil, false, fmt.Errorf("%w (rayd runs on, nothing changed)", err)
	}
	if len(users) == 0 {
		return nil, false, nil
	}
	if err := n.systemctl("stop", "rayd.service"); err != nil {
		return nil, false, fmt.Errorf("stopping rayd: %w", err)
	}
	if users, err = n.renewCopy(ctx, target, actor, op, true); err != nil {
		return nil, false, n.startAgain(err, "nothing changed")
	}
	return users, true, nil
}

// renewCopy renews the users of rotations a revocation with overlap
// began (store.RenewOverlapRotations) on root's copy of the database, when
// target needs it (rollbackRenewsOverlap), and with back puts the copy in
// place of the database.
func (n nodeEnv) renewCopy(ctx context.Context, target, actor, op string, back bool) ([]string, error) {
	work, done, err := rootCopy(n.db)
	if err != nil {
		return nil, err
	}
	defer done()
	rot, err := store.RotationAt(ctx, work)
	if err != nil || !rollbackRenewsOverlap(target, rot) {
		return nil, err
	}
	users, err := store.RenewOverlapRotations(ctx, work, actor, op)
	if err != nil || len(users) == 0 || !back {
		return users, err
	}
	if err := copyDB(work, n.db); err != nil {
		return nil, fmt.Errorf("putting the renewed database in place: %w", err)
	}
	return users, nil
}

// startAgain starts rayd again after err, once it was stopped for what
// failed, and says in the error what state the node is in: what of the
// change is done, and whether rayd runs.
func (n nodeEnv) startAgain(err error, done string) error {
	if serr := n.systemctl("start", "rayd.service"); serr != nil {
		return fmt.Errorf("%w; %s, and rayd is stopped: it did not start again: %w", err, done, serr)
	}
	return fmt.Errorf("%w; %s, rayd started again", err, done)
}

// stopForInstall stops rayd for an update and keeps its database in
// previousDir as it is (the copy a rollback puts back), then runs
// renewForOlder for target: an update going back to a rayd before
// overlapSince renews (audit user.renew:downgrade). On an error after the
// stop rayd is started again and nothing is installed: an update that
// cannot renew does not go back.
func (n nodeEnv) stopForInstall(ctx context.Context, target string) ([]string, error) {
	if err := n.systemctl("stop", "rayd.service"); err != nil {
		return nil, err
	}
	if err := copyDB(n.db, filepath.Join(previousDir, "rayd.db")); err != nil {
		return nil, n.startAgain(fmt.Errorf("keeping the database: %w", err), "nothing installed")
	}
	users, _, err := n.renewForOlder(ctx, target, true, "rayctl update -version "+target, "downgrade")
	if err != nil {
		return nil, n.startAgain(fmt.Errorf("renewing the users of revocations with overlap for %s: %w", target, err), "nothing installed")
	}
	return users, nil
}

// renewedForOlderText says which users a rollback or an update going back
// to target renewed (renewForOlder).
func renewedForOlderText(target string, users []string) string {
	return fmt.Sprintf("%s runs no credential rotation without -cred-period: the users of devices revoked with -overlap,\n"+
		"whose rotation it would never finish, have new credentials now, and their other devices reconnect after\n"+
		"their next subscription fetch: %s\n", target, strings.Join(users, ", "))
}
