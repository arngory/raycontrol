package main

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
)

// One update, rollback or apply at a time (roadmap: after v0.19.0): two of
// them would both rewrite previous/ and restart rayd. Root takes an
// exclusive flock; the rayctl it starts (the release's own in a handoff,
// the apply an update runs, the update a request runs) inherits lockEnv
// and does not take it again, so it never waits for its own parent.
const lockEnv = "RAYCONTROL_UPDATE_LOCK"

// updateLockPath is the lock: on tmpfs, gone with a reboot. Tests replace
// it.
var updateLockPath = "/run/raycontrol-update.lock"

// takeUpdateLock takes the lock for what ("update", "rollback", "apply"),
// waiting up to wait for one that holds it (0: not at all). The lock lasts
// as long as this process.
func takeUpdateLock(what string, wait time.Duration) error {
	if os.Getenv(lockEnv) == "held" {
		return nil // a parent rayctl holds it for this one
	}
	f, err := os.OpenFile(updateLockPath, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: a fixed path
	if err != nil {
		return fmt.Errorf("the update lock: %w", err)
	}
	deadline := time.Now().Add(wait)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = f.Close()
			return fmt.Errorf("the update lock: %w", err)
		}
		if time.Now().After(deadline) {
			holder, _ := os.ReadFile(updateLockPath) //nolint:gosec // G304: a fixed path
			_ = f.Close()
			return fmt.Errorf("another %s is running (%s); %s again once it ends",
				cmp.Or(strings.TrimSpace(string(holder)), "update, rollback or apply"), updateLockPath, what)
		}
		time.Sleep(time.Second)
	}
	// Who holds it, for the one that finds it held; f stays open, and the
	// lock with it, until this process ends.
	_ = f.Truncate(0)
	_, _ = fmt.Fprintf(f, "%s by pid %d since %s", what, os.Getpid(), time.Now().UTC().Format(time.RFC3339))
	_ = os.Setenv(lockEnv, "held")
	heldLock = f
	return nil
}

// heldLock keeps the lock's file open (and so the lock) for the process.
var heldLock *os.File
