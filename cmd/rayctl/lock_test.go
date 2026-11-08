package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// One update, rollback or apply at a time: a second refuses at once, naming
// the first; an update by request waits for it; a rayctl its holder starts
// does not wait for its own parent.
func TestUpdateLock(t *testing.T) {
	updateLockPath = filepath.Join(t.TempDir(), "lock")
	t.Setenv(lockEnv, "")
	t.Cleanup(func() {
		if heldLock != nil {
			heldLock.Close()
			heldLock = nil
		}
	})
	other, err := os.OpenFile(updateLockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(other.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	other.WriteString("update by pid 4242 since 2026-11-08T18:00:00Z")

	err = takeUpdateLock("apply", 0)
	if err == nil || !strings.Contains(err.Error(), "another update by pid 4242") || !strings.Contains(err.Error(), "apply again") {
		t.Fatalf("held: %v", err)
	}
	// The one that waits gets it when the other ends.
	go func() {
		time.Sleep(1500 * time.Millisecond)
		other.Close()
	}()
	start := time.Now()
	if err := takeUpdateLock("update by request", 10*time.Second); err != nil {
		t.Fatalf("waited: %v", err)
	}
	if time.Since(start) < time.Second {
		t.Fatal("took a lock that was held")
	}
	if os.Getenv(lockEnv) != "held" {
		t.Fatal("the children are not told")
	}
	if b, _ := os.ReadFile(updateLockPath); !strings.HasPrefix(string(b), "update by request by pid ") {
		t.Fatalf("holder: %q", b)
	}
	// A child of the holder: no wait, no error, though the lock is taken.
	if err := takeUpdateLock("apply", 0); err != nil {
		t.Fatalf("a child of the holder: %v", err)
	}
	// Another process (a fresh open file) still finds it held.
	t.Setenv(lockEnv, "")
	saved := heldLock
	heldLock = nil
	if err := takeUpdateLock("rollback", 0); err == nil {
		t.Fatal("a second holder")
	}
	heldLock = saved
}
