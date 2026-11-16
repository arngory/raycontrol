package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

// fakeNode is a node for renewForOlder, stopForInstall and rollback: its
// database in a directory of its own (owned by another user when the test
// runs as root, as rayd's is), systemctl and the install recorded, a hook
// run at systemctl stop. alice's phone is revoked with overlap, her
// rotation in flight; bob's without.
type fakeNode struct {
	dir, db string
	calls   []string
	onStop  func()
	failRun string // the systemctl verb that fails
	known   map[string]string
}

var errInstalled = errors.New("installed (test)")

func newFakeNode(t *testing.T, period time.Duration, crash bool) *fakeNode {
	t.Helper()
	ctx := context.Background()
	f := &fakeNode{dir: t.TempDir()}
	f.db = filepath.Join(f.dir, "rayd.db")
	if os.Geteuid() == 0 {
		if err := os.Chown(f.dir, 4321, 4321); err != nil {
			t.Fatal(err)
		}
	}
	s, err := store.Open(ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRotation(ctx, store.Rotation{Period: period, Lead: store.DefaultRotation.Lead, Grace: store.DefaultRotation.Grace}); err != nil {
		t.Fatal(err)
	}
	svc, err := s.CreateService(ctx, store.Service{Kind: "naive", Name: "naive", Enabled: true, Settings: "{}"})
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for _, n := range []string{"alice", "bob"} {
		u, err := s.CreateUser(ctx, store.User{Name: n, Enabled: true, Services: []int64{svc.ID}})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, u.ID)
	}
	if _, err := s.Credentials(ctx, svc.ID, ids, store.NewUUID); err != nil {
		t.Fatal(err)
	}
	a, _, _ := s.CreateDevice(ctx, "alice", "phone", "user")
	_, _, _ = s.CreateDevice(ctx, "alice", "laptop", "user")
	b, _, _ := s.CreateDevice(ctx, "bob", "phone", "user")
	s.SetClock(func() time.Time { return time.Now().Add(time.Minute) })
	if _, err := s.RevokeDeviceOverlap(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeDevice(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	f.known = currentSecrets(t, f.db)
	if crash {
		// rayd killed: the database with its WAL, committed frames in it.
		snap := map[string][]byte{}
		for _, suf := range []string{"", "-wal"} {
			b, err := os.ReadFile(f.db + suf)
			if err != nil {
				t.Fatal(err)
			}
			snap[suf] = b
		}
		s.Close()
		for _, suf := range []string{"", "-wal", "-shm"} {
			_ = os.Remove(f.db + suf)
		}
		for suf, b := range snap {
			if err := os.WriteFile(f.db+suf, b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	} else {
		s.Close()
	}
	return f
}

func (f *fakeNode) env() nodeEnv {
	return nodeEnv{
		db: f.db,
		systemctl: func(args ...string) error {
			f.calls = append(f.calls, strings.Join(args, " "))
			if args[0] == "stop" && f.onStop != nil {
				f.onStop()
			}
			if args[0] == f.failRun {
				return errors.New(args[0] + " failed")
			}
			return nil
		},
		install: func(stage string) error {
			f.calls = append(f.calls, "install")
			return errInstalled
		},
	}
}

// plantFIFO puts a FIFO where rayd's WAL is, at the stop: what a copy of
// the database reads then fails.
func (f *fakeNode) plantFIFO(t *testing.T) {
	f.onStop = func() {
		_ = os.Remove(f.db + "-wal")
		if err := syscall.Mkfifo(f.db+"-wal", 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = os.Remove(f.db + "-wal") })
}

// currentSecrets are the users' current naive secrets in the database at
// path.
func currentSecrets(t *testing.T, path string) map[string]string {
	t.Helper()
	ctx := context.Background()
	s, err := store.OpenReadOnly(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	users, _ := s.ListUsers(ctx)
	svcs, _ := s.ListServices(ctx)
	sets, _ := s.CredentialSets(ctx, svcs[0].ID, nil, nil)
	out := map[string]string{}
	for _, u := range users {
		out[u.Name] = sets[u.ID].Current
	}
	return out
}

// renewForOlder with rayd running (a rollback that keeps the database):
// alice, her rotation in flight, renewed on the live database, rayd
// stopped once, for that, and not started (the rollback's restart does);
// bob, revoked without overlap, as he was; the database rayd's, mode 0600.
// Again: nothing left, rayd not stopped. Review 3, N6 (X1, X2, X4).
func TestRenewForOlder(t *testing.T) {
	for _, crash := range []bool{false, true} {
		f := newFakeNode(t, 0, crash)
		n := f.env()
		users, stopped, err := n.renewForOlder(context.Background(), "v0.30.0", false, "rayctl update -rollback", "rollback")
		if err != nil || !slices.Equal(users, []string{"alice"}) || !stopped || !slices.Equal(f.calls, []string{"stop rayd.service"}) {
			t.Fatalf("crash=%v: %v %v %v; systemctl %q", crash, users, stopped, err, f.calls)
		}
		cur := currentSecrets(t, f.db)
		if cur["alice"] == f.known["alice"] || cur["bob"] != f.known["bob"] {
			t.Errorf("crash=%v: alice %v, bob %v", crash, cur["alice"] != f.known["alice"], cur["bob"] == f.known["bob"])
		}
		fi, err := os.Lstat(f.db)
		if err != nil {
			t.Fatal(err)
		}
		if st := fi.Sys().(*syscall.Stat_t); fi.Mode().Perm() != 0o600 || os.Geteuid() == 0 && (st.Uid != 4321 || st.Gid != 4321) {
			t.Errorf("crash=%v: mode %v, owner %d:%d", crash, fi.Mode(), st.Uid, st.Gid)
		}
		ents, _ := os.ReadDir(f.dir)
		for _, e := range ents {
			if strings.Contains(e.Name(), ".tmp") || strings.Contains(e.Name(), ".aside") {
				t.Errorf("crash=%v: %s left behind", crash, e.Name())
			}
		}
		f.calls = nil
		if users, stopped, err := n.renewForOlder(context.Background(), "v0.30.0", false, "rayctl update -rollback", "rollback"); err != nil ||
			len(users) != 0 || stopped || len(f.calls) != 0 {
			t.Errorf("crash=%v: again: %v %v %v %q", crash, users, stopped, err, f.calls)
		}
	}
}

// Nothing renewed, rayd not stopped: a node with a period (its older
// rayd's loop finishes the rotation); a target of v0.31.0 or later, whose
// database is not even read (review 3, N4).
func TestRenewForOlderNot(t *testing.T) {
	ctx := context.Background()
	f := newFakeNode(t, store.DefaultRotation.Period, false)
	if users, _, err := f.env().renewForOlder(ctx, "v0.30.0", false, "a", "rollback"); err != nil || len(users) != 0 || len(f.calls) != 0 {
		t.Errorf("with a period: %v %v %q", users, err, f.calls)
	}
	f = newFakeNode(t, 0, false)
	for _, target := range []string{"v0.31.0", "v0.32.1"} {
		n := f.env()
		n.db = filepath.Join(t.TempDir(), "none.db")
		if users, _, err := n.renewForOlder(ctx, target, false, "a", "rollback"); err != nil || len(users) != 0 || len(f.calls) != 0 {
			t.Errorf("to %s: %v %v %q", target, users, err, f.calls)
		}
	}
	n := f.env()
	n.db = filepath.Join(t.TempDir(), "none.db")
	if _, _, err := n.renewForOlder(ctx, "v0.30.0", false, "a", "rollback"); err == nil || !strings.Contains(err.Error(), "rayd runs on, nothing changed") {
		t.Errorf("to v0.30.0, no database: %v", err)
	}
	if cur := currentSecrets(t, f.db); cur["alice"] != f.known["alice"] {
		t.Error("alice renewed")
	}
}

// A renewal that fails after rayd was stopped starts it again and says so;
// one whose start fails too says rayd is stopped. The database is as it
// was (review 3, S1).
func TestRenewForOlderErrorAfterStop(t *testing.T) {
	ctx := context.Background()
	f := newFakeNode(t, 0, false)
	f.plantFIFO(t)
	_, stopped, err := f.env().renewForOlder(ctx, "v0.30.0", false, "a", "rollback")
	if err == nil || stopped || !strings.Contains(err.Error(), "rayd started again") ||
		!slices.Equal(f.calls, []string{"stop rayd.service", "start rayd.service"}) {
		t.Errorf("%v %v; systemctl %q", stopped, err, f.calls)
	}
	f = newFakeNode(t, 0, false)
	f.plantFIFO(t)
	f.failRun = "start"
	if _, _, err := f.env().renewForOlder(ctx, "v0.30.0", false, "a", "rollback"); err == nil ||
		!strings.Contains(err.Error(), "rayd is stopped: it did not start again") {
		t.Errorf("start failing: %v", err)
	}
	_ = os.Remove(f.db + "-wal")
	if cur := currentSecrets(t, f.db); cur["alice"] != f.known["alice"] {
		t.Error("alice renewed")
	}
}

// update -version going back (stopForInstall): rayd stopped, the database
// kept in previousDir as it was, then alice renewed on the live one,
// audited as a downgrade; to a later release nothing renewed. A renewal or
// a copy that fails starts rayd again, nothing installed (review 3, K1,
// S1).
func TestStopForInstall(t *testing.T) {
	ctx := context.Background()
	old := previousDir
	t.Cleanup(func() { previousDir = old })

	f := newFakeNode(t, 0, false)
	previousDir = t.TempDir()
	users, err := f.env().stopForInstall(ctx, "v0.30.2")
	if err != nil || !slices.Equal(users, []string{"alice"}) || !slices.Equal(f.calls, []string{"stop rayd.service"}) {
		t.Fatalf("to v0.30.2: %v %v %q", users, err, f.calls)
	}
	if kept := currentSecrets(t, filepath.Join(previousDir, "rayd.db")); kept["alice"] != f.known["alice"] {
		t.Error("the kept copy is not the database as it was")
	}
	if cur := currentSecrets(t, f.db); cur["alice"] == f.known["alice"] || cur["bob"] != f.known["bob"] {
		t.Errorf("live: %v", cur)
	}
	st, err := store.OpenReadOnly(ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	audit, _ := st.ListAudit(ctx, 10)
	st.Close()
	if !slices.ContainsFunc(audit, func(a store.AuditEntry) bool {
		return a.Action == "user.renew:downgrade" && a.Actor == "rayctl update -version v0.30.2" && strings.HasPrefix(a.Target, "alice: ")
	}) {
		t.Errorf("audit %+v", audit)
	}

	f = newFakeNode(t, 0, false)
	previousDir = t.TempDir()
	if users, err := f.env().stopForInstall(ctx, "v0.31.1"); err != nil || len(users) != 0 || currentSecrets(t, f.db)["alice"] != f.known["alice"] {
		t.Errorf("to v0.31.1: %v %v", users, err)
	}

	// The renewal fails: root's copy cannot be made.
	f = newFakeNode(t, 0, false)
	previousDir = t.TempDir()
	t.Setenv("TMPDIR", os.Getenv("TMPDIR"))
	gone := filepath.Join(t.TempDir(), "gone")
	f.onStop = func() { os.Setenv("TMPDIR", gone) }
	_, err = f.env().stopForInstall(ctx, "v0.30.2")
	os.Setenv("TMPDIR", "")
	if err == nil || !strings.Contains(err.Error(), "nothing installed, rayd started again") ||
		!slices.Equal(f.calls, []string{"stop rayd.service", "start rayd.service"}) || currentSecrets(t, f.db)["alice"] != f.known["alice"] {
		t.Errorf("renewal failing: %v %q", err, f.calls)
	}

	// The copy for previousDir fails.
	f = newFakeNode(t, 0, false)
	previousDir = t.TempDir()
	f.plantFIFO(t)
	if _, err := f.env().stopForInstall(ctx, "v0.30.2"); err == nil || !strings.Contains(err.Error(), "keeping the database") ||
		!strings.Contains(err.Error(), "rayd started again") || !slices.Equal(f.calls, []string{"stop rayd.service", "start rayd.service"}) {
		t.Errorf("copy failing: %v %q", err, f.calls)
	}
}

// rollback to a release before v0.31.0 that keeps the database: the
// renewal runs before the binaries go in; with carryMust one that fails
// rolls nothing back and says rayd runs; with carryTry the rollback goes
// on; -no-carry renews no one; to v0.31.0 nothing is read (review 3, N6:
// X3, X5).
func TestRollbackRenewsBeforeInstall(t *testing.T) {
	ctx := context.Background()
	oldPrev, oldNode := previousDir, localNode
	t.Cleanup(func() { previousDir, localNode = oldPrev, oldNode })
	setup := func(t *testing.T, to string) *fakeNode {
		f := newFakeNode(t, 0, false)
		previousDir = t.TempDir()
		if err := os.WriteFile(filepath.Join(previousDir, "VERSION"), []byte(to+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		localNode = f.env()
		return f
	}
	c := &cli{}

	f := setup(t, "v0.30.0")
	err := c.rollback(ctx, "asked for", false, carryMust)
	if !errors.Is(err, errInstalled) || !strings.Contains(err.Error(), "rayd started again") ||
		!slices.Equal(f.calls, []string{"stop rayd.service", "install", "start rayd.service"}) || currentSecrets(t, f.db)["alice"] == f.known["alice"] {
		t.Errorf("carryMust: %v %q", err, f.calls)
	}

	f = setup(t, "v0.30.0")
	f.plantFIFO(t)
	err = c.rollback(ctx, "asked for", false, carryMust)
	if err == nil || errors.Is(err, errInstalled) || !strings.Contains(err.Error(), "nothing rolled back") ||
		!strings.Contains(err.Error(), "rayd started again") || !slices.Equal(f.calls, []string{"stop rayd.service", "start rayd.service"}) {
		t.Errorf("carryMust, the renewal failing: %v %q", err, f.calls)
	}

	f = setup(t, "v0.30.0")
	f.plantFIFO(t)
	if err := c.rollback(ctx, "the update failed", false, carryTry); !errors.Is(err, errInstalled) ||
		!slices.Equal(f.calls, []string{"stop rayd.service", "start rayd.service", "install"}) {
		t.Errorf("carryTry, the renewal failing: %v %q", err, f.calls)
	}

	f = setup(t, "v0.30.0")
	if err := c.rollback(ctx, "asked for", false, carrySkip); !errors.Is(err, errInstalled) || !slices.Equal(f.calls, []string{"install"}) ||
		currentSecrets(t, f.db)["alice"] != f.known["alice"] {
		t.Errorf("-no-carry: %v %q", err, f.calls)
	}

	f = setup(t, "v0.31.0")
	localNode.db = filepath.Join(t.TempDir(), "none.db")
	if err := c.rollback(ctx, "asked for", false, carryMust); !errors.Is(err, errInstalled) || !slices.Equal(f.calls, []string{"install"}) {
		t.Errorf("to v0.31.0: %v %q", err, f.calls)
	}
}

// copyDB writes the copies before anything of the destination moves: a
// source that cannot be read leaves the destination's WAL, with what was
// committed in it, where it was (review 3, N7).
func TestCopyDBKeepsWALOnError(t *testing.T) {
	src, dst := filepath.Join(t.TempDir(), "rayd.db"), filepath.Join(t.TempDir(), "rayd.db")
	for name, body := range map[string]string{src: "new", dst: "old", dst + "-wal": "old frames"} {
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mkfifo(src+"-wal", 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyDB(src, dst); err == nil {
		t.Fatal("copied from a FIFO")
	}
	for name, want := range map[string]string{dst: "old", dst + "-wal": "old frames"} {
		if b, err := os.ReadFile(name); err != nil || string(b) != want {
			t.Errorf("%s: %q %v", filepath.Base(name), b, err)
		}
	}
	if err := os.Remove(src + "-wal"); err != nil {
		t.Fatal(err)
	}
	if err := copyDB(src, dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "new" {
		t.Errorf("dst %q", b)
	}
	if _, err := os.Lstat(dst + "-wal"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the old WAL beside the new file: %v", err)
	}
	ents, _ := os.ReadDir(filepath.Dir(dst))
	if len(ents) != 1 {
		t.Errorf("left behind: %v", ents)
	}
}
