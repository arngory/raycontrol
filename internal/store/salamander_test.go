package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

var salamanderShape = regexp.MustCompile(`^[A-Za-z0-9_-]{32}$`)

// A device's salamander password has the shape and length of S (32
// characters of base64url), is the same for the same S and device, and
// differs for another device or another S; no device, no password.
func TestSalamanderDevicePassword(t *testing.T) {
	s := "s3cret-obfs-password-0123456789ab"
	a, b := spaKey('a'), spaKey('b')
	pa := SalamanderDevicePassword(s, a)
	if !salamanderShape.MatchString(pa) {
		t.Fatalf("password %q", pa)
	}
	if SalamanderDevicePassword(s, a) != pa {
		t.Fatal("not the same twice")
	}
	if pb := SalamanderDevicePassword(s, b); pb == pa || pb == s || SalamanderDevicePassword("x", a) == pa {
		t.Fatal("two devices or two secrets share a password")
	}
	if SalamanderDevicePassword(s, nil) != "" || SalamanderDevicePassword("", a) != "" {
		t.Fatal("a password without a device or a secret")
	}
	// Computed apart from this code (Python hmac, base64): the contract
	// (spec/salamander-device-v1.md §2).
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	for _, v := range []struct{ secret, key, want string }{
		{s, string(a), "DqRIb_TIojmLIRd5xhvpw-kX3oYIhIJR"},
		{"x", string(a), "23brzvXGBw4P2hEG5OoNVrgMsEGyPa5s"},
		{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", string(key), "26sA7ZoWsEBgPWrMrHjMSWwTremAByFW"},
	} {
		if got := SalamanderDevicePassword(v.secret, []byte(v.key)); got != v.want {
			t.Errorf("vector %q: %q, want %q", v.secret, got, v.want)
		}
	}
}

// salamanderSeed is a node at schema 19 with two hy2-obfs services: alice
// and bob on the first, carol on the second; each a device, alice two.
var salamanderSeed = []string{
	`INSERT INTO services (id, kind, name, enabled, settings_json, created_at) VALUES
		(1, 'hy2-obfs', 'hy2o', 1, '{}', 1), (2, 'hy2-obfs', 'hy2o2', 1, '{}', 1)`,
	`INSERT INTO users (id, name, enabled, created_at) VALUES (1, 'alice', 1, 1), (2, 'bob', 1, 1), (3, 'carol', 1, 1)`,
	`INSERT INTO user_services (user_id, service_id) VALUES (1, 1), (2, 1), (3, 2)`,
	`INSERT INTO devices (id, user_id, name, role, spa_key, created_at, revoked_at) VALUES
		('a000000000000001', 1, 'a', 'user', x'0101010101010101010101010101010101010101010101010101010101010101', 10, NULL),
		('a000000000000002', 1, 'b', 'user', x'0202020202020202020202020202020202020202020202020202020202020202', 10, NULL),
		('a000000000000003', 1, 'old', 'user', x'0303030303030303030303030303030303030303030303030303030303030303', 10, 20),
		('b000000000000001', 2, 'c', 'user', x'0404040404040404040404040404040404040404040404040404040404040404', 10, NULL),
		('c000000000000001', 3, 'd', 'user', x'0505050505050505050505050505050505050505050505050505050505050505', 10, NULL)`,
}

func sharedOf(t *testing.T, s *Store, service int64, now time.Time) bool {
	t.Helper()
	ok, err := s.SalamanderShared(context.Background(), service, now)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// A database at schema 19 with hy2-obfs (raycontrol before v0.36.1 gave
// every device the service's S): migrated to 20, S is accepted for
// SalamanderSharedWindow from the upgrade, and not after, nor for a
// service made since. A device revoked since the upgrade ends it at once
// for its user's services, everyone on them included, and for no other
// service; one revoked before changes nothing. A database at 19 without
// hy2-obfs has no window.
func TestMigration20SharedWindow(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "rayd.db")
	schemaAt(t, path, 19, salamanderSeed...)
	before := time.Now()
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	until, err := s.SalamanderSharedUntil(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d := until.Sub(before); d < SalamanderSharedWindow-time.Second || d > SalamanderSharedWindow+5*time.Second {
		t.Fatalf("the window ends %v after the upgrade, want %v", d, SalamanderSharedWindow)
	}
	now := time.Now()
	if !sharedOf(t, s, 1, now) || !sharedOf(t, s, 2, now) {
		t.Fatal("no window after the upgrade")
	}
	if sharedOf(t, s, 1, until) || !sharedOf(t, s, 2, until.Add(-time.Second)) {
		t.Fatal("the window's end")
	}
	later, err := s.CreateService(ctx, Service{Kind: "hy2-obfs", Name: "later", Enabled: true, Settings: "{}"})
	if err != nil {
		t.Fatal(err)
	}
	// Made in the window's first second, it counts as before (seconds):
	// the window starts at until less its length, not at before.
	from := until.Add(-SalamanderSharedWindow).Unix()
	if sharedOf(t, s, later.ID, now.Add(time.Second)) && later.CreatedAt.Unix() > from {
		t.Fatal("a service made after the upgrade takes its S")
	}
	if _, err := s.RevokeDevice(ctx, "a000000000000001"); err != nil {
		t.Fatal(err)
	}
	if sharedOf(t, s, 1, time.Now()) || !sharedOf(t, s, 2, time.Now()) {
		t.Fatal("a device of alice's revoked in the window: hy2o stays open, or hy2o2 closed")
	}
	// The closure is recorded: alice's service taken from her keeps it.
	if err := s.SetUserServices(ctx, "alice", nil); err != nil {
		t.Fatal(err)
	}
	if sharedOf(t, s, 1, time.Now()) {
		t.Fatal("the window opens again when the revoked device's user loses the service")
	}
	// A second start changes nothing.
	s.Close()
	if s, err = Open(ctx, path); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.SalamanderSharedUntil(ctx); !again.Equal(until) {
		t.Fatalf("a second start moved the window: %v, %v", again, until)
	}

	plain := filepath.Join(t.TempDir(), "rayd.db")
	schemaAt(t, plain, 19,
		`INSERT INTO services (id, kind, name, enabled, settings_json, created_at) VALUES (1, 'hy2-masq', 'hy2', 1, '{}', 1)`)
	p, err := Open(ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if until, err := p.SalamanderSharedUntil(ctx); err != nil || !until.IsZero() {
		t.Fatalf("no hy2-obfs, a window: %v %v", until, err)
	}
	if sharedOf(t, p, 1, time.Now()) {
		t.Fatal("no window, S accepted")
	}
}

// A user deleted with an active device takes the device's revocation with
// it: the window closes for the user's hy2-obfs services all the same. A
// user with no device leaves it open.
func TestSalamanderSharedUserDeleted(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "rayd.db")
	schemaAt(t, path, 19, append(salamanderSeed,
		`INSERT INTO users (id, name, enabled, created_at) VALUES (4, 'dave', 1, 1)`,
		`INSERT INTO user_services (user_id, service_id) VALUES (4, 2)`)...)
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	must(t, s.DeleteUser(ctx, "dave"))
	if !sharedOf(t, s, 2, time.Now()) {
		t.Fatal("a user without devices deleted closed the window")
	}
	must(t, s.DeleteUser(ctx, "bob"))
	if sharedOf(t, s, 1, time.Now()) || !sharedOf(t, s, 2, time.Now()) {
		t.Fatal("bob deleted with his device: hy2o open, or hy2o2 closed")
	}
	// A revocation then a deletion: the revocation's record stays.
	if _, err := s.RevokeDevice(ctx, "c000000000000001"); err != nil {
		t.Fatal(err)
	}
	must(t, s.DeleteUser(ctx, "carol"))
	if sharedOf(t, s, 2, time.Now()) {
		t.Fatal("carol's revoked device, gone with her, opened the window again")
	}
}

// A restore takes the node's shared window, not the one rayd init opened
// on the restored copy (a backup from before schema 20): that one would
// take S for 72 hours more, past the revocations since the node's own
// began. A rollback keeps the copy's window when it is another (the copy
// is from before the upgrade: the update after opens one anew), and takes
// the node's closures when it is the same.
func TestCarrySalamanderShared(t *testing.T) {
	ctx := context.Background()
	t0 := time.Now().Unix()
	node := fmt.Appendf(nil, "%d %d 7", t0-100, t0+3600)
	f := newRestoreFix(t, func(s *Store) { must(t, s.SetSetting(ctx, settingSalamanderShared, node)) })
	b := f.open(t, f.backup)
	must(t, b.SetSetting(ctx, settingSalamanderShared, fmt.Appendf(nil, "%d %d", t0, t0+3*86400))) // rayd init's
	b.Close()
	if _, err := CarryRestore(ctx, f.backup, f.current, ""); err != nil {
		t.Fatal(err)
	}
	b = f.open(t, f.backup)
	if v, err := b.GetSetting(ctx, settingSalamanderShared); err != nil || string(v) != string(node) {
		t.Fatalf("restored: %q %v, want the node's %q", v, err, node)
	}
	// None on the node: none restored.
	must(t, b.DeleteSetting(ctx, settingSalamanderShared))
	b.Close()
	c := f.open(t, f.current)
	must(t, c.DeleteSetting(ctx, settingSalamanderShared))
	c.Close()
	b = f.open(t, f.backup)
	must(t, b.SetSetting(ctx, settingSalamanderShared, fmt.Appendf(nil, "%d %d", t0, t0+3*86400)))
	b.Close()
	if _, err := CarryRestore(ctx, f.backup, f.current, ""); err != nil {
		t.Fatal(err)
	}
	b = f.open(t, f.backup)
	if _, err := b.GetSetting(ctx, settingSalamanderShared); !errors.Is(err, ErrNotFound) {
		t.Fatalf("restored a window the node never had: %v", err)
	}
	b.Close()

	// Rollback.
	for _, tc := range []struct {
		name, saved, cur, want string
	}{
		{"same window", fmt.Sprintf("%d %d", t0-100, t0+3600), fmt.Sprintf("%d %d 3", t0-100, t0+3600), fmt.Sprintf("%d %d 3", t0-100, t0+3600)},
		{"another", fmt.Sprintf("%d %d", t0, t0+3600), fmt.Sprintf("%d %d 3", t0-100, t0+3600), fmt.Sprintf("%d %d", t0, t0+3600)},
		{"none in the copy", "", fmt.Sprintf("%d %d 3", t0-100, t0+3600), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			saved, current := filepath.Join(dir, "saved.db"), filepath.Join(dir, "rayd.db")
			for path, v := range map[string]string{saved: tc.saved, current: tc.cur} {
				s, err := Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				if v != "" {
					must(t, s.SetSetting(ctx, settingSalamanderShared, []byte(v)))
				}
				s.Close()
			}
			must(t, CarryRevocations(ctx, saved, current))
			s, err := Open(ctx, saved)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			v, err := s.GetSetting(ctx, settingSalamanderShared)
			if tc.want == "" && !errors.Is(err, ErrNotFound) || tc.want != "" && string(v) != tc.want {
				t.Fatalf("%q %v, want %q", v, err, tc.want)
			}
		})
	}
}

// A revocation that a rollback carries into a copy at schema 20 (no
// revokeDevice ran there) closes the copy's window too.
func TestSalamanderSharedCarriedRevocation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	saved, current := filepath.Join(dir, "saved.db"), filepath.Join(dir, "rayd.db")
	schemaAt(t, saved, 19, salamanderSeed...)
	s, err := Open(ctx, saved) // to 20: the window opens
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	copyFile(t, saved, current)
	c, err := Open(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.RevokeDevice(ctx, "b000000000000001"); err != nil {
		t.Fatal(err)
	}
	// The node's record of the closure aside: the devices say it.
	must(t, c.SetSetting(ctx, settingSalamanderShared, []byte("0 0")))
	c.Close()
	must(t, CarryRevocations(ctx, saved, current))
	s, err = Open(ctx, saved)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if sharedOf(t, s, 1, time.Now()) || !sharedOf(t, s, 2, time.Now()) {
		t.Fatal("bob's device revoked on the node since the copy: hy2o open, or hy2o2 closed")
	}
}
