package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// lanUser makes a user with a Yggdrasil service and LAN on, and its devices.
func lanUser(t *testing.T, s *Store, name string, devices ...string) (User, []Device) {
	t.Helper()
	ctx := context.Background()
	ygg, err := s.ServiceByName(ctx, "ygg")
	if errors.Is(err, ErrNotFound) {
		ygg, err = s.CreateService(ctx, Service{Kind: "yggdrasil", Name: "ygg", Enabled: true})
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, User{Name: name, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	must(t, s.SetUserServices(ctx, name, []int64{ygg.ID}))
	u, err := s.SetUserLAN(ctx, name, true)
	if err != nil {
		t.Fatal(err)
	}
	var out []Device
	for _, d := range devices {
		dev, _, err := s.CreateDevice(ctx, name, d, "user")
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, dev)
	}
	return u, out
}

func (s *Store) lanKey(t *testing.T, name string) []byte {
	t.Helper()
	var key []byte
	if err := s.db.QueryRow(`SELECT lan_key FROM users WHERE name = ?`, name).Scan(&key); err != nil {
		t.Fatal(err)
	}
	return key
}

// The update to v0.23.0 (lan-v1 §6): every user and device from before has
// LAN off, and no key.
func TestLANMigration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "rayd.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	// Back to schema 12, as v0.22.0 left it, with a user and devices.
	for _, q := range []string{
		`DELETE FROM schema_migrations WHERE version = 13`,
		`ALTER TABLE users DROP COLUMN lan`, `ALTER TABLE users DROP COLUMN lan_key`,
		`ALTER TABLE devices DROP COLUMN lan`, `ALTER TABLE devices DROP COLUMN lan_at`,
		`INSERT INTO users (name, enabled, created_at) VALUES ('alice', 1, 1)`,
		`INSERT INTO devices (id, user_id, name, role, spa_key, created_at, revoked_at) VALUES
			('0123456789abcdef', (SELECT id FROM users WHERE name = 'alice'), 'phone', 'user', x'00', 1, NULL),
			('fedcba9876543210', (SELECT id FROM users WHERE name = 'alice'), 'old', 'user', x'01', 1, 2)`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	s.Close()
	if s, err = Open(ctx, path); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if v, err := Schema(ctx, path); err != nil || v != 13 {
		t.Fatalf("schema %d %v", v, err)
	}
	u, err := s.UserByName(ctx, "alice")
	if err != nil || u.LAN {
		t.Fatalf("%+v %v", u, err)
	}
	if key := s.lanKey(t, "alice"); key != nil {
		t.Fatalf("a key %x", key)
	}
	devs, err := s.ListDevices(ctx, "alice")
	if err != nil || len(devs) != 2 || devs[0].LAN || devs[1].LAN {
		t.Fatalf("%+v %v", devs, err)
	}
	if key, list, err := s.LANDevices(ctx, u.ID); err != nil || key != nil || list != nil {
		t.Fatalf("%x %v %v", key, list, err)
	}
	// The revoked device stays revoked, and its revocation makes no key.
	if err := s.RevokeDevice(ctx, "0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if key := s.lanKey(t, "alice"); key != nil {
		t.Fatalf("a key after a revocation with LAN off: %x", key)
	}
}

// rayctl user lan NAME on|off (lan-v1 §1.1): only with a Yggdrasil service;
// a new key at every on, none after off.
func TestSetUserLAN(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.CreateUser(ctx, User{Name: "bob", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	hy, err := s.CreateService(ctx, Service{Kind: "hy2-masq", Name: "hy", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	must(t, s.SetUserServices(ctx, "bob", []int64{hy.ID}))
	if _, err := s.SetUserLAN(ctx, "bob", true); !errors.Is(err, ErrInvalid) {
		t.Fatalf("on without Yggdrasil: %v", err)
	}
	if u, err := s.UserByName(ctx, "bob"); err != nil || u.LAN || s.lanKey(t, "bob") != nil {
		t.Fatalf("refused, yet %+v %v", u, err)
	}
	// Off needs nothing.
	if u, err := s.SetUserLAN(ctx, "bob", false); err != nil || u.LAN {
		t.Fatalf("off: %+v %v", u, err)
	}
	if _, err := s.SetUserLAN(ctx, "nobody", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nobody: %v", err)
	}
	// A Yggdrasil service that is disabled carries no LAN.
	ygg, err := s.CreateService(ctx, Service{Kind: "yggdrasil", Name: "ygg-off", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	must(t, s.SetUserServices(ctx, "bob", []int64{hy.ID, ygg.ID}))
	must(t, s.SetServiceEnabled(ctx, "ygg-off", false))
	if _, err := s.SetUserLAN(ctx, "bob", true); !errors.Is(err, ErrInvalid) {
		t.Fatalf("on with a disabled Yggdrasil: %v", err)
	}
	must(t, s.SetServiceEnabled(ctx, "ygg-off", true))
	if u, err := s.SetUserLAN(ctx, "bob", true); err != nil || !u.LAN {
		t.Fatalf("on with an enabled Yggdrasil: %+v %v", u, err)
	}
	must(t, s.SetUserServices(ctx, "bob", []int64{hy.ID}))
	must(t, s.DeleteService(ctx, "ygg-off"))

	u, _ := lanUser(t, s, "alice", "phone")
	if !u.LAN {
		t.Fatalf("%+v", u)
	}
	k1 := s.lanKey(t, "alice")
	if len(k1) != LANKeySize {
		t.Fatalf("key %x", k1)
	}
	if _, err := s.SetUserLAN(ctx, "alice", true); err != nil {
		t.Fatal(err)
	}
	k2 := s.lanKey(t, "alice")
	if len(k2) != LANKeySize || bytes.Equal(k1, k2) {
		t.Fatalf("on again: %x, then %x", k1, k2)
	}
	users, err := s.ListUsers(ctx)
	if err != nil || !slices.ContainsFunc(users, func(u User) bool { return u.Name == "alice" && u.LAN }) {
		t.Fatalf("%+v %v", users, err)
	}
	if u, err := s.SetUserLAN(ctx, "alice", false); err != nil || u.LAN || s.lanKey(t, "alice") != nil {
		t.Fatalf("off: %+v %v %x", u, err, s.lanKey(t, "alice"))
	}
	if key, list, err := s.LANDevices(ctx, u.ID); err != nil || key != nil || list != nil {
		t.Fatalf("off: %x %v %v", key, list, err)
	}
}

// A device's consent (lan-v1 §1.1, §4.4): written when it changes, showing
// itself once a minute at most, hiding itself at once.
func TestSetDeviceLAN(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })
	_, devs := lanUser(t, s, "alice", "phone", "laptop")
	phone := devs[0].ID
	set := func(on bool) bool {
		t.Helper()
		changed, err := s.SetDeviceLAN(ctx, phone, on, LANShowEvery)
		if err != nil {
			t.Fatal(err)
		}
		return changed
	}
	shown := func() bool {
		t.Helper()
		list, err := s.ListDevices(ctx, "alice")
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range list {
			if d.ID == phone {
				return d.LAN
			}
		}
		t.Fatal("no phone")
		return false
	}
	if set(false) || shown() {
		t.Fatal("off at first: a change")
	}
	if !set(true) || !shown() {
		t.Fatal("on: not written")
	}
	if set(true) {
		t.Fatal("on again: written")
	}
	now = now.Add(time.Second)
	if !set(false) || shown() {
		t.Fatal("off a second later: not written at once")
	}
	now = now.Add(30 * time.Second)
	if set(true) || shown() {
		t.Fatal("on within the minute: written")
	}
	now = now.Add(29 * time.Second) // 59 s after the last change
	if set(true) || shown() {
		t.Fatal("on 59 s after the last change: written")
	}
	now = now.Add(time.Second)
	if !set(true) || !shown() {
		t.Fatal("on a minute after the last change: not written")
	}
	// A clock set back does not hold the device hidden for the hour.
	if !set(false) {
		t.Fatal("off")
	}
	now = now.Add(-time.Hour)
	if !set(true) {
		t.Fatal("after the clock went back")
	}
	if changed, err := s.SetDeviceLAN(ctx, "0000000000000000", true, LANShowEvery); err != nil || changed {
		t.Fatalf("an unknown device: %v %v", changed, err)
	}
	now = now.Add(time.Hour)
	must(t, s.RevokeDevice(ctx, devs[1].ID))
	if changed, err := s.SetDeviceLAN(ctx, devs[1].ID, true, LANShowEvery); err != nil || changed {
		t.Fatalf("a revoked device: %v %v", changed, err)
	}
}

// LANDevices: the user's key and the devices that show themselves and are
// not revoked, in the order they were added; a revocation renews the key of
// its user only (lan-v1 §3, §4.2).
func TestLANDevicesAndRevocation(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { now = now.Add(time.Second); return now })
	u, devs := lanUser(t, s, "alice", "tablet", "phone", "laptop", "watch")
	_, bobs := lanUser(t, s, "bob", "phone")
	for _, d := range append(devs[:3:3], bobs...) {
		if changed, err := s.SetDeviceLAN(ctx, d.ID, true, LANShowEvery); err != nil || !changed {
			t.Fatalf("%s: %v %v", d.Name, changed, err)
		}
	}
	key, list, err := s.LANDevices(ctx, u.ID)
	if err != nil || !bytes.Equal(key, s.lanKey(t, "alice")) {
		t.Fatalf("%x %v", key, err)
	}
	var names []string
	for _, d := range list {
		names = append(names, d.Name)
		if d.Key == ([32]byte{}) || d.CreatedAt.IsZero() {
			t.Errorf("%s: %+v", d.Name, d)
		}
	}
	// The watch has not shown itself; the order is the order of adding.
	if !slices.Equal(names, []string{"tablet", "phone", "laptop"}) {
		t.Fatalf("%v", names)
	}
	bobKey := s.lanKey(t, "bob")

	must(t, s.RevokeDevice(ctx, devs[1].ID))
	key2, list, err := s.LANDevices(ctx, u.ID)
	if err != nil || len(key2) != LANKeySize || bytes.Equal(key, key2) {
		t.Fatalf("revocation: the key %x, then %x (%v)", key, key2, err)
	}
	names = nil
	for _, d := range list {
		names = append(names, d.Name)
	}
	if !slices.Equal(names, []string{"tablet", "laptop"}) {
		t.Fatalf("after the revocation: %v", names)
	}
	if !bytes.Equal(bobKey, s.lanKey(t, "bob")) {
		t.Fatal("another user's key changed")
	}
	// A revocation of one already revoked (a retry: no error), or of none:
	// nothing changes.
	if err := s.RevokeDevice(ctx, devs[1].ID); err != nil {
		t.Fatalf("again: %v", err)
	}
	if err := s.RevokeDevice(ctx, "0000000000000000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("none: %v", err)
	}
	if !bytes.Equal(key2, s.lanKey(t, "alice")) {
		t.Fatal("the key changed without a revocation")
	}
	// The render's view: each device not revoked, with its consent.
	secrets, err := s.ActiveDeviceSecrets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lan := map[string]bool{}
	for _, d := range secrets[u.ID] {
		lan[d.ID] = d.LAN
	}
	if len(lan) != 3 || !lan[devs[0].ID] || !lan[devs[2].ID] || lan[devs[3].ID] {
		t.Fatalf("%v", lan)
	}
}
