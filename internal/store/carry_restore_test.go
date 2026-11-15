package store

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// thisNode gives the database the SPA parameters of a node, whose node_id
// CarryRestore compares: a copy of it is of the same node.
func thisNode(t *testing.T, s *Store) {
	t.Helper()
	must(t, s.SetSetting(context.Background(), settingSPAParams, []byte(`{"node_id":"00112233445566778899aabbccddeeff"}`)))
}

// restoreFix is a node with REALITY, DoH and naive, five users on all
// three with a phone each, and a backup of it.
type restoreFix struct {
	dir, current, backup string
	reality, doh, naive  int64
	ids                  map[string]int64
	phones               map[string]Device
}

var restoreUsers = []string{"alice", "bob", "carol", "dave", "erin"}

func newRestoreFix(t *testing.T, seed func(s *Store)) restoreFix {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	f := restoreFix{dir: dir, current: filepath.Join(dir, "rayd.db"), backup: filepath.Join(dir, "backup.db"),
		ids: map[string]int64{}, phones: map[string]Device{}}
	s, err := Open(ctx, f.current)
	if err != nil {
		t.Fatal(err)
	}
	thisNode(t, s)
	var svcs []int64
	for _, k := range []string{"reality", "doh", "naive"} {
		svc, err := s.CreateService(ctx, Service{Kind: k, Name: k, Enabled: true, Settings: "{}"})
		if err != nil {
			t.Fatal(err)
		}
		svcs = append(svcs, svc.ID)
	}
	f.reality, f.doh, f.naive = svcs[0], svcs[1], svcs[2]
	var all []int64
	for _, n := range restoreUsers {
		u, err := s.CreateUser(ctx, User{Name: n, Enabled: true, Services: svcs})
		if err != nil {
			t.Fatal(err)
		}
		f.ids[n] = u.ID
		all = append(all, u.ID)
		d, _, err := s.CreateDevice(ctx, n, "phone", "user")
		if err != nil {
			t.Fatal(err)
		}
		f.phones[n] = d
	}
	for _, svc := range svcs {
		if _, err := s.Credentials(ctx, svc, all, NewUUID); err != nil {
			t.Fatal(err)
		}
	}
	if seed != nil {
		seed(s)
	}
	s.Close()
	copyFile(t, f.current, f.backup)
	return f
}

func (f restoreFix) open(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// secrets reads every user's current secret per service, by name.
func secrets(t *testing.T, path string) map[string]map[int64]string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	out := map[string]map[int64]string{}
	for _, l := range strings.Split(strings.TrimSpace(rows(t, db,
		`SELECT u.name, c.service_id, c.secret FROM credentials c JOIN users u ON u.id = c.user_id`)), "\n") {
		if l == "" {
			continue
		}
		var n, sec string
		var svc int64
		if _, err := fmt.Sscan(l, &n, &svc, &sec); err != nil {
			t.Fatal(err)
		}
		if out[n] == nil {
			out[n] = map[int64]string{}
		}
		out[n][svc] = sec
	}
	return out
}

func auditOf(t *testing.T, path string) []AuditEntry {
	t.Helper()
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, err := s.ListAudit(context.Background(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func hasAudit(a []AuditEntry, action, target string) bool {
	return slices.ContainsFunc(a, func(e AuditEntry) bool { return e.Action == action && strings.HasPrefix(e.Target, target) })
}

// rayctl restore on the node the backup is of: every credential both have
// stays as the node has it now, with no audit line needed: a renewal
// (alice, whose LAN key is current's too) and an ordinary rotation (erin)
// since the backup stay; a device revoked since is carried and its user
// renewed (dave); a device made and revoked since renews its user
// (carol). The node's schema is 15 with no shared DoH window, so the
// renewals keep DoH, as RevokeDevice does. Every change has its audit
// line, without a secret.
func TestCarryRestoreKeepsCurrent(t *testing.T) {
	ctx := context.Background()
	f := newRestoreFix(t, func(s *Store) {
		if _, err := s.db.Exec(`UPDATE users SET lan = 1, lan_key = randomblob(?) WHERE name = 'alice'`, LANKeySize); err != nil {
			t.Fatal(err)
		}
	})
	before := secrets(t, f.backup)
	s := f.open(t, f.current)
	aliceKey := s.lanKey(t, "alice")
	if _, err := s.RenewUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE credentials SET prev_secret = secret, secret = '00000000-0000-4000-8000-00000000e1e1',
		prev_until = 9999999999 WHERE user_id = ?`, f.ids["erin"]); err != nil {
		t.Fatal(err)
	}
	watch, _, _ := s.CreateDevice(ctx, "carol", "watch", "user")
	if _, err := s.RevokeDevice(ctx, watch.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeDevice(ctx, f.phones["dave"].ID); err != nil {
		t.Fatal(err)
	}
	aliceKeyNow := s.lanKey(t, "alice")
	s.Close()
	now := secrets(t, f.current)

	r, err := CarryRestore(ctx, f.backup, f.current, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Foreign || r.Kept != 3 || len(r.Carried) != 1 || r.Carried[0].ID != f.phones["dave"].ID || len(r.Unknown) != 0 ||
		!slices.Equal(r.New, []Renewal{{User: "carol", Why: "a device added and revoked here since the backup"}}) ||
		len(r.Added) != 1 || r.Added[0].CarriedDevice != (CarriedDevice{ID: watch.ID, User: "carol", Name: "watch"}) || !r.Added[0].Revoked {
		t.Fatalf("%+v", r)
	}
	got := secrets(t, f.backup)
	for _, n := range []string{"alice", "bob", "erin"} {
		for svc, sec := range got[n] {
			if sec != now[n][svc] {
				t.Errorf("%s's credential on %d is %s, the node's %s (the backup's %s)", n, svc, sec, now[n][svc], before[n][svc])
			}
		}
	}
	for _, n := range []string{"carol", "dave"} {
		for _, svc := range []int64{f.reality, f.naive} {
			if sec := got[n][svc]; sec == now[n][svc] || sec == before[n][svc] || !isUUID(sec) {
				t.Errorf("%s's credential on %d is not new: %s", n, svc, sec)
			}
		}
		// No shared token can be open on a schema-15 copy without its
		// window: DoH stays, as RevokeDevice keeps it.
		if got[n][f.doh] != now[n][f.doh] {
			t.Errorf("%s's DoH secret renewed for nothing: %s, the node's %s", n, got[n][f.doh], now[n][f.doh])
		}
	}
	b := f.open(t, f.backup)
	if k := b.lanKey(t, "alice"); !bytes.Equal(k, aliceKeyNow) || bytes.Equal(k, aliceKey) {
		t.Errorf("alice's LAN key %x, the node's %x, the backup's %x", k, aliceKeyNow, aliceKey)
	}
	b.Close()
	a := auditOf(t, f.backup)
	for _, want := range [][2]string{
		{"user.carry:restore", "3 users: credentials and LAN keys as on the node"},
		{"user.renew:restore", "carol: 2 credentials new, a device added and revoked here since the backup"},
		{"user.renew:restore", "dave: 2 credentials new, a device of the user revoked"},
		{"device.revoke:restore", f.phones["dave"].ID + " dave/phone"},
	} {
		if !hasAudit(a, want[0], want[1]) {
			t.Errorf("no audit line %s %q in %+v", want[0], want[1], a)
		}
	}
	for _, e := range a {
		for _, m := range []map[string]map[int64]string{before, now, got} {
			for _, svcs := range m {
				for _, sec := range svcs {
					if strings.Contains(e.Target, sec) {
						t.Errorf("a secret in the audit: %+v", e)
					}
				}
			}
		}
	}
}

// A device enrolled since the backup and still active (bob's tablet, from
// an invite that leaked, say) is not in the backup and goes with the
// restore, but it fetched bob's credentials, current's: bob gets new ones,
// and restore lists the device. A device added since by a user dave who
// also had one revoked since is listed, and dave renewed once. erin, with
// nothing added, keeps current's.
func TestCarryRestoreDeviceAdded(t *testing.T) {
	ctx := context.Background()
	f := newRestoreFix(t, nil)
	s := f.open(t, f.current)
	tablet, _, err := s.CreateDevice(ctx, "bob", "tablet", "user")
	if err != nil {
		t.Fatal(err)
	}
	laptop, _, _ := s.CreateDevice(ctx, "dave", "laptop", "user")
	if _, err := s.RevokeDevice(ctx, f.phones["dave"].ID); err != nil {
		t.Fatal(err)
	}
	s.Close()
	now := secrets(t, f.current)
	r, err := CarryRestore(ctx, f.backup, f.current, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Foreign || r.Kept != 3 || len(r.Carried) != 1 ||
		!slices.Equal(r.New, []Renewal{{User: "bob", Why: "a device added here since the backup, not in it"}}) {
		t.Fatalf("%+v", r)
	}
	if len(r.Added) != 2 || r.Added[0].CarriedDevice != (CarriedDevice{ID: tablet.ID, User: "bob", Name: "tablet"}) || r.Added[0].Revoked ||
		r.Added[1].CarriedDevice != (CarriedDevice{ID: laptop.ID, User: "dave", Name: "laptop"}) {
		t.Fatalf("added %+v", r.Added)
	}
	got := secrets(t, f.backup)
	for _, n := range []string{"bob", "dave"} {
		for _, svc := range []int64{f.reality, f.naive} {
			if sec := got[n][svc]; sec == now[n][svc] || !isUUID(sec) {
				t.Errorf("%s's credential on %d is the one the added device fetched: %s", n, svc, sec)
			}
		}
	}
	for svc, sec := range got["erin"] {
		if sec != now["erin"][svc] {
			t.Errorf("erin's credential on %d changed", svc)
		}
	}
	if !hasAudit(auditOf(t, f.backup), "user.renew:restore", "bob: 2 credentials new, a device added here since the backup") {
		t.Error("no audit line for bob")
	}
}

// The reviewer's first case: the renewal's audit line is gone (rayd prunes
// them after 90 days), and the renewed secret still does not come back.
func TestCarryRestoreAuditPruned(t *testing.T) {
	ctx := context.Background()
	f := newRestoreFix(t, nil)
	before := secrets(t, f.backup)
	s := f.open(t, f.current)
	if _, err := s.RenewUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	must(t, s.Audit(ctx, "test", "user.renew", "alice: 3 credentials new", "ok"))
	must(t, s.PruneAudit(ctx, time.Now().Add(time.Hour)))
	s.Close()
	now := secrets(t, f.current)
	if _, err := CarryRestore(ctx, f.backup, f.current, ""); err != nil {
		t.Fatal(err)
	}
	for svc, sec := range secrets(t, f.backup)["alice"] {
		if sec != now["alice"][svc] || sec == before["alice"][svc] {
			t.Errorf("alice's credential on %d: %s, the node's %s, the leaked %s", svc, sec, now["alice"][svc], before["alice"][svc])
		}
	}
}

// The reviewer's second case: the same backup restored twice. The first
// restore's result is the node's database for the second, and the secret
// renewed before the first does not come back with the second.
func TestCarryRestoreTwice(t *testing.T) {
	ctx := context.Background()
	f := newRestoreFix(t, nil)
	leaked := secrets(t, f.backup)["alice"]
	s := f.open(t, f.current)
	if _, err := s.RenewUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	renewed := secrets(t, f.current)["alice"]
	for i := range 2 {
		work := filepath.Join(f.dir, fmt.Sprintf("restore%d.db", i))
		copyFile(t, f.backup, work)
		r, err := CarryRestore(ctx, work, f.current, "")
		if err != nil || r.Kept != len(restoreUsers) {
			t.Fatalf("restore %d: %+v %v", i, r, err)
		}
		for svc, sec := range secrets(t, work)["alice"] {
			if sec != renewed[svc] || sec == leaked[svc] {
				t.Errorf("restore %d: alice's credential on %d is %s, renewed %s, leaked %s", i, svc, sec, renewed[svc], leaked[svc])
			}
		}
		copyFile(t, work, f.current) // rayctl restore's swap
	}
}

// A rollback (which copies no audit line from the newer database), then a
// restore of a backup older than both: the renewal made before the update
// and the one made after it, carried by the rollback, both stay.
func TestCarryRestoreAfterRollback(t *testing.T) {
	ctx := context.Background()
	f := newRestoreFix(t, nil)
	old := secrets(t, f.backup)
	s := f.open(t, f.current)
	if _, err := s.RenewUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	pre := filepath.Join(f.dir, "pre-update.db") // the update's copy
	copyFile(t, f.current, pre)
	s = f.open(t, f.current)
	if _, err := s.RenewUser(ctx, "bob"); err != nil { // on the new version
		t.Fatal(err)
	}
	s.Close()
	must(t, CarryRevocations(ctx, pre, f.current))
	if !hasAudit(auditOf(t, pre), "user.carry:rollback", "5 users: credentials and LAN keys as on the node") {
		t.Errorf("no audit line of the rollback's carry: %+v", auditOf(t, pre))
	}
	copyFile(t, pre, f.current) // rolled back
	want := secrets(t, f.current)
	if _, err := CarryRestore(ctx, f.backup, f.current, ""); err != nil {
		t.Fatal(err)
	}
	got := secrets(t, f.backup)
	for _, n := range []string{"alice", "bob"} {
		for svc, sec := range got[n] {
			if sec != want[n][svc] || sec == old[n][svc] {
				t.Errorf("%s's credential on %d: %s, the node's %s, the backup's %s", n, svc, sec, want[n][svc], old[n][svc])
			}
		}
	}
}

// A user deleted since the backup (bob), and one deleted and made again
// under the same name (alice: another creation time): the backup's are
// not current's, and who else knew their secrets is not known. They come
// back with new credentials and a new LAN key, said so; their devices are
// Unknown.
func TestCarryRestoreUserRecreated(t *testing.T) {
	ctx := context.Background()
	f := newRestoreFix(t, func(s *Store) {
		if _, err := s.db.Exec(`UPDATE users SET lan = 1, lan_key = randomblob(?) WHERE name = 'alice'`, LANKeySize); err != nil {
			t.Fatal(err)
		}
	})
	before := secrets(t, f.backup)
	s := f.open(t, f.current)
	aliceKey := s.lanKey(t, "alice")
	must(t, s.DeleteUser(ctx, "alice"))
	must(t, s.DeleteUser(ctx, "bob"))
	a, err := s.CreateUser(ctx, User{Name: "alice", Enabled: true, Services: []int64{f.reality}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE users SET created_at = created_at + 100 WHERE id = ?`, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Credentials(ctx, f.reality, []int64{a.ID}, NewUUID); err != nil {
		t.Fatal(err)
	}
	s.Close()
	now := secrets(t, f.current)
	r, err := CarryRestore(ctx, f.backup, f.current, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Foreign || r.Kept != 3 || !slices.Equal(r.New, []Renewal{
		{User: "alice", Why: "deleted and made again here since the backup"},
		{User: "bob", Why: "deleted here since the backup"},
	}) || len(r.Unknown) != 2 {
		t.Fatalf("%+v", r)
	}
	got := secrets(t, f.backup)
	for _, n := range []string{"alice", "bob"} {
		if len(got[n]) != 3 {
			t.Fatalf("%s's credentials: %v", n, got[n])
		}
		for svc, sec := range got[n] {
			if sec == before[n][svc] || sec == now[n][svc] || !isUUID(sec) {
				t.Errorf("%s's credential on %d is not new: %s", n, svc, sec)
			}
		}
	}
	b := f.open(t, f.backup)
	defer b.Close()
	if k := b.lanKey(t, "alice"); len(k) != LANKeySize || bytes.Equal(k, aliceKey) {
		t.Errorf("alice's LAN key %x, the backup's %x", k, aliceKey)
	}
	if !hasAudit(auditOf(t, f.backup), "user.renew:restore", "alice: 3 credentials new, deleted and made again") {
		t.Error("no audit line for alice")
	}
}

// A service deleted since the backup: its credentials are in the backup
// only, and a renewal since may have retired them. They are new; the
// rest is the node's.
func TestCarryRestoreServiceDeleted(t *testing.T) {
	ctx := context.Background()
	f := newRestoreFix(t, nil)
	before := secrets(t, f.backup)
	s := f.open(t, f.current)
	must(t, s.DeleteService(ctx, "naive"))
	s.Close()
	now := secrets(t, f.current)
	r, err := CarryRestore(ctx, f.backup, f.current, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Kept != 0 || len(r.New) != len(restoreUsers) || r.New[0].Why != "a service of theirs deleted here since the backup" {
		t.Fatalf("%+v", r)
	}
	got := secrets(t, f.backup)
	for _, n := range restoreUsers {
		if got[n][f.reality] != now[n][f.reality] || got[n][f.doh] != now[n][f.doh] {
			t.Errorf("%s's other credentials changed", n)
		}
		if sec := got[n][f.naive]; sec == before[n][f.naive] || !isUUID(sec) {
			t.Errorf("%s's credential on the deleted service is the backup's", n)
		}
	}
}

// Another node's database (a new host): nothing to carry, nothing written,
// every active device Unknown.
func TestCarryRestoreForeign(t *testing.T) {
	ctx := context.Background()
	f := newRestoreFix(t, nil)
	before := secrets(t, f.backup)
	other := filepath.Join(f.dir, "other.db")
	o := f.open(t, other)
	must(t, o.SetSetting(ctx, settingSPAParams, []byte(`{"node_id":"ffeeddccbbaa99887766554433221100"}`)))
	o.Close()
	r, err := CarryRestore(ctx, f.backup, other, "")
	if err != nil || !r.Foreign || r.Kept != 0 || len(r.New) != 0 || len(r.Unknown) != len(restoreUsers) {
		t.Fatalf("%+v %v", r, err)
	}
	got := secrets(t, f.backup)
	for n, svcs := range before {
		for svc, sec := range svcs {
			if got[n][svc] != sec {
				t.Errorf("%s's credential changed against another node", n)
			}
		}
	}
	if hasAudit(auditOf(t, f.backup), "user.carry:restore", "") {
		t.Error("an audit line against another node")
	}
}

// With the copy's shared DoH window open, a user's DoH secret is a token
// a revoked device may hold: the renewals of a restore renew it too, both
// for a device revoked since (dave) and one made and revoked since
// (carol), and the restored node does not take the old one.
func TestCarryRestoreDoHWindowOpen(t *testing.T) {
	ctx := context.Background()
	t0 := time.Now().Unix()
	f := newRestoreFix(t, func(s *Store) {
		must(t, s.SetSetting(context.Background(), settingDoHShared, fmt.Appendf(nil, "%d %d", t0-10, t0+3600)))
	})
	before := secrets(t, f.backup)
	s := f.open(t, f.current)
	watch, _, _ := s.CreateDevice(ctx, "carol", "watch", "user")
	if _, err := s.RevokeDevice(ctx, watch.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeDevice(ctx, f.phones["dave"].ID); err != nil {
		t.Fatal(err)
	}
	s.Close()
	now := secrets(t, f.current)
	if _, err := CarryRestore(ctx, f.backup, f.current, ""); err != nil {
		t.Fatal(err)
	}
	got := secrets(t, f.backup)
	b := f.open(t, f.backup)
	defer b.Close()
	tokens, err := b.DoHTokens(ctx, f.doh, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"carol", "dave"} {
		if sec := got[n][f.doh]; sec == now[n][f.doh] || sec == before[n][f.doh] {
			t.Errorf("%s's DoH secret kept in an open window: %s", n, sec)
		}
		if tokens[before[n][f.doh]] {
			t.Errorf("the restored node takes %s's old DoH secret as a token", n)
		}
	}
}

// A rollback's carry renews DoH with the rest when the copy is older than
// schema 15 (its rayd takes the secret as the token), and keeps it when
// the copy is at 15 with no window open, as RevokeDevice does.
func TestCarryRevocationsDoH(t *testing.T) {
	ctx := context.Background()
	key := strings.Repeat("01", 32)
	seed := []string{
		`INSERT INTO services (id, kind, name, enabled, settings_json, created_at) VALUES (1, 'doh', 'doh', 1, '{}', 1), (2, 'naive', 'naive', 1, '{}', 1)`,
		`INSERT INTO users (id, name, enabled, created_at) VALUES (1, 'alice', 1, 1)`,
		`INSERT INTO user_services (user_id, service_id) VALUES (1, 1), (1, 2)`,
		`INSERT INTO credentials (user_id, service_id, secret, created_at, rotated_at) VALUES (1, 1, 'a-doh', 1, 1), (1, 2, 'a-pw', 1, 1)`,
		`INSERT INTO devices (id, user_id, name, role, spa_key, created_at) VALUES
			('a000000000000001', 1, 'a', 'user', x'` + key + `', 10), ('a000000000000002', 1, 'b', 'user', x'` + key + `', 10)`,
	}
	t.Run("schema 14", func(t *testing.T) {
		dir := t.TempDir()
		saved, current := filepath.Join(dir, "saved.db"), filepath.Join(dir, "rayd.db")
		schemaAt(t, saved, 14, seed...)
		copyFile(t, saved, current)
		s, err := Open(ctx, current) // to 15: the window opens
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.RevokeDevice(ctx, "a000000000000001"); err != nil {
			t.Fatal(err)
		}
		s.Close()
		must(t, CarryRevocations(ctx, saved, current))
		if got := secrets(t, saved)["alice"]; got[1] == "a-doh" || got[2] == "a-pw" {
			t.Errorf("a copy at 14 keeps a secret the revoked device knew: %v", got)
		}
	})
	t.Run("schema 15", func(t *testing.T) {
		dir := t.TempDir()
		saved, current := filepath.Join(dir, "saved.db"), filepath.Join(dir, "rayd.db")
		schemaAt(t, saved, 15, seed...)
		copyFile(t, saved, current)
		s, err := Open(ctx, current)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.RevokeDevice(ctx, "a000000000000001"); err != nil {
			t.Fatal(err)
		}
		s.Close()
		must(t, CarryRevocations(ctx, saved, current))
		if got := secrets(t, saved)["alice"]; got[1] != "a-doh" || got[2] == "a-pw" {
			t.Errorf("a copy at 15 without a window: %v", got)
		}
	})
}

// From schema 13 to 15 in one start, a device revoked at 13: the step of
// 14 renews DoH too, so the shared window that 15 opens does not take the
// secret the revoked device knew.
func TestMigration13To15RevokedDoH(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "rayd.db")
	key := strings.Repeat("02", 32)
	schemaAt(t, path, 13,
		`INSERT INTO services (id, kind, name, enabled, settings_json, created_at) VALUES (1, 'doh', 'doh', 1, '{}', 1)`,
		`INSERT INTO users (id, name, enabled, created_at) VALUES (1, 'alice', 1, 1)`,
		`INSERT INTO user_services (user_id, service_id) VALUES (1, 1)`,
		`INSERT INTO credentials (user_id, service_id, secret, created_at, rotated_at) VALUES (1, 1, 'old-doh', 1, 1)`,
		`INSERT INTO devices (id, user_id, name, role, spa_key, created_at, revoked_at) VALUES
			('a000000000000001', 1, 'old', 'user', x'`+strings.Repeat("01", 32)+`', 10, 20),
			('a000000000000002', 1, 'phone', 'user', x'`+key+`', 10, NULL)`)
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tokens, err := s.DoHTokens(ctx, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if tokens["old-doh"] || tokens[DoHDeviceToken("old-doh", spaKey(2))] {
		t.Fatalf("the secret of before the revocation is taken: %v", tokens)
	}
	if len(tokens) != 2 { // the new secret, shared in the window, and the phone's token
		t.Fatalf("tokens %v", tokens)
	}
}

// update -rollback to schema 13, a device revoked on the older rayd after
// it, and the update again: the step of 14 renews only that device's user
// (bob), not a second time the users the first update renewed, whose
// credentials the rollback carried.
func TestRollbackThenUpdateRenewsOnce(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	saved, current := filepath.Join(dir, "saved.db"), filepath.Join(dir, "current.db")
	schemaAt(t, saved, 13, matrix13()...)
	copyFile(t, saved, current)
	s, err := Open(ctx, current) // the update: alice, carol, dave, frank renewed
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	must(t, CarryRevocations(ctx, saved, current))
	db, err := sql.Open("sqlite", "file:"+saved)
	if err != nil {
		t.Fatal(err)
	}
	carried := credsByRow(t, db)
	if v := rows(t, db, `SELECT value FROM settings WHERE key = '`+settingRenewedRevoked+`'`); v == "" {
		t.Error("no marker in the copy")
	}
	// v0.26.0 after the rollback: bob's phone revoked, no renewal.
	if _, err := db.Exec(`UPDATE devices SET revoked_at = ? WHERE id = 'b1'`, time.Now().Unix()+1); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err = Open(ctx, saved) // the update again
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got := credsByRow(t, s.db)
	for k, v := range got {
		if bob := strings.HasPrefix(k, "2/"); (v == carried[k]) == bob {
			t.Errorf("credential %s: %q, carried %q", k, v, carried[k])
		}
	}
	if n := rows(t, s.db, `SELECT target FROM audit_log WHERE action = 'user.renew:revoked-before'`); !strings.HasPrefix(n, "bob: 2 credentials new") ||
		strings.Count(n, "\n") != 1 {
		t.Errorf("the step's audit lines:\n%s", n)
	}
	if v := rows(t, s.db, `SELECT value FROM settings WHERE key = '`+settingRenewedRevoked+`'`); v != "" {
		t.Errorf("the marker stays: %q", v)
	}
}

// renewedBefore is the step of schema 14's audit lines in a database.
func renewedBefore(t *testing.T, db *sql.DB) string {
	t.Helper()
	return rows(t, db, `SELECT target FROM audit_log WHERE action = 'user.renew:revoked-before' ORDER BY target`)
}

// An update that fails before the new rayd ran (staging rayspa's unit,
// installing the binaries): failUpdate rolls back with the carry, and the
// database is at 13 still, its step never run. The copy gets no mark, so
// the next update renews every user with a device revoked; with the mark
// an earlier rollback left in both, that mark stays as it was, not moved
// to the failed update's time.
func TestRollbackFailedUpdate(t *testing.T) {
	ctx := context.Background()
	mark := func(t *testing.T, db *sql.DB) string {
		t.Helper()
		return strings.TrimSpace(rows(t, db, `SELECT CAST(value AS TEXT) FROM settings WHERE key = '`+settingRenewedRevoked+`'`))
	}
	t.Run("no mark", func(t *testing.T) {
		dir := t.TempDir()
		saved, current := filepath.Join(dir, "saved.db"), filepath.Join(dir, "rayd.db")
		schemaAt(t, saved, 13, matrix13()...)
		copyFile(t, saved, current)
		must(t, CarryRevocations(ctx, saved, current))
		db, err := sql.Open("sqlite", "file:"+saved)
		if err != nil {
			t.Fatal(err)
		}
		if m := mark(t, db); m != "" {
			t.Errorf("a mark %s after a failed update", m)
		}
		db.Close()
		s, err := Open(ctx, saved) // the next update
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		got := renewedBefore(t, s.db)
		for _, n := range []string{"alice", "carol", "dave", "frank"} {
			if !strings.Contains(got, n+": ") {
				t.Errorf("%s not renewed at the next update:\n%s", n, got)
			}
		}
		if strings.Count(got, "\n") != 4 {
			t.Errorf("renewed:\n%s", got)
		}
	})
	t.Run("earlier mark", func(t *testing.T) {
		dir := t.TempDir()
		saved, current := filepath.Join(dir, "saved.db"), filepath.Join(dir, "rayd.db")
		// The first rollback's mark at 44: carol's two (45, 46), dave's (47)
		// and frank's (48) revoked after it, on the older rayd.
		schemaAt(t, saved, 13, append(matrix13(),
			`INSERT INTO settings (key, value) VALUES ('`+settingRenewedRevoked+`', CAST('44' AS BLOB))`)...)
		copyFile(t, saved, current)
		must(t, CarryRevocations(ctx, saved, current))
		db, err := sql.Open("sqlite", "file:"+saved)
		if err != nil {
			t.Fatal(err)
		}
		if m := mark(t, db); m != "44" {
			t.Errorf("the mark %q, want the first rollback's 44", m)
		}
		db.Close()
		s, err := Open(ctx, saved)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if got := renewedBefore(t, s.db); strings.Contains(got, "alice") || strings.Count(got, "\n") != 3 {
			t.Errorf("renewed at the next update:\n%s", got)
		}
	})
}

// Two rollbacks: the first marks the copy at T1; the older rayd revokes
// bob's phone; an update copies the database (the mark in the copy) and
// its step renews bob; a second rollback carries that. The copy's mark
// stays T1 (markRenewed), not the second rollback's time, and the step of
// the next update renews from T1 on, bob included once more.
func TestTwoRollbacksKeepFirstMark(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	saved, current := filepath.Join(dir, "saved.db"), filepath.Join(dir, "rayd.db")
	schemaAt(t, saved, 13, matrix13()...)
	copyFile(t, saved, current)
	s, err := Open(ctx, current) // the first update
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	must(t, CarryRevocations(ctx, saved, current)) // the first rollback
	db, err := sql.Open("sqlite", "file:"+saved)
	if err != nil {
		t.Fatal(err)
	}
	t1 := time.Now().Unix() - 1000
	if _, err := db.Exec(`UPDATE settings SET value = CAST(? AS BLOB) WHERE key = ?`, strconv.FormatInt(t1, 10), settingRenewedRevoked); err != nil {
		t.Fatal(err)
	}
	// v0.26.0: bob's phone revoked, no renewal.
	if _, err := db.Exec(`UPDATE devices SET revoked_at = ? WHERE id = 'b1'`, t1+10); err != nil {
		t.Fatal(err)
	}
	db.Close()
	saved2 := filepath.Join(dir, "saved2.db") // the second update's copy
	copyFile(t, saved, saved2)
	copyFile(t, saved, current)
	if s, err = Open(ctx, current); err != nil { // the second update: bob renewed
		t.Fatal(err)
	}
	if got := renewedBefore(t, s.db); !strings.HasPrefix(got, "bob: ") || strings.Count(got, "\n") != 1 {
		t.Fatalf("the second update renewed:\n%s", got)
	}
	s.Close()
	must(t, CarryRevocations(ctx, saved2, current)) // the second rollback
	db, err = sql.Open("sqlite", "file:"+saved2)
	if err != nil {
		t.Fatal(err)
	}
	if m := strings.TrimSpace(rows(t, db, `SELECT CAST(value AS TEXT) FROM settings WHERE key = '`+settingRenewedRevoked+`'`)); m != strconv.FormatInt(t1, 10) {
		t.Errorf("the mark %q, want the first rollback's %d", m, t1)
	}
	db.Close()
}
