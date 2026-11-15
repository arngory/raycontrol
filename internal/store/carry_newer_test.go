package store

import (
	"context"
	"database/sql"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// at is a clock d from now, for a store's changes made later.
func at(d time.Duration) func() time.Time {
	return func() time.Time { return time.Now().Add(d) }
}

// unchanged fails unless the database at path has the secrets want and
// the devices revoked as in revoked: CarryRestore wrote nothing.
func unchanged(t *testing.T, path string, want map[string]map[int64]string, revoked []string) {
	t.Helper()
	if got := secrets(t, path); !maps.EqualFunc(got, want, maps.Equal) {
		t.Errorf("the backup's credentials changed:\n%v\nwas\n%v", got, want)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if got := strings.Fields(rows(t, db, `SELECT id FROM devices WHERE revoked_at IS NOT NULL ORDER BY id`)); !slices.Equal(got, revoked) {
		t.Errorf("revoked in the backup: %v, want %v", got, revoked)
	}
	if a := rows(t, db, `SELECT action FROM audit_log WHERE action LIKE '%:restore'`); a != "" {
		t.Errorf("the carry's audit lines in the backup:\n%s", a)
	}
}

// activeIDs are the IDs of devices.
func activeIDs(ds []CarriedDevice) []string {
	var out []string
	for _, d := range ds {
		out = append(out, d.ID)
	}
	slices.Sort(out)
	return out
}

// The reviewer's first case: backup A1 restored on a new host B (B has
// A's node_id from it); the operator goes back to A, where dave's phone is
// revoked and alice renewed after a leak, a backup A2; A2 restored on B.
// B's database is no later state of A2, and carrying would put A1's
// secrets over A2's: alice's leaked one back, dave's credentials as his
// revoked phone knows them. Nothing is carried; every device active in A2
// is in the warning. Also with alice renewed alone, and B's clock a day
// ahead of A's with changes of its own: the renewal is still seen (B's
// credential of alice's is A1's, stamped by A's clock).
func TestCarryRestoreBackupNewer(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name, want   string
		revoke, bAhd bool
	}{
		{"revoked and renewed", "dave/phone is revoked in the backup and active here", true, false},
		{"renewed, B's clock ahead", "alice's credential on ", false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newRestoreFix(t, nil)
			hostB := filepath.Join(f.dir, "hostB.db")
			copyFile(t, f.backup, hostB) // A1, restored on B as it is
			if c.bAhd {
				b := f.open(t, hostB)
				b.SetClock(at(24 * time.Hour))
				if _, err := b.CreateUser(ctx, User{Name: "zed", Enabled: true}); err != nil {
					t.Fatal(err)
				}
				must(t, b.Audit(ctx, "root", "user.add", "zed", "ok"))
				b.Close()
			}
			a := f.open(t, f.current)
			a.SetClock(at(time.Hour))
			if c.revoke {
				if _, err := a.RevokeDevice(ctx, f.phones["dave"].ID); err != nil {
					t.Fatal(err)
				}
				must(t, a.Audit(ctx, "root", "device.revoke", f.phones["dave"].ID+" dave/phone", "ok"))
			}
			if _, err := a.RenewUser(ctx, "alice"); err != nil {
				t.Fatal(err)
			}
			must(t, a.Audit(ctx, "root", "user.renew", "alice: 3 credentials new", "ok"))
			a.Close()
			a2 := filepath.Join(f.dir, "a2.db")
			copyFile(t, f.current, a2)
			want := secrets(t, a2)
			var revoked, active []string
			for _, n := range restoreUsers {
				if c.revoke && n == "dave" {
					revoked = append(revoked, f.phones[n].ID)
				} else {
					active = append(active, f.phones[n].ID)
				}
			}
			slices.Sort(active)

			r, err := CarryRestore(ctx, a2, hostB, "")
			if err != nil {
				t.Fatal(err)
			}
			if !r.Foreign || !strings.Contains(r.Newer, c.want) || r.Kept != 0 || len(r.Carried) != 0 || len(r.New) != 0 || len(r.Added) != 0 {
				t.Fatalf("%+v", r)
			}
			if got := activeIDs(r.Unknown); !slices.Equal(got, active) {
				t.Errorf("unknown %v, want every active device of the backup %v", got, active)
			}
			unchanged(t, a2, want, revoked)
		})
	}
}

// The reviewer's second case, on one host: rayctl restore -no-carry of an
// older copy A0 leaves the node behind its later backup A2 (alice renewed,
// dave's phone revoked, bob's tablet enrolled since A0). Restoring A2 then
// carries nothing: A0's alice is the leaked one.
func TestCarryRestoreNodeBehind(t *testing.T) {
	ctx := context.Background()
	f := newRestoreFix(t, nil) // f.backup is A0
	s := f.open(t, f.current)
	s.SetClock(at(time.Hour))
	if _, err := s.RenewUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeDevice(ctx, f.phones["dave"].ID); err != nil {
		t.Fatal(err)
	}
	tablet, _, err := s.CreateDevice(ctx, "bob", "tablet", "user")
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	a2 := filepath.Join(f.dir, "a2.db")
	copyFile(t, f.current, a2)
	want := secrets(t, a2)
	copyFile(t, f.backup, f.current) // restore -no-carry of A0
	r, err := CarryRestore(ctx, a2, f.current, "")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Foreign || r.Newer == "" || len(r.Unknown) != len(restoreUsers) || r.Kept != 0 {
		t.Fatalf("%+v", r)
	}
	if !slices.Contains(activeIDs(r.Unknown), tablet.ID) {
		t.Errorf("the tablet is not in the warning: %v", r.Unknown)
	}
	unchanged(t, a2, want, []string{f.phones["dave"].ID})
}

// The normal case, with what a node writes: a backup with audit lines,
// the node's database later, with lines of its own, the backup's oldest
// pruned, then all of them. The backup is older: carried as before.
func TestCarryRestoreOlderBackup(t *testing.T) {
	ctx := context.Background()
	t0 := time.Now()
	f := newRestoreFix(t, func(s *Store) {
		s.SetClock(func() time.Time { return t0.Add(-48 * time.Hour) })
		must(t, s.Audit(ctx, "root", "user.add", "alice", "ok"))
		s.SetClock(func() time.Time { return t0 })
		must(t, s.Audit(ctx, "root", "user.add", "erin", "ok"))
	})
	for _, prune := range []time.Duration{0, -24 * time.Hour, time.Hour} {
		work := filepath.Join(f.dir, "work.db")
		copyFile(t, f.backup, work)
		s := f.open(t, f.current)
		s.SetClock(at(2 * time.Hour))
		if prune == 0 {
			if _, err := s.RenewUser(ctx, "alice"); err != nil {
				t.Fatal(err)
			}
			must(t, s.Audit(ctx, "root", "user.renew", "alice: 3 credentials new", "ok"))
			if _, err := s.RotateCredentials(ctx, time.Now().Add(40*24*time.Hour), Rotation{Period: 30 * 24 * time.Hour,
				Lead: time.Hour, Grace: 24 * time.Hour}, NewUUID); err != nil {
				t.Fatal(err)
			}
		} else {
			must(t, s.PruneAudit(ctx, t0.Add(prune)))
		}
		s.Close()
		now := secrets(t, f.current)
		r, err := CarryRestore(ctx, work, f.current, "")
		if err != nil {
			t.Fatal(err)
		}
		if r.Foreign || r.Newer != "" || r.Kept != len(restoreUsers) {
			t.Fatalf("pruned at %v: %+v", prune, r)
		}
		for n, svcs := range secrets(t, work) {
			for svc, sec := range svcs {
				if sec != now[n][svc] {
					t.Errorf("pruned at %v: %s's credential on %d is not the node's", prune, n, svc)
				}
			}
		}
	}
}

// Each sign that the backup is newer, alone, on a backup that is the
// node's database but for it; none at all is no sign.
func TestBackupNewerSigns(t *testing.T) {
	ctx := context.Background()
	later := time.Now().Add(time.Hour).Unix()
	for _, c := range []struct {
		name, want string
		backup     func(t *testing.T, f restoreFix, db *sql.DB)
		node       func(t *testing.T, f restoreFix, s *Store)
	}{
		{name: "none"},
		{"revoked", "device ", func(t *testing.T, f restoreFix, db *sql.DB) {
			exec(t, db, `UPDATE devices SET revoked_at = ? WHERE id = ?`, later, f.phones["bob"].ID)
		}, nil},
		{"device", "the backup has device ", func(t *testing.T, f restoreFix, db *sql.DB) {
			exec(t, db, `INSERT INTO devices (id, user_id, name, role, spa_key, created_at) VALUES ('ffffffffffffffff', ?, 'tv', 'user', x'00', 1)`, f.ids["bob"])
		}, nil},
		{"rotated later", "bob's credential on naive", func(t *testing.T, f restoreFix, db *sql.DB) {
			exec(t, db, `UPDATE credentials SET rotated_at = ? WHERE user_id = ? AND service_id = ?`, later, f.ids["bob"], f.naive)
		}, nil},
		{"switched from the node's", "bob's credential on naive", func(t *testing.T, f restoreFix, db *sql.DB) {
			exec(t, db, `UPDATE credentials SET prev_secret = secret, prev_until = 9999999999, secret = 'x' WHERE user_id = ? AND service_id = ?`,
				f.ids["bob"], f.naive)
		}, nil},
		{"to the node's next", "bob's credential on naive", func(t *testing.T, f restoreFix, db *sql.DB) {
			exec(t, db, `UPDATE credentials SET secret = 'n' WHERE user_id = ? AND service_id = ?`, f.ids["bob"], f.naive)
		}, func(t *testing.T, f restoreFix, s *Store) {
			exec(t, s.db, `UPDATE credentials SET next_secret = 'n', next_from = 9999999999 WHERE user_id = ? AND service_id = ?`, f.ids["bob"], f.naive)
		}},
		{"next published", "bob's credential on naive", func(t *testing.T, f restoreFix, db *sql.DB) {
			exec(t, db, `UPDATE credentials SET next_secret = 'n', next_from = 9999999999 WHERE user_id = ? AND service_id = ?`, f.ids["bob"], f.naive)
		}, nil},
		{"service", "the backup has service extra", func(t *testing.T, f restoreFix, db *sql.DB) {
			exec(t, db, `INSERT INTO services (kind, name, enabled, settings_json, created_at) VALUES ('naive', 'extra', 1, '{}', 1)`)
		}, nil},
		{"service made again", "the backup has service naive", func(t *testing.T, f restoreFix, db *sql.DB) {
			exec(t, db, `UPDATE services SET created_at = created_at - 5 WHERE id = ?`, f.naive)
		}, nil},
		{"invite used", "the invite of bob/tablet is used", func(t *testing.T, f restoreFix, db *sql.DB) {
			exec(t, db, `UPDATE invites SET used_at = 5`)
		}, func(t *testing.T, f restoreFix, s *Store) {}},
		{"invite tries", "fewer PIN tries", func(t *testing.T, f restoreFix, db *sql.DB) {
			exec(t, db, `UPDATE invites SET pin_tries = 1`)
		}, func(t *testing.T, f restoreFix, s *Store) {}},
		{"audit line", "the backup's audit line user.renew of ", func(t *testing.T, f restoreFix, db *sql.DB) {
			exec(t, db, `INSERT INTO audit_log (ts, actor, action, target, result) VALUES (?, 'root', 'user.renew', 'bob', 'ok')`, later)
		}, func(t *testing.T, f restoreFix, s *Store) {
			s.SetClock(at(2 * time.Hour)) // the node's lines are later: only the line tells
			must(t, s.Audit(context.Background(), "root", "user.add", "zed", "ok"))
		}},
		{"newest record", "the backup's newest record is of ", func(t *testing.T, f restoreFix, db *sql.DB) {
			exec(t, db, `INSERT INTO users (name, enabled, created_at) VALUES ('zed', 1, ?)`, later)
		}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newRestoreFix(t, func(s *Store) {
				must(t, s.Audit(ctx, "root", "user.add", "alice", "ok"))
				if c.node != nil {
					if _, _, err := s.CreateInvite(ctx, "bob", "tablet", "user", time.Hour, func(k [32]byte) []byte { return k[:] }); err != nil {
						t.Fatal(err)
					}
				}
			})
			if c.backup != nil {
				db, err := sql.Open("sqlite", "file:"+f.backup)
				if err != nil {
					t.Fatal(err)
				}
				c.backup(t, f, db)
				db.Close()
			}
			if c.node != nil {
				s := f.open(t, f.current)
				c.node(t, f, s)
				s.Close()
			}
			r, err := CarryRestore(ctx, f.backup, f.current, "")
			if err != nil {
				t.Fatal(err)
			}
			t.Log(r.Newer)
			if c.want == "" {
				if r.Foreign || r.Newer != "" {
					t.Fatalf("%+v", r)
				}
				return
			}
			if !r.Foreign || !strings.Contains(r.Newer, c.want) {
				t.Fatalf("Newer %q, want %q", r.Newer, c.want)
			}
		})
	}
}

func exec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

// rayctl restore of a backup older than the node's schema: rayd init
// migrates the copy first, and the step of schema 14 renews its users with
// a device revoked and audits it, at the restore's time, while the node's
// database went through that step long before. Read from the copy as
// migrated, those would be signs of a newer backup; read from the backup
// as it was made (made), there are none, and the carry runs.
func TestCarryRestoreMadeBeforeMigration(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	raw, current := filepath.Join(dir, "backup.db"), filepath.Join(dir, "rayd.db")
	schemaAt(t, raw, 13, append(matrix13(),
		`INSERT INTO settings (key, value) VALUES ('spa_params', '{"node_id":"00112233445566778899aabbccddeeff"}')`)...)
	copyFile(t, raw, current)
	s, err := Open(ctx, current) // the node's update, long ago
	if err != nil {
		t.Fatal(err)
	}
	exec(t, s.db, `UPDATE credentials SET rotated_at = rotated_at - 100000 WHERE rotated_at > 1000`)
	exec(t, s.db, `UPDATE audit_log SET ts = ts - 100000`)
	s.Close()
	restore := func() string {
		saved := filepath.Join(dir, "saved.db")
		copyFile(t, raw, saved)
		s, err := Open(ctx, saved) // rayd init on the copy
		if err != nil {
			t.Fatal(err)
		}
		s.Close()
		return saved
	}
	if r, err := CarryRestore(ctx, restore(), current, ""); err != nil || r.Newer == "" {
		t.Fatalf("read from the migrated copy: %+v %v", r, err)
	}
	r, err := CarryRestore(ctx, restore(), current, raw)
	if err != nil {
		t.Fatal(err)
	}
	if r.Foreign || r.Newer != "" || r.Kept == 0 {
		t.Fatalf("%+v", r)
	}
}
