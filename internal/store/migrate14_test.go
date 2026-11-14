package store

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// schemaAt builds a database at path as a raycontrol at schema version
// left it, from the migrations themselves (WAL, foreign keys on), and runs
// seed on it.
func schemaAt(t *testing.T, path string, version int, seed ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	names, _ := fs.Glob(migrations, "migrations/*.sql")
	sort.Strings(names)
	for i, n := range names[:version] {
		b, _ := migrations.ReadFile(n)
		if _, err := db.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations VALUES (?, 1)`, i+1); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range seed {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

// rows dumps a query's rows, one line each.
func rows(t *testing.T, db *sql.DB, q string) string {
	t.Helper()
	r, err := db.Query(q)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	cols, _ := r.Columns()
	var b strings.Builder
	for r.Next() {
		c := make([]any, len(cols))
		p := make([]any, len(cols))
		for i := range c {
			p[i] = &c[i]
		}
		if err := r.Scan(p...); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintln(&b, c...)
	}
	return b.String()
}

const (
	devicesDump = `SELECT id, user_id, name, role, hex(spa_key), created_at, coalesce(revoked_at, -1), coalesce(cert_pin, ''),
		lan, coalesce(lan_at, -1) FROM devices ORDER BY id`
	credsDump = `SELECT user_id, service_id, secret, coalesce(next_secret, ''), coalesce(next_from, 0), coalesce(prev_secret, ''),
		coalesce(prev_until, 0), coalesce(rotated_at, 0) FROM credentials ORDER BY user_id, service_id`
)

// A database as v0.26.0 left it (schema 13) migrated to 14: the devices
// and their indexes as before but for the name, free once revoked; and
// every user with a device revoked then gets new credentials once, in
// every slot (current, next, previous), and a new LAN key, since that
// revocation left them as they were (R4-36). Nobody else's change, and a
// later start changes nothing.
func TestMigration14FromSchema13(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "rayd.db")
	schemaAt(t, path, 13,
		`INSERT INTO services (id, kind, name, enabled, settings_json, created_at) VALUES (1, 'reality', 'reality', 1, '{}', 1), (2, 'hy2', 'hy2', 1, '{}', 1)`,
		`INSERT INTO users (id, name, enabled, created_at, lan, lan_key) VALUES (1, 'alice', 1, 1, 1, x'0102'), (2, 'bob', 1, 1, 1, x'0304'), (3, 'carol', 1, 1, 0, NULL)`,
		`INSERT INTO user_services (user_id, service_id) VALUES (1, 1), (1, 2), (2, 1), (2, 2)`,
		// alice's rotated after the revocation, a next published and a
		// previous in its grace: the device may know any of them.
		`INSERT INTO credentials (user_id, service_id, secret, created_at, rotated_at, next_secret, next_from, prev_secret, prev_until) VALUES
			(1, 1, 'a-cur', 1, 50, 'a-next', 9999999999, 'a-prev', 9999999999),
			(1, 2, 'a-cur2', 1, 1, NULL, NULL, NULL, NULL),
			(2, 1, 'b-cur', 1, 1, 'b-next', 9999999999, NULL, NULL),
			(2, 2, 'b-cur2', 1, 1, NULL, NULL, 'b-prev', 9999999999)`,
		`INSERT INTO devices (id, user_id, name, role, spa_key, created_at, revoked_at, cert_pin, lan, lan_at) VALUES
			('a000000000000001', 1, 'phone', 'user', x'01', 10, 20, 'pinA', 1, 11),
			('a000000000000002', 1, 'phone2', 'admin', x'02', 30, NULL, 'pinB', 0, NULL),
			('b000000000000001', 2, 'phone', 'user', x'03', 40, NULL, NULL, 0, NULL),
			('c000000000000001', 3, 'old', 'user', x'04', 40, 45, NULL, 0, NULL)`,
		`INSERT INTO invites (id, user_id, name, role, spa_key, created_at, expires_at, used_at, device_id) VALUES
			('i1', 1, 'phone2', 'admin', x'09', 25, 99999999999, 30, 'a000000000000002')`,
	)
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	devicesBefore := rows(t, db, devicesDump)
	db.Close()

	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if after := rows(t, s.db, devicesDump); after != devicesBefore {
		t.Fatalf("devices changed:\n%s\n%s", devicesBefore, after)
	}
	if ic := rows(t, s.db, `PRAGMA integrity_check`); ic != "ok\n" {
		t.Fatalf("integrity %q", ic)
	}
	if fk := rows(t, s.db, `PRAGMA foreign_key_check`); fk != "" {
		t.Fatalf("foreign keys %q", fk)
	}
	// The revoked name is free; an active one is not; the indexes and the
	// cascade from users are there.
	if _, _, err := s.CreateDevice(ctx, "alice", "phone", "user"); err != nil {
		t.Fatalf("reuse of a revoked name: %v", err)
	}
	if _, _, err := s.CreateDevice(ctx, "alice", "phone", "user"); err == nil {
		t.Fatal("two active devices named phone")
	}
	if _, err := s.DeviceByCertPin(ctx, "pinB"); err != nil {
		t.Fatalf("cert pin lookup: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO devices (id, user_id, name, role, spa_key, created_at, cert_pin) VALUES ('x1', 2, 'x', 'user', x'00', 1, 'pinB')`); err == nil {
		t.Fatal("cert_pin index lost")
	}
	if _, err := s.db.Exec(`INSERT INTO devices (id, user_id, name, role, spa_key, created_at) VALUES ('x2', 999, 'x', 'user', x'00', 1)`); err == nil {
		t.Fatal("foreign key to users lost")
	}

	// alice: every secret new, no next, no previous; bob as he was.
	got := rows(t, s.db, credsDump)
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 4 {
		t.Fatalf("credentials:\n%s", got)
	}
	for _, l := range lines[:2] {
		f := strings.Fields(l)
		// No next and no previous: their columns are empty, their times 0.
		if len(f) != 6 || f[0] != "1" || len(f[2]) != 36 || f[3] != "0" || f[4] != "0" {
			t.Errorf("alice's credential not renewed: %s", l)
		}
		for _, old := range []string{"a-cur", "a-next", "a-prev"} {
			if strings.Contains(l, old) {
				t.Errorf("an old secret of alice's left: %s", l)
			}
		}
	}
	if want := "2 1 b-cur b-next 9999999999  0 1\n2 2 b-cur2  0 b-prev 9999999999 1\n"; !strings.HasSuffix(got, want) {
		t.Errorf("bob's changed:\n%s", got)
	}
	var aliceKey, bobKey []byte
	if err := s.db.QueryRow(`SELECT lan_key FROM users WHERE id = 1`).Scan(&aliceKey); err != nil || len(aliceKey) != LANKeySize {
		t.Errorf("alice's LAN key %x %v", aliceKey, err)
	}
	if err := s.db.QueryRow(`SELECT lan_key FROM users WHERE id = 2`).Scan(&bobKey); err != nil || string(bobKey) != "\x03\x04" {
		t.Errorf("bob's LAN key %x %v", bobKey, err)
	}
	// One audit line a user renewed, carol's with none to renew; no secret.
	audit := rows(t, s.db, `SELECT actor, action, target FROM audit_log ORDER BY id`)
	if strings.Count(audit, "user.renew:revoked-before") != 2 || !strings.Contains(audit, "alice: 2 credentials new") ||
		!strings.Contains(audit, "carol: 0 credentials new") || strings.Contains(audit, "bob") {
		t.Errorf("audit:\n%s", audit)
	}
	aliceAfter := rows(t, s.db, credsDump)
	s.Close()

	// A later start: nothing again.
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if again := rows(t, s.db, credsDump); again != aliceAfter {
		t.Errorf("a second start renewed again:\n%s\n%s", aliceAfter, again)
	}
	if n := strings.Count(rows(t, s.db, `SELECT action FROM audit_log`), "user.renew"); n != 2 {
		t.Errorf("%d audit lines after a second start", n)
	}
	// A revocation by this raycontrol renews at once, and no start after
	// it renews again.
	if _, err := s.RevokeDevice(ctx, "b000000000000001"); err != nil {
		t.Fatal(err)
	}
	revoked := rows(t, s.db, credsDump)
	s.Close()
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if again := rows(t, s.db, credsDump); again != revoked {
		t.Errorf("a start after a revocation renewed again")
	}
}

// A database with no device revoked, at schema 13 or new: the step of 14
// changes nothing and writes no audit line.
func TestMigration14NothingRevoked(t *testing.T) {
	ctx := context.Background()
	for _, version := range []int{0, 13} {
		path := filepath.Join(t.TempDir(), "rayd.db")
		if version > 0 {
			schemaAt(t, path, version,
				`INSERT INTO services (id, kind, name, enabled, settings_json, created_at) VALUES (1, 'reality', 'reality', 1, '{}', 1)`,
				`INSERT INTO users (id, name, enabled, created_at) VALUES (1, 'alice', 1, 1)`,
				`INSERT INTO credentials (user_id, service_id, secret, created_at, rotated_at) VALUES (1, 1, 'a-cur', 1, 1)`,
				`INSERT INTO devices (id, user_id, name, role, spa_key, created_at) VALUES ('a000000000000001', 1, 'phone', 'user', x'01', 10)`)
		}
		s, err := Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		if a := rows(t, s.db, `SELECT action FROM audit_log`); a != "" {
			t.Errorf("schema %d: audit %q", version, a)
		}
		if version > 0 {
			if c := rows(t, s.db, `SELECT secret FROM credentials`); c != "a-cur\n" {
				t.Errorf("credentials %q", c)
			}
		}
		s.Close()
	}
}
