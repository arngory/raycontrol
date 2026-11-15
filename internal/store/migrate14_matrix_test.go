package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// matrixOthers dumps what the step of schema 14 must not change: users,
// their traffic, their services and devices.
const matrixOthers = `SELECT 'u', id, name, enabled, coalesce(expires_at,-1), coalesce(traffic_limit_bytes,-1), traffic_period, traffic_reset_day, lan FROM users
	UNION ALL SELECT 't', user_id, period_start, counted_from, up, down, '', '', '' FROM user_traffic
	UNION ALL SELECT 's', user_id, service_id, '', '', '', '', '', '' FROM user_services
	UNION ALL SELECT 'd', id, user_id, name, role, hex(spa_key), coalesce(revoked_at,-1), coalesce(cert_pin,''), lan FROM devices
	ORDER BY 1, 2, 3`

// matrix13 seeds a schema-13 database with six users: alice (a device
// revoked, two active, three credentials each with a next or a previous
// secret, LAN), bob (no device revoked), carol (two revoked), dave (one
// revoked, no credential, no LAN), erin (disabled, none revoked) and
// frank (disabled, one revoked).
func matrix13() []string {
	return []string{
		`INSERT INTO services (id, kind, name, enabled, settings_json, created_at) VALUES (1, 'reality', 'reality', 1, '{}', 1), (2, 'hy2', 'hy2', 1, '{}', 1), (3, 'naive', 'naive', 0, '{}', 1)`,
		`INSERT INTO users (id, name, enabled, created_at, lan, lan_key, traffic_limit_bytes, traffic_period, traffic_reset_day) VALUES
			(1, 'alice', 1, 1, 1, x'0102', 1000, 'monthly', 5),
			(2, 'bob', 1, 1, 1, x'0304', NULL, 'monthly', 1),
			(3, 'carol', 1, 1, 1, x'0506', NULL, 'monthly', 1),
			(4, 'dave', 1, 1, 0, NULL, NULL, 'monthly', 1),
			(5, 'erin', 0, 1, 1, x'0708', NULL, 'none', 1),
			(6, 'frank', 0, 1, 1, x'0909', NULL, 'monthly', 1)`,
		`INSERT INTO user_traffic (user_id, period_start, counted_from, up, down) VALUES (1, 100, 100, 111, 222), (2, 100, 100, 5, 6)`,
		`INSERT INTO user_services (user_id, service_id) VALUES (1,1),(1,2),(1,3),(2,1),(2,2),(3,1),(5,1),(6,1)`,
		`INSERT INTO credentials (user_id, service_id, secret, created_at, rotated_at, next_secret, next_from, prev_secret, prev_until) VALUES
			(1, 1, 'a1', 1, 50, 'a1n', 9999999999, 'a1p', 9999999999),
			(1, 2, 'a2', 1, 60, 'a2n', 9999999999, 'a2p', 9999999999),
			(1, 3, 'a3', 1, 70, NULL, NULL, 'a3p', 9999999999),
			(2, 1, 'b1', 1, 1, 'b1n', 9999999999, 'b1p', 9999999999),
			(2, 2, 'b2', 1, 1, NULL, NULL, NULL, NULL),
			(3, 1, 'c1', 1, 1, 'c1n', 9999999999, 'c1p', 9999999999),
			(5, 1, 'e1', 1, 1, 'e1n', 9999999999, NULL, NULL),
			(6, 1, 'f1', 1, 1, NULL, NULL, 'f1p', 9999999999)`,
		`INSERT INTO devices (id, user_id, name, role, spa_key, created_at, revoked_at, cert_pin, lan, lan_at) VALUES
			('a1', 1, 'old', 'user', x'01', 10, 20, NULL, 1, 11),
			('a2', 1, 'phone', 'admin', x'02', 30, NULL, 'pinA2', 1, 31),
			('a3', 1, 'tablet', 'user', x'03', 30, NULL, NULL, 0, NULL),
			('b1', 2, 'phone', 'user', x'04', 40, NULL, NULL, 0, NULL),
			('c1', 3, 'phone', 'user', x'05', 40, 45, NULL, 0, NULL),
			('c2', 3, 'phone2', 'user', x'06', 40, 46, NULL, 0, NULL),
			('d1', 4, 'phone', 'user', x'07', 40, 47, NULL, 0, NULL),
			('e1', 5, 'phone', 'user', x'08', 40, NULL, NULL, 0, NULL),
			('f1', 6, 'phone', 'user', x'09', 40, 48, NULL, 0, NULL)`,
	}
}

// matrixSecrets are the secrets matrix13 gives, in every slot.
var matrixSecrets = []string{"a1", "a1n", "a1p", "a2", "a2n", "a2p", "a3", "a3p", "b1", "b1n", "b1p", "b2", "c1", "c1n", "c1p", "e1", "e1n", "f1", "f1p"}

// credsByRow reads every credential as "user/service" to the rest of
// its credsDump line.
func credsByRow(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(rows(t, db, credsDump)), "\n") {
		if l == "" {
			continue
		}
		f := strings.SplitN(l, " ", 3)
		out[f[0]+"/"+f[1]] = f[2]
	}
	return out
}

// lanKeys reads every user's LAN key, in hex or NULL.
func lanKeys(t *testing.T, db *sql.DB) map[int]string {
	t.Helper()
	out := map[int]string{}
	r, err := db.Query(`SELECT id, coalesce(hex(lan_key), 'NULL') FROM users`)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for r.Next() {
		var id int
		var k string
		if err := r.Scan(&id, &k); err != nil {
			t.Fatal(err)
		}
		out[id] = k
	}
	return out
}

// The step of schema 14 over six users: those with a device revoked
// (alice, carol, dave, frank; enabled or not) get every credential new
// with no next and no previous, and a new LAN key where they had one;
// one audit line each, with the count and no secret; nothing else
// changes, a revoked name is free, and a second start renews nothing.
func TestMigration14Matrix(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "rayd.db")
	schemaAt(t, path, 13, matrix13()...)
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	othersBefore := rows(t, db, matrixOthers)
	credsBefore := credsByRow(t, db)
	lanBefore := lanKeys(t, db)
	db.Close()

	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if o := rows(t, s.db, matrixOthers); o != othersBefore {
		t.Errorf("users, traffic, services or devices changed:\n%s\n---\n%s", othersBefore, o)
	}
	after := credsByRow(t, s.db)
	renewed := map[string]bool{"1": true, "3": true, "6": true}
	for k, v := range credsBefore {
		if !renewed[strings.Split(k, "/")[0]] {
			if after[k] != v {
				t.Errorf("%s changed: %q -> %q", k, v, after[k])
			}
			continue
		}
		// secret, next_from 0, prev_until 0, rotated_at: no next, no previous.
		f := strings.Fields(after[k])
		if len(f) != 4 || !isUUID(f[0]) || f[1] != "0" || f[2] != "0" {
			t.Errorf("%s not renewed: %q", k, after[k])
		} else if f[3] == "50" || f[3] == "1" {
			t.Errorf("%s kept its rotation time %s", k, f[3])
		}
	}
	lanAfter := lanKeys(t, s.db)
	for id, k := range lanBefore {
		if id == 1 || id == 3 || id == 6 {
			if k == lanAfter[id] || len(lanAfter[id]) != 2*LANKeySize {
				t.Errorf("user %d's LAN key %s -> %s", id, k, lanAfter[id])
			}
		} else if k != lanAfter[id] {
			t.Errorf("user %d's LAN key changed", id)
		}
	}
	audit := rows(t, s.db, `SELECT actor, action, target, result FROM audit_log ORDER BY id`)
	if strings.Count(audit, "user.renew:revoked-before") != 4 {
		t.Errorf("audit:\n%s", audit)
	}
	for _, w := range []string{"alice: 3 credentials", "carol: 1 credentials", "dave: 0 credentials", "frank: 1 credentials"} {
		if !strings.Contains(audit, w) {
			t.Errorf("audit lacks %q:\n%s", w, audit)
		}
	}
	for _, sec := range matrixSecrets {
		if strings.Contains(audit, " "+sec+" ") {
			t.Errorf("secret %s in the audit", sec)
		}
	}
	if v := rows(t, s.db, `SELECT count(*) FROM schema_migrations WHERE version = 14`); v != "1\n" {
		t.Errorf("schema 14 recorded %q", v)
	}
	if _, _, err := s.CreateDevice(ctx, "carol", "phone", "user"); err != nil {
		t.Errorf("a revoked device's name: %v", err)
	}
	snap := rows(t, s.db, credsDump)
	s.Close()
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if rows(t, s.db, credsDump) != snap {
		t.Error("a second start renewed again")
	}
}

// The step fails after it has renewed: the migration goes back whole, the
// database is at 13 as it was, and the next start renews once.
func TestMigration14StepFails(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "rayd.db")
	schemaAt(t, path, 13, matrix13()...)
	state := func() string {
		db, err := sql.Open("sqlite", "file:"+path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		return rows(t, db, credsDump) + rows(t, db, matrixOthers) + rows(t, db, `SELECT * FROM audit_log`) + fmt.Sprint(lanKeys(t, db)) +
			rows(t, db, `SELECT max(version) FROM schema_migrations`) + rows(t, db, `SELECT sql FROM sqlite_master WHERE name = 'devices'`)
	}
	before := state()
	orig := migrationSteps[14]
	migrationSteps[14] = func(ctx context.Context, tx *sql.Tx, now int64) error {
		if err := orig(ctx, tx, now); err != nil {
			return err
		}
		return errors.New("injected")
	}
	_, err := Open(ctx, path)
	migrationSteps[14] = orig
	if err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("open: %v", err)
	}
	if after := state(); after != before {
		t.Errorf("not rolled back:\n%s\n---\n%s", before, after)
	}
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if n := strings.Count(rows(t, s.db, `SELECT action FROM audit_log`), "revoked-before"); n != 4 {
		t.Errorf("the retry renewed %d users", n)
	}
}
