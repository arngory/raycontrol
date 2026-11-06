package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// CarryRevocations brings into the database at saved what was taken away in
// the one at current since saved was copied, before saved goes back in its
// place (rayctl update -rollback):
//   - a device revoked or deleted stays revoked, and a device's certificate
//     replaced stays replaced;
//   - a user disabled or deleted stays disabled, an earlier expiry stays,
//     and a service taken from a user stays taken;
//   - a service disabled or deleted stays disabled, a REALITY no longer open
//     is not open, and a DNS tunnel keeps the stricter dnsauth mode;
//   - an unused invite withdrawn stays withdrawn, a relay removed stays
//     removed, and a relay's certificate, SPA, SSH access and probe
//     endpoint stay as now;
//   - the settings named in keep (the admin addresses) take current's value.
//
// Users and relays are matched by ID, name or address, and creation time:
// SQLite reuses the ID of a deleted row. What was added or changed since
// otherwise, credentials rotated included, is lost with the rest. Neither
// database may be open elsewhere.
func CarryRevocations(ctx context.Context, saved, current string, keep ...string) error {
	if strings.ContainsAny(current, "?#") {
		return fmt.Errorf("store: database path %q", current)
	}
	db, err := sql.Open("sqlite", "file:"+saved+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck // returns the connection to the pool
	if _, err := conn.ExecContext(ctx, `ATTACH DATABASE ? AS cur`, "file:"+current+"?mode=ro"); err != nil {
		return fmt.Errorf("store: opening %s: %w", current, err)
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // after Commit it does nothing
	// The same user in both: a deleted user's ID may have gone to another.
	const sameUser = `c.id = users.id AND c.name = users.name AND c.created_at = users.created_at`
	stmts := []string{
		`UPDATE devices SET revoked_at = COALESCE((SELECT c.revoked_at FROM cur.devices c WHERE c.id = devices.id), ?1)
		  WHERE revoked_at IS NULL
		    AND NOT EXISTS (SELECT 1 FROM cur.devices c WHERE c.id = devices.id AND c.revoked_at IS NULL)`,
		`UPDATE users SET enabled = 0
		  WHERE enabled = 1
		    AND NOT EXISTS (SELECT 1 FROM cur.users c WHERE ` + sameUser + ` AND c.enabled = 1)`,
		`UPDATE users SET expires_at = (SELECT c.expires_at FROM cur.users c WHERE ` + sameUser + `)
		  WHERE EXISTS (SELECT 1 FROM cur.users c WHERE ` + sameUser + ` AND c.expires_at IS NOT NULL
		                AND (users.expires_at IS NULL OR c.expires_at < users.expires_at))`,
		`DELETE FROM user_services
		  WHERE NOT EXISTS (SELECT 1 FROM cur.user_services cs
		                    WHERE cs.user_id = user_services.user_id AND cs.service_id = user_services.service_id)`,
		// Service IDs are never reused (AUTOINCREMENT).
		`UPDATE services SET enabled = 0
		  WHERE enabled = 1
		    AND NOT EXISTS (SELECT 1 FROM cur.services c WHERE c.id = services.id AND c.kind = services.kind AND c.enabled = 1)`,
		`UPDATE services SET settings_json = json_remove(settings_json, '$.open')
		  WHERE kind = 'reality' AND json_extract(settings_json, '$.open') = 1
		    AND NOT EXISTS (SELECT 1 FROM cur.services c WHERE c.id = services.id AND json_extract(c.settings_json, '$.open') = 1)`,
		// dnsauth (dnsauth-v1 §5): the stricter mode of the two stays.
		`UPDATE services SET settings_json = json_set(settings_json, '$.auth',
		    (SELECT json_extract(c.settings_json, '$.auth') FROM cur.services c WHERE c.id = services.id))
		  WHERE kind = 'dnstt'
		    AND (SELECT CASE json_extract(c.settings_json, '$.auth') WHEN 'required' THEN 2 WHEN 'optional' THEN 1 ELSE 0 END
		         FROM cur.services c WHERE c.id = services.id)
		      > CASE json_extract(settings_json, '$.auth') WHEN 'required' THEN 2 WHEN 'optional' THEN 1 ELSE 0 END`,
	}
	type table struct{ name, column, stmt string }
	for _, t := range []table{
		{"invites", "", `DELETE FROM invites WHERE used_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM cur.invites c WHERE c.id = invites.id AND c.used_at IS NULL)`},
		// A PIN's wrong tries since the copy count (api-v1 §3): fewer
		// left of the two, or a rollback would hand guesses back.
		{"invites", "pin_tries", `UPDATE invites SET pin_tries = (SELECT c.pin_tries FROM cur.invites c WHERE c.id = invites.id)
		  WHERE EXISTS (SELECT 1 FROM cur.invites c WHERE c.id = invites.id AND c.pin_tries < invites.pin_tries)`},
		{"devices", "cert_pin", `UPDATE devices SET cert_pin = (SELECT c.cert_pin FROM cur.devices c WHERE c.id = devices.id)
		  WHERE EXISTS (SELECT 1 FROM cur.devices c WHERE c.id = devices.id AND c.cert_pin IS NOT devices.cert_pin)`},
		{"relays", "", `DELETE FROM relays
		  WHERE NOT EXISTS (SELECT 1 FROM cur.relays c
		                    WHERE c.id = relays.id AND c.address = relays.address AND c.created_at = relays.created_at)`},
		{"relays", "cert_pin", `UPDATE relays SET cert_pin = (SELECT c.cert_pin FROM cur.relays c WHERE c.id = relays.id)
		  WHERE EXISTS (SELECT 1 FROM cur.relays c WHERE c.id = relays.id AND c.cert_pin IS NOT relays.cert_pin)`},
		// A relay's SPA goes with its certificate (new keys for a lost relay),
		// and its SSH access with both: the relay runs on what the current
		// database gave it.
		{"relays", "spa_json", `UPDATE relays SET spa_json = (SELECT c.spa_json FROM cur.relays c WHERE c.id = relays.id)
		  WHERE EXISTS (SELECT 1 FROM cur.relays c WHERE c.id = relays.id AND c.spa_json IS NOT relays.spa_json)`},
		{"relays", "ssh_port", `UPDATE relays SET ssh_port = (SELECT c.ssh_port FROM cur.relays c WHERE c.id = relays.id)
		  WHERE EXISTS (SELECT 1 FROM cur.relays c WHERE c.id = relays.id AND c.ssh_port IS NOT relays.ssh_port)`},
		{"relays", "admin_json", `UPDATE relays SET admin_json = (SELECT c.admin_json FROM cur.relays c WHERE c.id = relays.id)
		  WHERE EXISTS (SELECT 1 FROM cur.relays c WHERE c.id = relays.id AND c.admin_json IS NOT relays.admin_json)`},
		// Its probe endpoint came in the same bundle: the subscription names
		// the certificate the relay serves.
		{"relays", "probe_pin", `UPDATE relays SET probe_pin = (SELECT c.probe_pin FROM cur.relays c WHERE c.id = relays.id),
		    probe_port = (SELECT c.probe_port FROM cur.relays c WHERE c.id = relays.id)
		  WHERE EXISTS (SELECT 1 FROM cur.relays c WHERE c.id = relays.id
		                AND (c.probe_pin IS NOT relays.probe_pin OR c.probe_port IS NOT relays.probe_port))`},
	} {
		// The copy may be older than the table or the column; the current
		// database is newer, so it has them.
		has, err := hasTable(ctx, tx, "main", t.name)
		if err == nil && has && t.column != "" {
			has, err = hasColumn(ctx, tx, "main", t.name, t.column)
		}
		if err != nil {
			return err
		}
		if has {
			stmts = append(stmts, t.stmt)
		}
	}
	now := time.Now().Unix()
	for _, q := range stmts {
		if _, err := tx.ExecContext(ctx, q, now); err != nil {
			return fmt.Errorf("store: carrying revocations: %w", err)
		}
	}
	for _, k := range keep {
		if _, err := tx.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, k); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO settings (key, value) SELECT key, value FROM cur.settings WHERE key = ?`, k); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func hasTable(ctx context.Context, tx *sql.Tx, schema, name string) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM `+schema+`.sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&n)
	return n > 0, err
}

func hasColumn(ctx context.Context, tx *sql.Tx, schema, table, column string) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info(?, ?) WHERE name = ?`, table, schema, column).Scan(&n)
	return n > 0, err
}
