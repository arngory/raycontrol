package store

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"
)

// CarryRevocations brings into the database at saved what was taken away in
// the one at current since saved was copied, before saved goes back in its
// place (rayctl update -rollback):
//   - a device revoked or deleted stays revoked, and a device's certificate
//     replaced stays replaced; the user of a device revoked so gets new
//     credentials, as a revocation gives (carryDevices);
//   - a user disabled or deleted stays disabled, an earlier expiry stays,
//     and a service taken from a user stays taken;
//   - a user's or a device's LAN consent taken back stays taken back, and
//     a user's LAN key is the current one (a revocation renews it);
//   - a service disabled or deleted stays disabled, a REALITY no longer open
//     is not open, and a DNS tunnel keeps the stricter dnsauth mode;
//   - an unused invite withdrawn stays withdrawn, a relay removed stays
//     removed, and a relay's certificate, SPA, SSH access and probe
//     endpoint stay as now;
//   - the settings named in keep (the admin addresses) take current's value.
//
// And credentials do not go back: every credential saved and current both
// have, of the same user and the same service, takes current's values
// (carryCredentials), and the users of devices revoked since get new ones
// on top. A renewal since the copy (rayctl user renew, the step of schema
// 14) left no next and no previous secret, so the copy's would be the very
// ones it retired; and an ordinary rotation since is no worse kept than
// undone, its secrets being those the clients fetched.
//
// Users and relays are matched by ID, name or address, and creation time:
// SQLite reuses the ID of a deleted row. What was added or changed since
// otherwise is lost with the rest: a user or a credential made since is
// not in saved and does not come into it. Neither database may be open
// elsewhere.
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
	if _, err := carryCredentials(ctx, tx, false); err != nil {
		return err
	}
	if _, err := carryDevices(ctx, tx, true); err != nil {
		return err
	}
	stmts := []string{
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
		  WHERE kind IN ('dnstt', 'masterdns')
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
		// LAN (lan-v1): a consent taken back stays taken back, the
		// administrator's and a device's, and the user's LAN key is the
		// current one: a revocation since made it new, and the revoked
		// device knows the one before.
		{"users", "lan", `UPDATE users SET lan = 0, lan_key = NULL
		  WHERE lan = 1 AND NOT EXISTS (SELECT 1 FROM cur.users c WHERE ` + sameUser + ` AND c.lan = 1)`},
		{"users", "lan_key", `UPDATE users SET lan_key = (SELECT c.lan_key FROM cur.users c WHERE ` + sameUser + `)
		  WHERE lan = 1 AND EXISTS (SELECT 1 FROM cur.users c WHERE ` + sameUser + `
		                            AND c.lan_key IS NOT NULL AND c.lan_key IS NOT users.lan_key)`},
		{"devices", "lan", `UPDATE devices SET lan = 0
		  WHERE lan = 1 AND NOT EXISTS (SELECT 1 FROM cur.devices c WHERE c.id = devices.id AND c.lan = 1)`},
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

// CarriedDevice is a device revoked in the current database and active in
// the one carried into: carryDevices revoked it there.
type CarriedDevice struct {
	ID, User, Name string
}

// Restored is what CarryRestore carried into a backup from the node's
// database.
type Restored struct {
	// Carried are the devices revoked in current since the backup: revoked
	// in it too, their users with new credentials and a new LAN key.
	Carried []CarriedDevice
	// Unknown are the devices active in the backup that current has no
	// record of: whether one was revoked since cannot be known.
	Unknown []CarriedDevice
	// Renewed are the other users of the backup whose credentials current
	// renewed since: by rayctl user renew or the step of schema 14 (they
	// take current's credentials and LAN key), or by revoking a device made
	// since the backup (they get new ones).
	Renewed []string
}

// CarryDeviceRevocations is CarryRestore for a caller that reports only
// the devices: the users renewed are carried all the same.
func CarryDeviceRevocations(ctx context.Context, saved, current string) (carried, unknown []CarriedDevice, err error) {
	r, err := CarryRestore(ctx, saved, current)
	return r.Carried, r.Unknown, err
}

// CarryRestore is CarryRevocations for rayctl restore, which replaces the
// node's state with a backup on purpose (a user, a service or a setting
// back as it was is what it is for): only what retired a secret since the
// backup carries into saved, as it was given (R4-36):
//   - a device revoked in current since stays revoked in saved, and its
//     user gets new credentials and a new LAN key (carryDevices);
//   - a user renewed since (an audit line user.renew or
//     user.renew:revoked-before in current that the backup does not have)
//     takes current's credentials and LAN key, those its clients fetched;
//   - a user with a device in current made and revoked since the backup
//     gets new credentials and a new LAN key: the device may have had the
//     backup's.
//
// Devices are matched by their random ID, users by ID, name and creation
// time: a current database of another node (a new host) matches none, all
// of saved's devices are Unknown, and what was revoked or renewed after
// the backup cannot be known; a device current does not know stays as the
// backup has it. A renewal with no audit line (rayd stopped between the
// two) is not seen. Neither database may be open elsewhere.
func CarryRestore(ctx context.Context, saved, current string) (Restored, error) {
	var r Restored
	if strings.ContainsAny(current, "?#") {
		return r, fmt.Errorf("store: database path %q", current)
	}
	db, err := sql.Open("sqlite", "file:"+saved+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return r, err
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		return r, err
	}
	defer conn.Close() //nolint:errcheck // returns the connection to the pool
	if _, err := conn.ExecContext(ctx, `ATTACH DATABASE ? AS cur`, "file:"+current+"?mode=ro"); err != nil {
		return r, fmt.Errorf("store: opening %s: %w", current, err)
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return r, err
	}
	defer tx.Rollback() //nolint:errcheck // after Commit it does nothing
	took, err := carryCredentials(ctx, tx, true)
	if err != nil {
		return r, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users AS u SET lan_key = c.lan_key
		FROM cur.users c WHERE c.id = u.id AND c.name = u.name AND c.created_at = u.created_at
		  AND u.lan_key IS NOT NULL AND c.lan_key IS NOT NULL AND c.lan_key IS NOT u.lan_key AND `+renewedSince); err != nil {
		return r, fmt.Errorf("store: carrying renewals: %w", err)
	}
	// Then the revocations: new credentials for their users, over current's.
	if r.Carried, err = carryDevices(ctx, tx, false); err != nil {
		return r, err
	}
	carried := func(name string) bool {
		return slices.ContainsFunc(r.Carried, func(d CarriedDevice) bool { return d.User == name })
	}
	for _, n := range took {
		if !carried(n) {
			r.Renewed = append(r.Renewed, n)
		}
	}
	// A device made and revoked since: the backup's credentials of its
	// user may be those it had.
	rows, err := tx.QueryContext(ctx, `SELECT u.id, u.name FROM main.users u
		JOIN cur.users c ON c.id = u.id AND c.name = u.name AND c.created_at = u.created_at
		WHERE EXISTS (SELECT 1 FROM cur.devices d WHERE d.user_id = c.id AND d.revoked_at IS NOT NULL
		              AND NOT EXISTS (SELECT 1 FROM main.devices m WHERE m.id = d.id))
		ORDER BY u.name`)
	if err != nil {
		return r, fmt.Errorf("store: carrying revocations: %w", err)
	}
	type user struct {
		id   int64
		name string
	}
	var made []user
	for rows.Next() {
		var u user
		if err := rows.Scan(&u.id, &u.name); err != nil {
			rows.Close()
			return r, err
		}
		if !carried(u.name) {
			made = append(made, u)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return r, err
	}
	now := time.Now().Unix()
	for _, u := range made {
		key, err := newLANKey()
		if err != nil {
			return r, err
		}
		if _, err := renewUser(ctx, tx, u.id, now, key); err != nil {
			return r, fmt.Errorf("store: carrying revocations: %w", err)
		}
		if !slices.Contains(r.Renewed, u.name) {
			r.Renewed = append(r.Renewed, u.name)
		}
	}
	slices.Sort(r.Renewed)
	// What current cannot tell: the active devices it has no record of.
	rows, err = tx.QueryContext(ctx, `SELECT d.id, u.name, d.name FROM devices d JOIN users u ON u.id = d.user_id
		WHERE d.revoked_at IS NULL AND NOT EXISTS (SELECT 1 FROM cur.devices c WHERE c.id = d.id)
		ORDER BY u.name, d.name`)
	if err != nil {
		return r, err
	}
	for rows.Next() {
		var d CarriedDevice
		if err := rows.Scan(&d.ID, &d.User, &d.Name); err != nil {
			rows.Close()
			return r, err
		}
		r.Unknown = append(r.Unknown, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return r, err
	}
	return r, tx.Commit()
}

// renewedSince holds for a user u of main whom cur renewed since main was
// copied, by cur's audit: a renewal's line, its target the user's name
// and a colon (a name has none), that main does not have.
const renewedSince = `u.name IN (SELECT substr(a.target, 1, instr(a.target, ':') - 1) FROM cur.audit_log a
		WHERE a.action IN ('user.renew', 'user.renew:revoked-before') AND a.result = 'ok' AND instr(a.target, ':') > 1
		  AND NOT EXISTS (SELECT 1 FROM main.audit_log m
		                  WHERE m.id = a.id AND m.ts = a.ts AND m.action = a.action AND m.target = a.target))`

// carryCredentials gives each credential in main (with renewed, only of
// the users renewedSince), that cur has too, of the same user (ID, name
// and creation time) and the same service (ID and kind: service IDs are
// never reused), cur's secrets and rotation where they differ. Only rows
// main has change: a credential or a user made since is not made, one
// gone since is not dropped. The columns are those of schema 3, which no
// migration since changed, so an older rayd reads them as its own. It
// returns the names of the users whose credentials changed.
func carryCredentials(ctx context.Context, tx *sql.Tx, renewed bool) ([]string, error) {
	has, err := hasColumn(ctx, tx, "main", "credentials", "rotated_at")
	if err != nil || !has {
		return nil, err // before schema 3 there is no rotation to carry
	}
	const match = `FROM cur.credentials c
		JOIN main.users u ON u.id = c.user_id
		JOIN cur.users cu ON cu.id = u.id AND cu.name = u.name AND cu.created_at = u.created_at
		JOIN main.services s ON s.id = c.service_id
		JOIN cur.services cs ON cs.id = s.id AND cs.kind = s.kind
		WHERE c.user_id = mc.user_id AND c.service_id = mc.service_id AND (NOT ?1 OR ` + renewedSince + `)
		  AND (c.secret IS NOT mc.secret OR c.next_secret IS NOT mc.next_secret OR c.next_from IS NOT mc.next_from
		       OR c.prev_secret IS NOT mc.prev_secret OR c.prev_until IS NOT mc.prev_until OR c.rotated_at IS NOT mc.rotated_at)`
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT mu.name FROM main.credentials mc JOIN main.users mu ON mu.id = mc.user_id
		WHERE EXISTS (SELECT 1 `+match+`) ORDER BY mu.name`, renewed)
	if err != nil {
		return nil, fmt.Errorf("store: carrying credentials: %w", err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE credentials AS mc SET secret = c.secret, next_secret = c.next_secret,
		    next_from = c.next_from, prev_secret = c.prev_secret, prev_until = c.prev_until, rotated_at = c.rotated_at
		`+match, renewed); err != nil {
		return nil, fmt.Errorf("store: carrying credentials: %w", err)
	}
	return names, nil
}

// carryDevices revokes in main the devices active there and revoked in
// cur (with gone, also those cur does not have: a rollback's, where a
// device deleted since went with its user), at cur's time of revocation
// or now, and gives each of their users new credentials and, with LAN on,
// a new LAN key: the credentials main has are those the revoked device
// knew. New ones, not cur's: a device revoked by a rayd before R4-36 left
// them as they were. The users' other devices fetch them with their next
// subscription.
func carryDevices(ctx context.Context, tx *sql.Tx, gone bool) ([]CarriedDevice, error) {
	rows, err := tx.QueryContext(ctx, `SELECT d.id, d.user_id, u.name, d.name FROM devices d JOIN users u ON u.id = d.user_id
		WHERE d.revoked_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM cur.devices c WHERE c.id = d.id AND c.revoked_at IS NULL)
		  AND (?1 OR EXISTS (SELECT 1 FROM cur.devices c WHERE c.id = d.id))
		ORDER BY u.name, d.name`, gone)
	if err != nil {
		return nil, fmt.Errorf("store: carrying revocations: %w", err)
	}
	var carried []CarriedDevice
	var users []int64
	for rows.Next() {
		var d CarriedDevice
		var user int64
		if err := rows.Scan(&d.ID, &user, &d.User, &d.Name); err != nil {
			rows.Close()
			return nil, err
		}
		carried = append(carried, d)
		if !slices.Contains(users, user) {
			users = append(users, user)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	for _, d := range carried {
		if _, err := tx.ExecContext(ctx, `UPDATE devices SET revoked_at = COALESCE((SELECT c.revoked_at FROM cur.devices c WHERE c.id = devices.id), ?)
			WHERE id = ?`, now, d.ID); err != nil {
			return nil, fmt.Errorf("store: carrying revocations: %w", err)
		}
	}
	lan, err := hasColumn(ctx, tx, "main", "users", "lan_key")
	if err != nil {
		return nil, err
	}
	for _, user := range users {
		if _, err := renewCredentials(ctx, tx, user, now, false); err != nil {
			return nil, fmt.Errorf("store: carrying revocations: %w", err)
		}
		if !lan {
			continue
		}
		key, err := newLANKey()
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET lan_key = ? WHERE lan_key IS NOT NULL AND id = ?`, key, user); err != nil {
			return nil, err
		}
	}
	return carried, nil
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
