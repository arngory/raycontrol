package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// settingRenewedRevoked is the time (unix seconds) up to which every user
// with a device revoked has credentials no revoked device knew: a
// rollback's carry writes it into a copy older than schema 14, whose step
// (renewRevokedUsers) then renews only the users of devices revoked at
// that time or later, on the older rayd after the rollback. rayd before
// v0.27.0 reads settings by key and ignores it.
const settingRenewedRevoked = "revoked_renewed_at"

// settingSPAParams is the node's SPA parameters (internal/node), whose
// node_id tells one node from another.
const settingSPAParams = "spa_params"

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
// A copy older than schema 14 has revocations its step will renew again at
// the next update. When current is at 14 or later, its step renewed them,
// and the carry brought that into saved: a user of one that current does
// not have (deleted since) gets new credentials and LAN key here, and
// settingRenewedRevoked tells the step that every revocation until now is
// renewed; an existing mark (an earlier rollback's) keeps its earlier
// time (markRenewed). When current is older than 14 too (an update that
// failed before the new rayd migrated it), nothing renewed them: no mark,
// and the next update renews them all. Each change to credentials has an
// audit line in saved (user.renew:rollback, device.revoke:rollback,
// user.carry:rollback).
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
	now := time.Now().Unix()
	const actor = "rayctl update -rollback"
	keepDoH, err := carryKeepsDoH(ctx, tx, now)
	if err != nil {
		return err
	}
	version, err := schemaOf(ctx, tx, "main")
	if err != nil {
		return err
	}
	curVersion, err := schemaOf(ctx, tx, "cur")
	if err != nil {
		return err
	}
	// The step of schema 14 renewed current's revoked users, and saved may
	// say so once the carry brought their credentials: not after an update
	// that failed before the new rayd ran, current at 13 as saved is.
	renewedAll := version < 14 && curVersion >= 14
	// The same user in both: a deleted user's ID may have gone to another.
	const sameUser = `c.id = users.id AND c.name = users.name AND c.created_at = users.created_at`
	if _, err := carryCredentials(ctx, tx); err != nil {
		return err
	}
	users, err := carryUsers(ctx, tx)
	if err != nil {
		return err
	}
	renewed := map[string]int{}
	if renewedAll {
		// The step of schema 14 will skip what is renewed until now: the
		// credentials of a user with a device revoked that current does not
		// have are the copy's, of before the step, and get new ones here.
		fresh, err := freshenUnmatched(ctx, tx, now, true)
		if err != nil {
			return err
		}
		for _, u := range users {
			if !u.matched && u.revoked && u.lan {
				if err := newUserLANKey(ctx, tx, u.id); err != nil {
					return err
				}
				fresh[u.name] += 0
			}
		}
		for n, k := range fresh {
			renewed[n] = k
		}
	}
	carried, counts, err := carryDevices(ctx, tx, true, keepDoH, now)
	if err != nil {
		return err
	}
	if err := auditCarry(ctx, tx, now, actor, "rollback", users, carried, counts, nil, renewed); err != nil {
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
	if renewedAll {
		if err := markRenewed(ctx, tx, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// markRenewed writes settingRenewedRevoked into main at now, unless main
// has one already at an earlier time: a copy an earlier rollback marked at
// T1, on which the older rayd ran and revoked devices without renewing,
// and which an update then copied again. T1 stays. A mark claims that
// every revocation before it has its user renewed; the carry vouches only
// for what current's step renewed, and that step took T1 from this copy.
// Wrong the later way, a device revoked between T1 and now would keep its
// user's credentials for good, and nothing would say so; wrong the earlier
// way, the next update renews once more the users of devices revoked
// between T1 and now, whose other devices reconnect after their next
// fetch. A mark that does not read as a time stays too: the step takes it
// for none, and renews them all.
func markRenewed(ctx context.Context, tx *sql.Tx, now int64) error {
	var old []byte
	err := tx.QueryRowContext(ctx, `SELECT value FROM main.settings WHERE key = ?`, settingRenewedRevoked).Scan(&old)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return err
	default:
		if t, perr := strconv.ParseInt(string(old), 10, 64); perr != nil || t <= now {
			return nil
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO main.settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, settingRenewedRevoked, []byte(strconv.FormatInt(now, 10)))
	return err
}

// CarriedDevice is a device revoked in the current database and active in
// the one carried into: carryDevices revoked it there.
type CarriedDevice struct {
	ID, User, Name string
}

// Renewal is a user of the backup whom a restore gave new credentials,
// and why.
type Renewal struct {
	User, Why string
}

// Restored is what CarryRestore carried into a backup from the node's
// database.
type Restored struct {
	// Foreign: the node's database is another node's (a new host), and
	// nothing was carried; every active device of the backup is Unknown.
	Foreign bool
	// Kept is how many users of the backup have the credentials and LAN
	// key the node's database has, none new.
	Kept int
	// Carried are the devices revoked in current since the backup: revoked
	// in it too, their users with new credentials and a new LAN key.
	Carried []CarriedDevice
	// New are the other users of the backup with new credentials: deleted
	// here since (or deleted and made again), with a credential the node no
	// longer has, or with a device made and revoked since the backup.
	New []Renewal
	// Unknown are the devices active in the backup that current has no
	// record of: whether one was revoked since cannot be known.
	Unknown []CarriedDevice
}

// CarryDeviceRevocations is CarryRestore for a caller that reports only
// the devices: the rest is carried all the same.
func CarryDeviceRevocations(ctx context.Context, saved, current string) (carried, unknown []CarriedDevice, err error) {
	r, err := CarryRestore(ctx, saved, current)
	return r.Carried, r.Unknown, err
}

// CarryRestore is CarryRevocations for rayctl restore, which replaces the
// node's state with a backup on purpose: a user, a device, a service or a
// setting back as it was is what it is for, old secrets are not (R4-36).
// On the node the backup is of (the same node_id in both), the clients hold
// the secrets of current, so the backup's are the same or older: older
// ones would cut every client until it fetches, and may be ones retired
// because they leaked. So, on the same node:
//   - every credential saved and current both have, of the same user (ID,
//     name and creation time) and the same service (ID and kind), takes
//     current's values, and the user's LAN key is current's;
//   - a credential current does not have (its user deleted, or deleted and
//     made again, or its service deleted since) gets a new secret, and a
//     LAN key current does not have a new key: who else knew the backup's
//     is not known;
//   - a device revoked in current since stays revoked in saved, and its
//     user gets new credentials and a new LAN key (carryDevices);
//   - a user with a device in current made and revoked since the backup
//     gets new credentials and a new LAN key: the device knew the user's.
//
// The renewals keep DoH's secrets only where saved can have no shared DoH
// token (carryKeepsDoH). Each change has an audit line in saved
// (user.renew:restore, device.revoke:restore, user.carry:restore).
//
// A current database of another node (a new host) has none of the
// backup's secrets to carry: nothing changes, and all of saved's active
// devices are Unknown. Neither database may be open elsewhere.
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
	var same bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM main.settings m JOIN cur.settings c ON c.key = m.key
		WHERE m.key = ? AND json_valid(m.value) AND json_valid(c.value)
		  AND json_extract(m.value, '$.node_id') IS NOT NULL
		  AND json_extract(m.value, '$.node_id') = json_extract(c.value, '$.node_id'))`, settingSPAParams).Scan(&same); err != nil {
		return r, fmt.Errorf("store: carrying revocations: %w", err)
	}
	if !same {
		r.Foreign = true
		r.Unknown, err = unknownDevices(ctx, tx)
		return r, err // nothing written
	}
	now := time.Now().Unix()
	keepDoH, err := carryKeepsDoH(ctx, tx, now)
	if err != nil {
		return r, err
	}
	if _, err := carryCredentials(ctx, tx); err != nil {
		return r, err
	}
	users, err := carryUsers(ctx, tx)
	if err != nil {
		return r, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users AS u SET lan_key = c.lan_key
		FROM cur.users c WHERE c.id = u.id AND c.name = u.name AND c.created_at = u.created_at
		  AND u.lan_key IS NOT NULL AND c.lan_key IS NOT NULL AND c.lan_key IS NOT u.lan_key`); err != nil {
		return r, fmt.Errorf("store: carrying LAN keys: %w", err)
	}
	fresh, err := freshenUnmatched(ctx, tx, now, false)
	if err != nil {
		return r, err
	}
	why := map[string][]string{}
	renewed := map[string]int{}
	for _, u := range users {
		switch {
		case !u.matched && u.sameName:
			why[u.name] = append(why[u.name], "deleted and made again here since the backup")
		case !u.matched:
			why[u.name] = append(why[u.name], "deleted here since the backup")
		case fresh[u.name] > 0:
			why[u.name] = append(why[u.name], "a service of theirs deleted here since the backup")
		}
		if u.lan && (!u.matched || !u.curLAN) {
			if err := newUserLANKey(ctx, tx, u.id); err != nil {
				return r, err
			}
			if u.matched && fresh[u.name] == 0 {
				why[u.name] = append(why[u.name], "LAN key new: LAN turned off here since the backup")
			}
		}
		if len(why[u.name]) > 0 {
			renewed[u.name] = fresh[u.name]
		}
	}
	// Then the revocations: new credentials for their users, over current's.
	var counts map[string]int
	if r.Carried, counts, err = carryDevices(ctx, tx, false, keepDoH, now); err != nil {
		return r, err
	}
	carried := func(name string) bool {
		return slices.ContainsFunc(r.Carried, func(d CarriedDevice) bool { return d.User == name })
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
	for _, u := range made {
		key, err := newLANKey()
		if err != nil {
			return r, err
		}
		n, err := renewUser(ctx, tx, u.id, now, key, keepDoH)
		if err != nil {
			return r, fmt.Errorf("store: carrying revocations: %w", err)
		}
		why[u.name] = append(why[u.name], "a device added and revoked here since the backup")
		renewed[u.name] = max(renewed[u.name], n)
	}
	for _, u := range users {
		if carried(u.name) {
			delete(renewed, u.name)
			continue
		}
		if w, ok := why[u.name]; ok {
			r.New = append(r.New, Renewal{User: u.name, Why: strings.Join(w, "; ")})
		} else if u.matched {
			r.Kept++
		}
	}
	if err := auditCarry(ctx, tx, now, "rayctl restore", "restore", users, r.Carried, counts, why, renewed); err != nil {
		return r, err
	}
	if r.Unknown, err = unknownDevices(ctx, tx); err != nil {
		return r, err
	}
	return r, tx.Commit()
}

// unknownDevices are the active devices of main that cur has no record of.
func unknownDevices(ctx context.Context, tx *sql.Tx) ([]CarriedDevice, error) {
	rows, err := tx.QueryContext(ctx, `SELECT d.id, u.name, d.name FROM devices d JOIN users u ON u.id = d.user_id
		WHERE d.revoked_at IS NULL AND NOT EXISTS (SELECT 1 FROM cur.devices c WHERE c.id = d.id)
		ORDER BY u.name, d.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CarriedDevice
	for rows.Next() {
		var d CarriedDevice
		if err := rows.Scan(&d.ID, &d.User, &d.Name); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// carryUser is a user of main as cur knows it.
type carryUser struct {
	id   int64
	name string
	// matched: cur has the user (ID, name and creation time); sameName:
	// cur has a user of that name, another (deleted and made again).
	matched, sameName bool
	// lan: main has a LAN key for the user; curLAN: cur has one too.
	lan, curLAN bool
	// revoked: main has a device of the user's revoked.
	revoked bool
}

func carryUsers(ctx context.Context, tx *sql.Tx) ([]carryUser, error) {
	lan, err := hasColumn(ctx, tx, "main", "users", "lan_key")
	if err != nil {
		return nil, err
	}
	// The copy may be older than the LAN (schema 13): no key there.
	const (
		withLAN = `SELECT u.id, u.name,
		EXISTS (SELECT 1 FROM cur.users c WHERE c.id = u.id AND c.name = u.name AND c.created_at = u.created_at),
		EXISTS (SELECT 1 FROM cur.users c WHERE c.name = u.name),
		u.lan_key IS NOT NULL,
		coalesce((SELECT c.lan_key IS NOT NULL FROM cur.users c
		          WHERE c.id = u.id AND c.name = u.name AND c.created_at = u.created_at), 0),
		EXISTS (SELECT 1 FROM main.devices d WHERE d.user_id = u.id AND d.revoked_at IS NOT NULL)
		FROM main.users u ORDER BY u.name`
		withoutLAN = `SELECT u.id, u.name,
		EXISTS (SELECT 1 FROM cur.users c WHERE c.id = u.id AND c.name = u.name AND c.created_at = u.created_at),
		EXISTS (SELECT 1 FROM cur.users c WHERE c.name = u.name),
		0, 0,
		EXISTS (SELECT 1 FROM main.devices d WHERE d.user_id = u.id AND d.revoked_at IS NOT NULL)
		FROM main.users u ORDER BY u.name`
	)
	q := withoutLAN
	if lan {
		q = withLAN
	}
	rows, err := tx.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("store: carrying credentials: %w", err)
	}
	defer rows.Close()
	var out []carryUser
	for rows.Next() {
		var u carryUser
		if err := rows.Scan(&u.id, &u.name, &u.matched, &u.sameName, &u.lan, &u.curLAN, &u.revoked); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// carryCredentials gives each credential in main that cur has too, of the
// same user (ID, name and creation time) and the same service (ID and
// kind: service IDs are never reused), cur's secrets and rotation where
// they differ. Only rows main has change: a credential or a user made
// since is not made, one gone since is not dropped. The columns are those
// of schema 3, which no migration since changed, so an older rayd reads
// them as its own. It returns the names of the users whose credentials
// changed.
func carryCredentials(ctx context.Context, tx *sql.Tx) ([]string, error) {
	has, err := hasColumn(ctx, tx, "main", "credentials", "rotated_at")
	if err != nil || !has {
		return nil, err // before schema 3 there is no rotation to carry
	}
	const match = `FROM cur.credentials c
		JOIN main.users u ON u.id = c.user_id
		JOIN cur.users cu ON cu.id = u.id AND cu.name = u.name AND cu.created_at = u.created_at
		JOIN main.services s ON s.id = c.service_id
		JOIN cur.services cs ON cs.id = s.id AND cs.kind = s.kind
		WHERE c.user_id = mc.user_id AND c.service_id = mc.service_id
		  AND (c.secret IS NOT mc.secret OR c.next_secret IS NOT mc.next_secret OR c.next_from IS NOT mc.next_from
		       OR c.prev_secret IS NOT mc.prev_secret OR c.prev_until IS NOT mc.prev_until OR c.rotated_at IS NOT mc.rotated_at)`
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT mu.name FROM main.credentials mc JOIN main.users mu ON mu.id = mc.user_id
		WHERE EXISTS (SELECT 1 `+match+`) ORDER BY mu.name`)
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
		`+match); err != nil {
		return nil, fmt.Errorf("store: carrying credentials: %w", err)
	}
	return names, nil
}

// freshenUnmatched gives every credential of main that cur does not have
// (no row of the same user, by ID, name and creation time, and the same
// service, by ID and kind) a new secret, with no next and no previous one;
// with revoked, only those of users with a device revoked in main. It
// returns how many each user's name got.
func freshenUnmatched(ctx context.Context, tx *sql.Tx, now int64, revoked bool) (map[string]int, error) {
	out := map[string]int{}
	has, err := hasColumn(ctx, tx, "main", "credentials", "rotated_at")
	if err != nil || !has {
		return out, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT mc.user_id, mu.name, mc.service_id FROM main.credentials mc
		JOIN main.users mu ON mu.id = mc.user_id
		WHERE NOT EXISTS (SELECT 1 FROM cur.credentials c
		        JOIN cur.users cu ON cu.id = c.user_id AND cu.name = mu.name AND cu.created_at = mu.created_at
		        JOIN cur.services cs ON cs.id = c.service_id
		        JOIN main.services s ON s.id = mc.service_id AND s.kind = cs.kind
		        WHERE c.user_id = mc.user_id AND c.service_id = mc.service_id)
		  AND (NOT ?1 OR EXISTS (SELECT 1 FROM main.devices d WHERE d.user_id = mu.id AND d.revoked_at IS NOT NULL))
		ORDER BY mc.user_id, mc.service_id`, revoked)
	if err != nil {
		return nil, fmt.Errorf("store: carrying credentials: %w", err)
	}
	type row struct {
		user, service int64
		name          string
	}
	var todo []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.user, &x.name, &x.service); err != nil {
			rows.Close()
			return nil, err
		}
		todo = append(todo, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, x := range todo {
		secret, err := NewUUID()
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE credentials SET secret = ?, next_secret = NULL, next_from = NULL,
			prev_secret = NULL, prev_until = NULL, rotated_at = ? WHERE user_id = ? AND service_id = ?`,
			secret, now, x.user, x.service); err != nil {
			return nil, fmt.Errorf("store: carrying credentials: %w", err)
		}
		out[x.name]++
	}
	return out, nil
}

func newUserLANKey(ctx context.Context, tx *sql.Tx, user int64) error {
	key, err := newLANKey()
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE users SET lan_key = ? WHERE lan_key IS NOT NULL AND id = ?`, key, user)
	return err
}

// carryKeepsDoH reports whether a renewal in main may keep the users' DoH
// secrets, as RevokeDevice does (R4-37): only when main is at schema 15 or
// later with no shared window open. A copy before schema 15 opens the
// window at its update (or is read by a rayd that takes the secret as the
// token), and in a window open the secret is a token: a revoked device may
// know it, and main does not record its revocation.
func carryKeepsDoH(ctx context.Context, tx *sql.Tx, now int64) (bool, error) {
	v, err := schemaOf(ctx, tx, "main")
	if err != nil || v < 15 {
		return false, err
	}
	var value []byte
	err = tx.QueryRowContext(ctx, `SELECT value FROM main.settings WHERE key = ?`, settingDoHShared).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	_, until := parseDoHShared(value)
	return now >= until, nil
}

// schemaOf is the newest migration applied to the database schema.
func schemaOf(ctx context.Context, tx *sql.Tx, schema string) (int, error) {
	has, err := hasTable(ctx, tx, schema, "schema_migrations")
	if err != nil || !has {
		return 0, err
	}
	var v int
	err = tx.QueryRowContext(ctx, `SELECT coalesce(max(version), 0) FROM `+schema+`.schema_migrations`).Scan(&v)
	return v, err
}

// auditCarry writes into main the audit lines of what a carry (op: restore
// or rollback) did to credentials, with no secret: a line per device it
// revoked (device.revoke:<op>), per user it gave new credentials
// (user.renew:<op>; counts of carryDevices, renewed and why of the
// others), and one for the users whose credentials and LAN key it took
// from the node's database (user.carry:<op>).
func auditCarry(ctx context.Context, tx *sql.Tx, now int64, actor, op string, users []carryUser,
	carried []CarriedDevice, counts map[string]int, why map[string][]string, renewed map[string]int) error {
	write := func(action, target string) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO main.audit_log (ts, actor, action, target, result) VALUES (?, ?, ?, ?, 'ok')`,
			now, actor, action, target)
		return err
	}
	for _, d := range carried {
		if err := write("device.revoke:"+op, fmt.Sprintf("%s %s/%s: revoked on the node since the copy", d.ID, d.User, d.Name)); err != nil {
			return err
		}
	}
	kept := 0
	for _, u := range users {
		if n, ok := counts[u.name]; ok {
			if err := write("user.renew:"+op, fmt.Sprintf("%s: %d credentials new, a device of the user revoked on the node since the copy", u.name, n)); err != nil {
				return err
			}
			continue
		}
		if n, ok := renewed[u.name]; ok {
			w := "a device of the user revoked before schema 14, not on the node"
			if why != nil {
				w = strings.Join(why[u.name], "; ")
			}
			if err := write("user.renew:"+op, fmt.Sprintf("%s: %d credentials new, %s", u.name, n, w)); err != nil {
				return err
			}
			continue
		}
		if u.matched {
			kept++
		}
	}
	if kept > 0 {
		return write("user.carry:"+op, fmt.Sprintf("%d users: credentials and LAN keys as on the node", kept))
	}
	return nil
}

// carryDevices revokes in main the devices active there and revoked in
// cur (with gone, also those cur does not have: a rollback's, where a
// device deleted since went with its user), at cur's time of revocation
// or now, and gives each of their users new credentials and, with LAN on,
// a new LAN key: the credentials main has are those the revoked device
// knew. New ones, not cur's: a device revoked by a rayd before R4-36 left
// them as they were. With keepDoH (carryKeepsDoH) the DoH secrets stay,
// as RevokeDevice keeps them. The users' other devices fetch them with
// their next subscription. It returns the devices and how many
// credentials of each user are new.
func carryDevices(ctx context.Context, tx *sql.Tx, gone, keepDoH bool, now int64) ([]CarriedDevice, map[string]int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT d.id, d.user_id, u.name, d.name FROM devices d JOIN users u ON u.id = d.user_id
		WHERE d.revoked_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM cur.devices c WHERE c.id = d.id AND c.revoked_at IS NULL)
		  AND (?1 OR EXISTS (SELECT 1 FROM cur.devices c WHERE c.id = d.id))
		ORDER BY u.name, d.name`, gone)
	if err != nil {
		return nil, nil, fmt.Errorf("store: carrying revocations: %w", err)
	}
	var carried []CarriedDevice
	type user struct {
		id   int64
		name string
	}
	var users []user
	for rows.Next() {
		var d CarriedDevice
		var u user
		if err := rows.Scan(&d.ID, &u.id, &d.User, &d.Name); err != nil {
			rows.Close()
			return nil, nil, err
		}
		u.name = d.User
		carried = append(carried, d)
		if !slices.Contains(users, u) {
			users = append(users, u)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	for _, d := range carried {
		if _, err := tx.ExecContext(ctx, `UPDATE devices SET revoked_at = COALESCE((SELECT c.revoked_at FROM cur.devices c WHERE c.id = devices.id), ?)
			WHERE id = ?`, now, d.ID); err != nil {
			return nil, nil, fmt.Errorf("store: carrying revocations: %w", err)
		}
	}
	lan, err := hasColumn(ctx, tx, "main", "users", "lan_key")
	if err != nil {
		return nil, nil, err
	}
	counts := map[string]int{}
	for _, u := range users {
		n, err := renewCredentials(ctx, tx, u.id, now, keepDoH)
		if err != nil {
			return nil, nil, fmt.Errorf("store: carrying revocations: %w", err)
		}
		counts[u.name] = n
		if !lan {
			continue
		}
		if err := newUserLANKey(ctx, tx, u.id); err != nil {
			return nil, nil, err
		}
	}
	return carried, counts, nil
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
