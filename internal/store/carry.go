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
//     credentials, as a revocation gives (carryDevices), a revocation with
//     overlap (R4-43) too, its rotation in flight or not: the older rayd
//     the rollback goes back to runs no rotation loop without a period
//     (-cred-period 0, before v0.31.0), and the rotation would never
//     switch, leaving the revoked device's secret accepted for good;
//   - a device made since the copy, active in current or revoked there,
//     gives its user new credentials and a new LAN key, as a restore does
//     (renewAdded): the rollback drops it, and it knew the user's;
//   - a user disabled or deleted stays disabled, an earlier expiry stays,
//     and a service taken from a user stays taken;
//   - a user's or a device's LAN consent taken back stays taken back, and
//     a user's LAN key is the current one (a revocation renews it);
//   - a service disabled or deleted stays disabled, a REALITY no longer open
//     is not open, and a DNS tunnel keeps the stricter dnsauth mode;
//   - an unused invite withdrawn stays withdrawn, a relay removed stays
//     removed, and a relay's certificate, SPA, SSH access and probe
//     endpoint stay as now;
//   - the settings named in keep (the admin addresses, the node's own
//     name) take current's value.
//
// And credentials do not go back: every credential saved and current both
// have, of the same user and the same service, takes current's values
// (carryCredentials), and the users of devices revoked since get new ones
// on top. A renewal since the copy (rayctl user renew, the step of schema
// 14) left no next and no previous secret, so the copy's would be the very
// ones it retired; and an ordinary rotation since is no worse kept than
// undone, its secrets being those the clients fetched. A credential of
// saved that current does not have (its user deleted, or deleted and made
// again, or its service deleted since the copy) gets a new secret, as a
// restore gives it (freshenUnmatched), and such a user a new LAN key: the
// user or the service comes back disabled, and a device made and revoked
// since, gone with its user, may know the copy's ones; enabled again, the
// user would let it back in.
//
// A copy older than schema 14 has revocations its step will renew again at
// the next update. When current is at 14 or later, its step renewed them,
// and the carry brought that into saved (a user current does not have
// with new credentials, above): settingRenewedRevoked tells the step that
// every revocation until now is renewed; an existing mark (an earlier
// rollback's) keeps its earlier time (markRenewed). When current is older
// than 14 too (an update that failed before the new rayd migrated it),
// nothing renewed them: no mark, and the next update renews them all.
// Each change to credentials has an audit line in saved
// (user.renew:rollback, device.revoke:rollback, user.carry:rollback).
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
	// What current does not have is new, as a restore makes it.
	fresh, err := freshenUnmatched(ctx, tx, now)
	if err != nil {
		return err
	}
	why := map[string][]string{}
	renewed := map[string]int{}
	for _, u := range users {
		switch {
		case !u.matched && u.sameName:
			why[u.name] = append(why[u.name], "deleted and made again on the node since the copy")
		case !u.matched:
			why[u.name] = append(why[u.name], "deleted on the node since the copy")
		case fresh[u.name] > 0:
			why[u.name] = append(why[u.name], "a service of theirs deleted on the node since the copy")
		}
		if !u.matched && u.lan {
			if err := newUserLANKey(ctx, tx, u.id); err != nil {
				return err
			}
		}
		if len(why[u.name]) > 0 {
			renewed[u.name] = fresh[u.name]
		}
	}
	// No rotation kept: see above.
	carried, counts, err := carryDevices(ctx, tx, true, keepDoH, false, now)
	if err != nil {
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
	// After the statements, which give a user current's LAN key: the
	// users of devices the rollback drops get new ones.
	added, err := addedDevices(ctx, tx)
	if err != nil {
		return err
	}
	if _, err := renewAdded(ctx, tx, now, keepDoH, added, counts, why, renewed,
		"a device made on the node since the copy, not in it", "a device made and revoked on the node since the copy"); err != nil {
		return err
	}
	if err := auditCarry(ctx, tx, now, actor, "rollback", users, carried, counts, why, renewed); err != nil {
		return err
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
// the one carried into: carryDevices revoked it there. Rotating: it was
// revoked with overlap, and its user's rotation goes on as current has it
// (overlapInFlight); otherwise its user got new credentials.
type CarriedDevice struct {
	ID, User, Name string
	Rotating       bool
}

// Renewal is a user of the backup whom a restore gave new credentials,
// and why.
type Renewal struct {
	User, Why string
}

// Restored is what CarryRestore carried into a backup from the node's
// database.
type Restored struct {
	// Foreign: nothing was carried, and every active device of the backup
	// is Unknown. The node's database is another node's (a new host), or,
	// with Newer, it is the backup's node's but no later state of it.
	Foreign bool
	// Newer says what the backup has that the node's database does not
	// (backupNewer): the first sign found.
	Newer string
	// Kept is how many users of the backup have the credentials and LAN
	// key the node's database has, none new.
	Kept int
	// Carried are the devices revoked in current since the backup: revoked
	// in it too, their users with new credentials and a new LAN key; or,
	// Rotating, with current's credentials, in the rotation a revocation
	// with overlap began (R4-43).
	Carried []CarriedDevice
	// New are the other users of the backup with new credentials: deleted
	// here since (or deleted and made again), with a credential the node no
	// longer has, or with a device made since the backup (Added).
	New []Renewal
	// Added are the devices current has, of users the backup has, that the
	// backup does not: made since, revoked since or not. They are not in
	// the restored database, and their users have new credentials and a
	// new LAN key there: each device fetched the user's.
	Added []AddedDevice
	// Unknown are the devices active in the backup that current has no
	// record of: whether one was revoked since cannot be known.
	Unknown []CarriedDevice
}

// AddedDevice is a device of Restored.Added.
type AddedDevice struct {
	CarriedDevice
	Revoked bool // revoked here already
	userID  int64
}

// CarryDeviceRevocations is CarryRestore for a caller that reports only
// the devices: the rest is carried all the same.
func CarryDeviceRevocations(ctx context.Context, saved, current string) (carried, unknown []CarriedDevice, err error) {
	r, err := CarryRestore(ctx, saved, current, "")
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
//     user gets new credentials and a new LAN key (carryDevices); unless
//     it was revoked with overlap and its user's rotation has not switched
//     yet: current's credentials then go on as announced (R4-43,
//     overlapInFlight);
//   - a user with a device in current made since the backup, revoked
//     since or not, gets new credentials and a new LAN key: the device
//     knew the user's, and it is not in saved (Restored.Added). One still
//     active is cut with the restore, not at the next rotation; one
//     revoked with overlap too, its rotation in flight or not (renewAdded).
//
// The renewals keep DoH's secrets only where saved can have no shared DoH
// token (carryKeepsDoH). Each change has an audit line in saved
// (user.renew:restore, device.revoke:restore, user.carry:restore).
//
// A current database of another node (a new host) has none of the
// backup's secrets to carry: nothing changes, and all of saved's active
// devices are Unknown. The same when current is the backup's node's but
// not at least as new as the backup in every respect (backupNewer): a
// backup restored on a new host gives it the node_id, so does a disk
// cloned, and a restore -no-carry of an older copy leaves the node behind
// its newer backups. Carried then, current's older secrets would go over
// the backup's (a secret renewed after a leak back, a revoked device's
// user's credentials as the device knew them) with no word.
//
// made is the backup's database as it was made, when saved is that
// database migrated since (rayctl restore runs rayd init on it first, and
// the step of schema 14 renews and audits there at the restore's time);
// "" when saved is as made. backupNewer reads made. Neither database may
// be open elsewhere.
func CarryRestore(ctx context.Context, saved, current, made string) (Restored, error) {
	var r Restored
	if strings.ContainsAny(current, "?#") || strings.ContainsAny(made, "?#") {
		return r, fmt.Errorf("store: database path %q", current+made)
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
	bk := "main"
	if made != "" {
		if _, err := conn.ExecContext(ctx, `ATTACH DATABASE ? AS bk`, "file:"+made+"?mode=ro"); err != nil {
			return r, fmt.Errorf("store: opening %s: %w", made, err)
		}
		bk = "bk"
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
		r.Unknown, err = unknownDevices(ctx, tx, false)
		return r, err // nothing written
	}
	if r.Newer, err = backupNewer(ctx, tx, bk); err != nil {
		return r, err
	}
	if r.Newer != "" {
		// What current says of the backup's devices is of before them.
		r.Foreign = true
		r.Unknown, err = unknownDevices(ctx, tx, true)
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
	fresh, err := freshenUnmatched(ctx, tx, now)
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
	// Then the revocations: new credentials for their users, over
	// current's, but where a revocation with overlap's rotation goes on.
	keeps, err := carryKeepsRotation(ctx, tx, keepDoH)
	if err != nil {
		return r, err
	}
	var counts map[string]int
	if r.Carried, counts, err = carryDevices(ctx, tx, false, keepDoH, keeps, now); err != nil {
		return r, err
	}
	carried := func(name string) bool {
		_, ok := counts[name]
		return ok
	}
	// A device made since, revoked or not: it is not in saved and goes
	// with the restore, but it fetched its user's credentials, which are
	// current's now in saved.
	if r.Added, err = addedDevices(ctx, tx); err != nil {
		return r, err
	}
	renewedAdded, err := renewAdded(ctx, tx, now, keepDoH, r.Added, counts, why, renewed,
		"a device added here since the backup, not in it", "a device added and revoked here since the backup")
	if err != nil {
		return r, err
	}
	// A user renewed for a device added has no rotation going on, whatever
	// a carried revocation began.
	for i := range r.Carried {
		if renewedAdded[r.Carried[i].User] {
			r.Carried[i].Rotating = false
		}
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
	if r.Unknown, err = unknownDevices(ctx, tx, false); err != nil {
		return r, err
	}
	return r, tx.Commit()
}

// backupNewer says what the backup (schema bk of tx: its database as it
// was made) has that cur does not, the first sign found, or "" when there
// is none: cur is then a later state of the backup's node as far as can
// be told, which carrying takes for granted (current's secrets,
// revocations and devices are those of since the backup). The signs,
// those that compare no clocks first:
//   - a device revoked in the backup and active in cur: a revocation is
//     for good;
//   - a device in the backup that cur does not have, of a user cur has
//     (ID, name and creation time): a device goes only with its user;
//   - a credential both have that moved on in the backup: cur's secret is
//     the backup's previous one, or cur's next one is the backup's
//     current one, or the backup has a next one that cur, at the same
//     current, does not (unless cur has another next and a device of the
//     user revoked since the backup: a revocation with overlap replaces
//     the next, R4-43); or the backup's rotated_at (a switch and a
//     renewal set it) is later;
//   - a service of the backup whose ID cur never gave (above its
//     AUTOINCREMENT sequence) or gave to another (kind, creation time);
//   - an invite used in the backup and not in cur, or with fewer PIN
//     tries left;
//   - an audit line of the backup that cur does not have, though cur
//     still keeps lines that old (rayd prunes by time, the oldest first):
//     every change through the API has one;
//   - the backup's newest record (a user, device, service or invite
//     made, a device revoked or let into the LAN, an invite used, a
//     credential rotated, an audit line) later than cur's newest.
//
// The rotation, the audit lines' range and the newest record compare
// times. On one host there is one clock, and a later state of the node
// has every record of the backup's or one made later. Across two hosts (a
// backup restored on a new host, which went its own way) cur's records of
// before the hosts parted carry the backup's host's times; a clock behind
// on cur's host makes those signs fire sooner, one ahead may hide them,
// and the clock-free ones still see a revocation, a device or a service
// added, a rotation of a secret both knew and a line audited on the
// backup's side.
func backupNewer(ctx context.Context, tx *sql.Tx, bk string) (string, error) {
	has := func(schema, table, column string) (bool, error) {
		ok, err := hasTable(ctx, tx, schema, table)
		if err == nil && ok && column != "" {
			ok, err = hasColumn(ctx, tx, schema, table, column)
		}
		return ok, err
	}
	both := func(table, column string) (bool, error) {
		ok, err := has(bk, table, column)
		if err == nil && ok {
			ok, err = has("cur", table, column)
		}
		return ok, err
	}
	type sign struct {
		table, column string // both databases must have it ("": any)
		say, query    string
	}
	signs := []sign{
		{"", "", "device %s %s/%s is revoked in the backup and active here",
			`SELECT d.id, u.name, d.name FROM bk.devices d JOIN bk.users u ON u.id = d.user_id
			 JOIN cur.devices c ON c.id = d.id
			 WHERE d.revoked_at IS NOT NULL AND c.revoked_at IS NULL ORDER BY u.name, d.name`},
		{"", "", "the backup has device %s %s/%s, which this database never had",
			`SELECT d.id, u.name, d.name FROM bk.devices d JOIN bk.users u ON u.id = d.user_id
			 JOIN cur.users c ON c.id = u.id AND c.name = u.name AND c.created_at = u.created_at
			 WHERE NOT EXISTS (SELECT 1 FROM cur.devices x WHERE x.id = d.id) ORDER BY u.name, d.name`},
		{"credentials", "rotated_at", "%s's credential on %s changed in the backup after it did here",
			`SELECT u.name, s.name FROM bk.credentials b
			 JOIN bk.users u ON u.id = b.user_id
			 JOIN cur.users cu ON cu.id = u.id AND cu.name = u.name AND cu.created_at = u.created_at
			 JOIN bk.services s ON s.id = b.service_id
			 JOIN cur.services cs ON cs.id = s.id AND cs.kind = s.kind
			 JOIN cur.credentials c ON c.user_id = b.user_id AND c.service_id = b.service_id
			 WHERE c.secret = b.prev_secret
			    OR (c.next_secret = b.secret AND c.secret IS NOT b.secret)
			    OR (c.secret = b.secret AND b.next_secret IS NOT NULL AND c.next_secret IS NOT b.next_secret
			        AND NOT (c.next_secret IS NOT NULL AND EXISTS (SELECT 1 FROM cur.devices cd
			            WHERE cd.user_id = b.user_id AND cd.revoked_at IS NOT NULL
			              AND NOT EXISTS (SELECT 1 FROM bk.devices bd WHERE bd.id = cd.id AND bd.revoked_at IS NOT NULL))))
			    OR b.rotated_at > c.rotated_at
			 ORDER BY u.name, s.name`},
		{"sqlite_sequence", "", "the backup has service %s, which this database never had",
			`SELECT s.name FROM bk.services s
			 WHERE s.id > coalesce((SELECT seq FROM cur.sqlite_sequence WHERE name = 'services'), 0)
			    OR EXISTS (SELECT 1 FROM cur.services c WHERE c.id = s.id AND (c.kind IS NOT s.kind OR c.created_at IS NOT s.created_at))
			 ORDER BY s.id`},
		{"invites", "", "the invite of %s/%s is used in the backup and not here",
			`SELECT u.name, i.name FROM bk.invites i JOIN bk.users u ON u.id = i.user_id JOIN cur.invites c ON c.id = i.id
			 WHERE i.used_at IS NOT NULL AND c.used_at IS NULL ORDER BY u.name, i.name`},
		{"invites", "pin_tries", "the invite of %s/%s has fewer PIN tries left in the backup than here",
			`SELECT u.name, i.name FROM bk.invites i JOIN bk.users u ON u.id = i.user_id JOIN cur.invites c ON c.id = i.id
			 WHERE i.pin_tries < c.pin_tries ORDER BY u.name, i.name`},
		{"", "", "the backup's audit line %s of %s UTC is not in this database, which keeps lines that old",
			`SELECT b.action, datetime(b.ts, 'unixepoch') FROM bk.audit_log b
			 WHERE b.ts >= (SELECT min(ts) FROM cur.audit_log)
			   AND NOT EXISTS (SELECT 1 FROM cur.audit_log c WHERE c.ts = b.ts AND c.action = b.action
			                   AND c.actor = b.actor AND c.target = b.target AND c.result = b.result)
			 ORDER BY b.ts DESC, b.id DESC`},
	}
	for _, s := range signs {
		if s.table != "" {
			ok, err := both(s.table, s.column)
			if err != nil {
				return "", err
			}
			if !ok {
				continue
			}
		}
		got, err := firstRow(ctx, tx, strings.ReplaceAll(s.query, "bk.", bk+".")+` LIMIT 1`)
		if err != nil {
			return "", fmt.Errorf("store: comparing the backup: %w", err)
		}
		if got != nil {
			return fmt.Sprintf(s.say, got...), nil
		}
	}
	// The newest record of each.
	newest := func(schema string) (string, error) {
		terms := []string{
			`(SELECT max(created_at) FROM S.users)`, `(SELECT max(created_at) FROM S.devices)`,
			`(SELECT max(revoked_at) FROM S.devices)`, `(SELECT max(created_at) FROM S.services)`,
			`(SELECT max(ts) FROM S.audit_log)`,
		}
		for _, t := range []struct{ table, column, term string }{
			{"credentials", "rotated_at", `(SELECT max(rotated_at) FROM S.credentials)`},
			{"devices", "lan_at", `(SELECT max(lan_at) FROM S.devices)`},
			{"invites", "", `(SELECT max(created_at) FROM S.invites)`},
			{"invites", "", `(SELECT max(used_at) FROM S.invites)`},
		} {
			ok, err := has(schema, t.table, t.column)
			if err != nil {
				return "", err
			}
			if ok {
				terms = append(terms, t.term)
			}
		}
		for i, t := range terms {
			terms[i] = "coalesce(" + strings.ReplaceAll(t, "S.", schema+".") + ", 0)"
		}
		return "max(" + strings.Join(terms, ", ") + ")", nil
	}
	b, err := newest(bk)
	if err != nil {
		return "", err
	}
	c, err := newest("cur")
	if err != nil {
		return "", err
	}
	got, err := firstRow(ctx, tx, `SELECT datetime(b, 'unixepoch'), datetime(c, 'unixepoch') FROM (SELECT `+b+` AS b, `+c+` AS c) WHERE b > c`)
	if err != nil {
		return "", fmt.Errorf("store: comparing the backup: %w", err)
	}
	if got != nil {
		return fmt.Sprintf("the backup's newest record is of %s UTC, this database's of %s UTC", got...), nil
	}
	return "", nil
}

// firstRow is the first row of a query, its columns as text, or nil.
func firstRow(ctx context.Context, tx *sql.Tx, query string) ([]any, error) {
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	text := make([]sql.NullString, len(cols))
	dest := make([]any, len(cols))
	for i := range text {
		dest[i] = &text[i]
	}
	if err := rows.Scan(dest...); err != nil {
		return nil, err
	}
	out := make([]any, len(cols))
	for i, t := range text {
		out[i] = t.String
	}
	return out, nil
}

// addedDevices are the devices of cur that main does not have, of users
// main has (ID, name and creation time).
func addedDevices(ctx context.Context, tx *sql.Tx) ([]AddedDevice, error) {
	rows, err := tx.QueryContext(ctx, `SELECT d.id, u.id, u.name, d.name, d.revoked_at IS NOT NULL FROM cur.devices d
		JOIN main.users u ON u.id = d.user_id
		JOIN cur.users c ON c.id = u.id AND c.name = u.name AND c.created_at = u.created_at
		WHERE NOT EXISTS (SELECT 1 FROM main.devices m WHERE m.id = d.id)
		ORDER BY u.name, d.name, d.id`)
	if err != nil {
		return nil, fmt.Errorf("store: carrying revocations: %w", err)
	}
	defer rows.Close()
	var out []AddedDevice
	for rows.Next() {
		var d AddedDevice
		if err := rows.Scan(&d.ID, &d.userID, &d.User, &d.Name, &d.Revoked); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// renewAdded gives the users of the devices of added new credentials and,
// where main has LAN keys, a new LAN key, as a restore does (R4-36): each
// device knew its user's credentials, which are cur's in main, and it is
// not in main, so the carry drops it. One revoked with overlap too, its
// rotation in flight or not: main has no record of it, so a later
// revocation with overlap there would not count it in its chain
// (rotateForRevocation), and what it knew could outlive 2 x lead + grace.
// A user renewed already (counts, carryDevices) is not renewed twice. The
// reasons, active (a device the carry drops) and revoked, go into why,
// the counts into renewed. It returns the users it renewed, by name.
func renewAdded(ctx context.Context, tx *sql.Tx, now int64, keepDoH bool, added []AddedDevice,
	counts map[string]int, why map[string][]string, renewed map[string]int, active, revoked string) (map[string]bool, error) {
	type user struct {
		id   int64
		name string
	}
	var renew []user
	for _, d := range added {
		u := user{d.userID, d.User}
		if _, done := counts[u.name]; !done && !slices.Contains(renew, u) {
			renew = append(renew, u)
		}
		w := revoked
		if !d.Revoked {
			w = active
		}
		if !slices.Contains(why[d.User], w) {
			why[d.User] = append(why[d.User], w)
		}
	}
	// A copy older than the LAN (schema 13) has no LAN keys.
	lan, err := hasColumn(ctx, tx, "main", "users", "lan_key")
	if err != nil {
		return nil, err
	}
	done := map[string]bool{}
	for _, u := range renew {
		n, err := renewCredentials(ctx, tx, u.id, now, keepDoH)
		if err != nil {
			return nil, fmt.Errorf("store: carrying revocations: %w", err)
		}
		if lan {
			if err := newUserLANKey(ctx, tx, u.id); err != nil {
				return nil, err
			}
		}
		renewed[u.name] = max(renewed[u.name], n)
		done[u.name] = true
	}
	return done, nil
}

// overlapInFlight reports whether the user's credentials in main, cur's
// after carryCredentials, are in the rotation that the user's latest
// revocation in cur began with overlap (R4-43), not switched yet: a
// credential but DoH's with a next secret and a current one no newer than
// that revocation. A revocation without overlap leaves no next (its
// renewal makes every current secret new at the revocation), and a switch
// makes the current one newer. Then the carry keeps that rotation: new
// credentials would cut the user's other devices, which the operator
// chose to spare, and the revoked device knows none of the next ones. A
// next the schedule published a period after a revocation without overlap
// is taken for such a rotation too: keeping it is as safe, the current
// secret being newer than the revocation.
func overlapInFlight(ctx context.Context, tx *sql.Tx, user int64) (bool, error) {
	var ok bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM main.credentials c LEFT JOIN main.services s ON s.id = c.service_id
		WHERE c.user_id = ?1 AND coalesce(s.kind, '') != 'doh' AND c.next_secret IS NOT NULL
		  AND coalesce(c.rotated_at, c.created_at) <= (SELECT max(d.revoked_at) FROM cur.devices d WHERE d.user_id = ?1))`, user).Scan(&ok)
	return ok, err
}

// carryKeepsRotation reports whether a restore may keep a rotation that a
// revocation with overlap in current began (overlapInFlight): only with
// current at schema 14 or later (an older one knows no such revocation)
// and main keeping DoH's secrets (carryKeepsDoH): where main takes the DoH
// secret for a token, the revoked device may hold it, and no revocation
// rotates it, so the user gets new credentials, DoH's too. A rollback
// never keeps one (CarryRevocations).
func carryKeepsRotation(ctx context.Context, tx *sql.Tx, keepDoH bool) (bool, error) {
	v, err := schemaOf(ctx, tx, "cur")
	return err == nil && v >= 14 && keepDoH, err
}

// unknownDevices are the active devices of main that cur has no record
// of; with all, every active device of main.
func unknownDevices(ctx context.Context, tx *sql.Tx, all bool) ([]CarriedDevice, error) {
	rows, err := tx.QueryContext(ctx, `SELECT d.id, u.name, d.name FROM main.devices d JOIN main.users u ON u.id = d.user_id
		WHERE d.revoked_at IS NULL AND (?1 OR NOT EXISTS (SELECT 1 FROM cur.devices c WHERE c.id = d.id))
		ORDER BY u.name, d.name`, all)
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
		          WHERE c.id = u.id AND c.name = u.name AND c.created_at = u.created_at), 0)
		FROM main.users u ORDER BY u.name`
		withoutLAN = `SELECT u.id, u.name,
		EXISTS (SELECT 1 FROM cur.users c WHERE c.id = u.id AND c.name = u.name AND c.created_at = u.created_at),
		EXISTS (SELECT 1 FROM cur.users c WHERE c.name = u.name),
		0, 0
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
		if err := rows.Scan(&u.id, &u.name, &u.matched, &u.sameName, &u.lan, &u.curLAN); err != nil {
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
// service, by ID and kind) a new secret, with no next and no previous one.
// It returns how many each user's name got.
func freshenUnmatched(ctx context.Context, tx *sql.Tx, now int64) (map[string]int, error) {
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
		ORDER BY mc.user_id, mc.service_id`)
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
		target := fmt.Sprintf("%s %s/%s: revoked on the node since the copy", d.ID, d.User, d.Name)
		if d.Rotating {
			target += ", with overlap: its rotation goes on"
		}
		if err := write("device.revoke:"+op, target); err != nil {
			return err
		}
	}
	kept := 0
	for _, u := range users {
		if n, ok := counts[u.name]; ok {
			w := "a device of the user revoked on the node since the copy"
			if r, ok := renewed[u.name]; ok { // a rollback's user deleted since: new before
				n = max(n, r)
				w += "; " + strings.Join(why[u.name], "; ")
			}
			if err := write("user.renew:"+op, fmt.Sprintf("%s: %d credentials new, %s", u.name, n, w)); err != nil {
				return err
			}
			continue
		}
		if n, ok := renewed[u.name]; ok {
			if err := write("user.renew:"+op, fmt.Sprintf("%s: %d credentials new, %s", u.name, n, strings.Join(why[u.name], "; "))); err != nil {
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
// their next subscription. With keeps (carryKeepsRotation), a user whose
// rotation a revocation with overlap began is in flight in cur
// (overlapInFlight) keeps cur's credentials and LAN key, and the devices
// are Rotating. It returns the devices and how many credentials of each
// user are new.
func carryDevices(ctx context.Context, tx *sql.Tx, gone, keepDoH, keeps bool, now int64) ([]CarriedDevice, map[string]int, error) {
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
		if keeps {
			inFlight, err := overlapInFlight(ctx, tx, u.id)
			if err != nil {
				return nil, nil, err
			}
			if inFlight {
				// Rotating: the devices revoked with overlap, after the
				// current secrets became current (at it after a switch,
				// as the chain counts them, rotateForRevocation); one
				// revoked before without overlap renewed them, and is
				// labelled so.
				for i := range carried {
					if carried[i].User != u.name {
						continue
					}
					var after bool
					if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM main.credentials c
						JOIN main.devices d ON d.id = ?1 LEFT JOIN main.services s ON s.id = c.service_id
						WHERE c.user_id = ?2 AND coalesce(s.kind, '') != 'doh' AND c.next_secret IS NOT NULL
						  AND `+revokedSinceCurrent+`)`,
						carried[i].ID, u.id).Scan(&after); err != nil {
						return nil, nil, err
					}
					carried[i].Rotating = after
				}
				continue
			}
		}
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
