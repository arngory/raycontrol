package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// hy2-obfs's salamander password is a device's (spec/salamander-device-v1.md):
// SalamanderDevicePassword of the service's obfs_password secret S and
// the device's SPA key. The front, not the backend, takes salamander off
// with the passwords of every device allowed on the service. S itself is
// no password, but for the shared window after the upgrade that made the
// passwords the devices' (schema 20), for a device that has not fetched
// its subscription since (§5).

// SalamanderSharedWindow is how long after schema 20 a hy2-obfs
// service's S is still a password of its own: the life of a subscription
// (72 h, spec/subscription-v1.md §3), as DoHSharedWindow.
const SalamanderSharedWindow = 72 * time.Hour

// settingSalamanderShared is "<from> <until>[ <service ID>...]", unix
// seconds: when schema 20 came and when the shared password ends, then
// the services whose window a revocation or a user's deletion closed
// (closeSalamanderShared). No setting: there is none (a node made at
// schema 20 or later, or one without hy2-obfs then).
const settingSalamanderShared = "salamander_shared"

// SalamanderDevicePassword is a device's salamander password for a
// hy2-obfs service's secret S (spec/salamander-device-v1.md §2): the
// first 24 bytes of an HMAC-SHA256 keyed by the device's SPA key, with a
// label of its own, of S, in base64url without padding: 32 characters
// of [A-Za-z0-9_-], the shape and length S has, so the line and the
// client's salamander are as before. Another device's password takes its
// key; S alone gives none. Without a device there is none ("").
func SalamanderDevicePassword(secret string, device []byte) string {
	if len(device) == 0 || secret == "" {
		return ""
	}
	m := hmac.New(sha256.New, device)
	m.Write([]byte("raycontrol-salamander-device-v1\x00" + secret))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:24])
}

// salamanderShared is the window as stored: from and until (0, 0: none)
// and the services it is closed for.
type salamanderShared struct {
	from, until int64
	closed      []int64
}

// parseSalamanderShared reads the value of settingSalamanderShared; one
// not as written here is no window, the safe side.
func parseSalamanderShared(v []byte) salamanderShared {
	f := strings.Fields(string(v))
	if len(f) < 2 {
		return salamanderShared{}
	}
	from, ferr := strconv.ParseInt(f[0], 10, 64)
	until, uerr := strconv.ParseInt(f[1], 10, 64)
	if ferr != nil || uerr != nil {
		return salamanderShared{}
	}
	w := salamanderShared{from: from, until: until}
	for _, s := range f[2:] {
		id, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return salamanderShared{}
		}
		w.closed = append(w.closed, id)
	}
	return w
}

func (w salamanderShared) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d %d", w.from, w.until)
	for _, id := range w.closed {
		fmt.Fprintf(&b, " %d", id)
	}
	return b.String()
}

func salamanderSharedIn(ctx context.Context, q queryRower, schema string) (salamanderShared, error) {
	var v []byte
	err := q.QueryRowContext(ctx, `SELECT value FROM `+schema+`.settings WHERE key = ?`, settingSalamanderShared).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return salamanderShared{}, nil
	}
	if err != nil {
		return salamanderShared{}, err
	}
	return parseSalamanderShared(v), nil
}

// SalamanderSharedUntil is when the shared window ends (zero: there is
// none). It may be closed earlier for a service (SalamanderShared).
func (s *Store) SalamanderSharedUntil(ctx context.Context) (time.Time, error) {
	w, err := salamanderSharedIn(ctx, s.db, "main")
	if err != nil || w.until == 0 {
		return time.Time{}, err
	}
	return time.Unix(w.until, 0), nil
}

// SalamanderShared reports whether the hy2-obfs service's S is still
// accepted as a password of its own at now (spec/salamander-device-v1.md
// §5): in the window, for a service made before it, unless a device of a
// user with the service was revoked since the window began, or such a
// user was deleted with devices. Every device that knew S knew it as one secret of the
// service, so one revocation closes the window for all its users.
func (s *Store) SalamanderShared(ctx context.Context, service int64, now time.Time) (bool, error) {
	w, err := salamanderSharedIn(ctx, s.db, "main")
	if err != nil || now.Unix() >= w.until || now.Unix() < w.from || slices.Contains(w.closed, service) {
		return false, err
	}
	// A service made since had no S in any subscription. A revocation
	// carried in by a rollback or a restore (carryDevices) went by no
	// revokeDevice here: the devices say it.
	var open bool
	err = s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM services WHERE id = ?1 AND kind = 'hy2-obfs' AND created_at <= ?2)
		AND NOT EXISTS (SELECT 1 FROM devices d JOIN user_services us ON us.user_id = d.user_id AND us.service_id = ?1
			WHERE d.revoked_at >= ?2)`, service, w.from).Scan(&open)
	return open, err
}

// closeSalamanderShared closes the shared window, while it is open at now,
// for the hy2-obfs services of the user: a device of the user's was
// revoked or, with the user, deleted, and it knew their S. Recorded, not
// read from the devices alone: a user's service taken away or the user
// deleted would take the revocation's sign with it.
func closeSalamanderShared(ctx context.Context, tx *sql.Tx, user, now int64) error {
	w, err := salamanderSharedIn(ctx, tx, "main")
	if err != nil || now >= w.until {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT us.service_id FROM user_services us JOIN services s ON s.id = us.service_id
		WHERE us.user_id = ? AND s.kind = 'hy2-obfs' ORDER BY us.service_id`, user)
	if err != nil {
		return err
	}
	defer rows.Close()
	changed := false
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return err
		}
		if !slices.Contains(w.closed, id) {
			w.closed = append(w.closed, id)
			changed = true
		}
	}
	if err := rows.Err(); err != nil || !changed {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE settings SET value = ? WHERE key = ?`, []byte(w.String()), settingSalamanderShared)
	return err
}

// startSalamanderShared is the step of schema 20: a node with a hy2-obfs
// service then has devices holding its S, which their subscriptions
// carried; it stays a password for SalamanderSharedWindow. A node without
// one has no such device and no window.
func startSalamanderShared(ctx context.Context, tx *sql.Tx, now int64) error {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM services WHERE kind = 'hy2-obfs'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	w := salamanderShared{from: now, until: now + int64(SalamanderSharedWindow/time.Second)}
	_, err := tx.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING`,
		settingSalamanderShared, []byte(w.String()))
	return err
}

// carrySalamanderShared gives main the shared window current has (cur in
// a carry), for a restore (all) or a rollback (only when both have the
// same window, that is main is at schema 20 or later from the same
// upgrade: the closures since come with it). A restore's main was
// migrated at the restore (rayctl restore runs rayd init on it): from a
// backup older than schema 20 its step opened a window from now, which
// would take S again for 72 hours, past the revocations since the node's
// own window began; current's is the node's, closed where it is. A
// rollback to before schema 20 keeps none: the older rayd gives every
// device S again, and the update after opens a window anew.
func carrySalamanderShared(ctx context.Context, tx *sql.Tx, restore bool) error {
	if v, err := schemaOf(ctx, tx, "cur"); err != nil || v < 20 {
		return err
	}
	cur, err := salamanderSharedIn(ctx, tx, "cur")
	if err != nil {
		return err
	}
	main, err := salamanderSharedIn(ctx, tx, "main")
	if err != nil {
		return err
	}
	if !restore && (main.from == 0 || main.from != cur.from) {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM main.settings WHERE key = ?`, settingSalamanderShared); err != nil || cur.from == 0 {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO main.settings (key, value) VALUES (?, ?)`, settingSalamanderShared, []byte(cur.String()))
	return err
}
