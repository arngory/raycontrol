package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// DoH's token is a device's (docs/08-decisions.md, R4-37): DoHDeviceToken
// of the user's DoH secret, the credential of the user's that rotates
// (R4-1), and the device's SPA key, which only the device and the node
// hold. The secret itself is no token, but for DoHSharedWindow after the
// upgrade that made the tokens the devices' (schema 15), for a device
// that has not fetched its subscription since.

// DoHSharedWindow is how long after schema 15 a user's DoH secret is
// still a token of its own: the life of a subscription (72 h,
// spec/subscription-v1.md §3), after which every device that is on has
// fetched one with its own token.
const DoHSharedWindow = 72 * time.Hour

// settingDoHShared is "<from> <until>", unix seconds: when schema 15 came
// and when the shared token ends. No setting: there is none (a node made
// at schema 15 or later, or one without DoH then).
const settingDoHShared = "doh_shared"

// DoHDeviceToken is a device's DoH token for the user's DoH secret: an
// HMAC-SHA256 keyed by the device's SPA key, with a label of its own, of
// the secret, as YggdrasilDeviceKey (internal/render) makes the device's
// key in the mesh; its first 16 bytes written as a version 4 UUID, the
// shape and length the user's token had, so that the line, its path and
// the client's parser are as before. A sibling's token takes the
// sibling's key; the secret alone gives none. Without a device there is
// no token ("").
func DoHDeviceToken(secret string, device []byte) string {
	if len(device) == 0 || secret == "" {
		return ""
	}
	m := hmac.New(sha256.New, device)
	m.Write([]byte("raycontrol-doh-device-v1\x00" + secret))
	b := m.Sum(nil)[:16]
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// DoHTokens are the tokens a DoH service accepts at now: for every active
// user (User.Active) with the service, each device not revoked gets its
// token for each secret of the user's the rotation accepts (current, next,
// previous in its grace). In the shared window the user's secrets are
// tokens too, unless a device of the user was revoked since the window
// began: that device knew them (docs/08-decisions.md, R4-37).
func (s *Store) DoHTokens(ctx context.Context, service int64, now time.Time) (map[string]bool, error) {
	users, err := s.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	sets, err := s.CredentialSets(ctx, service, nil, nil)
	if err != nil {
		return nil, err
	}
	devices, err := s.ActiveDeviceSecrets(ctx)
	if err != nil {
		return nil, err
	}
	from, until, err := s.doHShared(ctx)
	if err != nil {
		return nil, err
	}
	var revokedSince map[int64]bool
	shared := now.Unix() < until
	if shared {
		if revokedSince, err = s.usersRevokedSince(ctx, from); err != nil {
			return nil, err
		}
	}
	out := make(map[string]bool, len(devices)*2)
	for _, u := range users {
		if !u.Active(now) || !slices.Contains(u.Services, service) {
			continue
		}
		set, ok := sets[u.ID]
		if !ok {
			continue
		}
		for _, secret := range set.Accepted(now) {
			if secret == "" {
				continue
			}
			for _, d := range devices[u.ID] {
				out[DoHDeviceToken(secret, d.Key[:])] = true
			}
			if shared && !revokedSince[u.ID] {
				out[secret] = true
			}
		}
	}
	return out, nil
}

// doHShared reads the shared window; none is 0, 0.
func (s *Store) doHShared(ctx context.Context) (from, until int64, err error) {
	v, err := s.GetSetting(ctx, settingDoHShared)
	if errors.Is(err, ErrNotFound) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	from, until = parseDoHShared(v)
	return from, until, nil
}

// parseDoHShared reads the value of settingDoHShared; one not as schema
// 15 wrote it is no window (0, 0), the safe side.
func parseDoHShared(v []byte) (from, until int64) {
	f, u, ok := strings.Cut(string(v), " ")
	from, ferr := strconv.ParseInt(f, 10, 64)
	until, uerr := strconv.ParseInt(u, 10, 64)
	if !ok || ferr != nil || uerr != nil {
		return 0, 0
	}
	return from, until
}

// DoHSharedUntil is when the shared window ends (zero: there is none).
func (s *Store) DoHSharedUntil(ctx context.Context) (time.Time, error) {
	_, until, err := s.doHShared(ctx)
	if err != nil || until == 0 {
		return time.Time{}, err
	}
	return time.Unix(until, 0), nil
}

// usersRevokedSince are the users with a device revoked at from or later.
func (s *Store) usersRevokedSince(ctx context.Context, from int64) (map[int64]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT user_id FROM devices WHERE revoked_at >= ?`, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]bool{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// startDoHShared is the step of schema 15 (R4-37): a node with DoH
// credentials then has devices holding the user's token, which their
// subscriptions carried; it stays a token for DoHSharedWindow. A node
// without them has no such device and no window.
func startDoHShared(ctx context.Context, tx *sql.Tx, now int64) error {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM credentials c JOIN services s ON s.id = c.service_id
		WHERE s.kind = 'doh'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING`,
		settingDoHShared, []byte(fmt.Sprintf("%d %d", now, now+int64(DoHSharedWindow/time.Second))))
	return err
}
