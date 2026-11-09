package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/arngory/raycontrol/internal/spa"
)

// LAN over Yggdrasil (docs/spec/lan-v1.md): a user's devices see each other
// by their mesh addresses, through the node or directly in one Wi-Fi. A
// device is in its user's LAN with both consents: the administrator's for
// the user (User.LAN) and its own (Device.LAN).

// LANKeySize is the size of a user's LAN key (lan-v1 §3).
const LANKeySize = 32

// LANShowEvery bounds how often a device's consent is written (lan-v1
// §4.4): once a minute, for the write and the render it brings. Taking it
// back is written at once, whenever it comes: a device that hides itself
// is out of the others' lists with the next render, not a minute later.
const LANShowEvery = time.Minute

func newLANKey() ([]byte, error) {
	key := make([]byte, LANKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// SetUserLAN gives or takes back the administrator's consent to a user's
// LAN (rayctl user lan NAME on|off) and returns the user as now stored. On
// needs a Yggdrasil service of the user's (the network runs in its core)
// and makes a new LAN key every time, so on again changes the multicast
// password; off drops the key.
func (s *Store) SetUserLAN(ctx context.Context, name string, on bool) (User, error) {
	var key any // NULL when off
	if on {
		k, err := newLANKey()
		if err != nil {
			return User{}, err
		}
		key = k
	}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var id int64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE name = ?`, name).Scan(&id); errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("user %q: %w", name, ErrNotFound)
		} else if err != nil {
			return err
		}
		if on {
			var ygg bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM user_services us JOIN services s ON s.id = us.service_id
				WHERE us.user_id = ? AND s.kind = 'yggdrasil')`, id).Scan(&ygg); err != nil {
				return err
			}
			if !ygg {
				return fmt.Errorf("%w: user %q has no Yggdrasil service, where the LAN runs (rayctl user services)", ErrInvalid, name)
			}
		}
		_, err := tx.ExecContext(ctx, `UPDATE users SET lan = ?, lan_key = ? WHERE id = ?`, on, key, id)
		return err
	})
	if err != nil {
		return User{}, err
	}
	return s.UserByName(ctx, name)
}

// SetDeviceLAN stores a device's consent as its X-Raycontrol-LAN header
// says (lan-v1 §1.1, §4.4): only a change, and showing itself not within
// every of the last change (then the device stays hidden until a request
// after that); hiding itself always. It reports whether anything was
// written: then the users files change. A revoked device changes nothing.
func (s *Store) SetDeviceLAN(ctx context.Context, id string, on bool, every time.Duration) (bool, error) {
	now := s.now().Unix()
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET lan = ?1, lan_at = ?2
		WHERE id = ?3 AND revoked_at IS NULL AND lan != ?1
		  AND (?1 = 0 OR lan_at IS NULL OR lan_at <= ?2 - ?4 OR lan_at > ?2)`,
		on, now, id, int64(every/time.Second))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// LANDevice is a device in its user's LAN: not revoked, shown.
type LANDevice struct {
	ID        string
	Name      string
	Key       [spa.KeySize]byte // its SPA key: its Yggdrasil keys come from it
	CreatedAt time.Time
}

// LANDevices returns a user's LAN key (nil: LAN off) and the user's devices
// that show themselves and are not revoked, in the order they were added
// (lan-v1 §1.3: a label taken goes to the device added first).
func (s *Store) LANDevices(ctx context.Context, userID int64) ([]byte, []LANDevice, error) {
	var key []byte
	if err := s.db.QueryRowContext(ctx, `SELECT lan_key FROM users WHERE id = ? AND lan = 1`, userID).Scan(&key); errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, spa_key, created_at FROM devices
		WHERE user_id = ? AND lan = 1 AND revoked_at IS NULL ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var out []LANDevice
	for rows.Next() {
		var d LANDevice
		var raw []byte
		var created int64
		if err := rows.Scan(&d.ID, &d.Name, &raw, &created); err != nil {
			return nil, nil, err
		}
		copy(d.Key[:], raw)
		d.CreatedAt = time.Unix(created, 0)
		out = append(out, d)
	}
	return key, out, rows.Err()
}
