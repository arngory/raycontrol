package store

import (
	"context"
	"time"
)

// SetDeviceClient keeps the client a device's request named (client-min-v1
// §5): product and version, as "niko/1.59.0". It writes when the client
// changes, or when it was last written more than every ago: a device asks
// for its subscription often, and the time seen needs no more precision.
func (s *Store) SetDeviceClient(ctx context.Context, id, client string, every time.Duration) error {
	now := s.now().Unix()
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET client = ?1, client_at = ?2
		WHERE id = ?3 AND revoked_at IS NULL
		  AND (client IS NOT ?1 OR client_at IS NULL OR client_at <= ?2 - ?4 OR client_at > ?2)`,
		client, now, id, int64(every/time.Second))
	return err
}

// ClientCount is how many devices last named a client, seen since a time.
type ClientCount struct {
	Client  string // "niko/1.59.0"; "" for devices that named none
	Devices int
}

// ClientCounts counts the devices that are not revoked by the client they
// last named, of those seen since (client-min-v1 §5), and the devices of
// enabled users never seen with a client, as Client "". Most first.
func (s *Store) ClientCounts(ctx context.Context, since time.Time) ([]ClientCount, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT coalesce(d.client, ''), count(*) FROM devices d JOIN users u ON u.id = d.user_id
		WHERE d.revoked_at IS NULL AND u.enabled = 1 AND (d.client IS NULL OR d.client_at >= ?)
		GROUP BY 1 ORDER BY 2 DESC, 1`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClientCount
	for rows.Next() {
		var c ClientCount
		if err := rows.Scan(&c.Client, &c.Devices); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
