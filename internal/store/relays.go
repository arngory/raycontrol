package store

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Relay is a relay in front of this node (relay-v1): one address.
type Relay struct {
	ID        int64
	Name      string
	Address   netip.Addr
	CreatedAt time.Time
}

// CreateRelay adds a relay: a name and one public address.
func (s *Store) CreateRelay(ctx context.Context, name string, addr netip.Addr) (Relay, error) {
	if err := checkName("relay", name); err != nil {
		return Relay{}, err
	}
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return Relay{}, fmt.Errorf("%w relay address %s: a public address", ErrInvalid, addr)
	}
	r := Relay{Name: name, Address: addr, CreatedAt: s.now().Truncate(time.Second)}
	res, err := s.db.ExecContext(ctx, `INSERT INTO relays (name, address, created_at) VALUES (?, ?, ?)`,
		name, addr.String(), r.CreatedAt.Unix())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Relay{}, fmt.Errorf("%w: a relay %s or with address %s exists", ErrInvalid, name, addr)
		}
		return Relay{}, err
	}
	r.ID, err = res.LastInsertId()
	return r, err
}

// ListRelays returns the relays by name.
func (s *Store) ListRelays(ctx context.Context) ([]Relay, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, address, created_at FROM relays ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Relay
	for rows.Next() {
		var r Relay
		var addr string
		var created int64
		if err := rows.Scan(&r.ID, &r.Name, &addr, &created); err != nil {
			return nil, err
		}
		if r.Address, err = netip.ParseAddr(addr); err != nil {
			return nil, err
		}
		r.CreatedAt = time.Unix(created, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteRelay removes a relay: its address loses the service ports.
func (s *Store) DeleteRelay(ctx context.Context, name string) error {
	return s.affectOne(ctx, "relay", name, `DELETE FROM relays WHERE name = ?`, name)
}
