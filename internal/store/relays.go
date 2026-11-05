package store

import (
	"context"
	"encoding/json"
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
	// SPA is the relay's own SPA parameters (JSON of node.SPAParams), empty
	// until the exit makes them (relay-v1 §3).
	SPA []byte
	// SSHPort is the relay host's SSH, which the admin addresses reach.
	SSHPort uint16
	// CertPin names the client certificate the exit made for the relay,
	// empty until then: with it the relay takes its perimeter.
	CertPin string
	// Admin are the prefixes that reach the relay host's SSH without SPA.
	Admin []string
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
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, address, created_at, COALESCE(spa_json, ''), ssh_port, COALESCE(cert_pin, ''), COALESCE(admin_json, '') FROM relays ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Relay
	for rows.Next() {
		var r Relay
		var addr, spaJSON, adminJSON string
		var created int64
		if err := rows.Scan(&r.ID, &r.Name, &addr, &created, &spaJSON, &r.SSHPort, &r.CertPin, &adminJSON); err != nil {
			return nil, err
		}
		if adminJSON != "" {
			if err := json.Unmarshal([]byte(adminJSON), &r.Admin); err != nil {
				return nil, fmt.Errorf("relay %s admin: %w", r.Name, err)
			}
		}
		if spaJSON != "" {
			r.SPA = []byte(spaJSON)
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
// RelayByName returns one relay, or ErrNotFound.
func (s *Store) RelayByName(ctx context.Context, name string) (Relay, error) {
	rs, err := s.ListRelays(ctx)
	if err != nil {
		return Relay{}, err
	}
	for _, r := range rs {
		if r.Name == name {
			return r, nil
		}
	}
	return Relay{}, fmt.Errorf("relay %q: %w", name, ErrNotFound)
}

// SetRelaySPA stores a relay's SPA parameters once: a relay that has them
// keeps them (its devices' knocks depend on them), and false says so.
func (s *Store) SetRelaySPA(ctx context.Context, name string, spaJSON []byte) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE relays SET spa_json = ? WHERE name = ? AND spa_json IS NULL`, string(spaJSON), name)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ReplaceRelaySPA replaces a relay's SPA parameters: its devices' keys for
// it change with them (relay-v1 §3).
func (s *Store) ReplaceRelaySPA(ctx context.Context, name string, spaJSON []byte) error {
	return s.affectOne(ctx, "relay", name, `UPDATE relays SET spa_json = ? WHERE name = ?`, string(spaJSON), name)
}

// SetRelayCertPin replaces the pin of a relay's client certificate: the one
// before stops working.
func (s *Store) SetRelayCertPin(ctx context.Context, name, pin string) error {
	if pin == "" {
		return fmt.Errorf("%w relay certificate pin empty", ErrInvalid)
	}
	return s.affectOne(ctx, "relay", name, `UPDATE relays SET cert_pin = ? WHERE name = ?`, pin, name)
}

// RelayByCertPin returns the relay whose client certificate has this pin,
// or ErrNotFound.
func (s *Store) RelayByCertPin(ctx context.Context, pin string) (Relay, error) {
	if pin == "" {
		return Relay{}, ErrNotFound
	}
	rs, err := s.ListRelays(ctx)
	if err != nil {
		return Relay{}, err
	}
	for _, r := range rs {
		if r.CertPin == pin {
			return r, nil
		}
	}
	return Relay{}, ErrNotFound
}

// SetRelayAdmin replaces the prefixes that reach the relay host's SSH
// without SPA (validated by the caller).
func (s *Store) SetRelayAdmin(ctx context.Context, name string, prefixes []string) error {
	b, err := json.Marshal(prefixes)
	if err != nil {
		return err
	}
	return s.affectOne(ctx, "relay", name, `UPDATE relays SET admin_json = ? WHERE name = ?`, string(b), name)
}

// SetRelaySSHPort sets the port of the relay host's SSH.
func (s *Store) SetRelaySSHPort(ctx context.Context, name string, port uint16) error {
	if port == 0 {
		return fmt.Errorf("%w relay SSH port 0", ErrInvalid)
	}
	return s.affectOne(ctx, "relay", name, `UPDATE relays SET ssh_port = ? WHERE name = ?`, port, name)
}

func (s *Store) DeleteRelay(ctx context.Context, name string) error {
	return s.affectOne(ctx, "relay", name, `DELETE FROM relays WHERE name = ?`, name)
}
