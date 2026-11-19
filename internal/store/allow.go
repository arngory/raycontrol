package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// MaxAllowPerDevice and MaxAllowPerNode bound the addresses of
// integrations (integrations-v1 §3.3): a list is a few servers, and the
// perimeter's sets stay small.
const (
	MaxAllowPerDevice = 8
	MaxAllowPerNode   = 64
)

// notAllowed are networks no integration calls from (integrations-v1
// §3.3): this host, nowhere, link-local, multicast, reserved.
var notAllowed = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// privateNets are taken with a warning: billing in one private network with
// the node happens.
var privateNets = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
}

// CheckAllow reads an integration's addresses (integrations-v1 §3.3): IPv4
// /28 to /32, IPv6 /64 to /128, addresses only (a name would change its
// address unseen), IPv4 in IPv6 as IPv4, at most MaxAllowPerDevice. It
// returns them masked, sorted and without repeats, and what to point out.
func CheckAllow(list []string) ([]netip.Prefix, []string, error) {
	var out []netip.Prefix
	var warnings []string
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := parseAllow(s)
		if err != nil {
			return nil, nil, err
		}
		for _, bad := range notAllowed {
			if bad.Overlaps(p) {
				return nil, nil, fmt.Errorf("%w address %s: loopback, link-local, multicast or reserved", ErrInvalid, p)
			}
		}
		for _, private := range privateNets {
			if private.Overlaps(p) {
				warnings = append(warnings, fmt.Sprintf("%s is in a private network: the node sees that address only from the same network", p))
				break
			}
		}
		out = append(out, p)
	}
	slices.SortFunc(out, comparePrefix)
	out = slices.Compact(out)
	if len(out) > MaxAllowPerDevice {
		return nil, nil, fmt.Errorf("%w: %d addresses, at most %d a device", ErrInvalid, len(out), MaxAllowPerDevice)
	}
	return out, warnings, nil
}

func parseAllow(s string) (netip.Prefix, error) {
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return p, fmt.Errorf("%w address %q: an IP address or prefix, not a name", ErrInvalid, s)
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return p, fmt.Errorf("%w address %q: an IP address or prefix, not a name", ErrInvalid, s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if a := p.Addr(); a.Is4In6() {
		if p.Bits() < 96 {
			return p, fmt.Errorf("%w address %q: IPv4 in IPv6 wider than /96", ErrInvalid, s)
		}
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	p = p.Masked()
	if p.Addr().Is4() && p.Bits() < 28 || p.Addr().Is6() && p.Bits() < 64 {
		return p, fmt.Errorf("%w address %q: at most a /28 (IPv4) or a /64 (IPv6)", ErrInvalid, s)
	}
	return p, nil
}

func comparePrefix(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}

// allowText is a list as the store keeps it; nil for none.
func allowText(ps []netip.Prefix) any {
	if len(ps) == 0 {
		return nil
	}
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, ",")
}

// parseAllowText reads a stored list; a part that does not read (it never
// is written so) is left out.
func parseAllowText(s sql.NullString) []netip.Prefix {
	if !s.Valid || s.String == "" {
		return nil
	}
	var out []netip.Prefix
	for _, part := range strings.Split(s.String, ",") {
		if p, err := netip.ParsePrefix(part); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// AllowCovers reports whether one of ps holds a.
func AllowCovers(ps []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// AllowEntry is one list of addresses: a device's (with the key of its
// client certificate) or an unused invite's.
type AllowEntry struct {
	DeviceID string // "" for an invite
	CertPin  string
	InviteID string // "" for a device
	// Whose: the user, the device's (or the invite's device's) name, the
	// role.
	UserName, Name, Role string
	Allow                []netip.Prefix
}

// AllowLists returns the lists of devices not revoked and of invites that
// may still register, for the check of every remote call (integrations-v1
// §3.2): an address in some list lets in only who has it. A device whose
// user is disabled keeps its list here: its address stays the
// integration's.
func (s *Store) AllowLists(ctx context.Context) ([]AllowEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.id, coalesce(d.cert_pin, ''), '', u.name, d.name, d.role, d.allow FROM devices d JOIN users u ON u.id = d.user_id
		WHERE d.allow IS NOT NULL AND d.revoked_at IS NULL
		UNION ALL
		SELECT '', '', i.id, u.name, i.name, i.role, i.allow FROM invites i JOIN users u ON u.id = i.user_id
		WHERE i.allow IS NOT NULL AND i.used_at IS NULL AND i.expires_at > ?`, s.now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AllowEntry
	for rows.Next() {
		var e AllowEntry
		var allow sql.NullString
		if err := rows.Scan(&e.DeviceID, &e.CertPin, &e.InviteID, &e.UserName, &e.Name, &e.Role, &allow); err != nil {
			return nil, err
		}
		e.Allow = parseAllowText(allow)
		out = append(out, e)
	}
	return out, rows.Err()
}

// AllowPrefixes are the prefixes the perimeter opens to the API without a
// knock: of devices that may connect now and of invites that may still
// register (ActiveInvite's).
func (s *Store) AllowPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	now := s.now().Unix()
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.allow FROM devices d JOIN users u ON u.id = d.user_id
		WHERE d.allow IS NOT NULL AND d.revoked_at IS NULL AND u.enabled = 1 AND (u.expires_at IS NULL OR u.expires_at > ?)
		UNION ALL
		SELECT i.allow FROM invites i JOIN users u ON u.id = i.user_id
		WHERE i.allow IS NOT NULL AND i.used_at IS NULL AND i.expires_at > ? AND u.enabled = 1 AND (u.expires_at IS NULL OR u.expires_at > ?)
			AND NOT (i.by_integration AND i.user_id IN (`+serviceUserIDs+`))`, now, now, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []netip.Prefix
	for rows.Next() {
		var allow sql.NullString
		if err := rows.Scan(&allow); err != nil {
			return nil, err
		}
		out = append(out, parseAllowText(allow)...)
	}
	slices.SortFunc(out, comparePrefix)
	return slices.Compact(out), rows.Err()
}

// countAllow counts the node's listed addresses in tx, but for device or
// invite skip.
func countAllow(ctx context.Context, tx *sql.Tx, now time.Time, skip string) (int, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, allow FROM devices WHERE allow IS NOT NULL AND revoked_at IS NULL
		UNION ALL
		SELECT id, allow FROM invites WHERE allow IS NOT NULL AND used_at IS NULL AND expires_at > ?`, now.Unix())
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id string
		var allow sql.NullString
		if err := rows.Scan(&id, &allow); err != nil {
			return 0, err
		}
		if id != skip {
			n += len(parseAllowText(allow))
		}
	}
	return n, rows.Err()
}

// errAllowFull is the node's limit of listed addresses.
func errAllowFull(n, more int) error {
	return fmt.Errorf("%w: the node lists %d addresses of integrations, %d more is over %d", ErrInvalid, n, more, MaxAllowPerNode)
}

// ErrAllowRole is a list for a device that is not an integration's.
var ErrAllowRole = fmt.Errorf("%w: addresses are for an integration's device (billing, support) only", ErrPrecondition)

// SetDeviceAllow replaces the addresses of an integration's device that is
// not revoked (integrations-v1 §3.2); none puts it back to SPA. It returns
// the device as ListDevices has it.
func (s *Store) SetDeviceAllow(ctx context.Context, id string, allow []netip.Prefix) (Device, error) {
	if len(allow) > MaxAllowPerDevice {
		return Device{}, fmt.Errorf("%w: %d addresses, at most %d a device", ErrInvalid, len(allow), MaxAllowPerDevice)
	}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var role string
		err := tx.QueryRowContext(ctx, `SELECT role FROM devices WHERE id = ? AND revoked_at IS NULL`, id).Scan(&role)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("device %q: %w", id, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if !IntegrationRole(role) {
			return fmt.Errorf("device %q (%s): %w", id, role, ErrAllowRole)
		}
		if len(allow) > 0 {
			n, err := countAllow(ctx, tx, s.now(), id)
			if err != nil {
				return err
			}
			if n+len(allow) > MaxAllowPerNode {
				return errAllowFull(n, len(allow))
			}
		}
		_, err = tx.ExecContext(ctx, `UPDATE devices SET allow = ? WHERE id = ?`, allowText(allow), id)
		return err
	})
	if err != nil {
		return Device{}, err
	}
	return s.deviceByID(ctx, id)
}

// deviceByID is one device as ListDevices has it.
func (s *Store) deviceByID(ctx context.Context, id string) (Device, error) {
	if id == "" {
		return Device{}, fmt.Errorf("device %q: %w", id, ErrNotFound)
	}
	ds, err := s.listDevices(ctx, "", id)
	if err != nil {
		return Device{}, err
	}
	if len(ds) == 0 {
		return Device{}, fmt.Errorf("device %q: %w", id, ErrNotFound)
	}
	return ds[0], nil
}

// LastCallEvery is how often a device's last call is written.
const LastCallEvery = time.Hour

// SetLastCall records an integration's device's call at, when the stored
// one is LastCallEvery older or none.
func (s *Store) SetLastCall(ctx context.Context, id string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET last_call = ? WHERE id = ? AND (last_call IS NULL OR last_call <= ?)`,
		at.Unix(), id, at.Add(-LastCallEvery).Unix())
	return err
}
