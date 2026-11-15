package store

import (
	"context"
	"database/sql"
	"errors"
)

// The node's egress policy (spec/egress-policy-v1.md): what the data plane
// may not send, on every profile. BitTorrent and SMTP are blocked while
// their setting is "on"; no setting, allowed. The node's own and local
// networks (R4-38) the other way round: blocked unless their setting is
// "allow".
const (
	settingEgressBitTorrent = "egress_bittorrent"
	settingEgressSMTP       = "egress_smtp"
	settingEgressLocal      = "egress_local"
)

// Egress is the node's egress policy.
type Egress struct {
	BitTorrent bool // the BitTorrent signatures: handshake, uTP SYN, UDP tracker, DHT
	SMTP       bool // TCP to port 25
	Local      bool // the node's own and local networks: loopback, private, link-local, CGNAT, multicast
}

// Egress returns the node's egress policy.
func (s *Store) Egress(ctx context.Context) (Egress, error) {
	var e Egress
	for _, p := range []struct {
		key, value string // value: the part is blocked when the setting has it
		on         *bool
		inverse    bool // blocked unless the setting has value
	}{{settingEgressBitTorrent, "on", &e.BitTorrent, false}, {settingEgressSMTP, "on", &e.SMTP, false},
		{settingEgressLocal, "allow", &e.Local, true}} {
		v, err := s.GetSetting(ctx, p.key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return Egress{}, err
		}
		*p.on = (string(v) == p.value) != p.inverse
	}
	return e, nil
}

// SetEgress blocks (true) or allows (false) the parts given, in one
// transaction; nil leaves a part as it is. It returns the policy as kept.
func (s *Store) SetEgress(ctx context.Context, bittorrent, smtp, local *bool) (Egress, error) {
	err := s.tx(ctx, func(tx *sql.Tx) error {
		for _, p := range []struct {
			key   string
			block *bool
			value []byte // what the setting holds when it is there
			when  bool   // the setting is there when block is this
		}{{settingEgressBitTorrent, bittorrent, []byte("on"), true}, {settingEgressSMTP, smtp, []byte("on"), true},
			{settingEgressLocal, local, []byte("allow"), false}} {
			var err error
			switch {
			case p.block == nil:
			case *p.block == p.when:
				_, err = tx.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
					p.key, p.value)
			default:
				_, err = tx.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, p.key)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return Egress{}, err
	}
	return s.Egress(ctx)
}
