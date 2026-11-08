package store

import (
	"context"
	"database/sql"
	"errors"
)

// The node's egress policy (spec/egress-policy-v1.md): what the data plane
// may not send, on every profile. Each part is blocked while its setting
// is "on"; no setting, nothing blocked.
const (
	settingEgressBitTorrent = "egress_bittorrent"
	settingEgressSMTP       = "egress_smtp"
)

// Egress is the node's egress policy.
type Egress struct {
	BitTorrent bool // the BitTorrent signatures: handshake, uTP SYN, UDP tracker, DHT
	SMTP       bool // TCP to port 25
}

// Egress returns the node's egress policy.
func (s *Store) Egress(ctx context.Context) (Egress, error) {
	var e Egress
	for _, p := range []struct {
		key string
		on  *bool
	}{{settingEgressBitTorrent, &e.BitTorrent}, {settingEgressSMTP, &e.SMTP}} {
		v, err := s.GetSetting(ctx, p.key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return Egress{}, err
		}
		*p.on = string(v) == "on"
	}
	return e, nil
}

// SetEgress blocks (true) or allows (false) the parts given, in one
// transaction; nil leaves a part as it is. It returns the policy as kept.
func (s *Store) SetEgress(ctx context.Context, bittorrent, smtp *bool) (Egress, error) {
	err := s.tx(ctx, func(tx *sql.Tx) error {
		for _, p := range []struct {
			key   string
			block *bool
		}{{settingEgressBitTorrent, bittorrent}, {settingEgressSMTP, smtp}} {
			var err error
			switch {
			case p.block == nil:
			case *p.block:
				_, err = tx.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
					p.key, []byte("on"))
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
