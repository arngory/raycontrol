package store

import (
	"context"
	"errors"
)

// settingConnLimit turns the connection limits off (spec/conn-limit-v1.md
// §8): "off" in it; no setting, the limits are on.
const settingConnLimit = "conn_limit"

// ConnLimitOff reports whether the connection limits are off: the
// per-user limits in the processes and the per-address limit on new
// inbound connections. The table's size, notrack and the guard are not
// under it.
func (s *Store) ConnLimitOff(ctx context.Context) (bool, error) {
	v, err := s.GetSetting(ctx, settingConnLimit)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return string(v) == "off", nil
}

// SetConnLimitOff turns the limits off (true) or back on (false: the
// setting goes, as it was before there was one). It returns the state as
// kept.
func (s *Store) SetConnLimitOff(ctx context.Context, off bool) (bool, error) {
	var err error
	if off {
		err = s.SetSetting(ctx, settingConnLimit, []byte("off"))
	} else {
		_, err = s.db.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, settingConnLimit)
	}
	if err != nil {
		return false, err
	}
	return s.ConnLimitOff(ctx)
}
