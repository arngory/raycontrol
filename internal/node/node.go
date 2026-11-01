// Package node holds the per-installation parameters of a node and the
// device bundle a client imports at enrollment.
package node

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
)

const (
	settingSPA  = "spa_params"
	settingHost = "public_host"

	// BundlePrefix marks an encoded device bundle.
	BundlePrefix = "rcdev1:"
)

// SPAParams is the JSON form of spa.Params, shared by the settings table and
// the device bundle.
type SPAParams struct {
	NodeID    string `json:"node_id"`
	EpochLenS int64  `json:"epoch_len_s"`
	SlotLenS  int64  `json:"slot_len_s"`
	PortKey   string `json:"port_key"`
	PortBase  uint16 `json:"port_base"`
	PortRange uint16 `json:"port_range"`
	LenMin    int    `json:"len_min"`
	LenMax    int    `json:"len_max"`
}

// FromParams converts spa.Params to their JSON form.
func FromParams(p spa.Params) SPAParams {
	return SPAParams{
		NodeID:    hex.EncodeToString(p.NodeID[:]),
		EpochLenS: int64(p.EpochLen / time.Second),
		SlotLenS:  int64(p.SlotLen / time.Second),
		PortKey:   hex.EncodeToString(p.PortKey[:]),
		PortBase:  p.PortBase,
		PortRange: p.PortRange,
		LenMin:    p.LenMin,
		LenMax:    p.LenMax,
	}
}

// Params converts back to spa.Params and validates them.
func (j SPAParams) Params() (spa.Params, error) {
	p := spa.Params{
		EpochLen:  time.Duration(j.EpochLenS) * time.Second,
		SlotLen:   time.Duration(j.SlotLenS) * time.Second,
		PortBase:  j.PortBase,
		PortRange: j.PortRange,
		LenMin:    j.LenMin,
		LenMax:    j.LenMax,
	}
	if err := decodeHex(j.NodeID, p.NodeID[:]); err != nil {
		return p, fmt.Errorf("node_id: %w", err)
	}
	if err := decodeHex(j.PortKey, p.PortKey[:]); err != nil {
		return p, fmt.Errorf("port_key: %w", err)
	}
	return p, p.Validate()
}

func decodeHex(s string, dst []byte) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(b) != len(dst) {
		return fmt.Errorf("want %d bytes, got %d", len(dst), len(b))
	}
	copy(dst, b)
	return nil
}

// Init creates the installation parameters on first run and keeps them on
// later runs. host is the address clients use; empty keeps the stored one.
func Init(ctx context.Context, st *store.Store, host string) (spa.Params, error) {
	if host != "" {
		if err := st.SetSetting(ctx, settingHost, []byte(host)); err != nil {
			return spa.Params{}, err
		}
	}
	p, err := LoadParams(ctx, st)
	if !errors.Is(err, store.ErrNotFound) {
		return p, err
	}
	if p, err = spa.RandomParams(nil); err != nil {
		return p, err
	}
	b, err := json.Marshal(FromParams(p))
	if err != nil {
		return p, err
	}
	return p, st.SetSetting(ctx, settingSPA, b)
}

// LoadParams returns the stored parameters or store.ErrNotFound before Init.
func LoadParams(ctx context.Context, st *store.Store) (spa.Params, error) {
	b, err := st.GetSetting(ctx, settingSPA)
	if err != nil {
		return spa.Params{}, err
	}
	var j SPAParams
	if err := json.Unmarshal(b, &j); err != nil {
		return spa.Params{}, err
	}
	return j.Params()
}

// Host returns the public address clients use, or "" if unset.
func Host(ctx context.Context, st *store.Store) (string, error) {
	b, err := st.GetSetting(ctx, settingHost)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	return string(b), err
}

// BundleService tells the client which SPA scope ID a service has.
type BundleService struct {
	ID   uint16 `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// Bundle is everything a client needs to pass SPA for one device. It holds
// the device key, so it is shown once and must travel over a trusted channel.
type Bundle struct {
	Version   int             `json:"v"`
	Host      string          `json:"host"`
	SPA       SPAParams       `json:"spa"`
	DeviceID  string          `json:"device_id"`
	DeviceKey string          `json:"device_key"`
	Services  []BundleService `json:"services"`
}

// Encode returns the bundle as "rcdev1:" + base64url(JSON), without padding.
func (b Bundle) Encode() (string, error) {
	j, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	return BundlePrefix + base64.RawURLEncoding.EncodeToString(j), nil
}

// DecodeBundle parses an encoded bundle.
func DecodeBundle(s string) (Bundle, error) {
	var b Bundle
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), BundlePrefix)
	if !ok {
		return b, fmt.Errorf("bundle must start with %q", BundlePrefix)
	}
	j, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(j, &b); err != nil {
		return b, err
	}
	if b.Version != 1 {
		return b, fmt.Errorf("unsupported bundle version %d", b.Version)
	}
	return b, nil
}
