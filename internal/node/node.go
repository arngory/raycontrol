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
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
)

const (
	settingSPA   = "spa_params"
	settingHost  = "public_host"
	settingAdmin = "admin_access"

	// BundlePrefix marks an encoded device bundle.
	BundlePrefix = "rcdev1:"
	// InvitePrefix marks an encoded invite: a bundle of a one-time SPA key
	// that opens the API only, for registration (R3-3).
	InvitePrefix = "rcinv1:"
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
	// UDP port schedule of the service (spa-v2.md §11), if it rotates.
	PortKey   string `json:"port_key,omitempty"`
	PortBase  uint16 `json:"port_base,omitempty"`
	PortRange uint16 `json:"port_range,omitempty"`
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
	// NodeKeys verify subscription signatures: "ed25519" (hex) and
	// "mldsa65" (base64url).
	NodeKeys map[string]string `json:"node_keys,omitempty"`
	Sub      *BundleSub        `json:"sub,omitempty"`
	// API locates the remote API (R3-3), for admin devices and invites;
	// same shape as Sub, served at https://<host>:<port>/.
	API *BundleSub `json:"api,omitempty"`
	// Expires is when an invite stops working (Unix time); bundles have none.
	Expires int64 `json:"expires,omitempty"`
}

// BundleSub locates the subscription endpoint: https://<host>:<port>/sub/v1,
// certificate pinned by SPKI SHA-256 (base64url).
type BundleSub struct {
	Port uint16 `json:"port"`
	Pin  string `json:"pin"`
}

// Encode returns the bundle as "rcdev1:" + base64url(JSON), without padding.
func (b Bundle) Encode() (string, error) { return b.encode(BundlePrefix) }

// EncodeInvite returns the bundle of an invite as "rcinv1:" + base64url(JSON).
func (b Bundle) EncodeInvite() (string, error) { return b.encode(InvitePrefix) }

func (b Bundle) encode(prefix string) (string, error) {
	j, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(j), nil
}

// DecodeBundle parses an encoded bundle.
func DecodeBundle(s string) (Bundle, error) { return decode(s, BundlePrefix) }

// DecodeInvite parses an encoded invite.
func DecodeInvite(s string) (Bundle, error) {
	b, err := decode(s, InvitePrefix)
	if err == nil && (b.API == nil || b.Expires == 0) {
		err = errors.New("the invite has no API endpoint or no expiry")
	}
	return b, err
}

func decode(s, prefix string) (Bundle, error) {
	var b Bundle
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), prefix)
	if !ok {
		return b, fmt.Errorf("must start with %q", prefix)
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

// AdminAccess returns the prefixes that reach SSH without SPA.
func AdminAccess(ctx context.Context, st *store.Store) ([]netip.Prefix, error) {
	b, err := st.GetSetting(ctx, settingAdmin)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list []string
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	ps, err := ParsePrefixes(list)
	if err != nil {
		return nil, err
	}
	// A database from before the limit (S-3) may hold a wider prefix:
	// it reaches nothing until set again within the limit.
	return slices.DeleteFunc(ps, func(p netip.Prefix) bool { return p.Bits() < MinAdminBits(p.Addr()) }), nil
}

// SetAdminAccess replaces the admin prefixes. Single addresses are accepted
// and stored as /32 or /128.
func SetAdminAccess(ctx context.Context, st *store.Store, list []string) ([]netip.Prefix, error) {
	ps, err := ParsePrefixes(list)
	if err != nil {
		return nil, err
	}
	for _, p := range ps {
		if p.Bits() < MinAdminBits(p.Addr()) {
			return nil, fmt.Errorf("%w admin prefix %s: wider than /%d opens SSH to a whole provider; from changing addresses use SPA (rayctl knock)",
				store.ErrInvalid, p, MinAdminBits(p.Addr()))
		}
	}
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return ps, st.SetSetting(ctx, settingAdmin, b)
}

// MinAdminBits is the widest admin prefix: /16 for IPv4, /48 for IPv6, a
// site, not a provider's /32 (S-3). Admin addresses reach SSH without SPA,
// so 0.0.0.0/0 there would open SSH to everyone, through the API too.
func MinAdminBits(a netip.Addr) int {
	if a.Is4() {
		return 16
	}
	return 48
}

// ParsePrefixes parses CIDRs or bare addresses.
func ParsePrefixes(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return nil, fmt.Errorf("%w admin address %q: use an IP or CIDR", store.ErrInvalid, s)
			}
			p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		}
		// ::ffff:a.b.c.d/n is IPv4: the firewall matches IPv4 packets by
		// their IPv4 address.
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return nil, fmt.Errorf("%w admin address %q: an IPv4-mapped prefix shorter than /96", store.ErrInvalid, s)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
