package spa

import (
	"errors"
	"slices"
	"sync"
	"time"
)

// Device is an enrolled device as the verifier sees it.
type Device struct {
	ID      string
	Key     [KeySize]byte
	Allowed []uint16 // service IDs the device may open
}

// Grant is the outcome of a valid packet: open Scope for the sender address
// for TTL.
type Grant struct {
	DeviceID string
	Scope    []uint16
	TTL      time.Duration
}

var (
	ErrStale  = errors.New("spa: packet time outside the allowed skew")
	ErrReplay = errors.New("spa: nonce already used")
	ErrScope  = errors.New("spa: nothing in the requested scope is allowed")
	ErrBusy   = errors.New("spa: replay cache full")
)

// Verifier checks packets against the enrolled devices. It is safe for
// concurrent use. Rate limiting per source address happens before it, in the
// firewall.
type Verifier struct {
	params     Params
	defaultTTL time.Duration
	maxTTL     time.Duration
	maxSeen    int
	now        func() time.Time

	mu      sync.Mutex
	devices []Device
	keys    map[uint64][][KeySize]byte // epoch -> key per device, same order as devices
	seen    map[[NonceSize]byte]time.Time
}

// NewVerifier returns a verifier with the given TTL policy. maxSeen bounds the
// replay cache; when it is full and nothing has expired, packets are refused
// rather than risking a replay.
func NewVerifier(p Params, defaultTTL, maxTTL time.Duration, maxSeen int) *Verifier {
	return &Verifier{
		params:     p,
		defaultTTL: defaultTTL,
		maxTTL:     maxTTL,
		maxSeen:    maxSeen,
		now:        time.Now,
		keys:       map[uint64][][KeySize]byte{},
		seen:       map[[NonceSize]byte]time.Time{},
	}
}

// SetDevices replaces the device list, e.g. after enrollment or revocation.
func (v *Verifier) SetDevices(devices []Device) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.devices = slices.Clone(devices)
	clear(v.keys)
}

// Verify authenticates pkt and returns what to open for its sender.
func (v *Verifier) Verify(pkt []byte) (Grant, error) {
	if len(pkt) < v.params.LenMin || len(pkt) > v.params.LenMax {
		return Grant{}, ErrLength
	}
	var nonce [NonceSize]byte
	copy(nonce[:], pkt)

	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	if exp, ok := v.seen[nonce]; ok && now.Before(exp) {
		return Grant{}, ErrReplay
	}

	cur := v.params.Epoch(now)
	for _, e := range []uint64{cur, cur - 1, cur + 1} {
		for i, key := range v.epochKeys(e) {
			req, err := open(v.params, key, pkt)
			if errors.Is(err, ErrAuth) {
				continue
			}
			if err != nil {
				return Grant{}, err
			}
			return v.accept(v.devices[i], e, req, nonce, now)
		}
	}
	return Grant{}, ErrAuth
}

func (v *Verifier) accept(d Device, epoch uint64, req Request, nonce [NonceSize]byte, now time.Time) (Grant, error) {
	if v.params.Epoch(req.Time) != epoch {
		return Grant{}, ErrFormat
	}
	if skew := now.Sub(req.Time); skew > MaxSkew || skew < -MaxSkew {
		return Grant{}, ErrStale
	}
	if err := v.remember(nonce, now); err != nil {
		return Grant{}, err
	}

	scope := d.Allowed
	if len(req.Scope) > 0 {
		scope = nil
		for _, id := range req.Scope {
			if slices.Contains(d.Allowed, id) && !slices.Contains(scope, id) {
				scope = append(scope, id)
			}
		}
	}
	if len(scope) == 0 {
		return Grant{}, ErrScope
	}

	ttl := req.TTL
	if ttl == 0 {
		ttl = v.defaultTTL
	}
	ttl = min(ttl, v.maxTTL)
	return Grant{DeviceID: d.ID, Scope: slices.Clone(scope), TTL: ttl}, nil
}

// remember stores the nonce for as long as a packet carrying it could still
// pass the skew check.
func (v *Verifier) remember(nonce [NonceSize]byte, now time.Time) error {
	if len(v.seen) >= v.maxSeen {
		for n, exp := range v.seen {
			if !now.Before(exp) {
				delete(v.seen, n)
			}
		}
		if len(v.seen) >= v.maxSeen {
			return ErrBusy
		}
	}
	v.seen[nonce] = now.Add(2 * MaxSkew)
	return nil
}

// epochKeys returns the per-device keys of an epoch, deriving them once.
// Only the three epochs around the current one are kept.
func (v *Verifier) epochKeys(e uint64) [][KeySize]byte {
	if ks, ok := v.keys[e]; ok {
		return ks
	}
	if len(v.keys) >= 3 {
		cur := v.params.Epoch(v.now())
		for k := range v.keys {
			if k+1 < cur || k > cur+1 {
				delete(v.keys, k)
			}
		}
	}
	ks := make([][KeySize]byte, len(v.devices))
	for i, d := range v.devices {
		ks[i] = EpochKey(d.Key, v.params.NodeID, e)
	}
	v.keys[e] = ks
	return ks
}
