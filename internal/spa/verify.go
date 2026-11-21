package spa

import (
	"errors"
	"net/netip"
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
	// Dst is the address a v3 packet names (spa-v3 §3), unset for v2: the
	// caller opens nothing unless OwnDst takes it.
	Dst netip.Addr
}

var (
	ErrStale  = errors.New("spa: packet time outside the allowed skew")
	ErrReplay = errors.New("spa: nonce already used")
	ErrScope  = errors.New("spa: nothing in the requested scope is allowed")
	ErrBusy   = errors.New("spa: replay cache full")
	// ErrQuota: the device sent more knocks than DeviceNonces in the
	// window; the others' still pass.
	ErrQuota = errors.New("spa: the device's knocks are over its quota")
)

// DeviceNonces bounds the nonces one device has in the replay cache: the
// knocks it sent in the last 2*MaxSkew, which pass or not (a scope or a
// destination refused counts too). Without it one device, or a leaked
// invite, filled the cache, and the node refused every knock until it
// emptied (protocol review 2026-11). 256 a minute is far above a client's
// knocks; the cache holds the quotas of hundreds of devices at once.
const DeviceNonces = 256

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
	// The nonces of seen in the order they came, which with one expiry for
	// all is the order they expire in: forgotten from the front, without
	// a walk over the cache.
	order []seenNonce
	head  int
	// perDevice counts each device's nonces in seen.
	perDevice map[string]int
}

type seenNonce struct {
	nonce  [NonceSize]byte
	until  time.Time
	device string
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
		perDevice:  map[string]int{},
	}
}

// SetClock replaces the time source (tests, and callers that share one clock).
func (v *Verifier) SetClock(now func() time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.now = now
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
	if err := v.remember(nonce, d.ID, now); err != nil {
		// Over its quota: whose, for the operator; nothing to open.
		return Grant{DeviceID: d.ID}, err
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
	return Grant{DeviceID: d.ID, Scope: slices.Clone(scope), TTL: ttl, Dst: req.Dst}, nil
}

// nat64 is the well-known NAT64 prefix (RFC 6052): no one but a translator
// on the client's own path is routed to it, unlike a prefix of a network's
// own, which anyone may set up with any low bits.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

var broadcast4 = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// OwnDst reports whether a v3 packet's destination is the node's (spa-v3
// §4): the address the packet came to (wire, unset when unknown), one of
// the node's public addresses (own), or one of these IPv4 addresses inside
// the well-known NAT64 prefix.
func OwnDst(dst, wire netip.Addr, own []netip.Addr) bool {
	if !dst.IsValid() {
		return false
	}
	dst = dst.Unmap()
	if nat64.Contains(dst) {
		a := dst.As16()
		dst = netip.AddrFrom4([4]byte(a[12:]))
	}
	// A packet to a multicast or broadcast address came to no one address
	// of the node's.
	if wire = wire.Unmap().WithZone(""); wire.IsValid() && !wire.IsMulticast() && wire != broadcast4 && dst == wire {
		return true
	}
	for _, a := range own {
		if dst == a.Unmap().WithZone("") {
			return true
		}
	}
	return false
}

// remember stores the nonce for as long as a packet carrying it could still
// pass the skew check, under the device's quota.
func (v *Verifier) remember(nonce [NonceSize]byte, device string, now time.Time) error {
	v.forget(now)
	if v.perDevice[device] >= DeviceNonces {
		return ErrQuota
	}
	if len(v.seen) >= v.maxSeen {
		return ErrBusy
	}
	until := now.Add(2 * MaxSkew)
	v.seen[nonce] = until
	v.order = append(v.order, seenNonce{nonce: nonce, until: until, device: device})
	v.perDevice[device]++
	return nil
}

// forget drops the nonces that can no longer pass the skew check: those
// expired, and those from a clock that has since stepped back by more than
// 2*MaxSkew (taken more than that ahead of now, their packets' time is past
// the skew). Without the second, entries from before such a step held the
// ones after them, and the devices' quotas, until the clock caught up. A
// smaller step keeps some a little longer.
func (v *Verifier) forget(now time.Time) {
	ahead := now.Add(4 * MaxSkew)
	for v.head < len(v.order) && (!now.Before(v.order[v.head].until) || v.order[v.head].until.After(ahead)) {
		n := v.order[v.head]
		v.order[v.head] = seenNonce{}
		v.head++
		if v.seen[n.nonce].Equal(n.until) {
			delete(v.seen, n.nonce)
		}
		if v.perDevice[n.device]--; v.perDevice[n.device] <= 0 {
			delete(v.perDevice, n.device)
		}
	}
	if v.head > 0 && v.head*2 >= len(v.order) {
		v.order = append(v.order[:0], v.order[v.head:]...)
		v.head = 0
	}
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
