package spa

import (
	"container/heap"
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

// DeviceNonces bounds the knocks one device has made in the last 2*MaxSkew
// (a minute), which pass or not (a scope or a destination refused counts
// too). Without it one device, or a leaked
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
	index   map[string]int             // device ID -> its place in devices
	keys    map[uint64][][KeySize]byte // epoch -> key per device, same order as devices
	// seen holds each nonce until a packet with it can no longer pass the
	// skew check: until a minute has passed on a monotonic clock (since)
	// and the wall clock, which the skew check reads, is past the packet's
	// time plus MaxSkew. Either alone is not enough: the wall clock alone
	// loses the nonce when it steps forward and back again, the monotonic
	// one when the wall clock steps back.
	seen map[[NonceSize]byte]time.Time
	// knocks are the nonces of the last minute in the order they came,
	// with their devices: the quotas (perDevice), and the first half of
	// seen's expiry. Past the minute a nonce whose wall time has not come
	// waits in expiry.
	knocks    []knock
	head      int
	expiry    nonceHeap
	perDevice map[string]int
	since     func() time.Duration
	// forgotten is the latest end of a nonce forgotten: a packet whose own
	// would be no later could be its copy, which a wall clock stepped back
	// past it lets through the skew check again. Refused (ErrReplay):
	// with a clock that does not step back, none ever is.
	forgotten time.Time
}

// knockWindow is how long, on the monotonic clock, a knock counts against
// its device's quota and holds its nonce: the skew both ways and a second
// for the skew check's rounding.
const knockWindow = 2*MaxSkew + time.Second

type knock struct {
	at     time.Duration
	device string
	nonce  [NonceSize]byte
	until  time.Time
}

type nonceExpiry struct {
	until time.Time
	nonce [NonceSize]byte
}

// nonceHeap orders the nonces by when they expire (container/heap).
type nonceHeap []nonceExpiry

func (h nonceHeap) Len() int           { return len(h) }
func (h nonceHeap) Less(i, j int) bool { return h[i].until.Before(h[j].until) }
func (h nonceHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *nonceHeap) Push(x any)        { *h = append(*h, x.(nonceExpiry)) }
func (h *nonceHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
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
		since:      monotonic(),
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
	v.index = make(map[string]int, len(devices))
	for i, d := range v.devices {
		v.index[d.ID] = i
	}
	clear(v.keys)
}

// Verify authenticates pkt and returns what to open for its sender.
func (v *Verifier) Verify(pkt []byte) (Grant, error) {
	return v.verify(pkt, nil)
}

// VerifyDevices is Verify that tries only the devices named, those not
// enrolled skipped: ErrAuth when the packet is none of theirs. Its cost is
// theirs, not every device's.
func (v *Verifier) VerifyDevices(pkt []byte, ids []string) (Grant, error) {
	if len(ids) == 0 {
		return Grant{}, ErrAuth
	}
	return v.verify(pkt, ids)
}

func (v *Verifier) verify(pkt []byte, ids []string) (Grant, error) {
	if len(pkt) < v.params.LenMin || len(pkt) > v.params.LenMax {
		return Grant{}, ErrLength
	}
	var nonce [NonceSize]byte
	copy(nonce[:], pkt)

	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	v.forget(now)
	if _, ok := v.seen[nonce]; ok {
		return Grant{}, ErrReplay
	}

	var only []int
	for _, id := range ids {
		if i, ok := v.index[id]; ok {
			only = append(only, i)
		}
	}
	if ids != nil && only == nil {
		return Grant{}, ErrAuth
	}
	cur := v.params.Epoch(now)
	for _, e := range []uint64{cur, cur - 1, cur + 1} {
		keys := v.epochKeys(e)
		// try opens pkt with device i's key; done once one does.
		try := func(i int) (g Grant, done bool, err error) {
			req, err := open(v.params, keys[i], pkt)
			if errors.Is(err, ErrAuth) {
				return Grant{}, false, nil
			}
			if err != nil {
				return Grant{}, true, err
			}
			g, err = v.accept(v.devices[i], e, req, nonce, now)
			return g, true, err
		}
		if only != nil {
			for _, i := range only {
				if g, done, err := try(i); done {
					return g, err
				}
			}
			continue
		}
		for i := range keys {
			if g, done, err := try(i); done {
				return g, err
			}
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
	if !req.Time.Round(0).Add(MaxSkew + time.Second).After(v.forgotten) {
		return Grant{}, ErrReplay
	}
	if err := v.remember(nonce, d.ID, req.Time, now); err != nil {
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

// monotonic is a clock that steps neither way: time since its start.
func monotonic() func() time.Duration {
	start := time.Now()
	return func() time.Duration { return time.Since(start) }
}

// Precheck is what Verify checks before any decryption, the length and a
// nonce already seen: a caller that pays for checks (the gate's budget)
// pays nothing for these.
func (v *Verifier) Precheck(pkt []byte) error {
	if len(pkt) < v.params.LenMin || len(pkt) > v.params.LenMax {
		return ErrLength
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.forget(v.now())
	if _, ok := v.seen[[NonceSize]byte(pkt[:NonceSize])]; ok {
		return ErrReplay
	}
	return nil
}

// remember stores the nonce of a packet of the given time for as long as
// it could pass the skew check, under the device's quota.
func (v *Verifier) remember(nonce [NonceSize]byte, device string, sent, now time.Time) error {
	v.forget(now)
	if v.perDevice[device] >= DeviceNonces {
		return ErrQuota
	}
	if len(v.seen) >= v.maxSeen {
		return ErrBusy
	}
	// A second over, for the rounding of the skew check.
	until := sent.Round(0).Add(MaxSkew + time.Second)
	v.seen[nonce] = until
	v.knocks = append(v.knocks, knock{at: v.since(), device: device, nonce: nonce, until: until})
	v.perDevice[device]++
	return nil
}

// forget drops what has passed, each in its order, with no walk over the
// cache: the knocks out of the window, whose quotas free; of their nonces
// those whose wall time has come too, the others into expiry; and from
// expiry those whose wall time has come.
func (v *Verifier) forget(now time.Time) {
	wall, at := now.Round(0), v.since()
	for v.head < len(v.knocks) && at-v.knocks[v.head].at >= knockWindow {
		k := v.knocks[v.head]
		v.knocks[v.head] = knock{}
		v.head++
		if v.perDevice[k.device]--; v.perDevice[k.device] <= 0 {
			delete(v.perDevice, k.device)
		}
		switch {
		case !v.seen[k.nonce].Equal(k.until):
		case k.until.Before(wall):
			delete(v.seen, k.nonce)
			v.forgotten = maxTime(v.forgotten, k.until)
		default:
			heap.Push(&v.expiry, nonceExpiry{until: k.until, nonce: k.nonce})
		}
	}
	if v.head > 0 && v.head*2 >= len(v.knocks) {
		n := copy(v.knocks, v.knocks[v.head:])
		clear(v.knocks[n:])
		v.knocks, v.head = v.knocks[:n], 0
	}
	for len(v.expiry) > 0 && v.expiry[0].until.Before(wall) {
		e := heap.Pop(&v.expiry).(nonceExpiry)
		if v.seen[e.nonce].Equal(e.until) {
			delete(v.seen, e.nonce)
			v.forgotten = maxTime(v.forgotten, e.until)
		}
	}
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
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
