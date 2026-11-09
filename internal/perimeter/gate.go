package perimeter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/spa"
)

// ErrNotReady is returned before the first snapshot arrives.
var ErrNotReady = errors.New("perimeter: no snapshot yet")

// ErrPending: the snapshot is the gate's now, but the firewall took it only
// in part; Tick applies the rest. It is worth saving all the same.
var ErrPending = errors.New("perimeter: snapshot applied in part, the rest follows")

// rotation is a UDP port schedule: spa.Params reused with the service's key
// and range (spa-v2.md §11).
type rotation struct {
	sched  spa.Params
	target uint16
}

type grantKey struct {
	addr netip.Addr
	port Port
}

// Gate checks SPA packets and keeps the firewall in step with the
// snapshots from rayd.
type Gate struct {
	fw  Firewall
	log *slog.Logger
	now func() time.Time

	mu         sync.Mutex
	params     spa.Params
	tcpCarrier bool
	defaultTTL time.Duration
	maxTTL     time.Duration
	verifier   *spa.Verifier
	services   map[uint16][]Port
	rotations  []rotation
	rotMap     map[uint16]uint16
	allowed    map[string][]uint16 // device -> service IDs
	public     []Port
	admin      []netip.Prefix
	adminPorts []Port
	relays     []netip.Prefix
	relayPorts []Port
	relaysSet  bool              // SetRelays has run: relay_check is on
	restoring  bool              // a restore of the table has not finished
	pending    *update           // a snapshot not applied in full yet
	revoking   map[grantKey]bool // revoked grants the firewall has not closed yet
	regrant    map[grantKey]bool // grants to set to their longest holder left
	failures   int               // catching up failed so many times in a row
	retryAt    time.Time         // and is tried again from then on
	forward    []Port            // every service port: what a relay forwards
	// holders tracks which devices opened an address and port and until
	// when, so that a revocation closes only what nobody else still holds.
	holders  map[grantKey]map[string]time.Time
	udpPorts []uint16
	tcpPorts []uint16
	// ACME window as last applied.
	acmePort  uint16
	acmeUntil time.Time
	// The egress policy of the last snapshot (egressSeen: there was one),
	// whether the table has it (egressOn), and its own backoff: a policy
	// the kernel refuses holds back neither a snapshot nor a restore.
	egress         Egress
	egressSeen     bool
	egressOn       bool
	egressFailures int
	egressRetryAt  time.Time
	// The per-address limit on new inbound flows (spec/conn-limit-v1.md
	// §6.2): off as the last snapshot says (inLimitOff), and as the table
	// has it (inLimitTableOff; a new table has it on).
	inLimitOff, inLimitTableOff bool
	// guard is the conntrack table's guard (§6.3); nil: none (a relay).
	guard *Guard
}

// NewGate returns a gate that drives fw.
func NewGate(fw Firewall, log *slog.Logger) *Gate {
	return &Gate{fw: fw, log: log, now: time.Now, holders: map[grantKey]map[string]time.Time{}}
}

func portsOf(ps []*perimeterv1.Port) []Port {
	out := make([]Port, 0, len(ps))
	for _, p := range ps {
		out = append(out, Port{p.Proto, uint16(p.Port)})
	}
	return out
}

func paramsOf(p *perimeterv1.SPAParams) (spa.Params, error) {
	out := spa.Params{
		EpochLen:  time.Duration(p.EpochLenS) * time.Second,
		SlotLen:   time.Duration(p.SlotLenS) * time.Second,
		PortBase:  uint16(p.PortBase),
		PortRange: uint16(p.PortRange),
		LenMin:    int(p.LenMin),
		LenMax:    int(p.LenMax),
	}
	if len(p.NodeId) != spa.NodeIDSize || len(p.PortKey) != spa.KeySize {
		return out, errors.New("perimeter: bad node id or port key size")
	}
	copy(out.NodeID[:], p.NodeId)
	copy(out.PortKey[:], p.PortKey)
	return out, out.Validate()
}

// Update applies a snapshot: devices, service ports, public ports. Grants of
// devices that lost access are closed at once.
func (g *Gate) Update(snap *perimeterv1.Snapshot) error {
	params, err := paramsOf(snap.GetSpa())
	if err != nil {
		return err
	}
	devices := make([]spa.Device, 0, len(snap.Devices))
	allowed := make(map[string][]uint16, len(snap.Devices))
	for _, d := range snap.Devices {
		if len(d.Key) != spa.KeySize {
			return fmt.Errorf("perimeter: device %s key size %d", d.Id, len(d.Key))
		}
		sd := spa.Device{ID: d.Id}
		copy(sd.Key[:], d.Key)
		for _, id := range d.Allowed {
			sd.Allowed = append(sd.Allowed, uint16(id))
		}
		devices = append(devices, sd)
		allowed[d.Id] = sd.Allowed
	}
	services := make(map[uint16][]Port, len(snap.Services))
	local := map[uint16]bool{}
	var rotations []rotation
	for _, s := range snap.Services {
		services[uint16(s.Id)] = portsOf(s.Ports)
		local[uint16(s.Id)] = s.Local
		if r := s.Rotation; r != nil {
			if len(r.PortKey) != spa.KeySize || r.PortRange == 0 || r.PortBase+r.PortRange > 65536 {
				return fmt.Errorf("perimeter: bad rotation of service %d", s.Id)
			}
			sched := params
			copy(sched.PortKey[:], r.PortKey)
			sched.PortBase, sched.PortRange = uint16(r.PortBase), uint16(r.PortRange)
			rotations = append(rotations, rotation{sched: sched, target: uint16(r.TargetPort)})
		}
	}
	public := portsOf(snap.PublicPorts)
	var admin []netip.Prefix
	for _, s := range snap.AdminPrefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("perimeter: admin prefix %q: %w", s, err)
		}
		if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96) // or IPv4 packets never match it
		}
		admin = append(admin, p)
	}
	admin = mergePrefixes(admin)
	adminPorts := portsOf(snap.AdminPorts)
	var relays []netip.Prefix
	for _, a := range snap.RelayPrefixes {
		p, err := netip.ParsePrefix(a)
		if err != nil || !p.IsSingleIP() {
			return fmt.Errorf("perimeter: relay address %q: one address only", a)
		}
		relays = append(relays, p)
	}
	relayPorts := portsOf(snap.RelayPorts)
	sp := snap.Spa
	u := &update{
		params: params, devices: devices, allowed: allowed, services: services, local: local, rotations: rotations,
		public: public, admin: admin, adminPorts: adminPorts, relays: relays, relayPorts: relayPorts,
		defTTL: time.Duration(sp.DefaultTtlS) * time.Second, maxTTL: time.Duration(sp.MaxTtlS) * time.Second,
		tcpCarrier: sp.TcpCarrier, acme: snap.GetAcme(), egress: egressOf(snap.GetEgress()),
		connLimitOff: snap.GetConnLimitOff(),
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	g.pending = u
	err = g.catchUpLocked(g.now())
	// Into the table as it is, apart from the rest: its failure is logged
	// and tried again by Tick.
	g.egressLocked(g.now())
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPending, err)
	}
	return nil
}

// mergePrefixes leaves out prefixes inside others, and repeats: an interval
// set takes no overlaps ("conflicting intervals specified"), and rayctl
// admin set takes 198.51.100.0/24 with 198.51.100.7 in it.
func mergePrefixes(ps []netip.Prefix) []netip.Prefix {
	in := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		in = append(in, p.Masked())
	}
	slices.SortFunc(in, func(a, b netip.Prefix) int {
		if a.Bits() != b.Bits() {
			return a.Bits() - b.Bits()
		}
		return a.Addr().Compare(b.Addr())
	})
	var out []netip.Prefix
	for _, p := range in {
		if !slices.ContainsFunc(out, func(q netip.Prefix) bool { return q.Bits() <= p.Bits() && q.Contains(p.Addr()) }) {
			out = append(out, p)
		}
	}
	return out
}

// update is a snapshot checked, to be applied.
type update struct {
	params             spa.Params
	devices            []spa.Device
	allowed            map[string][]uint16
	services           map[uint16][]Port
	local              map[uint16]bool
	rotations          []rotation
	public, adminPorts []Port
	relayPorts         []Port
	admin, relays      []netip.Prefix
	defTTL, maxTTL     time.Duration
	tcpCarrier         bool
	acme               *perimeterv1.AcmeWindow
	egress             Egress
	connLimitOff       bool
}

// catchUpLocked finishes a restore of the table, then applies the snapshot
// still pending. What fails stays to do, and Tick tries again, less and
// less often (1 s doubling to 30 s): rayd sends a snapshot again only when
// something changes.
func (g *Gate) catchUpLocked(now time.Time) error {
	err := func() error {
		if g.pending != nil {
			// Devices and scopes first: a restore must not open again what
			// the snapshot revokes.
			g.adoptLocked(g.pending)
		}
		if g.restoring {
			// Into whatever table there is: a Setup that keeps failing
			// should not keep revoked grants open, or long.
			_ = g.regrantLocked()
			_ = g.denyLocked()
			if err := g.restoreLocked(); err != nil {
				return err
			}
		}
		if g.pending != nil {
			if err := g.applyLocked(g.pending); err != nil {
				return err
			}
			g.pending = nil
		}
		return nil
	}()
	if err != nil {
		g.failures++
		g.retryAt = now.Add(min(30*time.Second, time.Second<<min(g.failures-1, 5)))
		return err
	}
	if g.failures > 0 {
		g.log.Info("perimeter caught up", "failures", g.failures)
	}
	g.failures, g.retryAt = 0, time.Time{}
	return nil
}

// applyLocked brings the table in line with u. The gate's copies change only
// with the firewall: after a failure, the same u applies what is left.
//
// Each part goes on its own: one the firewall keeps refusing does not hold
// back the others (the admin addresses after a broken public port).
func (g *Gate) applyLocked(u *update) error {
	g.adoptLocked(u)
	var errs []error
	// Revocations first: they wait for nothing else.
	errs = append(errs, g.regrantLocked(), g.denyLocked())
	if !slices.Equal(u.public, g.public) {
		if err := g.fw.SetPublic(u.public); err != nil {
			errs = append(errs, err)
		} else {
			g.public = u.public
		}
	}
	if !slices.Equal(u.admin, g.admin) || !slices.Equal(u.adminPorts, g.adminPorts) {
		if err := g.fw.SetAdmin(u.admin, u.adminPorts); err != nil {
			errs = append(errs, err)
		} else {
			g.admin, g.adminPorts = u.admin, u.adminPorts
		}
	}
	// Once at least, even with no relays: it also ends flows of relays
	// removed while rayspa was down. A relay port becoming public waits for
	// the public ports: relay_check would cut its flows meanwhile.
	// Only those ports wait: the relays' addresses, a removal above all,
	// go through.
	relayPorts := u.relayPorts
	if !slices.Equal(u.public, g.public) {
		for _, p := range g.relayPorts {
			if !slices.Contains(relayPorts, p) && slices.Contains(u.public, p) {
				relayPorts = append(slices.Clone(relayPorts), p)
			}
		}
	}
	if !g.relaysSet || !slices.Equal(u.relays, g.relays) || !slices.Equal(relayPorts, g.relayPorts) {
		if err := g.fw.SetRelays(u.relays, relayPorts); err != nil {
			errs = append(errs, err)
		} else {
			g.relays, g.relayPorts, g.relaysSet = u.relays, relayPorts, true
		}
	}
	var forward []Port
	for id, ps := range u.services {
		if u.local[id] {
			continue // served here: a relay's own SSH
		}
		for _, p := range ps {
			if !slices.Contains(forward, p) {
				forward = append(forward, p)
			}
		}
	}
	slices.SortFunc(forward, func(a, b Port) int { return strings.Compare(a.String(), b.String()) })
	if !slices.Equal(forward, g.forward) {
		if err := g.fw.SetForward(forward); err != nil {
			errs = append(errs, err)
		} else {
			g.forward = forward
		}
	}
	errs = append(errs, g.acmeLocked(u.acme), g.inLimitLocked(), g.slotsLocked())
	return errors.Join(errs...)
}

// inLimitLocked puts the per-address limit into the table as the last
// snapshot has it, on or off.
func (g *Gate) inLimitLocked() error {
	if g.inLimitOff == g.inLimitTableOff {
		return nil
	}
	if err := g.fw.SetInLimit(!g.inLimitOff); err != nil {
		return err
	}
	g.inLimitTableOff = g.inLimitOff
	g.log.Info("per-address limit on new inbound connections", "on", !g.inLimitOff)
	return nil
}

// adoptLocked takes the devices, their scopes and the SPA parameters of u,
// and drops the holders u revokes: their grants wait in revoking until the
// firewall closes them (denyLocked), and a restore does not open them again.
func (g *Gate) adoptLocked(u *update) {
	// A new verifier also drops the replay cache, so keep it unless the
	// parameters really changed.
	if g.verifier == nil || u.params != g.params || u.defTTL != g.defaultTTL || u.maxTTL != g.maxTTL {
		g.verifier = spa.NewVerifier(u.params, u.defTTL, u.maxTTL, 100000)
		g.verifier.SetClock(g.now)
	}
	g.verifier.SetDevices(u.devices)
	g.params, g.tcpCarrier = u.params, u.tcpCarrier
	g.defaultTTL, g.maxTTL = u.defTTL, u.maxTTL
	g.services, g.allowed, g.rotations = u.services, u.allowed, u.rotations
	g.inLimitOff = u.connLimitOff
	if !g.egressSeen || !u.egress.Equal(g.egress) {
		// A new policy goes in at once, whatever the backoff of the old.
		g.egress, g.egressSeen, g.egressOn = u.egress, true, false
		g.egressFailures, g.egressRetryAt = 0, time.Time{}
	}
	now := g.now()
	for key, devs := range g.holders {
		revoked := false
		for dev, until := range devs {
			switch {
			case !now.Before(until):
				delete(devs, dev) // expired: the element goes by itself
			case !slices.Contains(g.portsFor(g.allowed[dev]), key.port):
				delete(devs, dev)
				revoked = true
			}
		}
		switch {
		case len(devs) == 0 && !revoked && !g.regrant[key]:
			delete(g.holders, key) // expired: so is its element
		case len(devs) == 0:
			delete(g.holders, key)
			delete(g.regrant, key)
			g.revokeLater(key)
		case revoked:
			// Others hold it still: as long as the longest of them, not
			// as long as the device revoked.
			if g.regrant == nil {
				g.regrant = map[grantKey]bool{}
			}
			g.regrant[key] = true
		}
	}
}

// longest is when the last of a grant's holders expires.
func longest(devs map[string]time.Time) time.Time {
	var until time.Time
	for _, u := range devs {
		if u.After(until) {
			until = u
		}
	}
	return until
}

// regrantLocked sets grants that lost a holder to their longest holder
// left; those the firewall refuses stay to do.
func (g *Gate) regrantLocked() error {
	var errs []error
	now := g.now()
	for key := range g.regrant {
		ttl := longest(g.holders[key]).Sub(now)
		if ttl <= 0 {
			// The others went meanwhile: the element still has the
			// revoked device's time, so it is closed instead.
			delete(g.regrant, key)
			g.revokeLater(key)
			continue
		}
		if err := g.fw.Allow(key.addr, []Port{key.port}, ttl); err != nil {
			errs = append(errs, fmt.Errorf("shortening a grant on %v: %w", key.port, err))
			continue
		}
		delete(g.regrant, key)
	}
	return errors.Join(errs...)
}

// revokeLater puts a grant to close in revoking (denyLocked).
func (g *Gate) revokeLater(key grantKey) {
	if g.revoking == nil {
		g.revoking = map[grantKey]bool{}
	}
	g.revoking[key] = true
}

// denyLocked closes the revoked grants; those the firewall refuses stay to
// do, and the snapshot with them.
func (g *Gate) denyLocked() error {
	var errs []error
	for key := range g.revoking {
		if err := g.fw.Deny(key.addr, []Port{key.port}); err != nil {
			errs = append(errs, fmt.Errorf("closing a revoked grant on %v: %w", key.port, err))
			continue
		}
		delete(g.revoking, key)
		g.log.Debug("revoked", "addr", key.addr, "port", key.port)
	}
	return errors.Join(errs...)
}

// egressLocked puts the egress policy of the last snapshot in force, into
// the table as it is. It stands apart from the rest of the snapshot: a
// kernel that refuses the policy holds back neither the snapshot
// (ErrPending) nor a restore of the table (catchUpLocked's backoff). It is
// tried again on its own, less and less often (1 s doubling to 30 s); the
// first refusal of a streak is a warning, the rest go to debug.
func (g *Gate) egressLocked(now time.Time) {
	if !g.egressSeen || g.egressOn || g.restoring || now.Before(g.egressRetryAt) {
		return
	}
	if err := g.fw.SetEgress(g.egress); err != nil {
		g.egressFailures++
		wait := min(30*time.Second, time.Second<<min(g.egressFailures-1, 5))
		g.egressRetryAt = now.Add(wait)
		// Warn once per streak of refusals, then quietly: a kernel that never
		// takes the policy would otherwise log about 2,900 lines a day.
		level := slog.LevelDebug
		if g.egressFailures == 1 {
			level = slog.LevelWarn
		}
		g.log.Log(context.Background(), level, "egress policy not in force, trying again", "smtp", g.egress.SMTP,
			"bittorrent", g.egress.BitTorrent, "err", err, "in", wait)
		return
	}
	g.egressOn, g.egressFailures, g.egressRetryAt = true, 0, time.Time{}
	g.log.Info("egress policy", "smtp", g.egress.SMTP, "bittorrent", g.egress.BitTorrent, "uids", g.egress.UIDs)
}

// acmeLocked opens, moves or closes the ACME window.
func (g *Gate) acmeLocked(w *perimeterv1.AcmeWindow) error {
	var port uint16
	var until time.Time
	if w != nil && w.Port != 0 && w.Until > g.now().Unix() {
		port, until = uint16(w.Port), time.Unix(w.Until, 0)
	}
	if port == g.acmePort && until.Equal(g.acmeUntil) {
		return nil
	}
	if err := g.fw.SetACME(port, until.Sub(g.now())); err != nil {
		return err
	}
	if port != 0 {
		g.log.Info("acme window open", "port", port, "until", until)
	} else if g.acmePort != 0 {
		g.log.Info("acme window closed")
	}
	g.acmePort, g.acmeUntil = port, until
	return nil
}

// portsFor returns the ports of the given services.
func (g *Gate) portsFor(ids []uint16) []Port {
	var out []Port
	for _, id := range ids {
		for _, p := range g.services[id] {
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	return out
}

// Handle checks one SPA packet from src and opens the granted ports.
func (g *Gate) Handle(src netip.Addr, pkt []byte) (spa.Grant, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.verifier == nil {
		return spa.Grant{}, ErrNotReady
	}
	grant, err := g.verifier.Verify(pkt)
	if err != nil {
		return grant, err
	}
	ports := g.portsFor(grant.Scope)
	now := g.now()
	until := now.Add(grant.TTL)
	// A grant lasts as long as its longest holder: a shorter knock from
	// the same address (CGNAT) does not cut another device's grant short.
	byTTL := map[time.Duration][]Port{}
	for _, p := range ports {
		end := until
		for dev, u := range g.holders[grantKey{src.Unmap(), p}] {
			if dev != grant.DeviceID && u.After(end) {
				end = u // another device's, longer
			}
		}
		byTTL[end.Sub(now)] = append(byTTL[end.Sub(now)], p)
	}
	for _, ttl := range slices.Sorted(maps.Keys(byTTL)) {
		ps := byTTL[ttl]
		if err := g.fw.Allow(src, ps, ttl); err != nil {
			return grant, err
		}
		// Held as soon as open: a revocation must find what is open.
		for _, p := range ps {
			key := grantKey{src.Unmap(), p}
			if g.holders[key] == nil {
				g.holders[key] = map[string]time.Time{}
			}
			delete(g.revoking, key) // held again: not to be closed
			delete(g.regrant, key)  // set to its longest just now
			g.holders[key][grant.DeviceID] = until
		}
	}
	return grant, nil
}

// Tick restores the table if something removed it, moves the SPA ports to
// the current slots and forgets expired holders (the firewall expires the
// elements itself). It returns the TCP carrier ports that should be
// listening, also with an error while a snapshot is behind.
func (g *Gate) Tick() ([]uint16, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	present, err := g.fw.Present()
	if err != nil {
		return nil, err
	}
	if !present && !g.restoring {
		g.restoring = true
		g.log.Warn("nftables table was removed (flush ruleset? nftables or firewalld reload?), restoring", "table", Table)
	}
	var behind error
	if g.restoring || g.pending != nil {
		// A firewall that keeps failing is tried again less and less often.
		if now := g.now(); now.Before(g.retryAt) {
			behind = fmt.Errorf("%w: catching up with the table", ErrNotReady)
		} else {
			behind = g.catchUpLocked(now)
		}
		// Without the whole table the slots have nowhere to go; with only a
		// snapshot behind, they move on as ever, or SPA stops for everyone.
		if behind != nil && g.restoring {
			return nil, behind
		}
	}
	// After a restore, or a refusal: on its own (egressLocked).
	g.egressLocked(g.now())
	// The conntrack guard, whatever the snapshot (spec/conn-limit-v1.md
	// §6.3): it guards the node while rayd is away too.
	g.guardLocked(g.now())
	if g.verifier == nil {
		return nil, ErrNotReady
	}
	now := g.now()
	for key, devs := range g.holders {
		for dev, until := range devs {
			if !now.Before(until) {
				delete(devs, dev)
			}
		}
		if len(devs) == 0 {
			delete(g.holders, key)
		}
	}
	if err := g.slotsLocked(); err != nil {
		return nil, err
	}
	// The ports are good even when a snapshot is behind; none is an empty
	// list, not nil: the carrier closes what it has.
	return append([]uint16{}, g.tcpPorts...), behind
}

// restoreLocked re-creates the table with everything the gate had put in
// it, grants included with the time they have left. Until then the node
// was as open as the rest of the ruleset let it be, so this runs on every
// tick.
//
// A restore that fails halfway is tried again at the next tick, the table
// being there or not.
func (g *Gate) restoreLocked() error {
	g.restoring = true
	if err := g.fw.Setup(); err != nil {
		return err
	}
	g.revoking, g.regrant = nil, nil // a new table: grants come back at their longest
	// Its egress chains are empty: the policy goes in once the restore is
	// done (egressLocked), at once.
	g.egressOn, g.egressFailures, g.egressRetryAt = false, 0, time.Time{}
	// The per-address limit is on in a new table, the guard off: the
	// guard goes back at the next tick (guardLocked).
	g.inLimitTableOff = false
	if g.guard != nil {
		g.guard.applied = false
	}
	if err := g.inLimitLocked(); err != nil {
		return err
	}
	if len(g.public) > 0 {
		if err := g.fw.SetPublic(g.public); err != nil {
			return err
		}
	}
	if len(g.admin) > 0 || len(g.adminPorts) > 0 {
		if err := g.fw.SetAdmin(g.admin, g.adminPorts); err != nil {
			return err
		}
	}
	if len(g.forward) > 0 {
		if err := g.fw.SetForward(g.forward); err != nil {
			return err
		}
	}
	g.rotMap, g.udpPorts, g.tcpPorts = nil, nil, nil
	now := g.now()
	if g.acmePort != 0 && g.acmeUntil.After(now) {
		if err := g.fw.SetACME(g.acmePort, g.acmeUntil.Sub(now)); err != nil {
			return err
		}
	}
	var grants []Grant
	for key, devs := range g.holders {
		var until time.Time
		for _, u := range devs {
			if u.After(until) {
				until = u
			}
		}
		if ttl := until.Sub(now); ttl > 0 {
			grants = append(grants, Grant{Addr: key.addr, Port: key.port, TTL: ttl})
		}
	}
	if all, ok := g.fw.(interface{ AllowAll([]Grant) error }); ok {
		// One transaction, not one nft call per grant.
		if err := all.AllowAll(grants); err != nil {
			return err
		}
	} else {
		for _, gr := range grants {
			if err := g.fw.Allow(gr.Addr, []Port{gr.Port}, gr.TTL); err != nil {
				return err
			}
		}
	}
	// Last, with the grants back: relay_check cuts what nothing lets in.
	if g.relaysSet {
		if err := g.fw.SetRelays(g.relays, g.relayPorts); err != nil {
			return err
		}
	}
	if g.verifier != nil {
		if err := g.slotsLocked(); err != nil {
			return err
		}
	}
	g.restoring = false
	g.log.Info("perimeter table restored", "table", Table, "grants", len(grants))
	return nil
}

func (g *Gate) slotsLocked() error {
	now := g.now()
	rot := map[uint16]uint16{}
	for _, r := range g.rotations {
		for _, p := range r.sched.ActivePorts(now) {
			rot[p] = r.target
		}
	}
	if !maps.Equal(rot, g.rotMap) {
		if err := g.fw.SetRotation(rot); err != nil {
			return err
		}
		g.rotMap = rot
	}

	udp := g.params.ActivePorts(now)
	slices.Sort(udp)
	var tcp []uint16
	if g.tcpCarrier {
		tcp = udp
	}
	if slices.Equal(udp, g.udpPorts) && slices.Equal(tcp, g.tcpPorts) {
		return nil
	}
	if err := g.fw.SetSPAPorts(udp, tcp); err != nil {
		return err
	}
	g.udpPorts, g.tcpPorts = udp, slices.Clone(tcp)
	g.log.Debug("spa ports", "udp", udp, "tcp", tcp)
	return nil
}

// LenMax is the largest valid packet, so carriers know how much to read.
func (g *Gate) LenMax() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.params.LenMax
}
