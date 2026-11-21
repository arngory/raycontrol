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

// ErrFlood: the SPA ports get more packets than the gate checks
// (verifyShare): from sources without a grant, or over the TCP carrier. A
// source that holds a grant is tried first against its own devices, apart
// from both (knownShare).
var ErrFlood = errors.New("perimeter: SPA packets over what the node checks: a flood?")

// ErrChanges: a device's knocks change its grants in the table more than
// DeviceChanges times a minute, past as many at once. Each change is an
// nft transaction under the gate's lock (3 ms an element added, some 20 ms
// one replaced or removed: fourth review of the protocol review's change),
// and a device that changes them this often (new addresses, TTLs that
// grow) is no phone but its packets forwarded, or a leaked invite. A knock
// that leaves the table as it is takes none (handle).
var ErrChanges = errors.New("perimeter: the device's knocks change its grants too often")

// DeviceChanges bounds the knocks a device changes the table with: as
// many a minute, as many at once (ErrChanges).
const DeviceChanges = 32

// renewSlack is how much less than its TTL a knock may leave a grant with
// to spare the table a change: the grant lasts at least TTL − slack.
func renewSlack(ttl time.Duration) time.Duration { return min(30*time.Second, ttl/2) }

// wholeSeconds is d rounded up to whole seconds, as nft takes it: never 0,
// which would be no timeout at all.
func wholeSeconds(d time.Duration) time.Duration {
	return max(time.Second, (d + time.Second - 1).Truncate(time.Second))
}

// DeviceAddrs bounds the source addresses one device holds grants from at
// once: a grant from one more closes the one that ends first. Without it
// one device, or a leaked invite, knocking from the addresses of an IPv6
// /64 filled the allow sets of every device's grants (protocol review
// 2026-11). Closed, not refused: the source of a knock is not its proof,
// and one who forwards a device's knocks from addresses of its own must
// not shut the device out.
const DeviceAddrs = 32

// The budgets of SPA checks, at what a packet costs that opens for none of
// the devices (three epochs each, 2 µs a device on a 2.1 GHz Xeon at 288
// bytes, the largest LenMax rayd picks; one set by hand up to 512 costs
// 2.6-2.9 µs).
// Every check runs under the gate's lock, and the UDP ones on the one
// goroutine that reads NFLOG: together they leave the core more than half
// of its time (third review of the protocol review's change).
//   - verifyShare each: packets from sources without a grant (UDP), and
//     packets of the TCP carrier. A flood past one costs no check.
//     At least verifyRateMin a second: past 75 000 devices a budget costs
//     more than its share.
//   - knownShare: a packet from a source with a grant (an IPv4 address, an
//     IPv6 /64), tried against the devices that hold it, at most knownTry
//     of them, each a check of the budget, and knownSourceRate a second of
//     one source: one spoofing a client's source drains that source alone.
//     A packet none of them opens goes on to the budget of its kind.
const (
	verifyShare     = 150 * time.Millisecond
	knownShare      = 100 * time.Millisecond
	verifyPerDevice = 2 * time.Microsecond
	verifyRateMin   = 1
	knownTry        = 32
	knownSourceRate = 8
)

func verifyRate(devices int) float64 {
	return max(float64(verifyShare)/float64(max(devices, 1)*int(verifyPerDevice)), verifyRateMin)
}

// knownRate is the known sources' budget in checks of one device a second.
var knownRate = float64(knownShare) / float64(verifyPerDevice)

// knownSource is a source with a grant: the devices that hold one from its
// addresses, how many addresses each, and its own budget.
type knownSource struct {
	devices map[string]int
	b       bucket
}

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
	integ      []netip.Prefix // integrations' servers (integrations-v1 §3.2)
	integPorts []Port
	relays     []netip.Prefix
	relayPorts []Port
	relaysSet  bool              // SetRelays has run: relay_check is on
	restoring  bool              // a restore of the table has not finished
	pending    *update           // a snapshot not applied in full yet
	revoking   map[grantKey]bool // revoked grants the firewall has not closed yet
	regrant    map[grantKey]bool // grants to set to their longest holder left
	failures   int               // catching up failed so many times in a row
	retryAt    time.Time         // and is tried again from then on
	// Closing and shortening grants (flushLocked) out of a snapshot failed
	// so many times in a row, and is tried again from then on.
	flushFailures int
	flushRetryAt  time.Time
	forward       []Port // every service port: what a relay forwards
	// holders tracks which devices opened an address and port and until
	// when, so that a revocation closes only what nobody else still holds.
	holders map[grantKey]map[string]time.Time
	// addrs are the addresses each device holds grants from, until when
	// (DeviceAddrs).
	addrs map[string]map[netip.Addr]time.Time
	// known are the sources (an IPv4 address, an IPv6 /64) with addresses
	// of addrs in them: a packet from one is tried first against their
	// devices (knownShare).
	known                             map[netip.Prefix]*knownSource
	budget, knownBudget, streamBudget bucket
	budgetRate                        float64
	// changes are the devices' budgets of changes to the table
	// (ErrChanges).
	changes  map[string]*changeBudget
	udpPorts []uint16
	tcpPorts []uint16
	// ACME window as last applied.
	acmePort  uint16
	acmeUntil time.Time
	// A relay's forward of TCP 80 to its exit (relay-names-v1 §6), as last
	// applied: zero when closed.
	acmeFwdUntil time.Time
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
	// own are the node's public addresses (spa-v3 §4): a v3 packet names
	// one of them or the address it came to.
	own []netip.Addr
	// guard is the conntrack table's guard (§6.3); nil: none (a relay).
	guard *Guard
}

// NewGate returns a gate that drives fw.
func NewGate(fw Firewall, log *slog.Logger) *Gate {
	return &Gate{fw: fw, log: log, now: time.Now, holders: map[grantKey]map[string]time.Time{},
		addrs: map[string]map[netip.Addr]time.Time{}, known: map[netip.Prefix]*knownSource{}, changes: map[string]*changeBudget{},
		budgetRate: verifyRateMin}
}

// SetupAtFirstSnapshot makes the gate take the table only with its first
// snapshot (rayspa's start, docs/decisions.md R4-40): Update then makes
// the table and fills it in one go, and until then the gate leaves the
// kernel as it is. A table an earlier rayspa left there (a restart) stays
// in force, its admin addresses with it; with none (a boot without a saved
// snapshot, or with one that does not apply) the host stays as open as the
// rest of the ruleset leaves it. An empty table would close it to everyone,
// the administrator included, until rayd answers, and rayd may not.
func (g *Gate) SetupAtFirstSnapshot() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.restoring = true
}

// GateState is where the gate's table stands, as rayspa says it (STATUS,
// its report to rayd).
type GateState int

const (
	// GateNoSnapshot: no snapshot yet, so no table of this gate; one an
	// earlier rayspa left may be in force, or none.
	GateNoSnapshot GateState = iota
	// GateNotIn: a snapshot, but its table is not in: the kernel refused
	// it, or it went (flush ruleset) and is not back yet.
	GateNotIn
	// GateBehind: the table is in, the last snapshot only in part (Tick
	// applies the rest).
	GateBehind
	// GateUp: the table is in with all of the last snapshot.
	GateUp
)

func (s GateState) String() string {
	switch s {
	case GateNoSnapshot:
		return "no snapshot yet"
	case GateNotIn:
		return "table not in"
	case GateBehind:
		return "snapshot applied in part"
	case GateUp:
		return "up"
	}
	return "unknown"
}

// State says where the gate's table stands.
func (g *Gate) State() GateState {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case g.verifier == nil:
		return GateNoSnapshot
	case g.restoring:
		return GateNotIn
	case g.pending != nil:
		return GateBehind
	}
	return GateUp
}

// Up reports whether the gate's table is in the kernel with all of its
// last snapshot: false before the first snapshot, while a table that went
// is being restored, and while a snapshot is in only in part (the admin
// addresses of a new one, say). The egress policy stands apart
// (egressLocked): a kernel that refuses it does not take the gate down.
func (g *Gate) Up() bool { return g.State() == GateUp }

// Forwarded are the ports a relay's table forwards to its exit (relay_fwd)
// for these services of its snapshot: every port of a service not served
// here (Local: a relay's own SSH, the probe), once, in order. They are in
// the set from the snapshot on, before any client's knock (a knock's grant
// goes to allow4 or allow6). None: relay_dnat's DNAT rule matches nothing.
func Forwarded(services []*perimeterv1.Service) []Port {
	var forward []Port
	for _, s := range services {
		if s.Local {
			continue // served here
		}
		for _, p := range portsOf(s.Ports) {
			if !slices.Contains(forward, p) {
				forward = append(forward, p)
			}
		}
	}
	slices.SortFunc(forward, func(a, b Port) int { return strings.Compare(a.String(), b.String()) })
	return forward
}

func portsOf(ps []*perimeterv1.Port) []Port {
	out := make([]Port, 0, len(ps))
	for _, p := range ps {
		out = append(out, Port{p.Proto, uint16(p.Port)})
	}
	return out
}

func paramsOf(p *perimeterv1.SPAParams) (spa.Params, error) {
	if p == nil {
		return spa.Params{}, errors.New("perimeter: no SPA parameters")
	}
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
	if p.PortBase > 65535 || p.PortRange > 65535 {
		return out, fmt.Errorf("perimeter: SPA port range %d+%d out of bounds", p.PortBase, p.PortRange)
	}
	copy(out.NodeID[:], p.NodeId)
	copy(out.PortKey[:], p.PortKey)
	return out, out.Validate()
}

// checkPorts refuses a snapshot with a port of another protocol than TCP
// or UDP: the protocol is a string, and goes into the nft transactions as
// it is (portElems, elements), where one with a newline or a brace would
// be commands of its own, run by root. And a number past its 16 bits (a
// port, a service, a scope), which would be cut to another.
func checkPorts(snap *perimeterv1.Snapshot) error {
	lists := [][]*perimeterv1.Port{snap.GetPublicPorts(), snap.GetAdminPorts(), snap.GetRelayPorts(), snap.GetIntegPorts()}
	for _, s := range snap.GetServices() {
		lists = append(lists, s.GetPorts())
	}
	for _, ps := range lists {
		for _, p := range ps {
			if p.GetProto() != "tcp" && p.GetProto() != "udp" {
				return fmt.Errorf("perimeter: port %d of protocol %.16q: tcp or udp", p.GetPort(), p.GetProto())
			}
			if p.GetPort() > 65535 {
				return fmt.Errorf("perimeter: port %s/%d out of range", p.GetProto(), p.GetPort())
			}
		}
	}
	for _, s := range snap.GetServices() {
		if r := s.GetRotation(); s.GetId() > 65535 || r != nil && r.GetTargetPort() > 65535 {
			return fmt.Errorf("perimeter: service %d out of range, or its rotation's port", s.GetId())
		}
	}
	for _, d := range snap.GetDevices() {
		if slices.ContainsFunc(d.GetAllowed(), func(id uint32) bool { return id > 65535 }) {
			return fmt.Errorf("perimeter: device %.64q allowed a service out of range", d.GetId())
		}
	}
	if snap.GetAcme().GetPort() > 65535 {
		return fmt.Errorf("perimeter: ACME port %d out of range", snap.GetAcme().GetPort())
	}
	return nil
}

// Update applies a snapshot: devices, service ports, public ports. Grants of
// devices that lost access are closed at once.
func (g *Gate) Update(snap *perimeterv1.Snapshot) error {
	params, err := paramsOf(snap.GetSpa())
	if err != nil {
		return err
	}
	if err := checkPorts(snap); err != nil {
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
	var rotations []rotation
	for _, s := range snap.Services {
		services[uint16(s.Id)] = portsOf(s.Ports)
		if r := s.Rotation; r != nil {
			if len(r.PortKey) != spa.KeySize || r.PortRange == 0 || uint64(r.PortBase)+uint64(r.PortRange) > 65536 {
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
	var integ []netip.Prefix
	for _, s := range snap.GetIntegPrefixes() {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("perimeter: integration prefix %q: %w", s, err)
		}
		if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
		}
		integ = append(integ, p.Masked())
	}
	integ = mergePrefixes(integ)
	integPorts := portsOf(snap.GetIntegPorts())
	if len(integ) == 0 || len(integPorts) == 0 {
		integ, integPorts = nil, nil
	}
	var relays []netip.Prefix
	for _, a := range snap.RelayPrefixes {
		p, err := netip.ParsePrefix(a)
		if err != nil || !p.IsSingleIP() {
			return fmt.Errorf("perimeter: relay address %q: one address only", a)
		}
		relays = append(relays, p)
	}
	relayPorts := portsOf(snap.RelayPorts)
	own := ownAddrsOf(snap.GetOwnAddrs())
	sp := snap.Spa
	u := &update{
		params: params, devices: devices, allowed: allowed, services: services, forward: Forwarded(snap.Services), rotations: rotations,
		public: public, admin: admin, adminPorts: adminPorts, relays: relays, relayPorts: relayPorts,
		integ: integ, integPorts: integPorts,
		defTTL: time.Duration(sp.DefaultTtlS) * time.Second, maxTTL: time.Duration(sp.MaxTtlS) * time.Second,
		tcpCarrier: sp.TcpCarrier, acme: snap.GetAcme(), egress: egressOf(snap.GetEgress()),
		connLimitOff: snap.GetConnLimitOff(), own: own,
	}
	if until := snap.GetAcmeForwardUntil(); until > 0 {
		u.acmeForward = time.Unix(until, 0)
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

// SPAVersions are the SPA versions this gate takes (spa-v3 §5). A
// relay's rayspa tells the exit, which lists them for the relay.
var SPAVersions = []uint32{2, 3}

// maxOwnAddrs bounds own_addrs: a node has a few public addresses, and
// every v3 packet is checked against them.
const maxOwnAddrs = 16

// ownAddrsOf parses the node's public addresses of a snapshot, the first
// maxOwnAddrs. One that is no address of a node is left out, not the
// snapshot refused: a refused snapshot would hold back revocations too.
// Leaving one out only takes fewer v3 packets.
func ownAddrsOf(addrs []string) []netip.Addr {
	own := make([]netip.Addr, 0, min(len(addrs), maxOwnAddrs))
	for _, s := range addrs {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" || len(own) == maxOwnAddrs {
			continue
		}
		if a = a.Unmap(); a.IsUnspecified() || a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			continue
		}
		own = append(own, a)
	}
	return own
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
	forward            []Port // Forwarded
	rotations          []rotation
	public, adminPorts []Port
	relayPorts         []Port
	admin, relays      []netip.Prefix
	integ              []netip.Prefix
	integPorts         []Port
	defTTL, maxTTL     time.Duration
	tcpCarrier         bool
	acme               *perimeterv1.AcmeWindow
	acmeForward        time.Time // a relay's: TCP 80 to the exit until then
	egress             Egress
	connLimitOff       bool
	own                []netip.Addr
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
			_ = g.flushLocked()
			if err := g.restoreLocked(g.pending); err != nil {
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
	errs = append(errs, g.flushLocked())
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
	if !slices.Equal(u.integ, g.integ) || !slices.Equal(u.integPorts, g.integPorts) {
		if err := g.fw.SetInteg(u.integ, u.integPorts); err != nil {
			errs = append(errs, err)
		} else {
			g.integ, g.integPorts = u.integ, u.integPorts
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
	if forward := u.forward; !slices.Equal(forward, g.forward) {
		if err := g.fw.SetForward(forward); err != nil {
			errs = append(errs, err)
		} else {
			g.forward = forward
		}
	}
	errs = append(errs, g.acmeLocked(u.acme), g.acmeForwardLocked(u.acmeForward), g.inLimitLocked(), g.slotsLocked())
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
// firewall closes them (flushLocked), and a restore does not open them again.
func (g *Gate) adoptLocked(u *update) {
	// A new verifier also drops the replay cache, so keep it unless the
	// parameters really changed: new TTLs keep it.
	if g.verifier == nil || u.params != g.params {
		g.verifier = spa.NewVerifier(u.params, u.defTTL, u.maxTTL, 100000)
		g.verifier.SetClock(g.now)
	} else if u.defTTL != g.defaultTTL || u.maxTTL != g.maxTTL {
		g.verifier.SetTTL(u.defTTL, u.maxTTL)
	}
	g.verifier.SetDevices(u.devices)
	g.budgetRate = verifyRate(len(u.devices))
	g.params, g.tcpCarrier = u.params, u.tcpCarrier
	g.defaultTTL, g.maxTTL = u.defTTL, u.maxTTL
	g.services, g.allowed, g.rotations = u.services, u.allowed, u.rotations
	for dev := range g.changes {
		if _, ok := g.allowed[dev]; !ok {
			delete(g.changes, dev)
		}
	}
	g.inLimitOff = u.connLimitOff
	g.own = u.own
	if !g.egressSeen || !u.egress.Equal(g.egress) {
		// A new policy goes in at once, whatever the backoff of the old.
		g.egress, g.egressSeen, g.egressOn = u.egress, true, false
		g.egressFailures, g.egressRetryAt = 0, time.Time{}
	}
	now := g.now()
	defer g.addrsLocked(now)
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

// flushLocked closes the revoked grants and sets those that lost a holder
// to their longest holder left, all in one transaction: a removal waits
// for the kernel, some 20 ms, once a transaction (fourth review of the
// protocol review's change). What the firewall refuses stays to do, and
// the snapshot with it. Done, it ends a streak of refusals
// (flushLaterLocked), whoever ran it.
func (g *Gate) flushLocked() error {
	if len(g.revoking)+len(g.regrant) == 0 {
		return nil
	}
	keys := make([]grantKey, 0, len(g.revoking)+len(g.regrant))
	for key := range g.regrant {
		keys = append(keys, key)
	}
	for key := range g.revoking {
		if !g.regrant[key] {
			keys = append(keys, key)
		}
	}
	allow, deny := g.flushItemsLocked(keys, g.now())
	if err := g.fw.SetGrants(allow, deny); err != nil {
		return fmt.Errorf("closing %d grants and shortening %d: %w", len(deny), len(allow), err)
	}
	for _, key := range keys {
		delete(g.regrant, key)
		delete(g.revoking, key)
	}
	g.log.Debug("grants closed or shortened", "closed", len(deny), "shortened", len(allow))
	if g.flushFailures > 0 {
		g.log.Info("grants closed or shortened after refusals", "failures", g.flushFailures)
	}
	g.flushFailures, g.flushRetryAt = 0, time.Time{}
	return nil
}

// flushItemsLocked is what keys of regrant and revoking take of the
// firewall: a grant that lost a holder set to its longest holder left, or
// closed when the others went meanwhile (the element still has the revoked
// device's time); a revoked one closed.
func (g *Gate) flushItemsLocked(keys []grantKey, now time.Time) (allow []Grant, deny []Elem) {
	for _, key := range keys {
		if g.regrant[key] {
			if ttl := longest(g.holders[key]).Sub(now); ttl > 0 {
				allow = append(allow, Grant{Addr: key.addr, Port: key.port, TTL: wholeSeconds(ttl)})
				continue
			}
			delete(g.regrant, key)
			g.revokeLater(key)
		}
		if g.revoking[key] {
			deny = append(deny, Elem{key.addr, key.port})
		}
	}
	return allow, deny
}

// flushLaterLocked runs flushLocked out of a snapshot (a tick), less and
// less often while the firewall refuses (1 s doubling to 30 s); the first
// refusal of a streak is a warning, the rest go to debug.
func (g *Gate) flushLaterLocked(now time.Time) {
	if len(g.revoking)+len(g.regrant) == 0 || now.Before(g.flushRetryAt) {
		return
	}
	if err := g.flushLocked(); err != nil {
		g.flushRefusedLocked(now, err)
	}
}

// flushRefusedLocked counts a refusal of closings and shortenings in the
// streak, and puts the next try off.
func (g *Gate) flushRefusedLocked(now time.Time, err error) {
	g.flushFailures++
	g.flushRetryAt = now.Add(min(30*time.Second, time.Second<<min(g.flushFailures-1, 5)))
	if g.flushFailures == 1 {
		g.log.Warn("grants to close or shorten: the firewall refused, trying again", "err", err)
	} else {
		g.log.Debug("grants to close or shorten: the firewall refused again", "failures", g.flushFailures, "err", err)
	}
}

// revokeLater puts a grant to close in revoking (flushLocked).
func (g *Gate) revokeLater(key grantKey) {
	if g.revoking == nil {
		g.revoking = map[grantKey]bool{}
	}
	g.revoking[key] = true
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
		g.log.Log(context.Background(), level, "egress policy not in force, trying again", "smtp", g.egress.SMTP, "local", g.egress.Local,
			"bittorrent", g.egress.BitTorrent, "err", err, "in", wait)
		return
	}
	g.egressOn, g.egressFailures, g.egressRetryAt = true, 0, time.Time{}
	g.log.Info("egress policy", "smtp", g.egress.SMTP, "bittorrent", g.egress.BitTorrent, "local", g.egress.Local, "uids", g.egress.UIDs)
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

// maxACMEForward bounds a relay's forward of TCP 80: an exit's ACME
// window lasts 3 minutes (certs.WindowLen), and a forward set years ahead
// would leave the exit's port 80 open to everyone through the relay.
const maxACMEForward = 10 * time.Minute

// acmeForwardFor is how long a relay forwards TCP 80 from now for a
// snapshot's deadline: 0 when it is past, at most maxACMEForward.
func acmeForwardFor(until, now time.Time) time.Duration {
	if !until.After(now) {
		return 0
	}
	return min(until.Sub(now), maxACMEForward)
}

// acmeForwardLocked opens, moves or closes a relay's forward of TCP 80 to
// its exit (relay-names-v1 §6).
func (g *Gate) acmeForwardLocked(until time.Time) error {
	now := g.now()
	ttl := acmeForwardFor(until, now)
	open := g.acmeFwdUntil.After(now)
	switch {
	case ttl == 0 && !open:
		// Closed, or its element gone by itself.
		g.acmeFwdUntil = time.Time{}
		return nil
	case ttl > 0 && open && now.Add(ttl).Sub(g.acmeFwdUntil).Abs() < time.Second:
		return nil // the same window again
	}
	if err := g.fw.SetACMEForward(ttl); err != nil {
		return err
	}
	g.acmeFwdUntil = time.Time{}
	if ttl > 0 {
		g.acmeFwdUntil = now.Add(ttl)
		g.log.Info("acme forward to the exit open", "until", g.acmeFwdUntil)
	} else {
		g.log.Info("acme forward to the exit closed")
	}
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

// Handle checks one SPA packet from src, which came to dst (unset when not
// known), and opens the granted ports. A v3 packet must name one of the
// node's addresses (spa-v3 §4): one caught at another address and sent
// on from there opens nothing.
func (g *Gate) Handle(src, dst netip.Addr, pkt []byte) (spa.Grant, error) {
	return g.handle(src, dst, pkt, false)
}

// HandleStream is Handle for a packet of the TCP carrier, checked on its
// own budget.
func (g *Gate) HandleStream(src, dst netip.Addr, pkt []byte) (spa.Grant, error) {
	return g.handle(src, dst, pkt, true)
}

func (g *Gate) handle(src, dst netip.Addr, pkt []byte, stream bool) (spa.Grant, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.verifier == nil {
		return spa.Grant{}, ErrNotReady
	}
	// What costs no decryption first: no budget spent on it.
	if err := g.verifier.Precheck(pkt); err != nil {
		return spa.Grant{}, err
	}
	now := g.now()
	grant, err := spa.Grant{}, spa.ErrAuth
	// A source with a grant: its own devices first, apart from the flood
	// of the others, UDP and TCP alike.
	// Each device tried is a check of the budget; the source's own budget
	// first takes nothing when the other refuses.
	if ks, n := g.knownLocked(src); ks != nil && g.knownBudget.has(knownRate, n, now) && ks.b.take(knownSourceRate, 1, now) {
		g.knownBudget.take(knownRate, n, now)
		ids := make([]string, 0, int(n))
		for dev := range ks.devices {
			if len(ids) == knownTry {
				break
			}
			ids = append(ids, dev)
		}
		grant, err = g.verifier.VerifyDevices(pkt, ids)
	}
	if errors.Is(err, spa.ErrAuth) {
		budget := &g.budget
		if stream {
			budget = &g.streamBudget
		}
		if !budget.take(g.budgetRate, 1, now) {
			return spa.Grant{}, ErrFlood
		}
		grant, err = g.verifier.Verify(pkt)
	}
	if err != nil {
		return grant, err
	}
	if grant.Dst.IsValid() && !spa.OwnDst(grant.Dst, dst, g.own) {
		return grant, spa.ErrDst
	}
	return grant, g.grantLocked(grant, src.Unmap(), now)
}

// grantLocked opens grant's ports to src, in one transaction, or leaves
// the table as it is when that changes a port's end by less than
// renewSlack (another device's longer grant from src, a knock again). A
// knock that changes the table takes one of the device's changes
// (ErrChanges).
func (g *Gate) grantLocked(grant spa.Grant, src netip.Addr, now time.Time) error {
	dev := grant.DeviceID
	ttl := max(grant.TTL, time.Second) // nft would take 0 for no timeout at all
	until := now.Add(ttl)
	var writes []Grant
	holds := map[grantKey]time.Time{}
	for _, p := range g.portsFor(grant.Scope) {
		key := grantKey{src, p}
		devs := g.holders[key]
		var others time.Time
		for d, u := range devs {
			if d != dev && u.After(others) {
				others = u
			}
		}
		// A grant lasts as long as its longest holder: a shorter knock
		// from the same address (CGNAT) does not cut another device's
		// grant short. Its own shorter knock is the device's to make.
		end, cur := maxTime(until, others), longest(devs)
		if !g.revoking[key] && !g.regrant[key] && !end.Before(cur) && end.Sub(cur) < renewSlack(ttl) {
			// The element ends at cur, at least TTL − slack from now: the
			// device holds it as long as it lasts.
			holds[key] = minTime(until, cur)
			continue
		}
		writes = append(writes, Grant{Addr: src, Port: p, TTL: wholeSeconds(end.Sub(now))})
		holds[key] = until
	}
	u, ok := g.addrs[dev][src]
	held := ok && now.Before(u)
	evicts := !held && g.liveAddrsLocked(dev, now) >= DeviceAddrs
	if (len(writes) > 0 || evicts) && !g.changeLocked(dev, now) {
		return ErrChanges
	}
	// An eviction's closings and shortenings go in the knock's own
	// transaction: one wait for the kernel, one change (fifth review: two
	// transactions a change doubled what a leaked invite holds the lock).
	var evicted []grantKey
	if evicts {
		evicted = g.evictLocked(dev, src, now)
	}
	allow, deny := g.flushItemsLocked(evicted, now)
	if err := g.fw.SetGrants(append(slices.Clip(writes), allow...), deny); err == nil {
		for _, key := range evicted {
			delete(g.regrant, key)
			delete(g.revoking, key)
		}
	} else if len(allow)+len(deny) == 0 {
		return err
	} else {
		// The knock's own grants alone; what the eviction asks for stays
		// to do, a refusal of the streak (flushLaterLocked).
		g.flushRefusedLocked(now, err)
		if err := g.fw.SetGrants(writes, nil); err != nil {
			return err
		}
	}
	// Held as soon as open: a revocation must find what is open.
	for key, u := range holds {
		if g.holders[key] == nil {
			g.holders[key] = map[string]time.Time{}
		}
		delete(g.revoking, key) // held again: not to be closed
		delete(g.regrant, key)  // set to its longest just now
		g.holders[key][dev] = u
	}
	g.holdAddrLocked(dev, src, now)
	return nil
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// knownLocked is src's known source, if it is one, and how many of its
// devices a packet from it is tried against.
func (g *Gate) knownLocked(src netip.Addr) (*knownSource, float64) {
	ks := g.known[knockSource(src)]
	if ks == nil {
		return nil, 0
	}
	return ks, float64(min(len(ks.devices), knownTry))
}

// knockSource is what the budgets know a source by: an IPv4 address, an
// IPv6 /64.
func knockSource(src netip.Addr) netip.Prefix {
	src = src.Unmap()
	bits := 64
	if src.Is4() {
		bits = 32
	}
	p, _ := src.Prefix(bits)
	return p
}

// bucket is a token bucket of one second's burst.
type bucket struct {
	tokens float64
	last   time.Time
}

// take takes n tokens of a bucket that gets rate a second, as many at
// once, if it has them.
func (b *bucket) take(rate, n float64, now time.Time) bool {
	if !b.has(rate, n, now) {
		return false
	}
	b.tokens -= n
	return true
}

// has reports whether the bucket has n tokens, taking none.
func (b *bucket) has(rate, n float64, now time.Time) bool {
	if b.last.IsZero() {
		b.tokens = rate
	} else {
		b.tokens = min(rate, b.tokens+max(now.Sub(b.last).Seconds(), 0)*rate)
	}
	b.last = now
	return b.tokens >= max(n, 1)
}

// changeBudget is a device's budget of changes to the table: DeviceChanges
// a minute, as many at once.
type changeBudget struct {
	tokens float64
	last   time.Time
}

// changeLocked takes one of device's changes, if it has one left.
func (g *Gate) changeLocked(device string, now time.Time) bool {
	c := g.changes[device]
	if c == nil {
		c = &changeBudget{tokens: DeviceChanges, last: now}
		g.changes[device] = c
	}
	c.tokens = min(DeviceChanges, c.tokens+max(now.Sub(c.last).Minutes(), 0)*DeviceChanges)
	c.last = now
	if c.tokens < 1 {
		return false
	}
	c.tokens--
	return true
}

// liveAddrsLocked is how many addresses device holds grants from now.
func (g *Gate) liveAddrsLocked(device string, now time.Time) int {
	live := 0
	for _, u := range g.addrs[device] {
		if now.Before(u) {
			live++
		}
	}
	return live
}

// holdAddrLocked counts src among the addresses device holds grants from,
// until its grants from there end. Room for it was made first
// (evictLocked); what has expired goes, should the address be one too many.
func (g *Gate) holdAddrLocked(device string, src netip.Addr, now time.Time) {
	addrs := g.addrs[device]
	if addrs == nil {
		addrs = map[netip.Addr]time.Time{}
		g.addrs[device] = addrs
	}
	if _, ok := addrs[src]; !ok {
		g.knowLocked(device, src)
	}
	addrs[src] = g.heldUntilLocked(device, src)
	if len(addrs) > DeviceAddrs {
		for a, u := range addrs {
			if a != src && !now.Before(u) {
				g.dropAddrLocked(device, a)
			}
		}
	}
}

// evictLocked makes room for one more address of device, src: the expired
// go, then, past DeviceAddrs, those whose grants end first (another
// device's grants from there stay, as long as it holds them). It returns
// the grants that lost device as a holder: their closing and shortening go
// in the knock's own transaction (grantLocked).
func (g *Gate) evictLocked(device string, src netip.Addr, now time.Time) []grantKey {
	for a, u := range g.addrs[device] {
		if !now.Before(u) {
			g.dropAddrLocked(device, a)
		}
	}
	var keys []grantKey
	for len(g.addrs[device]) >= DeviceAddrs {
		addrs := g.addrs[device]
		var first netip.Addr
		for a, u := range addrs {
			if a != src && (!first.IsValid() || u.Before(addrs[first])) {
				first = a
			}
		}
		if !first.IsValid() {
			break
		}
		g.dropAddrLocked(device, first)
		keys = append(keys, g.releaseLocked(device, first)...)
	}
	return keys
}

// heldUntilLocked is when device's grants from addr end: the latest of
// its holds of addr's ports (a shorter knock cuts its own grant short).
func (g *Gate) heldUntilLocked(device string, addr netip.Addr) time.Time {
	var end time.Time
	for _, p := range g.portsFor(g.allowed[device]) {
		if u, ok := g.holders[grantKey{addr, p}][device]; ok && u.After(end) {
			end = u
		}
	}
	return end
}

// addrsLocked brings addrs to the holders after a snapshot: an address of
// a device that holds none of its ports any more (revoked, its scope
// narrowed, expired) is no longer its, nor its source known for it.
func (g *Gate) addrsLocked(now time.Time) {
	for dev, addrs := range g.addrs {
		for a := range addrs {
			end := g.heldUntilLocked(dev, a)
			if !now.Before(end) {
				g.dropAddrLocked(dev, a)
				continue
			}
			addrs[a] = end
		}
	}
}

// knowLocked counts addr of device in its source's known devices.
func (g *Gate) knowLocked(device string, addr netip.Addr) {
	src := knockSource(addr)
	ks := g.known[src]
	if ks == nil {
		ks = &knownSource{devices: map[string]int{}}
		g.known[src] = ks
	}
	ks.devices[device]++
}

// dropAddrLocked takes addr off device's addresses, and its source off the
// known when no address of a device is in it.
func (g *Gate) dropAddrLocked(device string, addr netip.Addr) {
	addrs := g.addrs[device]
	if _, ok := addrs[addr]; !ok {
		return
	}
	delete(addrs, addr)
	if len(addrs) == 0 {
		delete(g.addrs, device)
	}
	src := knockSource(addr)
	ks := g.known[src]
	if ks == nil {
		return
	}
	if ks.devices[device]--; ks.devices[device] <= 0 {
		delete(ks.devices, device)
	}
	if len(ks.devices) == 0 {
		delete(g.known, src)
	}
}

// releaseLocked takes device off the grants of addr: one no one else holds
// closes, one another holds shortens to its longest holder (revoking,
// regrant). It returns those grants.
func (g *Gate) releaseLocked(device string, addr netip.Addr) (keys []grantKey) {
	for _, p := range g.portsFor(g.allowed[device]) {
		key := grantKey{addr, p}
		devs := g.holders[key]
		if _, ok := devs[device]; !ok {
			continue
		}
		delete(devs, device)
		keys = append(keys, key)
		if len(devs) == 0 {
			delete(g.holders, key)
			delete(g.regrant, key)
			g.revokeLater(key)
			continue
		}
		if g.regrant == nil {
			g.regrant = map[grantKey]bool{}
		}
		g.regrant[key] = true
	}
	return keys
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
	if g.verifier == nil {
		// No snapshot yet: nothing to put into a table, and an empty one
		// would shut the administrator out (SetupAtFirstSnapshot).
		return nil, ErrNotReady
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
	for dev, addrs := range g.addrs {
		for a, until := range addrs {
			if !now.Before(until) {
				g.dropAddrLocked(dev, a)
			}
		}
	}
	// Grants an eviction closed or shortened that the firewall refused
	// then: again, less and less often, when no snapshot or restore does it.
	if !g.restoring && g.pending == nil {
		g.flushLaterLocked(now)
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
//
// With u (a snapshot not applied yet: the first one at rayspa's start)
// the table is made with u's sets, not the gate's: the admin addresses,
// the public ports and the slots go in with the table, so that no new SYN
// of the administrator meets a table without them. A firewall that can
// (TableSetup, NFT) takes it all in one transaction: the table is in
// whole, or not at all and the kernel stays as it was.
func (g *Gate) restoreLocked(u *update) error {
	g.restoring = true
	now := g.now()
	c := TableContents{
		Public: g.public, Admin: g.admin, AdminPorts: g.adminPorts, Forward: g.forward,
		Relays: g.relays, RelayPorts: g.relayPorts, Relayed: g.relaysSet, InLimitOff: g.inLimitOff,
		Integ: g.integ, IntegPorts: g.integPorts,
	}
	acmePort, acmeUntil := g.acmePort, g.acmeUntil
	acmeFwd := g.acmeFwdUntil
	if u != nil {
		acmeFwd = u.acmeForward
		c.Public, c.Admin, c.AdminPorts, c.Forward = u.public, u.admin, u.adminPorts, u.forward
		c.Relays, c.RelayPorts, c.Relayed = u.relays, u.relayPorts, true
		c.Integ, c.IntegPorts = u.integ, u.integPorts
		acmePort, acmeUntil = 0, time.Time{}
		if w := u.acme; w != nil && w.Port != 0 && w.Until > now.Unix() {
			acmePort, acmeUntil = uint16(w.Port), time.Unix(w.Until, 0)
		}
	}
	if acmePort != 0 && acmeUntil.After(now) {
		c.ACMEPort, c.ACMETTL = acmePort, acmeUntil.Sub(now)
	} else {
		acmePort, acmeUntil = 0, time.Time{}
	}
	if c.ACMEForwardTTL = acmeForwardFor(acmeFwd, now); c.ACMEForwardTTL > 0 {
		acmeFwd = now.Add(c.ACMEForwardTTL)
	} else {
		acmeFwd = time.Time{}
	}
	for key, devs := range g.holders {
		if ttl := longest(devs).Sub(now); ttl > 0 {
			c.Grants = append(c.Grants, Grant{Addr: key.addr, Port: key.port, TTL: wholeSeconds(ttl)})
		}
	}
	if g.verifier != nil {
		c.Rotation, c.SPAUDP, c.SPATCP = g.slotsAt(now)
	}
	if ts, ok := g.fw.(TableSetup); ok {
		if err := ts.SetupWith(c); err != nil {
			return err
		}
	} else if err := g.restoreSteps(c); err != nil {
		return err
	}
	g.public, g.admin, g.adminPorts, g.forward = c.Public, c.Admin, c.AdminPorts, c.Forward
	g.relays, g.relayPorts, g.relaysSet = c.Relays, c.RelayPorts, c.Relayed
	g.integ, g.integPorts = c.Integ, c.IntegPorts
	g.acmePort, g.acmeUntil = acmePort, acmeUntil
	g.acmeFwdUntil = acmeFwd
	g.inLimitTableOff = c.InLimitOff
	g.rotMap, g.udpPorts, g.tcpPorts = nil, nil, nil
	if g.verifier != nil {
		g.rotMap, g.udpPorts, g.tcpPorts = c.Rotation, c.SPAUDP, slices.Clone(c.SPATCP)
	}
	g.revoking, g.regrant = nil, nil // a new table: grants come back at their longest
	g.flushFailures, g.flushRetryAt = 0, time.Time{}
	// Its egress chains are empty: the policy goes in once the restore is
	// done (egressLocked), at once. The guard is off in a new table: it
	// goes back at the next tick (guardLocked).
	g.egressOn, g.egressFailures, g.egressRetryAt = false, 0, time.Time{}
	if g.guard != nil {
		g.guard.applied = false
	}
	g.restoring = false
	g.log.Info("perimeter table restored", "table", Table, "grants", len(c.Grants))
	return nil
}

// TableContents is what a table of the gate holds besides its rules: the
// sets, maps and grants of a snapshot (restoreLocked).
type TableContents struct {
	Public, AdminPorts, Forward, RelayPorts []Port
	Admin, Relays                           []netip.Prefix
	// Integ and IntegPorts: integrations' servers to the API (SetInteg).
	Integ      []netip.Prefix
	IntegPorts []Port
	// Relayed turns relay_check on (SetRelays), with the grants in.
	Relayed    bool
	InLimitOff bool
	ACMEPort   uint16
	ACMETTL    time.Duration
	Grants     []Grant
	Rotation   map[uint16]uint16
	SPAUDP     []uint16
	SPATCP     []uint16
	// ACMEForwardTTL: a relay forwards TCP 80 to its exit so long
	// (SetACMEForward).
	ACMEForwardTTL time.Duration
}

// TableSetup is a firewall that makes the table with its contents in one
// transaction (NFT).
type TableSetup interface {
	SetupWith(c TableContents) error
}

// restoreSteps is restoreLocked for a firewall without SetupWith: one
// call per part, the table first. Until the last is in, restoring stays
// set and the gate is not up.
func (g *Gate) restoreSteps(c TableContents) error {
	if err := g.fw.Setup(); err != nil {
		return err
	}
	if c.InLimitOff {
		if err := g.fw.SetInLimit(false); err != nil {
			return err
		}
	}
	if len(c.Public) > 0 {
		if err := g.fw.SetPublic(c.Public); err != nil {
			return err
		}
	}
	if len(c.Admin) > 0 || len(c.AdminPorts) > 0 {
		if err := g.fw.SetAdmin(c.Admin, c.AdminPorts); err != nil {
			return err
		}
	}
	if len(c.Integ) > 0 || len(c.IntegPorts) > 0 {
		if err := g.fw.SetInteg(c.Integ, c.IntegPorts); err != nil {
			return err
		}
	}
	if len(c.Forward) > 0 {
		if err := g.fw.SetForward(c.Forward); err != nil {
			return err
		}
	}
	if c.ACMEPort != 0 {
		if err := g.fw.SetACME(c.ACMEPort, c.ACMETTL); err != nil {
			return err
		}
	}
	if c.ACMEForwardTTL > 0 {
		if err := g.fw.SetACMEForward(c.ACMEForwardTTL); err != nil {
			return err
		}
	}
	if err := g.fw.SetGrants(c.Grants, nil); err != nil {
		return err
	}
	// Last, with the grants back: relay_check cuts what nothing lets in.
	if c.Relayed {
		if err := g.fw.SetRelays(c.Relays, c.RelayPorts); err != nil {
			return err
		}
	}
	if g.verifier != nil {
		if err := g.fw.SetRotation(c.Rotation); err != nil {
			return err
		}
		if err := g.fw.SetSPAPorts(c.SPAUDP, c.SPATCP); err != nil {
			return err
		}
	}
	return nil
}

// slotsAt are the rotation map and the SPA slot ports at now.
func (g *Gate) slotsAt(now time.Time) (rot map[uint16]uint16, udp, tcp []uint16) {
	rot = map[uint16]uint16{}
	for _, r := range g.rotations {
		for _, p := range r.sched.ActivePorts(now) {
			rot[p] = r.target
		}
	}
	udp = g.params.ActivePorts(now)
	slices.Sort(udp)
	if g.tcpCarrier {
		tcp = slices.Clone(udp)
	}
	return rot, udp, tcp
}

func (g *Gate) slotsLocked() error {
	rot, udp, tcp := g.slotsAt(g.now())
	if !maps.Equal(rot, g.rotMap) {
		if err := g.fw.SetRotation(rot); err != nil {
			return err
		}
		g.rotMap = rot
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
