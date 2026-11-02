package perimeter

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/spa"
)

// ErrNotReady is returned before the first snapshot arrives.
var ErrNotReady = errors.New("perimeter: no snapshot yet")

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
	// holders tracks which devices opened an address and port and until
	// when, so that a revocation closes only what nobody else still holds.
	holders  map[grantKey]map[string]time.Time
	udpPorts []uint16
	tcpPorts []uint16
	// ACME window as last applied.
	acmePort  uint16
	acmeUntil time.Time
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
	var rotations []rotation
	for _, s := range snap.Services {
		services[uint16(s.Id)] = portsOf(s.Ports)
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
		admin = append(admin, p)
	}
	adminPorts := portsOf(snap.AdminPorts)

	g.mu.Lock()
	defer g.mu.Unlock()
	sp := snap.Spa
	defTTL, maxTTL := time.Duration(sp.DefaultTtlS)*time.Second, time.Duration(sp.MaxTtlS)*time.Second
	// A new verifier also drops the replay cache, so keep it unless the
	// parameters really changed.
	if g.verifier == nil || params != g.params || defTTL != g.defaultTTL || maxTTL != g.maxTTL {
		g.verifier = spa.NewVerifier(params, defTTL, maxTTL, 100000)
		g.verifier.SetClock(g.now)
	}
	g.verifier.SetDevices(devices)
	g.params, g.tcpCarrier = params, sp.TcpCarrier
	g.defaultTTL, g.maxTTL = defTTL, maxTTL
	g.services, g.allowed, g.rotations = services, allowed, rotations

	if !slices.Equal(public, g.public) {
		if err := g.fw.SetPublic(public); err != nil {
			return err
		}
		g.public = public
	}
	if !slices.Equal(admin, g.admin) || !slices.Equal(adminPorts, g.adminPorts) {
		if err := g.fw.SetAdmin(admin, adminPorts); err != nil {
			return err
		}
		g.admin, g.adminPorts = admin, adminPorts
	}
	g.revokeLocked()
	if err := g.acmeLocked(snap.GetAcme()); err != nil {
		return err
	}
	return g.slotsLocked()
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

// revokeLocked drops holders whose device no longer has the port and closes
// address/port pairs nobody holds any more.
func (g *Gate) revokeLocked() {
	for key, devs := range g.holders {
		for dev := range devs {
			if !slices.Contains(g.portsFor(g.allowed[dev]), key.port) {
				delete(devs, dev)
			}
		}
		if len(devs) == 0 {
			delete(g.holders, key)
			if err := g.fw.Deny(key.addr, []Port{key.port}); err != nil {
				g.log.Warn("closing revoked grant failed", "addr", key.addr, "port", key.port, "err", err)
			} else {
				g.log.Info("revoked", "addr", key.addr, "port", key.port)
			}
		}
	}
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
	if err := g.fw.Allow(src, ports, grant.TTL); err != nil {
		return grant, err
	}
	until := g.now().Add(grant.TTL)
	for _, p := range ports {
		key := grantKey{src.Unmap(), p}
		if g.holders[key] == nil {
			g.holders[key] = map[string]time.Time{}
		}
		g.holders[key][grant.DeviceID] = until
	}
	return grant, nil
}

// Tick restores the table if something removed it, moves the SPA ports to
// the current slots and forgets expired holders (the firewall expires the
// elements itself). It returns the TCP carrier ports that should be
// listening.
func (g *Gate) Tick() ([]uint16, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	present, err := g.fw.Present()
	if err != nil {
		return nil, err
	}
	if !present {
		if err := g.restoreLocked(); err != nil {
			return nil, err
		}
	}
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
	err = g.slotsLocked()
	return slices.Clone(g.tcpPorts), err
}

// restoreLocked re-creates the table with everything the gate had put in
// it, grants included with the time they have left. Until then the node
// was as open as the rest of the ruleset let it be, so this runs on every
// tick.
func (g *Gate) restoreLocked() error {
	if err := g.fw.Setup(); err != nil {
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
	g.rotMap, g.udpPorts, g.tcpPorts = nil, nil, nil
	now := g.now()
	if g.acmePort != 0 && g.acmeUntil.After(now) {
		if err := g.fw.SetACME(g.acmePort, g.acmeUntil.Sub(now)); err != nil {
			return err
		}
	}
	grants := 0
	for key, devs := range g.holders {
		var until time.Time
		for _, u := range devs {
			if u.After(until) {
				until = u
			}
		}
		if ttl := until.Sub(now); ttl > 0 {
			if err := g.fw.Allow(key.addr, []Port{key.port}, ttl); err != nil {
				return err
			}
			grants++
		}
	}
	g.log.Warn("nftables table was removed (flush ruleset? nftables or firewalld reload?), restored", "table", Table, "grants", grants)
	if g.verifier == nil {
		return nil
	}
	return g.slotsLocked()
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
