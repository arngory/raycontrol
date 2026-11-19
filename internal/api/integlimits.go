package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

// callClass is what a method counts against in an integration's rate
// limits (integrations-v1 §2.6): reads, changes, or invites, revocations
// and renewals.
type callClass int

const (
	classRead callClass = iota
	classWrite
	classHeavy
)

// callClasses are the classes of the NodeService methods an integration
// may call, by name (TestCallClasses: each of them has one).
var callClasses = map[string]callClass{
	"GetStatus": classRead, "ListUsers": classRead, "GetUser": classRead, "ListServices": classRead,
	"ListDevices": classRead, "GetMetrics": classRead, "GetUpdateStatus": classRead, "GetStats": classRead,
	"CreateUser": classWrite, "SetUserEnabled": classWrite, "SetUserServices": classWrite, "DeleteUser": classWrite,
	"SetUserTraffic": classWrite, "SetUserExpiry": classWrite,
	"CreateInvite": classHeavy, "RevokeDevice": classHeavy, "RenewUser": classHeavy,
}

// limitRate is a token bucket's: burst calls at once, refilled at perHour.
type limitRate struct {
	Burst   uint32 `json:"burst"`
	PerHour uint32 `json:"per_hour"`
}

// limitSet is the rate limits of an integration's device: one bucket a
// class, and the calls under way at once.
type limitSet struct {
	Read     limitRate `json:"read"`
	Write    limitRate `json:"write"`
	Heavy    limitRate `json:"heavy"`
	Inflight uint32    `json:"inflight"`
}

func (l limitSet) rate(c callClass) limitRate {
	switch c {
	case classWrite:
		return l.Write
	case classHeavy:
		return l.Heavy
	}
	return l.Read
}

// defaultLimits are the roles' limits in code (integrations-v1 §2.6);
// root changes them for a role or a device (integrationSettings).
var defaultLimits = map[string]limitSet{
	"billing": {Read: limitRate{100, 10 * 3600}, Write: limitRate{50, 5 * 3600}, Heavy: limitRate{20, 60}, Inflight: 4},
	"support": {Read: limitRate{20, 2 * 3600}, Inflight: 2},
}

// globalRate bounds the calls of all integrations' devices together, so
// that they do not take rayd's time from its loops: 20 a second, with room
// for the devices' own bursts (a billing's reads and a support's at once).
var globalRate = limitRate{200, 20 * 3600}

// defaultMassLimit is billing's deletions and disables an hour before a
// call needs confirm_mass (integrations-v1 §2.4).
const defaultMassLimit = 50

// settingIntegrations holds integrationSettings as JSON.
const settingIntegrations = "integrations"

// integrationSettings are what root and administrators set for the
// integrations; the zero value is the defaults.
type integrationSettings struct {
	// SupportNotes: support sees users' notes (an administrator's).
	SupportNotes bool `json:"support_notes,omitempty"`
	// MassLimit: billing's mass actions an hour (root's); nil: the default.
	MassLimit *uint32 `json:"mass_limit,omitempty"`
	// Roles and Devices: limits in place of the defaults (root's).
	Roles   map[string]limitSet `json:"roles,omitempty"`
	Devices map[string]limitSet `json:"devices,omitempty"`
}

func (s integrationSettings) limits(device, role string) limitSet {
	if l, ok := s.Devices[device]; ok {
		return l
	}
	if l, ok := s.Roles[role]; ok {
		return l
	}
	return defaultLimits[role]
}

func (s integrationSettings) massLimit() int {
	if s.MassLimit != nil {
		return int(*s.MassLimit)
	}
	return defaultMassLimit
}

// bucket is a token bucket's state.
type bucket struct {
	tokens float64
	at     time.Time
}

// take spends a token of r at now, false when there is none.
func (b *bucket) take(r limitRate, now time.Time) bool {
	if r.Burst == 0 {
		return false
	}
	if b.at.IsZero() {
		b.tokens = float64(r.Burst)
	} else if d := now.Sub(b.at); d > 0 {
		b.tokens = min(float64(r.Burst), b.tokens+d.Hours()*float64(r.PerHour))
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// integDevice is an integration's device as rayd saw it since it started.
type integDevice struct {
	user, name, role string
	buckets          [3]bucket
	inflight         uint32
	last             time.Time
	calls, denied    uint64
	limited          uint64
}

// integrations is the node's state of its integrations: settings, read
// once and kept as set, and in memory only, the calls of each device, the
// rate limits' buckets, billing's mass actions of the last hour, and the
// audit's once-in-a-while lines.
type integrations struct {
	mu       sync.Mutex
	loaded   bool
	settings integrationSettings
	devices  map[string]*integDevice
	global   bucket
	mass     []time.Time // billing's mass actions in the last hour, oldest first
	massDone struct{ done, refused, confirmed uint64 }
	calls    map[[2]string]uint64 // role and code: calls through the remote API
	limited  map[string]uint64    // by role
	quiet    map[quietKey]quietMark
}

// integrationSettings reads the settings once; the setters keep them.
func (s *Server) integrationSettings(ctx context.Context) (integrationSettings, error) {
	in := &s.integ
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.loaded {
		return in.settings, nil
	}
	b, err := s.Store.GetSetting(ctx, settingIntegrations)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return integrationSettings{}, err
	default:
		if err := json.Unmarshal(b, &in.settings); err != nil {
			return integrationSettings{}, fmt.Errorf("the integrations' settings: %w", err)
		}
	}
	in.loaded = true
	return in.settings, nil
}

// changeIntegrationSettings applies change to the settings and stores
// them, as one under the lock.
func (s *Server) changeIntegrationSettings(ctx context.Context, change func(*integrationSettings) error) error {
	if _, err := s.integrationSettings(ctx); err != nil {
		return err
	}
	in := &s.integ
	in.mu.Lock()
	defer in.mu.Unlock()
	next := in.settings
	next.Roles, next.Devices = maps.Clone(in.settings.Roles), maps.Clone(in.settings.Devices)
	if err := change(&next); err != nil {
		return err
	}
	b, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := s.Store.SetSetting(ctx, settingIntegrations, b); err != nil {
		return err
	}
	in.settings = next
	return nil
}

// device is an integration's device's entry, made on first sight.
func (in *integrations) device(d store.Device) *integDevice {
	if in.devices == nil {
		in.devices = map[string]*integDevice{}
	}
	e, ok := in.devices[d.ID]
	if !ok {
		e = &integDevice{user: d.UserName, name: d.Name, role: d.Role}
		in.devices[d.ID] = e
	}
	return e
}

// errLimited answers a call over an integration's rate limits:
// resource_exhausted, nothing done, safe to repeat later.
var errLimited = errors.New("over the rate limit of this device or of all integrations: try again later")

// admit lets an integration's device call method now, or not: its class's
// bucket, then the bucket of all integrations, then the calls under way.
// release ends an admitted call.
func (s *Server) admit(ctx context.Context, d store.Device, method string, now time.Time) (release func(), err error) {
	set, err := s.integrationSettings(ctx)
	if err != nil {
		return nil, err
	}
	l := set.limits(d.ID, d.Role)
	in := &s.integ
	in.mu.Lock()
	defer in.mu.Unlock()
	e := in.device(d)
	e.last = now
	e.calls++
	class := callClasses[method]
	b := &e.buckets[class]
	ok := e.inflight < l.Inflight && b.take(l.rate(class), now)
	if ok && !in.global.take(globalRate, now) {
		b.tokens++ // not this device's: its token back
		ok = false
	}
	if !ok {
		e.limited++
		if in.limited == nil {
			in.limited = map[string]uint64{}
		}
		in.limited[d.Role]++
		return nil, errLimited
	}
	e.inflight++
	return func() {
		in.mu.Lock()
		e.inflight--
		in.mu.Unlock()
	}, nil
}

// refill starts every device's buckets full again: new limits take
// effect from their burst, not from what the old ones left.
func (in *integrations) refill() {
	in.mu.Lock()
	defer in.mu.Unlock()
	for _, e := range in.devices {
		e.buckets = [3]bucket{}
	}
}

// countCall counts a remote call by the caller's role and its answer's
// code (raycontrol_api_calls_total).
func (s *Server) countCall(role, code string) {
	in := &s.integ
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.calls == nil {
		in.calls = map[[2]string]uint64{}
	}
	in.calls[[2]string{role, code}]++
}

// errMassLimit refuses billing a deletion or disable over the hour's
// limit without confirm_mass (integrations-v1 §2.4).
var errMassLimit = fmt.Errorf("%w: over the hourly limit of mass actions: confirm", store.ErrPrecondition)

// massAction counts a deletion or disable by billing against the hour's
// limit, or refuses it (errMassLimit) without confirm over the limit.
// done says whether the action went through: one that did not gives its
// place back. confirmed: it went over the limit with confirm_mass.
func (s *Server) massAction(ctx context.Context, confirm bool, now time.Time) (done func(ok bool), confirmed bool, err error) {
	set, err := s.integrationSettings(ctx)
	if err != nil {
		return nil, false, err
	}
	in := &s.integ
	in.mu.Lock()
	defer in.mu.Unlock()
	hourAgo := now.Add(-time.Hour)
	i := 0
	for i < len(in.mass) && !in.mass[i].After(hourAgo) {
		i++
	}
	in.mass = in.mass[i:]
	if len(in.mass) >= set.massLimit() {
		if !confirm {
			in.massDone.refused++
			return nil, false, errMassLimit
		}
		confirmed = true
	}
	in.mass = append(in.mass, now)
	return func(ok bool) {
		in.mu.Lock()
		defer in.mu.Unlock()
		if !ok {
			if j := slices.Index(in.mass, now); j >= 0 {
				in.mass = slices.Delete(in.mass, j, j+1)
			}
			return
		}
		if confirmed {
			in.massDone.confirmed++
		} else {
			in.massDone.done++
		}
	}, confirmed, nil
}

// quietEvery is how often the audit takes a refusal of one kind for one
// device and method: the first, then one line a period at most with the
// count since the last, so that a broken integration does not fill the
// log (integrations-v1 §2.5).
const quietEvery = 10 * time.Minute

type quietKey struct{ device, action, method string }

type quietMark struct {
	at     time.Time // of the last line
	missed int       // refusals since, not written
}

// auditQuietly writes an integration's refusal (api.denied, api.limited,
// api.mass) to the audit once in quietEvery for its device and method.
func (s *Server) auditQuietly(ctx context.Context, d store.Device, action, method string, now time.Time) {
	in := &s.integ
	k := quietKey{d.ID, action, method}
	in.mu.Lock()
	if in.quiet == nil {
		in.quiet = map[quietKey]quietMark{}
	}
	m, seen := in.quiet[k]
	if seen && now.Sub(m.at) < quietEvery {
		m.missed++
		in.quiet[k] = m
		in.mu.Unlock()
		return
	}
	in.quiet[k] = quietMark{at: now}
	if len(in.quiet) > 4096 {
		for k, m := range in.quiet {
			if now.Sub(m.at) >= quietEvery {
				delete(in.quiet, k)
			}
		}
	}
	if action == "api.denied" {
		in.device(d).denied++
	}
	in.mu.Unlock()
	result := "refused"
	if m.missed > 0 {
		result = fmt.Sprintf("refused; %d more since the last line", m.missed)
	}
	// A refusal stands whether its line is written or not.
	_ = s.Store.Audit(ctx, d.UserName+"/"+d.Name+actorSuffix(d.Role), action, method, result)
}

// methodName is a procedure's method, "/raycontrol.node.v1.NodeService/GetUser" → "GetUser".
func methodName(procedure string) string {
	return procedure[strings.LastIndexByte(procedure, '/')+1:]
}

// integrationMetrics adds the remote API's calls by role and code, the
// integrations' calls over their limits by role, and billing's mass
// actions by result.
func (s *Server) integrationMetrics(m *Metrics) {
	in := &s.integ
	in.mu.Lock()
	defer in.mu.Unlock()
	for _, k := range slices.SortedFunc(maps.Keys(in.calls), func(a, b [2]string) int {
		return strings.Compare(a[0]+" "+a[1], b[0]+" "+b[1])
	}) {
		m.Add("raycontrol_api_calls_total", "Calls through the remote API by the device's role and the answer's code.", float64(in.calls[k]), "role", k[0], "code", k[1])
	}
	for _, role := range []string{"billing", "support"} {
		m.Add("raycontrol_api_limited_total", "Integrations' calls refused over their rate limits.", float64(in.limited[role]), "role", role)
	}
	for _, r := range []struct {
		result string
		n      uint64
	}{{"done", in.massDone.done}, {"refused", in.massDone.refused}, {"confirmed", in.massDone.confirmed}} {
		m.Add("raycontrol_integration_mass_actions_total", "billing's deletions and disables of users: within the hour's limit, refused over it, confirmed over it.", float64(r.n), "result", r.result)
	}
}
