// Package api serves the node API (api/proto/raycontrol/node/v1).
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/appmirror"
	"github.com/arngory/raycontrol/internal/connlimit"
	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/dnscheck"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/memlimit"
	"github.com/arngory/raycontrol/internal/naive"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/stats"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
)

// Server implements NodeService on top of the store.
type Server struct {
	Store   *store.Store
	Params  spa.Params
	Version string
	// Paths and Binaries describe the installed node for GetDeployment.
	Paths    render.Paths
	Binaries deploy.Binaries
	// OnChange, if set, runs after every successful change (tests).
	OnChange func()
	// CheckRealityTarget, if set, vets the target of a new REALITY service
	// (provision.CheckRealityTarget; tests leave it nil).
	CheckRealityTarget func(ctx context.Context, target, sni string) error
	// RealityLead is how long before a requested REALITY switch the next
	// keys are published; Rotate, if set, runs the rotation at once.
	RealityLead time.Duration
	Rotate      func()
	// NaivePeriod is rayd -naive-sni-period: how long a naive service's
	// previous names stay routed after their switch (0: the default,
	// provision.NaivePrevious).
	NaivePeriod time.Duration
	// CredGrace is how long a previous dnstt seal key stays accepted after
	// the operator switched it (rayd -cred-grace); zero: not at all.
	CredGrace time.Duration
	// SiteKeyLead is how long a site's next certificate key must have been
	// in subscriptions before the operator's switch to it (rayd
	// -site-key-lead, spec/cert-pin-v1.md §5). Certificates says rayd
	// issues the sites' certificates (ACME on): the switch is an issuance,
	// and without it nothing would make it.
	SiteKeyLead  time.Duration
	Certificates bool
	// DNSChanged runs after the operator changed the DNS provider or its
	// records: the certificates are tried again (certs.Manager.Retry).
	DNSChanged func()
	// SiteKeyAsked runs after a site's switch was asked, again too
	// (certs.Manager.RetrySite): the same request again gets a try
	// RetryGap after its last failed one, not after the back-off.
	SiteKeyAsked func(name string)
	// Health is where rayd's loops report (O-2): status and metrics.
	Health *health.Board
	// DNSCheck checks the DNS tunnel zones from the node (CheckDNSZones);
	// nil: the call is unavailable.
	DNSCheck *dnscheck.Monitor
	// RelayNameStatus says whether clients may be given a relay's name,
	// and if not why (spec/relay-names-v1.md §4, §5: rayd's check), for
	// ListRelays; nil: none is ready, none checked.
	RelayNameStatus func(name string) (ready bool, problem string)
	// AppMirror keeps the client's releases (spec/app-update-v1.md); nil:
	// the setting alone (tests).
	AppMirror *appmirror.Mirror
	// NodeUpdate is the update by request (spec/node-update-v1.md); nil:
	// the node's paths.
	NodeUpdate *NodeUpdate
	// ConnLimit keeps the refusals, the table and the guard
	// (spec/conn-limit-v1.md §7); nil shows nothing of them.
	ConnLimit *connlimit.Monitor
	// NaiveUDP reads a naive service's datagram requests from its stats
	// socket (traffic.ReadLine, spec/naive-udp-v1.md §7) for the metrics:
	// nil without udp=on, or an error when it cannot be read. nil: the
	// metrics show none.
	NaiveUDP func(ctx context.Context, service string) (*naive.UDPStats, error)
	// NaiveMemory reads a naive service's TCP tunnels' memory from its
	// stats socket (traffic.ReadLine, spec/memory-v1.md §5) for the
	// metrics: nil from a naive too old to give it. nil: the metrics show
	// none.
	NaiveMemory func(ctx context.Context, service string) (*naive.MemoryStats, error)
	// SubRequests counts the subscription's answers (sub.Server.Requests);
	// nil: the metrics show none.
	SubRequests *sub.Requests
	// LocalAddrs are the node's own addresses, which no integration's list
	// may hold (integrations-v1 §3.3); nil: the host's interfaces.
	LocalAddrs func() ([]netip.Addr, error)
	// Stats keeps the samples rayctl stats reports (spec/stats-v1.md);
	// nil: GetStats is unavailable. Started is when rayd started.
	Stats   *stats.Sampler
	Started time.Time

	// Wrong invite PINs, and the invites the last of them withdrew, since
	// rayd started (rayctl metrics).
	pinWrong, pinWithdrawn atomic.Uint64

	// sshMu holds lastSSH's check and the write it allows as one: two
	// calls that each take out one of the last two ssh services would
	// both pass the check otherwise. Every change of the services goes
	// through this server.
	sshMu sync.Mutex

	// The node's own addresses (spa-v3 §4), for the perimeter's snapshot
	// and for the SPA versions the node offers.
	own ownAddrs

	mu    sync.Mutex
	rev   uint64
	wake  chan struct{} // closed on the next change
	after []func()      // AfterChange
	// ACME window (certs.Issuer): rayspa points TCP 80 to acmePort; the
	// order's names, for the relays whose names are among them
	// (relay-names-v1 §6).
	acmePort  uint16
	acmeUntil time.Time
	acmeNames []string
	// relayACME: what each relay's rayspa said of TCP 80 for the ACME
	// windows when its feed opened (relay-names-v1 §6), the last word kept
	// after the feed closed, and its feeds open now that said yes. Under
	// mu.
	relayACME map[string]relayACMEState

	// The relays' updates by the node's word (relayupdate.go).
	relayUpd relayUpdates

	// The integrations' settings, rate limits and calls (limits.go).
	integ integrations
}

// SetACMEWindow opens the perimeter window for an ACME order of names to
// port until the given time, or closes it when until is zero. A relay
// with one of its names among them forwards TCP 80 to the node meanwhile
// (RelaySnapshot).
func (s *Server) SetACMEWindow(port uint16, until time.Time, names []string) {
	s.mu.Lock()
	s.acmePort, s.acmeUntil, s.acmeNames = port, until, slices.Clone(names)
	if until.IsZero() {
		s.acmeNames = nil
	}
	s.mu.Unlock()
	s.notify()
}

// acmeOrder is the window's deadline and the names of its order, while
// one is open.
func (s *Server) acmeOrder(now time.Time) (time.Time, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.acmePort == 0 || !s.acmeUntil.After(now) {
		return time.Time{}, nil
	}
	return s.acmeUntil, slices.Clone(s.acmeNames)
}

// relayACMEState is what a relay's rayspa said of TCP 80 (relayACME).
type relayACMEState struct {
	said bool // at its last feed's opening; an older rayspa says nothing: false
	open int  // its feeds open now that said yes
}

// relayACMEFeed records what a relay's rayspa said of TCP 80 for the ACME
// windows as its feed opened, the feed open until done. Its names go into
// an order only while such a feed is open: through a relay whose feed is
// gone the window would not reach it, and the CA's challenges would not
// reach the node. A change is news: the certificates may order the
// relay's names now, or no more.
func (s *Server) relayACMEFeed(name string, said bool) (done func()) {
	s.setRelayACME(name, func(st *relayACMEState) {
		st.said = said
		if said {
			st.open++
		}
	})
	return func() {
		if said {
			s.setRelayACME(name, func(st *relayACMEState) { st.open-- })
		}
	}
}

func (s *Server) setRelayACME(name string, change func(*relayACMEState)) {
	s.mu.Lock()
	if s.relayACME == nil {
		s.relayACME = map[string]relayACMEState{}
	}
	was := s.relayACME[name]
	st := was
	change(&st)
	s.relayACME[name] = st
	s.mu.Unlock()
	if st.said != was.said || st.forwards() != was.forwards() {
		s.notify()
	}
}

// forwards: a feed that said yes is open, and the last word is yes. A
// rayspa put back to an older one says nothing while the newer one's feed
// still ends: from its word on, none forwards.
func (st relayACMEState) forwards() bool { return st.said && st.open > 0 }

// RelayACMEForward reports what a relay's rayspa said of TCP 80 for the
// ACME windows when its last feed opened since this node started (said),
// and whether it forwards it now (open): a feed of it that said yes is
// open and the last word is yes (relay-names-v1 §6).
func (s *Server) RelayACMEForward(name string) (said, open bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.relayACME[name]
	return st.said, st.forwards()
}

func (s *Server) acmeWindow() (uint16, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acmePort, s.acmeUntil
}

// notify records a change and wakes the perimeter watchers.
// Notify records a change made outside the API (a stored certificate).
func (s *Server) Notify() { s.notify() }

func (s *Server) notify() {
	s.mu.Lock()
	s.rev++
	if s.wake != nil {
		close(s.wake)
		s.wake = nil
	}
	after := s.after
	s.mu.Unlock()
	for _, f := range after {
		f()
	}
	if s.OnChange != nil {
		s.OnChange()
	}
}

// AfterChange adds f to what runs at every change, in the call that made
// it, before that call returns: rayd's DoH Forget, so that once
// RevokeDevice has answered, the revoked device's token is refused from
// the next query (R4-37). What watches Changes (the data plane's apply)
// runs in the background as before. f must not block.
func (s *Server) AfterChange(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.after = append(s.after, f)
}

// Changes returns a channel closed at the next change.
func (s *Server) Changes() <-chan struct{} {
	_, c := s.changes()
	return c
}

// changes returns the current revision and a channel closed at the next change.
func (s *Server) changes() (uint64, <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wake == nil {
		s.wake = make(chan struct{})
	}
	return s.rev, s.wake
}

var _ nodev1connect.NodeServiceHandler = (*Server)(nil)

// Handler returns the HTTP handler for the service.
func (s *Server) Handler(policy PeerPolicy) (string, http.Handler) {
	return nodev1connect.NewNodeServiceHandler(s, connect.WithInterceptors(policy.interceptor()), readLimit())
}

// ServeUnix serves the API on a unix socket until ctx ends. Every local user
// may connect; PeerPolicy (peer credentials) decides who may call what.
// Extra handlers (e.g. the perimeter feed) are mounted next to NodeService
// and do their own caller checks.
func (s *Server) ServeUnix(ctx context.Context, path string, policy PeerPolicy, extra ...func() (string, http.Handler)) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // G301: peers are checked by credentials
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	//nolint:gosec // G302: access is decided by peer credentials, not by the file mode.
	if err := os.Chmod(path, 0o666); err != nil {
		ln.Close()
		return err
	}

	mux := http.NewServeMux()
	mux.Handle(s.Handler(policy))
	for _, h := range extra {
		mux.Handle(h())
	}
	srv := &http.Server{Handler: mux, ConnContext: connContext, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		// ctx is done: the shutdown has its own time.
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// toConnect maps store errors to API codes.
func toConnect(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, errForRole):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, store.ErrInvalid):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, store.ErrPrecondition):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case strings.Contains(err.Error(), "UNIQUE constraint failed"):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case strings.Contains(err.Error(), "FOREIGN KEY constraint failed"):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	}
	return connect.NewError(connect.CodeInternal, err)
}

// done audits a mutating call and notifies the perimeter when the store
// call succeeded, whatever the audit write did: the change is made, and
// what follows it (DoH's Forget, the data plane's apply) must run, or a
// revoked device's token works until the cache expires. The caller still
// gets the audit's error.
func (s *Server) done(ctx context.Context, action, target string, err error) error {
	result := "ok"
	if err != nil {
		result = "error: " + err.Error()
	}
	changed := err == nil
	// An integration's failed call: once in a while (integrations-v1
	// §2.5), so that a broken one does not fill the log.
	if d, ok := caller(ctx); ok && err != nil && store.IntegrationRole(d.Role) {
		s.auditQuietly(ctx, d, action, target, result, time.Now())
		return toConnect(err)
	}
	if aerr := s.Store.Audit(ctx, actorFrom(ctx), action, target, result); aerr != nil && err == nil {
		err = aerr
	}
	if changed {
		s.notify()
	}
	return toConnect(err)
}

// unixOf is t in Unix seconds, 0 for the zero time.
func unixOf(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func unixOrZero(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return t.Unix()
}

func (s *Server) GetStatus(ctx context.Context, _ *connect.Request[nodev1.GetStatusRequest]) (*connect.Response[nodev1.GetStatusResponse], error) {
	// The counts are the node's, whoever asks: numbers only.
	integration := store.IntegrationRole(callerRole(ctx))
	ctx = store.AllUsers(ctx)
	users, err := s.Store.ListUsers(ctx)
	if err != nil {
		return nil, toConnect(err)
	}
	services, err := s.Store.ListServices(ctx)
	if err != nil {
		return nil, toConnect(err)
	}
	devices, err := s.Store.SPADevices(ctx)
	if err != nil {
		return nil, toConnect(err)
	}
	host, err := node.Host(ctx, s.Store)
	if err != nil {
		return nil, toConnect(err)
	}
	name, err := node.Name(ctx, s.Store)
	if err != nil {
		return nil, toConnect(err)
	}
	note, err := node.Note(ctx, s.Store)
	if err != nil {
		return nil, toConnect(err)
	}
	resp := &nodev1.GetStatusResponse{
		Version:       s.Version,
		NodeId:        hex.EncodeToString(s.Params.NodeID[:]),
		Host:          host,
		Name:          name,
		Note:          note,
		Users:         uint32(len(users)),
		Services:      uint32(len(services)),
		ActiveDevices: uint32(len(devices)),
		DebugUntil:    unixOf(debugUntil(ctx, s.Store)),
	}
	for _, p := range s.Params.ActivePorts(time.Now()) {
		resp.SpaPorts = append(resp.SpaPorts, uint32(p))
	}
	for _, l := range s.Health.Loops() {
		// A loop's name may carry a site's or a zone's ("acme <site>",
		// "dns-zone <service> <zone>"): an integration gets its kind.
		if integration {
			l.Name, _, _ = strings.Cut(l.Name, " ")
		}
		resp.Loops = append(resp.Loops, &nodev1.LoopHealth{Name: l.Name, LastOk: unixOf(l.LastOK), LastError: unixOf(l.LastErr),
			Error: l.Err, Runs: l.Runs, Errors: l.Errors, Failing: l.Failing(), Detail: l.Detail})
	}
	// The egress policy, as GetEgress: on the node's socket only.
	if isLocal(ctx) {
		e, err := s.Store.Egress(ctx)
		if err != nil {
			return nil, toConnect(err)
		}
		resp.Egress = egressPB(e)
	}
	if !integration {
		resp.Warnings = brutalWarnings(services, render.HostLink)
		// A policy that does not read leaves the zones unchecked, not the
		// status unanswered.
		if policy, err := node.ClientPolicy(ctx, s.Store); err == nil {
			resp.Warnings = append(resp.Warnings, provision.ZoneWarnings(services, policy, time.Now())...)
		}
		if names, err := provision.RelayNames(ctx, s.Store); err == nil {
			resp.Warnings = append(resp.Warnings, provision.RelayNameWarnings(names)...)
		}
		if render.SalamanderDevice() {
			if devices, err := s.Store.SPADevices(ctx); err == nil {
				resp.Warnings = append(resp.Warnings, salamanderListWarnings(services, devices)...)
			}
		}
	}
	return connect.NewResponse(resp), nil
}

// salamanderListMax is the most lines the front takes in a hy2-obfs
// service's list of passwords (niko-server's): past it the front keeps the
// list it had, revocations included in nothing (salamander-device-v1 §4.2).
const salamanderListMax = 65536

// salamanderListWarnings are the hy2-obfs services whose list of the
// devices' passwords could pass salamanderListMax: a line a device allowed
// on the service for each S the service takes, up to three in a rotation
// (current, next, previous), and S itself in the shared window. Warned from
// nine tenths of the most, before a rotation would take it past.
func salamanderListWarnings(services []store.Service, devices []spa.Device) []string {
	var out []string
	for _, svc := range services {
		if svc.Kind != "hy2-obfs" || !svc.Enabled {
			continue
		}
		n := 0
		for _, d := range devices {
			if slices.Contains(d.Allowed, uint16(svc.ID)) { //nolint:gosec // G115: service IDs fit (CHECK)
				n++
			}
		}
		if lines := 3*n + 2; lines > salamanderListMax*9/10 {
			out = append(out, fmt.Sprintf("service %s (hy2-obfs): %d devices, up to %d lines in the front's list of salamander passwords in a rotation; past %d the front keeps its old list and revocations stop reaching it (salamander-device-v1 §4.2): spread the users over another hy2-obfs service",
				svc.Name, n, lines, salamanderListMax))
		}
	}
	return out
}

// brutalWarnings are the enabled Hysteria2 services whose Brutal has no
// ceiling of the operator's (render.BrutalCeiling, protocol review
// 2026-11, M1): the speed of the node's link taken in its place, or none,
// the speed unknown or too low to trust (an emulated NIC tells its own
// whatever the channel). The server sends each client as fast as the
// client asks. link is asked only when some service has no up_mbps of its
// own.
func brutalWarnings(services []store.Service, link func() (int, string)) []string {
	var out []string
	mbps, iface, asked := 0, "", false
	for _, svc := range services {
		if !svc.Enabled || (svc.Kind != "hy2-masq" && svc.Kind != "hy2-obfs") {
			continue
		}
		if _, from := render.BrutalCeiling(svc.Settings, 0); from == "" && !asked {
			mbps, iface = link()
			asked = true
		}
		up, from := render.BrutalCeiling(svc.Settings, mbps)
		set := fmt.Sprintf("rayctl service set %s up_mbps=N, N the channel's Mbit/s (0: no ceiling)", svc.Name)
		switch from {
		case "up_mbps":
			continue
		case "link":
			// Taken, and said: the port's speed is no channel's, and the
			// operator alone knows the channel (second review).
			out = append(out, fmt.Sprintf("%s %s: Brutal up to %d Mbit/s, the speed %s tells, which may be more than the channel; %s",
				svc.Kind, svc.Name, up, iface, set))
			continue
		}
		if mbps > 0 {
			out = append(out, fmt.Sprintf("%s %s: Brutal has no ceiling: %s tells %d Mbit/s, which an emulated NIC tells whatever the channel, so it is not taken; %s",
				svc.Kind, svc.Name, iface, mbps, set))
			continue
		}
		out = append(out, fmt.Sprintf("%s %s: Brutal has no ceiling, the speed of the node's link unknown: it sends each client as fast as the client asks; %s",
			svc.Kind, svc.Name, set))
	}
	return out
}

// serviceIDs resolves service names to IDs, each once: a name given twice
// would otherwise fail the one write as "already exists", which a retry
// takes for "the first try worked".
// serviceIDs are the IDs of the services named; billing names data
// services only (dataKinds, integrations-v1 §2.2).
func (s *Server) serviceIDs(ctx context.Context, names []string) (ids []int64, enabled int, err error) {
	ids = make([]int64, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		svc, err := s.Store.ServiceByName(ctx, n)
		if err != nil {
			return nil, 0, err
		}
		if callerRole(ctx) == "billing" && !dataKinds[svc.Kind] {
			return nil, 0, fmt.Errorf("%w: service %q is not a data service", errForRole, n)
		}
		ids = append(ids, svc.ID)
		if svc.Enabled {
			enabled++
		}
	}
	return ids, enabled, nil
}

func (s *Server) userPB(ctx context.Context, u store.User) (*nodev1.User, error) {
	all, err := s.Store.ListServices(ctx)
	if err != nil {
		return nil, err
	}
	pb := &nodev1.User{
		Id: u.ID, Name: u.Name, Enabled: u.Enabled, ExpiresAt: unixOrZero(u.ExpiresAt),
		Note: u.Note, CreatedAt: u.CreatedAt.Unix(), Lan: u.LAN,
	}
	if u.TrafficLimit != nil {
		// The count at this moment: a period that reset since rayd last
		// wrote reads as zero (traffic-limit-v1 §3.6).
		now := time.Now()
		pb.TrafficLimitBytes = *u.TrafficLimit
		pb.TrafficUsedBytes = u.Used(now)
		pb.TrafficPeriodStart = unixOf(u.PeriodStart(now))
		pb.TrafficPeriod = u.TrafficPeriod
		pb.TrafficResetDay = int32(u.TrafficResetDay) //nolint:gosec // G115: 1..28
		pb.TrafficNextReset = unixOf(u.NextResetAt(now))
		pb.TrafficExhausted = u.Live(now) && u.OverLimit(now) // as the subscription: disabled and expired are not "exhausted"
	}
	for _, id := range u.Services {
		for _, svc := range all {
			if svc.ID == id {
				pb.Services = append(pb.Services, svc.Name)
			}
		}
	}
	return pb, nil
}

func (s *Server) ListUsers(ctx context.Context, _ *connect.Request[nodev1.ListUsersRequest]) (*connect.Response[nodev1.ListUsersResponse], error) {
	users, err := s.Store.ListUsers(ctx)
	if err != nil {
		return nil, toConnect(err)
	}
	resp := &nodev1.ListUsersResponse{}
	for _, u := range users {
		pb, err := s.userPB(ctx, u)
		if err != nil {
			return nil, toConnect(err)
		}
		resp.Users = append(resp.Users, pb)
	}
	return connect.NewResponse(resp), nil
}

func (s *Server) CreateUser(ctx context.Context, req *connect.Request[nodev1.CreateUserRequest]) (*connect.Response[nodev1.CreateUserResponse], error) {
	m := req.Msg
	u := store.User{Name: m.Name, Enabled: true, Note: m.Note, TrafficPeriod: m.TrafficPeriod, TrafficResetDay: int(m.TrafficResetDay)}
	if m.ExpiresAt != 0 {
		t := time.Unix(m.ExpiresAt, 0)
		u.ExpiresAt = &t
	}
	if m.TrafficLimitBytes != 0 {
		u.TrafficLimit = &m.TrafficLimitBytes
	}
	// The period's text is the admin's: checked before it can reach any
	// error, and so the audit (as SetUserTraffic).
	if m.TrafficPeriod != "" && store.CheckTrafficPeriod(m.TrafficPeriod, 1) != nil {
		return nil, s.done(ctx, "user.create", m.Name, fmt.Errorf("%w traffic period: use monthly or none", store.ErrInvalid))
	}
	ids, _, err := s.serviceIDs(ctx, m.Services)
	if err == nil {
		// One write: a user without the services asked for would make
		// the retry "already exists".
		u.Services = ids
		u, err = s.Store.CreateUser(ctx, u)
	}
	if err := s.done(ctx, "user.create", m.Name, err); err != nil {
		return nil, err
	}
	pb, err := s.userPB(ctx, u)
	if err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&nodev1.CreateUserResponse{User: pb}), nil
}

func (s *Server) SetUserEnabled(ctx context.Context, req *connect.Request[nodev1.SetUserEnabledRequest]) (*connect.Response[nodev1.SetUserEnabledResponse], error) {
	action := "user.enable=" + strconv.FormatBool(req.Msg.Enabled)
	done, suffix := func(bool) {}, ""
	var err error
	if !req.Msg.Enabled {
		// billing's disables are mass actions (integrations-v1 §2.4).
		if done, suffix, err = s.massGuard(ctx, "SetUserEnabled", req.Msg.ConfirmMass); err != nil {
			return nil, toConnect(err)
		}
	}
	err = s.Store.SetUserEnabled(ctx, req.Msg.Name, req.Msg.Enabled)
	done(err == nil)
	if err := s.done(ctx, action+suffix, req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetUserEnabledResponse{}), nil
}

func (s *Server) SetUserServices(ctx context.Context, req *connect.Request[nodev1.SetUserServicesRequest]) (*connect.Response[nodev1.SetUserServicesResponse], error) {
	done, suffix := func(bool) {}, ""
	ids, enabled, err := s.serviceIDs(ctx, req.Msg.Services)
	if err == nil && enabled == 0 {
		// billing's list without an enabled service is a disable by
		// another name (integrations-v1 §2.4); checked after the names,
		// so that a call refused anyway is not counted.
		if done, suffix, err = s.massGuard(ctx, "SetUserServices", req.Msg.ConfirmMass); err != nil {
			return nil, toConnect(err)
		}
	}
	if err == nil {
		err = s.Store.SetUserServices(ctx, req.Msg.Name, ids)
	}
	done(err == nil)
	if err := s.done(ctx, "user.services="+strings.Join(req.Msg.Services, ",")+suffix, req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetUserServicesResponse{}), nil
}

// SetUserTraffic changes a user's traffic limit, its period or reset day,
// or zeroes the count (traffic-limit-v1 §3.6), audited as user.traffic
// with what was asked.
func (s *Server) SetUserTraffic(ctx context.Context, req *connect.Request[nodev1.SetUserTrafficRequest]) (*connect.Response[nodev1.SetUserTrafficResponse], error) {
	m := req.Msg
	var c store.TrafficChange
	var asked []string
	if m.LimitBytes != nil {
		c.Limit = m.LimitBytes
		asked = append(asked, "limit="+strconv.FormatInt(*m.LimitBytes, 10))
	}
	if m.Period != nil {
		c.Period = m.Period
		asked = append(asked, "period="+*m.Period)
	}
	if m.ResetDay != nil {
		day := int(*m.ResetDay)
		c.ResetDay = &day
		asked = append(asked, "reset-day="+strconv.Itoa(day))
	}
	if m.ResetUsage {
		c.ResetUsage = true
		asked = append(asked, "reset-usage")
	}
	// What was asked goes to the audit as text the node checked: a period
	// that is not one is refused before, and its words never logged.
	if m.Period != nil && store.CheckTrafficPeriod(*m.Period, 1) != nil {
		return nil, s.done(ctx, "user.traffic", m.Name, fmt.Errorf("%w traffic period: use monthly or none", store.ErrInvalid))
	}
	done, suffix := func(bool) {}, ""
	if cuts, err := s.limitCutsOff(ctx, m); err != nil {
		return nil, s.done(ctx, "user.traffic", m.Name, err)
	} else if cuts {
		if done, suffix, err = s.massGuard(ctx, "SetUserTraffic", m.ConfirmMass); err != nil {
			return nil, toConnect(err)
		}
	}
	u, err := s.Store.SetUserTraffic(ctx, m.Name, c)
	done(err == nil)
	if err := s.done(ctx, "user.traffic "+strings.Join(asked, " ")+suffix, m.Name, err); err != nil {
		return nil, err
	}
	pb, err := s.userPB(ctx, u)
	if err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&nodev1.SetUserTrafficResponse{User: pb}), nil
}

// SetUserLAN gives or takes back the administrator's consent to a user's
// LAN (lan-v1 §1.1), audited as user.lan=on|off (lan-v1 §4.3).
func (s *Server) SetUserLAN(ctx context.Context, req *connect.Request[nodev1.SetUserLANRequest]) (*connect.Response[nodev1.SetUserLANResponse], error) {
	u, err := s.Store.SetUserLAN(ctx, req.Msg.Name, req.Msg.Lan)
	state := "off"
	if req.Msg.Lan {
		state = "on"
	}
	if err := s.done(ctx, "user.lan="+state, req.Msg.Name, err); err != nil {
		return nil, err
	}
	pb, err := s.userPB(ctx, u)
	if err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&nodev1.SetUserLANResponse{User: pb}), nil
}

func (s *Server) DeleteUser(ctx context.Context, req *connect.Request[nodev1.DeleteUserRequest]) (*connect.Response[nodev1.DeleteUserResponse], error) {
	// billing's deletions are mass actions (integrations-v1 §2.4).
	done, suffix, err := s.massGuard(ctx, "DeleteUser", req.Msg.ConfirmMass)
	if err != nil {
		return nil, toConnect(err)
	}
	err = s.Store.DeleteUser(ctx, req.Msg.Name)
	done(err == nil)
	if err := s.done(ctx, "user.delete"+suffix, req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.DeleteUserResponse{}), nil
}

// ExportUser returns the links of a user's subscription (P-10). They hold
// credentials, so every call is audited, failed ones too; nothing changes.
func (s *Server) ExportUser(ctx context.Context, req *connect.Request[nodev1.ExportUserRequest]) (*connect.Response[nodev1.ExportUserResponse], error) {
	name := req.Msg.Name
	profiles, err := s.export(ctx, name)
	result := "ok"
	if err != nil {
		result = "error: " + err.Error()
	}
	if aerr := s.Store.Audit(ctx, actorFrom(ctx), "user.export", name, result); aerr != nil && err == nil {
		err = aerr
	}
	if err != nil {
		if errors.Is(err, errUserInactive) {
			return nil, connect.NewError(connect.CodeFailedPrecondition, err)
		}
		return nil, toConnect(err)
	}
	resp := &nodev1.ExportUserResponse{}
	for _, p := range profiles {
		pb := &nodev1.Profile{ServiceId: uint32(p.Svc), Service: p.Name, Link: p.Link}
		if p.Next != nil {
			pb.NextLink, pb.NextFrom = p.Next.Link, p.Next.From
		}
		resp.Profiles = append(resp.Profiles, pb)
	}
	return connect.NewResponse(resp), nil
}

// RenewUser gives a user new credentials at once (R4-36). The audit says
// how many, never what they are.
func (s *Server) RenewUser(ctx context.Context, req *connect.Request[nodev1.RenewUserRequest]) (*connect.Response[nodev1.RenewUserResponse], error) {
	n, err := s.Store.RenewUser(ctx, req.Msg.Name)
	target := req.Msg.Name
	if err == nil {
		target += fmt.Sprintf(": %d credentials new", n)
	}
	if err := s.done(ctx, "user.renew", target, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.RenewUserResponse{Name: req.Msg.Name, Credentials: uint32(n)}), nil //nolint:gosec // G115: one a service
}

var errUserInactive = errors.New("user is disabled, expired or over the traffic limit")

func (s *Server) export(ctx context.Context, name string) ([]sub.Profile, error) {
	if _, err := s.Store.UserByName(ctx, name); err != nil {
		return nil, err
	}
	m, err := render.Collect(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	for _, u := range m.Users {
		if u.Name == name {
			return sub.Profiles(m, u)
		}
	}
	return nil, errUserInactive
}

func servicePB(svc store.Service) *nodev1.Service {
	// The published switch only: naive's next name is chosen, and served,
	// an epoch ahead (R4-42), REALITY's waits for its certificate before.
	// Not in the settings either (provision.ShownSettings).
	pb := &nodev1.Service{Id: uint32(svc.ID), Kind: svc.Kind, Name: svc.Name, Enabled: svc.Enabled,
		SettingsJson: provision.ShownSettings(svc), CreatedAt: svc.CreatedAt.Unix(), Uid: uint32(svc.UID), Sni: provision.SiteName(svc)}
	switch svc.Kind {
	case "reality":
		if st := provision.ParseRealityState(svc); st.NextFrom != 0 {
			pb.NextFrom, pb.SniNext = st.NextFrom, st.SNINext
		}
	case "naive":
		if st := provision.ParseNaiveState(svc); st.NextFrom != 0 {
			pb.NextFrom, pb.SniNext = st.NextFrom, st.SNINext
		}
	}
	return pb
}

func (s *Server) ListServices(ctx context.Context, _ *connect.Request[nodev1.ListServicesRequest]) (*connect.Response[nodev1.ListServicesResponse], error) {
	services, err := s.Store.ListServices(ctx)
	if err != nil {
		return nil, toConnect(err)
	}
	resp := &nodev1.ListServicesResponse{Kinds: store.ServiceKinds}
	for _, svc := range services {
		resp.Services = append(resp.Services, servicePB(svc))
	}
	return connect.NewResponse(resp), nil
}

func (s *Server) CreateService(ctx context.Context, req *connect.Request[nodev1.CreateServiceRequest]) (*connect.Response[nodev1.CreateServiceResponse], error) {
	if req.Msg.Kind == "reality" && s.CheckRealityTarget != nil && strings.Contains(req.Msg.SettingsJson, `"target"`) {
		// A foreign target is checked from the node; the own site is not up yet.
		target, sni, err := provision.RealityTargetFromJSON(req.Msg.SettingsJson)
		if err == nil {
			err = s.CheckRealityTarget(ctx, target, sni)
		}
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}
	svc, err := provision.CreateService(ctx, s.Store, store.Service{Kind: req.Msg.Kind, Name: req.Msg.Name, Enabled: true, Settings: req.Msg.SettingsJson})
	if err := s.done(ctx, "service.create:"+req.Msg.Kind, req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.CreateServiceResponse{Service: servicePB(svc)}), nil
}

func (s *Server) SetServiceEnabled(ctx context.Context, req *connect.Request[nodev1.SetServiceEnabledRequest]) (*connect.Response[nodev1.SetServiceEnabledResponse], error) {
	var err error
	if req.Msg.Enabled {
		err = provision.CheckRequirements(ctx, s.Store, req.Msg.Name)
	} else {
		s.sshMu.Lock()
		defer s.sshMu.Unlock()
		err = provision.CheckNoDependents(ctx, s.Store, req.Msg.Name)
		if err == nil {
			err = lastSSH(ctx, s.Store, req.Msg.Name, "disable", req.Msg.Force)
		}
	}
	if err == nil {
		err = s.Store.SetServiceEnabled(ctx, req.Msg.Name, req.Msg.Enabled)
	}
	action := "service.enable=" + strconv.FormatBool(req.Msg.Enabled)
	if req.Msg.Force {
		action += " force"
	}
	if err := s.done(ctx, action, req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetServiceEnabledResponse{}), nil
}

func (s *Server) DeleteService(ctx context.Context, req *connect.Request[nodev1.DeleteServiceRequest]) (*connect.Response[nodev1.DeleteServiceResponse], error) {
	s.sshMu.Lock()
	defer s.sshMu.Unlock()
	err := provision.CheckNoDependents(ctx, s.Store, req.Msg.Name)
	if err == nil {
		err = lastSSH(ctx, s.Store, req.Msg.Name, "delete", req.Msg.Force)
	}
	if err == nil {
		err = s.Store.DeleteService(ctx, req.Msg.Name)
	}
	action := "service.delete"
	if req.Msg.Force {
		action += " force"
	}
	if err := s.done(ctx, action, req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.DeleteServiceResponse{}), nil
}

func (s *Server) SetServiceOption(ctx context.Context, req *connect.Request[nodev1.SetServiceOptionRequest]) (*connect.Response[nodev1.SetServiceOptionResponse], error) {
	if req.Msg.Key == "target" && s.CheckRealityTarget != nil {
		// A REALITY service's new target, checked from the node as a new
		// service's is, with its server name (which stays). One that
		// steals from the node's site takes none (provision says why).
		if svc, err := s.Store.ServiceByName(ctx, req.Msg.Name); err == nil && svc.Kind == "reality" {
			if old, sni, err := provision.RealityTargetFromJSON(svc.Settings); err == nil && !strings.HasPrefix(old, "site:") {
				if err := s.CheckRealityTarget(ctx, req.Msg.Value, sni); err != nil {
					return nil, connect.NewError(connect.CodeInvalidArgument, err)
				}
			}
		}
	}
	svc, err := provision.SetServiceOption(ctx, s.Store, req.Msg.Name, req.Msg.Key, req.Msg.Value)
	if err := s.done(ctx, "service.set "+req.Msg.Key+"="+req.Msg.Value, req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetServiceOptionResponse{Service: servicePB(svc)}), nil
}

// SetCertificate puts the operator's certificate on a site: root on the
// node only, as Backup. The request carries a private key, and the call
// replaces the key the clients pin and takes the pins off the lines
// (spec/cert-pin-v1.md §7): a member of the API group must not do what
// rotateSiteKey keeps to root.
func (s *Server) SetCertificate(ctx context.Context, req *connect.Request[nodev1.SetCertificateRequest]) (*connect.Response[nodev1.SetCertificateResponse], error) {
	if !isRoot(ctx) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("a site's certificate: root on the node only"))
	}
	c, err := provision.SetCertificate(ctx, s.Store, req.Msg.Service, req.Msg.ChainPem, req.Msg.KeyPem, time.Now(), req.Msg.Force)
	action := "service.cert"
	if req.Msg.Force {
		action += " force"
	}
	if err := s.done(ctx, action, req.Msg.Service, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetCertificateResponse{Names: c.Names, NotAfter: c.NotAfter.Unix(), MissingNext: c.MissingNext,
		Unpinned: c.Unpinned}), nil
}

// rotateSiteKey asks for another key of a site's certificate
// (spec/cert-pin-v1.md §5): root on the node only, as the site's own
// certificate is. The certificate manager, woken by the change, gives the
// order one try at once, whatever its back-off, and goes on by the
// back-off if that fails; an upgrade (-force, then -fresh) is a request of
// its own. The same request again gets a try RetryGap (15 minutes) after
// the last failed one at the earliest. how is one of provision's
// SiteSwitch values; each is audited under its own action.
func (s *Server) rotateSiteKey(ctx context.Context, name, how string, now time.Time) (*connect.Response[nodev1.RotateServiceResponse], error) {
	if !isRoot(ctx) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("a site's certificate key: root on the node only"))
	}
	var err error
	if !s.Certificates {
		err = fmt.Errorf("%w: rayd issues no certificates here (-acme-directory is empty): the key of %s changes with the certificate you import "+
			"(rayctl service cert)", store.ErrPrecondition, name)
	} else {
		err = provision.RequestSiteKeyRotation(ctx, s.Store, name, now, s.SiteKeyLead, how)
	}
	action := "service.rotate"
	if how != provision.SiteSwitchLead {
		action += " " + how
	}
	if err := s.done(ctx, action, name, err); err != nil {
		return nil, err
	}
	if s.SiteKeyAsked != nil {
		s.SiteKeyAsked(name)
	}
	return connect.NewResponse(&nodev1.RotateServiceResponse{SwitchAt: now.Unix(), Key: "tls", Kind: "site"}), nil
}

func (s *Server) RotateService(ctx context.Context, req *connect.Request[nodev1.RotateServiceRequest]) (*connect.Response[nodev1.RotateServiceResponse], error) {
	now := time.Now()
	if svc, err := s.Store.ServiceByName(ctx, req.Msg.Name); err == nil && svc.Kind == "site" {
		how := provision.SiteSwitchLead
		switch {
		case req.Msg.Fresh:
			how = provision.SiteSwitchFresh
		case req.Msg.Force:
			how = provision.SiteSwitchForce
		}
		return s.rotateSiteKey(ctx, req.Msg.Name, how, now)
	}
	if svc, err := s.Store.ServiceByName(ctx, req.Msg.Name); err == nil && svc.Kind == "masterdns" {
		// masterdns-key-rotation §2: the new key at once, in subscriptions
		// from now; the previous one for the grace (its sessions go on).
		state, err := provision.RotateMasterDNSKey(ctx, s.Store, req.Msg.Name, now, s.CredGrace, req.Msg.Now, req.Msg.Force)
		if err := s.done(ctx, "service.rotate", req.Msg.Name, err); err != nil {
			return nil, err
		}
		return connect.NewResponse(&nodev1.RotateServiceResponse{SwitchAt: now.Unix(), Seal: true, Key: "service", PrevUntil: state.PrevUntil, Kind: "masterdns"}), nil
	}
	if svc, err := s.Store.ServiceByName(ctx, req.Msg.Name); err == nil && svc.Kind == "dnstt" {
		// dnsseal-v1 §8: the new key at once, the previous one for the grace.
		state, err := provision.RotateSealKey(ctx, s.Store, req.Msg.Name, now, s.CredGrace, req.Msg.Now, req.Msg.Force)
		if err := s.done(ctx, "service.rotate", req.Msg.Name, err); err != nil {
			return nil, err
		}
		return connect.NewResponse(&nodev1.RotateServiceResponse{SwitchAt: now.Unix(), Seal: true, Key: "seal", PrevUntil: state.PrevUntil, Kind: "dnstt"}), nil
	}
	if svc, err := s.Store.ServiceByName(ctx, req.Msg.Name); err == nil && svc.Kind == "hy2-obfs" && render.SalamanderDevice() {
		// spec/salamander-device-v1.md §3: the next S in subscriptions and
		// accepted from now, its switch a lead away, the current one for
		// the grace after; with now, the new one at once and nothing kept.
		state, err := provision.RotateObfsPassword(ctx, s.Store, req.Msg.Name, now, s.RealityLead, req.Msg.Now)
		if err := s.done(ctx, "service.rotate", req.Msg.Name, err); err != nil {
			return nil, err
		}
		if s.Rotate != nil {
			s.Rotate()
		}
		r := &nodev1.RotateServiceResponse{SwitchAt: now.Unix(), Kind: "hy2-obfs"}
		if state.NextFrom != 0 {
			r.SwitchAt, r.PrevUntil = state.NextFrom, state.NextFrom+int64(s.CredGrace/time.Second)
		}
		return connect.NewResponse(r), nil
	}
	at := now.Add(s.RealityLead)
	if req.Msg.Now {
		at = now
	}
	names, err := provision.RequestRotationNames(ctx, s.Store, req.Msg.Name, now, s.RealityLead, req.Msg.Now, s.NaivePeriod)
	action := "service.rotate"
	if len(names.Dropped) > 0 {
		// naive: previous names the switch takes off the front.
		action += " drops " + strings.Join(names.Dropped, ",")
	}
	if err := s.done(ctx, action, req.Msg.Name, err); err != nil {
		return nil, err
	}
	if s.Rotate != nil {
		s.Rotate()
	}
	kind := ""
	if svc, err := s.Store.ServiceByName(ctx, req.Msg.Name); err == nil {
		kind = svc.Kind
	}
	return connect.NewResponse(&nodev1.RotateServiceResponse{SwitchAt: at.Unix(), Kind: kind, KeptNames: names.Kept, DroppedNames: names.Dropped}), nil
}

func devicePB(d store.Device) *nodev1.Device {
	return &nodev1.Device{Id: d.ID, User: d.UserName, Name: d.Name, Role: d.Role,
		CreatedAt: d.CreatedAt.Unix(), RevokedAt: unixOrZero(d.RevokedAt), Registered: d.CertPin != "", Lan: d.LAN,
		Client: d.Client, ClientAt: unixOrZero(d.ClientAt), Allow: prefixStrings(d.Allow), LastCall: unixOrZero(d.LastCall)}
}

func invitePB(inv store.Invite) *nodev1.Invite {
	return &nodev1.Invite{Id: inv.ID, User: inv.UserName, Name: inv.Name, Role: inv.Role,
		CreatedAt: inv.CreatedAt.Unix(), ExpiresAt: inv.ExpiresAt.Unix(), PinTries: int32(inv.PinTries), Allow: prefixStrings(inv.Allow)}
}

func (s *Server) ListDevices(ctx context.Context, req *connect.Request[nodev1.ListDevicesRequest]) (*connect.Response[nodev1.ListDevicesResponse], error) {
	devices, err := s.Store.ListDevices(ctx, req.Msg.User)
	if err != nil {
		return nil, toConnect(err)
	}
	resp := &nodev1.ListDevicesResponse{}
	for _, d := range devices {
		resp.Devices = append(resp.Devices, devicePB(d))
	}
	invites, err := s.Store.ListInvites(ctx)
	if err != nil {
		return nil, toConnect(err)
	}
	for _, inv := range invites {
		if req.Msg.User == "" || req.Msg.User == inv.UserName {
			resp.Invites = append(resp.Invites, invitePB(inv))
		}
	}
	return connect.NewResponse(resp), nil
}

func (s *Server) CreateDevice(ctx context.Context, req *connect.Request[nodev1.CreateDeviceRequest]) (*connect.Response[nodev1.CreateDeviceResponse], error) {
	role := req.Msg.Role
	if role == "" {
		role = "user"
	}
	d, key, err := s.Store.CreateDevice(ctx, req.Msg.User, req.Msg.Name, role)
	var encoded string
	if err == nil {
		encoded, err = s.bundle(ctx, d, key)
	}
	if err := s.done(ctx, "device.create:"+role, req.Msg.User+"/"+req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.CreateDeviceResponse{Device: devicePB(d), Bundle: encoded}), nil
}

// bundle builds the enrollment bundle: node SPA parameters, the device key
// and the services the user may reach.
func (s *Server) bundle(ctx context.Context, d store.Device, key [spa.KeySize]byte) (string, error) {
	host, err := node.Host(ctx, s.Store)
	if err != nil {
		return "", err
	}
	u, err := s.Store.UserByName(ctx, d.UserName)
	if err != nil {
		return "", err
	}
	services, err := s.Store.ListServices(ctx)
	if err != nil {
		return "", err
	}
	// The node's name first, its addresses as the fallback (names-v1 §3).
	dnsName, err := provision.NodeDNSName(ctx, s.Store)
	if err != nil {
		return "", err
	}
	b := node.Bundle{Version: 1, Host: host, DNSName: dnsName, Addrs: node.Addrs(host), SPA: s.nodeSPA(ctx),
		DeviceID: d.ID, DeviceKey: hex.EncodeToString(key[:])}
	if d.Role != "user" {
		b.Role = d.Role
	}
	// An integration's device gets the API alone: no subscription, no
	// data service (integrations-v1 §2.1); its user has none.
	integration := store.IntegrationRole(d.Role)
	for _, svc := range services {
		if integration {
			continue
		}
		if svc.Kind == "subscription" && svc.Enabled {
			ports, err := svc.Ports()
			if err != nil || len(ports) == 0 {
				return "", fmt.Errorf("subscription service has no port: %w", err)
			}
			secrets, err := s.Store.ServiceSecrets(ctx, svc.ID)
			if err != nil {
				return "", err
			}
			pin, err := provision.SPKIPin(secrets[provision.SecretTLSCert])
			if err != nil {
				return "", err
			}
			b.Sub = &node.BundleSub{Port: ports[0].Num, Pin: pin}
			continue
		}
		for _, id := range u.Services {
			if svc.ID != id || d.ByIntegration && store.NotForIntegrationDevices(svc.Kind) {
				continue
			}
			bs := node.BundleService{ID: uint16(svc.ID), Kind: svc.Kind, Name: svc.Name}
			if rot, ok := provision.ServiceRotation(svc); ok {
				secrets, err := s.Store.ServiceSecrets(ctx, svc.ID)
				if err != nil {
					return "", err
				}
				bs.PortKey = hex.EncodeToString(secrets[provision.SecretPortKey])
				bs.PortBase, bs.PortRange = rot.Base, rot.Range
			}
			b.Services = append(b.Services, bs)
		}
	}
	if (d.Role == "admin" || integration) && d.CertPin != "" {
		api, err := s.apiEndpoint(ctx)
		if err != nil {
			return "", err
		}
		if api != nil {
			ep := api.endpoint
			b.API = &ep
			b.Services = append(b.Services, node.BundleService{ID: uint16(api.svc.ID), Kind: api.svc.Kind, Name: api.svc.Name})
		}
	}
	keys, err := provision.LoadNodeKeys(ctx, s.Store)
	if err != nil {
		return "", err
	}
	b.NodeKeys = keys.PublicJSON()
	return b.Encode()
}

func (s *Server) RevokeDevice(ctx context.Context, req *connect.Request[nodev1.RevokeDeviceRequest]) (*connect.Response[nodev1.RevokeDeviceResponse], error) {
	action, target := "device.revoke", req.Msg.Id
	resp := &nodev1.RevokeDeviceResponse{}
	// With overlap (R4-43) the credentials rotate instead of being new at
	// once. An admin device may ask for it as root may: it revokes the
	// device all the same, and gives no more than a revocation does.
	revoke := s.Store.RevokeDevice
	if req.Msg.Overlap {
		revoke = s.Store.RevokeDeviceOverlap
	}
	r, err := revoke(ctx, req.Msg.Id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if ierr := s.Store.DeleteInvite(ctx, req.Msg.Id); ierr == nil || !errors.Is(ierr, store.ErrNotFound) {
			action, err = "invite.delete", ierr
			resp.Invite = true
		}
	case err == nil:
		// The audit says whose device and that the user's credentials
		// changed (R4-36) or rotate (with overlap, R4-43, and when), never
		// what they are.
		resp.User, resp.Device, resp.Already = r.User, r.Device, r.Already
		resp.Credentials = uint32(r.Credentials) //nolint:gosec // G115: one a service
		resp.SwitchAt, resp.Until = unixOf(r.SwitchAt), unixOf(r.Until)
		switch {
		case r.Already:
			target += " " + r.User + "/" + r.Device + ": revoked already, nothing changed"
		case r.Overlap:
			target += fmt.Sprintf(" %s/%s: with overlap: %d credentials of %s rotate", r.User, r.Device, r.Credentials, r.User)
			if r.Credentials > 0 {
				target += fmt.Sprintf(": next published, switch at %s, the old ones accepted until %s",
					r.SwitchAt.UTC().Format(time.RFC3339), r.Until.UTC().Format(time.RFC3339))
			}
		default:
			target += fmt.Sprintf(" %s/%s: %d credentials of %s new", r.User, r.Device, r.Credentials, r.User)
		}
	}
	if err := s.done(ctx, action, target, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(resp), nil
}

// DefaultInviteTTL is how long an invite works when the request says nothing.
const DefaultInviteTTL = 24 * time.Hour

func (s *Server) CreateInvite(ctx context.Context, req *connect.Request[nodev1.CreateInviteRequest]) (*connect.Response[nodev1.CreateInviteResponse], error) {
	role := req.Msg.Role
	if role == "" {
		role = "user"
	}
	ttl := time.Duration(req.Msg.TtlSeconds) * time.Second
	if ttl == 0 {
		ttl = DefaultInviteTTL
	}
	var code, short, v3, pin string
	err := billingInviteRole(ctx, role)
	var api *apiService
	if err == nil {
		api, err = s.apiEndpoint(ctx)
	}
	if err == nil && api == nil {
		err = fmt.Errorf("%w: no remote API on the node (rayctl service add api api, then rayctl apply)", store.ErrInvalid)
	}
	// A PIN (api-v1 §3): 6 digits, told by another channel; the node
	// keeps only the proof Register must bring.
	var withPIN store.InvitePIN
	if err == nil && req.Msg.Pin {
		if pin, err = newPIN(); err == nil {
			withPIN = func(key [spa.KeySize]byte) []byte { return InvitePinProof(key, pin) }
		}
	}
	// The addresses of the integration's server (integrations-v1 §3.2).
	var allow []netip.Prefix
	var warnings []string
	if err == nil && len(req.Msg.Allow) > 0 {
		// The role first: billing's invites are users', and the checks of
		// the addresses would tell it the node's and the relays'.
		if !store.IntegrationRole(role) {
			err = fmt.Errorf("role %q: %w", role, store.ErrAllowRole)
		} else {
			allow, warnings, err = s.checkAllow(ctx, req.Msg.Allow)
		}
	}
	var inv store.Invite
	if err == nil {
		var key [spa.KeySize]byte
		inv, key, err = s.Store.CreateInviteAllow(ctx, req.Msg.User, req.Msg.Name, role, ttl, allow, withPIN)
		if err == nil {
			code, short, v3, err = s.inviteCode(ctx, inv, key, api)
		}
	}
	what, target := "invite.create:"+role, req.Msg.User+"/"+req.Msg.Name
	if req.Msg.Pin {
		what += ":pin"
	}
	if len(req.Msg.Allow) > 0 {
		what += ":allow"
		if err == nil {
			target += ": " + strings.Join(prefixStrings(allow), ",")
		}
	}
	if err := s.done(ctx, what, target, err); err != nil {
		return nil, err
	}
	if !req.Msg.Pin && InvitePINByDefault(role) {
		warnings = append(warnings, fmt.Sprintf("the invite of role %s has no PIN: whoever registers with it first gets the API as %s", role, role))
	}
	return connect.NewResponse(&nodev1.CreateInviteResponse{Invite: invitePB(inv), InviteCode: code, Pin: pin, InviteCodeShort: short,
		InviteCodeV3: v3, Warnings: warnings}), nil
}

// newPIN is a PIN of 6 digits, uniform.
func newPIN() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// apiEndpoint returns the enabled API service and where clients reach it,
// or nil without one.
func (s *Server) apiEndpoint(ctx context.Context) (*apiService, error) {
	services, err := s.Store.ListServices(ctx)
	if err != nil {
		return nil, err
	}
	for _, svc := range services {
		if svc.Kind != "api" || !svc.Enabled {
			continue
		}
		ports, err := svc.Ports()
		if err != nil || len(ports) == 0 {
			return nil, fmt.Errorf("api service has no port: %w", err)
		}
		secrets, err := s.Store.ServiceSecrets(ctx, svc.ID)
		if err != nil {
			return nil, err
		}
		pin, err := provision.SPKIPin(secrets[provision.SecretTLSCert])
		if err != nil {
			return nil, err
		}
		return &apiService{svc: svc, endpoint: node.BundleSub{Port: ports[0].Num, Pin: pin}}, nil
	}
	return nil, nil
}

type apiService struct {
	svc      store.Service
	endpoint node.BundleSub
}

// inviteCode encodes an invite: what SPA needs, with the invite's key and
// the API as its only service, and where the API is; as rcinv1, in the
// short form rcinv2 (api-v1 §3a) and by name, rcinv3 (§3b), the short
// ones "" when the host cannot go in them.
func (s *Server) inviteCode(ctx context.Context, inv store.Invite, key [spa.KeySize]byte, api *apiService) (code, short, v3 string, err error) {
	host, err := node.Host(ctx, s.Store)
	if err != nil {
		return "", "", "", err
	}
	// rcinv3 alone needs the name: if it cannot be read, the invite goes
	// without rcinv3, and the call does not fail for rcinv1 and rcinv2.
	dnsName, nameErr := provision.NodeDNSName(ctx, s.Store)
	ep := api.endpoint
	// rcinv1 and rcinv2 as before: the host alone, no SPA versions (they
	// knock at the host, names-v1 §9 п. 3); rcinv3 by name, with them.
	b := node.Bundle{Version: 1, Host: host, SPA: node.FromParams(s.Params), DeviceID: inv.ID,
		DeviceKey: hex.EncodeToString(key[:]), API: &ep, Expires: inv.ExpiresAt.Unix(), PIN: inv.PinProof != nil,
		Services: []node.BundleService{{ID: uint16(api.svc.ID), Kind: api.svc.Kind, Name: api.svc.Name}}}
	if code, err = b.EncodeInvite(); err != nil {
		return "", "", "", err
	}
	short, _ = b.EncodeInvite2()
	if nameErr == nil {
		b.DNSName, b.Addrs, b.SPA = dnsName, node.Addrs(host), s.nodeSPA(ctx)
		v3, _ = b.EncodeInvite3()
	}
	return code, short, v3, nil
}

func (s *Server) ListAudit(ctx context.Context, req *connect.Request[nodev1.ListAuditRequest]) (*connect.Response[nodev1.ListAuditResponse], error) {
	limit := int(req.Msg.Limit)
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	entries, err := s.Store.ListAudit(ctx, limit)
	if err != nil {
		return nil, toConnect(err)
	}
	resp := &nodev1.ListAuditResponse{}
	for _, e := range entries {
		resp.Entries = append(resp.Entries, &nodev1.AuditEntry{Time: e.Time.Unix(), Actor: e.Actor, Action: e.Action, Target: e.Target, Result: e.Result})
	}
	return connect.NewResponse(resp), nil
}

func (s *Server) GetAdminAccess(ctx context.Context, _ *connect.Request[nodev1.GetAdminAccessRequest]) (*connect.Response[nodev1.GetAdminAccessResponse], error) {
	ps, err := node.AdminAccess(ctx, s.Store)
	if err != nil {
		return nil, toConnect(err)
	}
	resp := &nodev1.GetAdminAccessResponse{}
	for _, p := range ps {
		resp.Cidrs = append(resp.Cidrs, p.String())
	}
	return connect.NewResponse(resp), nil
}

func (s *Server) SetAdminAccess(ctx context.Context, req *connect.Request[nodev1.SetAdminAccessRequest]) (*connect.Response[nodev1.SetAdminAccessResponse], error) {
	err := s.relaysOutside(ctx, req.Msg.Cidrs)
	if err == nil {
		_, err = node.SetAdminAccess(ctx, s.Store, req.Msg.Cidrs)
	}
	if err := s.done(ctx, "admin.access", strings.Join(req.Msg.Cidrs, ","), err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetAdminAccessResponse{}), nil
}

// hostPorts lists the ports clients reach: the SPA range (UDP and the TCP
// carrier) and the ports of enabled services. Rotated UDP slot ports need no
// entry: they are redirected to the service port before any input chain.
// outside is the same list before the node's redirects, for a provider's
// firewall: TCP 80 for the ACME window, and only while HTTP-01 is in use,
// and the UDP rotation ranges.
func (s *Server) hostPorts(ctx context.Context) (host, outside []deploy.PortRange, err error) {
	last := uint16(int(s.Params.PortBase) + int(s.Params.PortRange) - 1)
	ports := []deploy.PortRange{
		{Proto: "udp", From: s.Params.PortBase, To: last},
		{Proto: "tcp", From: s.Params.PortBase, To: last},
	}
	services, err := s.Store.ListServices(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, svc := range services {
		if !svc.Enabled {
			continue
		}
		ps, err := svc.Ports()
		if err != nil {
			continue // not rendered, not in the perimeter (snapshot)
		}
		for _, p := range ps {
			ports = append(ports, deploy.PortRange{Proto: p.Proto, From: p.Num, To: p.Num})
		}
	}
	outside = slices.Clone(ports)
	// The UDP rotation ranges reach the host as they are: a provider's
	// firewall sees them before the redirect.
	for _, svc := range services {
		if rot, ok := provision.ServiceRotation(svc); ok && svc.Enabled {
			outside = append(outside, deploy.PortRange{Proto: "udp", From: rot.Base, To: uint16(int(rot.Base) + int(rot.Range) - 1)})
		}
	}
	if slices.ContainsFunc(services, func(svc store.Service) bool { return svc.Enabled && svc.Kind == "site" }) {
		// The ACME window redirects TCP 80 here; host firewalls must pass it.
		port, err := provision.ACMEPort(ctx, s.Store)
		if err != nil {
			return nil, nil, err
		}
		ports = append(ports, deploy.PortRange{Proto: "tcp", From: port, To: port})
		// With a DNS provider certificates come through DNS-01: no window.
		if c, _, err := provision.Cloudflare(ctx, s.Store); err == nil && c == nil {
			outside = append(outside, deploy.PortRange{Proto: "tcp", From: 80, To: 80})
		}
	}
	return deploy.MergePorts(ports), deploy.MergePorts(outside), nil
}

// deployInputs are what the deployment is built from: the rendered
// model's inputs, the host's ports, and rayd's warnings. rayctl apply
// builds it itself from them (GetDeployInputs), as root, with its own
// paths and binaries; GetDeployment builds it here.
func (s *Server) deployInputs(ctx context.Context) (deploy.Inputs, error) {
	m, err := render.CollectForRender(ctx, s.Store)
	if err != nil {
		return deploy.Inputs{}, toConnect(err)
	}
	// A broken service is named in the warnings; the rest is deployed (Q-1).
	files, skipped, rerr := render.Render(m, s.Paths)
	if rerr != nil && !render.Partial(rerr) {
		return deploy.Inputs{}, connect.NewError(connect.CodeFailedPrecondition, rerr)
	}
	in := deploy.InputsOf(m, files, s.Paths)
	in.HostPorts, in.OutsidePorts, err = s.hostPorts(ctx)
	if err != nil {
		return deploy.Inputs{}, toConnect(err)
	}
	// niko-server's backends that go out resolve with the host's resolver,
	// which their sandbox may keep out of reach.
	for _, svc := range m.Services {
		out := svc.Kind == "hy2-masq" || svc.Kind == "hy2-obfs"
		if svc.Kind == "yggdrasil" {
			st, _, _ := render.YggdrasilNode(svc)
			out = len(st.Peers) > 0
		}
		if out {
			if p := deploy.SandboxResolverProblem(""); p != "" {
				in.Warnings = append(in.Warnings, p)
			}
			break
		}
	}
	if ignored, err := node.AdminAccessIgnored(ctx, s.Store); err == nil {
		for _, p := range ignored {
			in.Warnings = append(in.Warnings, fmt.Sprintf("admin address %s is ignored: wider than /%d (rayctl admin to set it again)", p, node.MinAdminBits(p.Addr())))
		}
	}
	ssh := map[store.Port]string{}
	for _, svc := range m.Services {
		if svc.Kind == "ssh" {
			ports, _ := svc.Ports()
			for _, p := range ports {
				ssh[p] = svc.Name
			}
		}
	}
	for _, svc := range m.Services {
		ports, err := svc.Ports()
		if err != nil {
			in.Warnings = append(in.Warnings, "closed in the perimeter: "+err.Error())
			continue
		}
		for _, p := range ports {
			if name, ok := ssh[p]; ok && svc.Kind != "ssh" {
				in.Warnings = append(in.Warnings, fmt.Sprintf("closed in the perimeter: port %s of %s is %s's", p, svc.Name, name))
			}
		}
	}
	for _, name := range skipped {
		in.Warnings = append(in.Warnings, "not rendered yet: "+name)
	}
	var broken render.ServiceErrors
	if errors.As(rerr, &broken) {
		for _, e := range broken {
			in.Warnings = append(in.Warnings, "not rendered: "+e.Error())
		}
	}
	return in, nil
}

// GetDeployInputs returns what root builds the deployment from
// (spec/apply-plan-v1.md): rayctl apply checks them and builds the plan
// itself.
func (s *Server) GetDeployInputs(ctx context.Context, _ *connect.Request[nodev1.GetDeployInputsRequest]) (*connect.Response[nodev1.GetDeployInputsResponse], error) {
	in, err := s.deployInputs(ctx)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(DeployInputsProto(in)), nil
}

// GetDeployment returns the deployment as rayd builds it: what rayctl
// before v0.21.0 installs (and takes its units from after an update).
func (s *Server) GetDeployment(ctx context.Context, _ *connect.Request[nodev1.GetDeploymentRequest]) (*connect.Response[nodev1.GetDeploymentResponse], error) {
	in, err := s.deployInputs(ctx)
	if err != nil {
		return nil, err
	}
	in.MemTotal = memlimit.Read(memlimit.System).MemTotal
	plan := deploy.Build(in, s.Paths, s.Binaries)
	plan.HostPorts = in.HostPorts
	plan.Files = append(plan.Files, deploy.FirewallFiles(plan.HostPorts)...)
	resp := &nodev1.GetDeploymentResponse{Units: plan.Units, Warnings: plan.Warnings, FrontDns: plan.FrontDNS, Icmp: plan.ICMP,
		HostPorts: portRanges(plan.HostPorts), OutsidePorts: portRanges(in.OutsidePorts)}
	for _, u := range plan.Users {
		resp.Users = append(resp.Users, &nodev1.SystemUser{Name: u.Name, Uid: uint32(u.UID), ExtraGroups: u.ExtraGroups})
	}
	for _, f := range plan.Files {
		resp.Files = append(resp.Files, &nodev1.DeployFile{Path: f.Path, Mode: f.Mode, Content: f.Content})
	}
	return connect.NewResponse(resp), nil
}

// dnsStatus describes the node's DNS provider and the records it needs.
func (s *Server) dnsStatus(ctx context.Context, changes, problems []string) (*nodev1.DNSStatus, error) {
	st := &nodev1.DNSStatus{Changes: changes, Problems: problems}
	c, zone, err := provision.Cloudflare(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	if c != nil {
		st.Provider, st.Zone = "cloudflare", zone.Name
	}
	records, warnings, err := provision.DNSRecords(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	for _, r := range records {
		st.Records = append(st.Records, &nodev1.DNSRecord{Type: r.Type, Name: r.Name, Content: r.Content})
	}
	for _, w := range warnings {
		if !slices.Contains(st.Problems, w) {
			st.Problems = append(st.Problems, w)
		}
	}
	return st, nil
}

func (s *Server) SetDNSProvider(ctx context.Context, req *connect.Request[nodev1.SetDNSProviderRequest]) (*connect.Response[nodev1.SetDNSProviderResponse], error) {
	var err error
	if req.Msg.Provider != "cloudflare" {
		err = fmt.Errorf("%w: DNS provider %q: only cloudflare", store.ErrInvalid, req.Msg.Provider)
	} else {
		_, err = provision.SetCloudflare(ctx, s.Store, req.Msg.Token)
	}
	// The token never goes into the audit log.
	if err := s.done(ctx, "dns.provider", req.Msg.Provider, err); err != nil {
		return nil, err
	}
	changes, problems, err := provision.SyncDNS(ctx, s.Store)
	if err != nil {
		problems = append(problems, "sync: "+err.Error())
	}
	if s.DNSChanged != nil {
		s.DNSChanged()
	}
	status, err := s.dnsStatus(ctx, changes, problems)
	if err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&nodev1.SetDNSProviderResponse{Status: status}), nil
}

func (s *Server) GetDNS(ctx context.Context, _ *connect.Request[nodev1.GetDNSRequest]) (*connect.Response[nodev1.GetDNSResponse], error) {
	status, err := s.dnsStatus(ctx, nil, nil)
	if err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&nodev1.GetDNSResponse{Status: status}), nil
}

func (s *Server) SyncDNS(ctx context.Context, _ *connect.Request[nodev1.SyncDNSRequest]) (*connect.Response[nodev1.SyncDNSResponse], error) {
	changes, problems, err := provision.SyncDNS(ctx, s.Store)
	if err := s.done(ctx, "dns.sync", "", err); err != nil {
		return nil, err
	}
	// Records fixed by hand: the certificates need not wait for their
	// back-off.
	if s.DNSChanged != nil {
		s.DNSChanged()
	}
	status, err := s.dnsStatus(ctx, changes, problems)
	if err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&nodev1.SyncDNSResponse{Status: status}), nil
}

func (s *Server) RemoveDNS(ctx context.Context, req *connect.Request[nodev1.RemoveDNSRequest]) (*connect.Response[nodev1.RemoveDNSResponse], error) {
	removed, err := provision.RemoveDNS(ctx, s.Store, req.Msg.KeepRecords)
	if err := s.done(ctx, "dns.remove", "", err); err != nil {
		return nil, err
	}
	if s.DNSChanged != nil {
		s.DNSChanged()
	}
	return connect.NewResponse(&nodev1.RemoveDNSResponse{Removed: removed}), nil
}
