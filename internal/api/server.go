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
	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/dnscheck"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/spa"
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
	// CredGrace is how long a previous dnstt seal key stays accepted after
	// the operator switched it (rayd -cred-grace); zero: not at all.
	CredGrace time.Duration
	// DNSChanged runs after the operator changed the DNS provider or its
	// records: the certificates are tried again (certs.Manager.Retry).
	DNSChanged func()
	// Health is where rayd's loops report (O-2): status and metrics.
	Health *health.Board
	// DNSCheck checks the DNS tunnel zones from the node (CheckDNSZones);
	// nil: the call is unavailable.
	DNSCheck *dnscheck.Monitor
	// AppMirror keeps the client's releases (spec/app-update-v1.md); nil:
	// the setting alone (tests).
	AppMirror *appmirror.Mirror
	// NodeUpdate is the update by request (spec/node-update-v1.md); nil:
	// the node's paths.
	NodeUpdate *NodeUpdate

	// Wrong invite PINs, and the invites the last of them withdrew, since
	// rayd started (rayctl metrics).
	pinWrong, pinWithdrawn atomic.Uint64

	mu   sync.Mutex
	rev  uint64
	wake chan struct{} // closed on the next change
	// ACME window (certs.Issuer): rayspa points TCP 80 to acmePort.
	acmePort  uint16
	acmeUntil time.Time
}

// SetACMEWindow opens the perimeter window for an ACME order to port until
// the given time, or closes it when until is zero.
func (s *Server) SetACMEWindow(port uint16, until time.Time) {
	s.mu.Lock()
	s.acmePort, s.acmeUntil = port, until
	s.mu.Unlock()
	s.notify()
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
	s.mu.Unlock()
	if s.OnChange != nil {
		s.OnChange()
	}
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
	return nodev1connect.NewNodeServiceHandler(s, connect.WithInterceptors(policy.interceptor()))
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
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
	case errors.Is(err, store.ErrInvalid):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case strings.Contains(err.Error(), "UNIQUE constraint failed"):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case strings.Contains(err.Error(), "FOREIGN KEY constraint failed"):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	}
	return connect.NewError(connect.CodeInternal, err)
}

// done audits a mutating call and notifies the perimeter on success.
func (s *Server) done(ctx context.Context, action, target string, err error) error {
	result := "ok"
	if err != nil {
		result = "error: " + err.Error()
	}
	if aerr := s.Store.Audit(ctx, actorFrom(ctx), action, target, result); aerr != nil && err == nil {
		err = aerr
	}
	if err == nil {
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
	resp := &nodev1.GetStatusResponse{
		Version:       s.Version,
		NodeId:        hex.EncodeToString(s.Params.NodeID[:]),
		Host:          host,
		Name:          name,
		Users:         uint32(len(users)),
		Services:      uint32(len(services)),
		ActiveDevices: uint32(len(devices)),
		DebugUntil:    unixOf(debugUntil(ctx, s.Store)),
	}
	for _, p := range s.Params.ActivePorts(time.Now()) {
		resp.SpaPorts = append(resp.SpaPorts, uint32(p))
	}
	for _, l := range s.Health.Loops() {
		resp.Loops = append(resp.Loops, &nodev1.LoopHealth{Name: l.Name, LastOk: unixOf(l.LastOK), LastError: unixOf(l.LastErr),
			Error: l.Err, Runs: l.Runs, Errors: l.Errors, Failing: l.Failing(), Detail: l.Detail})
	}
	return connect.NewResponse(resp), nil
}

// serviceIDs resolves service names to IDs.
func (s *Server) serviceIDs(ctx context.Context, names []string) ([]int64, error) {
	ids := make([]int64, 0, len(names))
	for _, n := range names {
		svc, err := s.Store.ServiceByName(ctx, n)
		if err != nil {
			return nil, err
		}
		ids = append(ids, svc.ID)
	}
	return ids, nil
}

func (s *Server) userPB(ctx context.Context, u store.User) (*nodev1.User, error) {
	all, err := s.Store.ListServices(ctx)
	if err != nil {
		return nil, err
	}
	pb := &nodev1.User{
		Id: u.ID, Name: u.Name, Enabled: u.Enabled, ExpiresAt: unixOrZero(u.ExpiresAt),
		Note: u.Note, CreatedAt: u.CreatedAt.Unix(),
	}
	if u.TrafficLimit != nil {
		pb.TrafficLimitBytes = *u.TrafficLimit
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
	u := store.User{Name: m.Name, Enabled: true, Note: m.Note}
	if m.ExpiresAt != 0 {
		t := time.Unix(m.ExpiresAt, 0)
		u.ExpiresAt = &t
	}
	if m.TrafficLimitBytes != 0 {
		u.TrafficLimit = &m.TrafficLimitBytes
	}
	ids, err := s.serviceIDs(ctx, m.Services)
	if err == nil {
		u, err = s.Store.CreateUser(ctx, u)
	}
	if err == nil && len(ids) > 0 {
		err = s.Store.SetUserServices(ctx, u.Name, ids)
		u.Services = ids
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
	err := s.Store.SetUserEnabled(ctx, req.Msg.Name, req.Msg.Enabled)
	if err := s.done(ctx, "user.enable="+strconv.FormatBool(req.Msg.Enabled), req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetUserEnabledResponse{}), nil
}

func (s *Server) SetUserServices(ctx context.Context, req *connect.Request[nodev1.SetUserServicesRequest]) (*connect.Response[nodev1.SetUserServicesResponse], error) {
	ids, err := s.serviceIDs(ctx, req.Msg.Services)
	if err == nil {
		err = s.Store.SetUserServices(ctx, req.Msg.Name, ids)
	}
	if err := s.done(ctx, "user.services="+strings.Join(req.Msg.Services, ","), req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetUserServicesResponse{}), nil
}

func (s *Server) DeleteUser(ctx context.Context, req *connect.Request[nodev1.DeleteUserRequest]) (*connect.Response[nodev1.DeleteUserResponse], error) {
	err := s.Store.DeleteUser(ctx, req.Msg.Name)
	if err := s.done(ctx, "user.delete", req.Msg.Name, err); err != nil {
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

var errUserInactive = errors.New("user is disabled or expired")

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
	return &nodev1.Service{Id: uint32(svc.ID), Kind: svc.Kind, Name: svc.Name, Enabled: svc.Enabled,
		SettingsJson: svc.Settings, CreatedAt: svc.CreatedAt.Unix(), Uid: uint32(svc.UID)}
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
		err = provision.CheckNoDependents(ctx, s.Store, req.Msg.Name)
	}
	if err == nil {
		err = s.Store.SetServiceEnabled(ctx, req.Msg.Name, req.Msg.Enabled)
	}
	if err := s.done(ctx, "service.enable="+strconv.FormatBool(req.Msg.Enabled), req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetServiceEnabledResponse{}), nil
}

func (s *Server) DeleteService(ctx context.Context, req *connect.Request[nodev1.DeleteServiceRequest]) (*connect.Response[nodev1.DeleteServiceResponse], error) {
	err := provision.CheckNoDependents(ctx, s.Store, req.Msg.Name)
	if err == nil {
		err = s.Store.DeleteService(ctx, req.Msg.Name)
	}
	if err := s.done(ctx, "service.delete", req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.DeleteServiceResponse{}), nil
}

func (s *Server) SetServiceOption(ctx context.Context, req *connect.Request[nodev1.SetServiceOptionRequest]) (*connect.Response[nodev1.SetServiceOptionResponse], error) {
	svc, err := provision.SetServiceOption(ctx, s.Store, req.Msg.Name, req.Msg.Key, req.Msg.Value)
	if err := s.done(ctx, "service.set "+req.Msg.Key+"="+req.Msg.Value, req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetServiceOptionResponse{Service: servicePB(svc)}), nil
}

func (s *Server) SetCertificate(ctx context.Context, req *connect.Request[nodev1.SetCertificateRequest]) (*connect.Response[nodev1.SetCertificateResponse], error) {
	c, err := provision.SetCertificate(ctx, s.Store, req.Msg.Service, req.Msg.ChainPem, req.Msg.KeyPem, time.Now())
	if err := s.done(ctx, "service.cert", req.Msg.Service, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetCertificateResponse{Names: c.Names, NotAfter: c.NotAfter.Unix(), MissingNext: c.MissingNext}), nil
}

func (s *Server) RotateService(ctx context.Context, req *connect.Request[nodev1.RotateServiceRequest]) (*connect.Response[nodev1.RotateServiceResponse], error) {
	now := time.Now()
	if svc, err := s.Store.ServiceByName(ctx, req.Msg.Name); err == nil && svc.Kind == "masterdns" {
		// masterdns-key-rotation §2: the new key at once, in subscriptions
		// from now; the previous one for the grace (its sessions go on).
		state, err := provision.RotateMasterDNSKey(ctx, s.Store, req.Msg.Name, now, s.CredGrace, req.Msg.Now)
		if err := s.done(ctx, "service.rotate", req.Msg.Name, err); err != nil {
			return nil, err
		}
		return connect.NewResponse(&nodev1.RotateServiceResponse{SwitchAt: now.Unix(), Seal: true, Key: "service", PrevUntil: state.PrevUntil}), nil
	}
	if svc, err := s.Store.ServiceByName(ctx, req.Msg.Name); err == nil && svc.Kind == "dnstt" {
		// dnsseal-v1 §8: the new key at once, the previous one for the grace.
		state, err := provision.RotateSealKey(ctx, s.Store, req.Msg.Name, now, s.CredGrace, req.Msg.Now)
		if err := s.done(ctx, "service.rotate", req.Msg.Name, err); err != nil {
			return nil, err
		}
		return connect.NewResponse(&nodev1.RotateServiceResponse{SwitchAt: now.Unix(), Seal: true, Key: "seal", PrevUntil: state.PrevUntil}), nil
	}
	at := now.Add(s.RealityLead)
	if req.Msg.Now {
		at = now
	}
	err := provision.RequestRealityRotation(ctx, s.Store, req.Msg.Name, now, s.RealityLead, req.Msg.Now)
	if err := s.done(ctx, "service.rotate", req.Msg.Name, err); err != nil {
		return nil, err
	}
	if s.Rotate != nil {
		s.Rotate()
	}
	return connect.NewResponse(&nodev1.RotateServiceResponse{SwitchAt: at.Unix()}), nil
}

func devicePB(d store.Device) *nodev1.Device {
	return &nodev1.Device{Id: d.ID, User: d.UserName, Name: d.Name, Role: d.Role,
		CreatedAt: d.CreatedAt.Unix(), RevokedAt: unixOrZero(d.RevokedAt), Registered: d.CertPin != ""}
}

func invitePB(inv store.Invite) *nodev1.Invite {
	return &nodev1.Invite{Id: inv.ID, User: inv.UserName, Name: inv.Name, Role: inv.Role,
		CreatedAt: inv.CreatedAt.Unix(), ExpiresAt: inv.ExpiresAt.Unix(), PinTries: int32(inv.PinTries)}
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
	b := node.Bundle{Version: 1, Host: host, SPA: node.FromParams(s.Params), DeviceID: d.ID, DeviceKey: hex.EncodeToString(key[:])}
	for _, svc := range services {
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
			if svc.ID != id {
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
	if d.Role == "admin" && d.CertPin != "" {
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
	action := "device.revoke"
	err := s.Store.RevokeDevice(ctx, req.Msg.Id)
	if errors.Is(err, store.ErrNotFound) {
		if ierr := s.Store.DeleteInvite(ctx, req.Msg.Id); ierr == nil || !errors.Is(ierr, store.ErrNotFound) {
			action, err = "invite.delete", ierr
		}
	}
	if err := s.done(ctx, action, req.Msg.Id, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.RevokeDeviceResponse{}), nil
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
	var code, short, pin string
	api, err := s.apiEndpoint(ctx)
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
	var inv store.Invite
	if err == nil {
		var key [spa.KeySize]byte
		inv, key, err = s.Store.CreateInvite(ctx, req.Msg.User, req.Msg.Name, role, ttl, withPIN)
		if err == nil {
			code, short, err = s.inviteCode(ctx, inv, key, api)
		}
	}
	what := "invite.create:" + role
	if req.Msg.Pin {
		what += ":pin"
	}
	if err := s.done(ctx, what, req.Msg.User+"/"+req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.CreateInviteResponse{Invite: invitePB(inv), InviteCode: code, Pin: pin, InviteCodeShort: short}), nil
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
// the API as its only service, and where the API is; as rcinv1 and in the
// short form rcinv2 (api-v1 §3a), "" when the host cannot go in it.
func (s *Server) inviteCode(ctx context.Context, inv store.Invite, key [spa.KeySize]byte, api *apiService) (string, string, error) {
	host, err := node.Host(ctx, s.Store)
	if err != nil {
		return "", "", err
	}
	ep := api.endpoint
	b := node.Bundle{Version: 1, Host: host, SPA: node.FromParams(s.Params), DeviceID: inv.ID,
		DeviceKey: hex.EncodeToString(key[:]), API: &ep, Expires: inv.ExpiresAt.Unix(), PIN: inv.PinProof != nil,
		Services: []node.BundleService{{ID: uint16(api.svc.ID), Kind: api.svc.Kind, Name: api.svc.Name}}}
	code, err := b.EncodeInvite()
	if err != nil {
		return "", "", err
	}
	short, _ := b.EncodeInvite2()
	return code, short, nil
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
// firewall: TCP 80 for the ACME window, and only while HTTP-01 is in use.
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

func (s *Server) GetDeployment(ctx context.Context, _ *connect.Request[nodev1.GetDeploymentRequest]) (*connect.Response[nodev1.GetDeploymentResponse], error) {
	m, err := render.CollectForRender(ctx, s.Store)
	if err != nil {
		return nil, toConnect(err)
	}
	// A broken service is named in the warnings; the rest is deployed (Q-1).
	files, skipped, rerr := render.Render(m, s.Paths)
	if rerr != nil && !render.Partial(rerr) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, rerr)
	}
	plan := deploy.Build(m, files, s.Paths, s.Binaries)
	var outside []deploy.PortRange
	plan.HostPorts, outside, err = s.hostPorts(ctx)
	if err != nil {
		return nil, toConnect(err)
	}
	plan.Files = append(plan.Files, deploy.FirewallFiles(plan.HostPorts)...)
	resp := &nodev1.GetDeploymentResponse{Units: plan.Units, Warnings: plan.Warnings, FrontDns: plan.FrontDNS, Icmp: plan.ICMP}
	for _, r := range plan.HostPorts {
		resp.HostPorts = append(resp.HostPorts, &nodev1.PortRange{Proto: r.Proto, From: uint32(r.From), To: uint32(r.To)})
	}
	for _, r := range outside {
		resp.OutsidePorts = append(resp.OutsidePorts, &nodev1.PortRange{Proto: r.Proto, From: uint32(r.From), To: uint32(r.To)})
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
				resp.Warnings = append(resp.Warnings, p)
			}
			break
		}
	}
	if ignored, err := node.AdminAccessIgnored(ctx, s.Store); err == nil {
		for _, p := range ignored {
			resp.Warnings = append(resp.Warnings, fmt.Sprintf("admin address %s is ignored: wider than /%d (rayctl admin to set it again)", p, node.MinAdminBits(p.Addr())))
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
			resp.Warnings = append(resp.Warnings, "closed in the perimeter: "+err.Error())
			continue
		}
		for _, p := range ports {
			if name, ok := ssh[p]; ok && svc.Kind != "ssh" {
				resp.Warnings = append(resp.Warnings, fmt.Sprintf("closed in the perimeter: port %s of %s is %s's", p, svc.Name, name))
			}
		}
	}
	for _, name := range skipped {
		resp.Warnings = append(resp.Warnings, "not rendered yet: "+name)
	}
	var broken render.ServiceErrors
	if errors.As(rerr, &broken) {
		for _, e := range broken {
			resp.Warnings = append(resp.Warnings, "not rendered: "+e.Error())
		}
	}
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
