// Package api serves the node API (api/proto/raycontrol/node/v1).
package api

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/deploy"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
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
	resp := &nodev1.GetStatusResponse{
		Version:       s.Version,
		NodeId:        hex.EncodeToString(s.Params.NodeID[:]),
		Host:          host,
		Users:         uint32(len(users)),
		Services:      uint32(len(services)),
		ActiveDevices: uint32(len(devices)),
	}
	for _, p := range s.Params.ActivePorts(time.Now()) {
		resp.SpaPorts = append(resp.SpaPorts, uint32(p))
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
	if req.Msg.Kind == "reality" && s.CheckRealityTarget != nil {
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
	err := s.Store.SetServiceEnabled(ctx, req.Msg.Name, req.Msg.Enabled)
	if err := s.done(ctx, "service.enable="+strconv.FormatBool(req.Msg.Enabled), req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetServiceEnabledResponse{}), nil
}

func (s *Server) DeleteService(ctx context.Context, req *connect.Request[nodev1.DeleteServiceRequest]) (*connect.Response[nodev1.DeleteServiceResponse], error) {
	err := s.Store.DeleteService(ctx, req.Msg.Name)
	if err := s.done(ctx, "service.delete", req.Msg.Name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.DeleteServiceResponse{}), nil
}

func devicePB(d store.Device) *nodev1.Device {
	return &nodev1.Device{Id: d.ID, User: d.UserName, Name: d.Name, Role: d.Role,
		CreatedAt: d.CreatedAt.Unix(), RevokedAt: unixOrZero(d.RevokedAt)}
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
	keys, err := provision.LoadNodeKeys(ctx, s.Store)
	if err != nil {
		return "", err
	}
	b.NodeKeys = keys.PublicJSON()
	return b.Encode()
}

func (s *Server) RevokeDevice(ctx context.Context, req *connect.Request[nodev1.RevokeDeviceRequest]) (*connect.Response[nodev1.RevokeDeviceResponse], error) {
	err := s.Store.RevokeDevice(ctx, req.Msg.Id)
	if err := s.done(ctx, "device.revoke", req.Msg.Id, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.RevokeDeviceResponse{}), nil
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
	_, err := node.SetAdminAccess(ctx, s.Store, req.Msg.Cidrs)
	if err := s.done(ctx, "admin.access", strings.Join(req.Msg.Cidrs, ","), err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetAdminAccessResponse{}), nil
}

// hostPorts lists the ports clients reach: the SPA range (UDP and the TCP
// carrier) and the ports of enabled services. Rotated UDP slot ports need no
// entry: they are redirected to the service port before any input chain.
func (s *Server) hostPorts(ctx context.Context) ([]deploy.PortRange, error) {
	last := uint16(int(s.Params.PortBase) + int(s.Params.PortRange) - 1)
	ports := []deploy.PortRange{
		{Proto: "udp", From: s.Params.PortBase, To: last},
		{Proto: "tcp", From: s.Params.PortBase, To: last},
	}
	services, err := s.Store.ListServices(ctx)
	if err != nil {
		return nil, err
	}
	for _, svc := range services {
		if !svc.Enabled {
			continue
		}
		ps, err := svc.Ports()
		if err != nil {
			return nil, err
		}
		for _, p := range ps {
			ports = append(ports, deploy.PortRange{Proto: p.Proto, From: p.Num, To: p.Num})
		}
	}
	return deploy.MergePorts(ports), nil
}

func (s *Server) GetDeployment(ctx context.Context, _ *connect.Request[nodev1.GetDeploymentRequest]) (*connect.Response[nodev1.GetDeploymentResponse], error) {
	m, err := render.Collect(ctx, s.Store)
	if err != nil {
		return nil, toConnect(err)
	}
	files, skipped, err := render.Render(m, s.Paths)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	plan := deploy.Build(m, files, s.Paths, s.Binaries)
	plan.HostPorts, err = s.hostPorts(ctx)
	if err != nil {
		return nil, toConnect(err)
	}
	plan.Files = append(plan.Files, deploy.FirewallFiles(plan.HostPorts)...)
	resp := &nodev1.GetDeploymentResponse{Units: plan.Units, Warnings: plan.Warnings}
	for _, r := range plan.HostPorts {
		resp.HostPorts = append(resp.HostPorts, &nodev1.PortRange{Proto: r.Proto, From: uint32(r.From), To: uint32(r.To)})
	}
	for _, name := range skipped {
		resp.Warnings = append(resp.Warnings, "not rendered by this version: "+name)
	}
	for _, u := range plan.Users {
		resp.Users = append(resp.Users, &nodev1.SystemUser{Name: u.Name, Uid: uint32(u.UID), ExtraGroups: u.ExtraGroups})
	}
	for _, f := range plan.Files {
		resp.Files = append(resp.Files, &nodev1.DeployFile{Path: f.Path, Mode: f.Mode, Content: f.Content})
	}
	return connect.NewResponse(resp), nil
}
