package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/gen/raycontrol/device/v1/devicev1connect"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/store"
)

// prefixStrings are prefixes as the API gives them.
func prefixStrings(ps []netip.Prefix) []string {
	if len(ps) == 0 {
		return nil
	}
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

// checkAllow reads an integration's addresses (integrations-v1 §3.3):
// store.CheckAllow, and none of the node's own addresses or a relay's. It
// warns of an admin address in the list: the admin's devices are refused
// from it (§3.2).
func (s *Server) checkAllow(ctx context.Context, list []string) ([]netip.Prefix, []string, error) {
	allow, warnings, err := store.CheckAllow(list)
	if err != nil {
		return nil, nil, err
	}
	if len(allow) == 0 {
		// Blank entries are no list: clearing one is asked for with none.
		return nil, nil, fmt.Errorf("%w: no address in %q", store.ErrInvalid, list)
	}
	own, err := s.localAddrs()
	if err != nil {
		return nil, nil, err
	}
	relays, err := s.Store.ListRelays(ctx)
	if err != nil {
		return nil, nil, err
	}
	admin, err := node.AdminAccess(ctx, s.Store)
	if err != nil {
		return nil, nil, err
	}
	for _, p := range allow {
		for _, a := range own {
			if p.Contains(a) {
				return nil, nil, fmt.Errorf("%w address %s: it holds the node's own address", store.ErrInvalid, p)
			}
		}
		for _, r := range relays {
			if p.Contains(r.Address.Unmap()) {
				return nil, nil, fmt.Errorf("%w address %s: it holds the address of relay %s", store.ErrInvalid, p, r.Name)
			}
		}
		for _, a := range admin {
			if a.Overlaps(p) {
				warnings = append(warnings, fmt.Sprintf("%s overlaps the admin addresses (%s): admins' devices calling from it are refused", p, a))
				break
			}
		}
	}
	return allow, warnings, nil
}

// localAddrs are the node's own addresses.
func (s *Server) localAddrs() ([]netip.Addr, error) {
	if s.LocalAddrs != nil {
		return s.LocalAddrs()
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out, nil
}

// SetDeviceAllow gives an integration's device its addresses or takes them
// away (integrations-v1 §3.2), audited as device.allow with the device and
// the addresses, or "cleared". The perimeter has them with its next
// snapshot.
func (s *Server) SetDeviceAllow(ctx context.Context, req *connect.Request[nodev1.SetDeviceAllowRequest]) (*connect.Response[nodev1.SetDeviceAllowResponse], error) {
	var allow []netip.Prefix
	var warnings []string
	var err error
	if len(req.Msg.Prefixes) > 0 {
		allow, warnings, err = s.checkAllow(ctx, req.Msg.Prefixes)
	}
	var d store.Device
	if err == nil {
		d, err = s.Store.SetDeviceAllow(ctx, req.Msg.Id, allow)
	}
	target := req.Msg.Id
	if err == nil {
		what := "cleared"
		if len(allow) > 0 {
			what = strings.Join(prefixStrings(allow), ",")
		}
		target = fmt.Sprintf("%s %s/%s: %s", d.ID, d.UserName, d.Name, what)
	}
	if err := s.done(ctx, "device.allow", target, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetDeviceAllowResponse{Device: devicePB(d), Warnings: warnings}), nil
}

// sourceKey holds the address a remote call came from, read once.
type sourceKey struct{}

type source struct {
	addr    netip.Addr // invalid: none read
	claimed bool       // some integration's list holds it
}

func sourceFrom(ctx context.Context) source {
	src, _ := ctx.Value(sourceKey{}).(source)
	return src
}

var errSource = errors.New("not from this address: it is an integration's, or not one of this device's (integrations-v1 §3.2)")

// checkSource is the remote API's check of the address a call comes from
// (integrations-v1 §3.2): the perimeter sees the address, not the device.
// A device with a list calls from it only; an address in some list lets
// in only the device whose list holds it, and Register, which then wants
// an invite whose list holds it. Every call, the store's lists as they are
// now: one taken away refuses the next call on a connection still open.
func (r *Remote) checkSource(ctx context.Context, remoteAddr, pin, path string) (context.Context, error) {
	var src source
	if ap, err := netip.ParseAddrPort(remoteAddr); err == nil {
		src.addr = ap.Addr().Unmap().WithZone("")
	}
	lists, err := r.Server.Store.AllowLists(ctx)
	if err != nil {
		return ctx, connect.NewError(connect.CodeInternal, err)
	}
	if len(lists) > 0 && !src.addr.IsValid() {
		// No address to check (not a TCP peer): nobody, while lists exist.
		return ctx, connect.NewError(connect.CodePermissionDenied, errSource)
	}
	for _, e := range lists {
		if e.DeviceID != "" && pin != "" && e.CertPin == pin {
			if !store.AllowCovers(e.Allow, src.addr) {
				d := store.Device{ID: e.DeviceID, UserName: e.UserName, Name: e.Name, Role: e.Role}
				r.Server.auditQuietly(ctx, d, "api.address", procedureName(path), "refused: not from its addresses", r.clock())
				r.Server.countCall(e.Role, connect.CodePermissionDenied.String())
				return ctx, connect.NewError(connect.CodePermissionDenied, errSource)
			}
			return context.WithValue(ctx, sourceKey{}, source{addr: src.addr, claimed: true}), nil
		}
		if src.addr.IsValid() && store.AllowCovers(e.Allow, src.addr) {
			src.claimed = true
		}
	}
	if src.claimed && path != devicev1connect.DeviceServiceRegisterProcedure {
		return ctx, connect.NewError(connect.CodePermissionDenied, errSource)
	}
	return context.WithValue(ctx, sourceKey{}, src), nil
}

// procedureName is a request path's method for the audit, "other" for a
// path that is no method of the API: the path is the caller's, and would
// make each refusal a line of its own (or a line of its own text).
func procedureName(path string) string {
	if _, ok := methodRoles[path]; ok {
		return methodName(path)
	}
	return "other"
}

// inviteSource lets an invite register from where it may (integrations-v1
// §3.2): an invite with a list from it only, one without from no address
// in some list.
func inviteSource(ctx context.Context, inv store.Invite) error {
	src := sourceFrom(ctx)
	if len(inv.Allow) > 0 {
		if !src.addr.IsValid() || !store.AllowCovers(inv.Allow, src.addr) {
			return connect.NewError(connect.CodePermissionDenied, errors.New("the invite registers from its addresses only (integrations-v1 §3.2)"))
		}
		return nil
	}
	if src.claimed {
		return connect.NewError(connect.CodePermissionDenied, errSource)
	}
	return nil
}

// sourceRefused answers a call checkSource refused, in the request's
// protocol.
func sourceRefused(w http.ResponseWriter, req *http.Request, err error) {
	_ = connect.NewErrorWriter().Write(w, req, err)
}

// touchLastCall keeps an integration's device's last call in the store, at
// most once in store.LastCallEvery (integrations-v1 §3.4: a list with no
// calls for 30 days is pointed out).
func (s *Server) touchLastCall(ctx context.Context, d store.Device, now time.Time) {
	in := &s.integ
	in.mu.Lock()
	e := in.device(d)
	due := now.Sub(e.stored) >= store.LastCallEvery
	if due {
		e.stored = now
	}
	in.mu.Unlock()
	if due {
		_ = s.Store.SetLastCall(context.WithoutCancel(ctx), d.ID, now)
	}
}
