package api

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	visibility "github.com/arngory/raycontrol/internal/gen/google/api"
	devicev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/device/v1"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/store"
)

// The labels of the proto's visibility rules (integrations-v1 §5.1): a
// device role each, NODE for root on the node's socket only, NOTES for
// support's sight of a user's note.
const (
	labelAdmin   = "ADMIN"
	labelBilling = "BILLING"
	labelSupport = "SUPPORT"
	labelUser    = "USER"
	labelNode    = "NODE"
	labelNotes   = "NOTES"
)

// roleLabel is a device role's label, "" for none the node knows.
func roleLabel(role string) string {
	switch role {
	case "admin":
		return labelAdmin
	case "billing":
		return labelBilling
	case "support":
		return labelSupport
	case "user":
		return labelUser
	}
	return ""
}

// ruleLabels are the labels of a visibility rule: the restriction's,
// comma-separated; none without a rule.
func ruleLabels(opts proto.Message, xt protoreflect.ExtensionType) []string {
	if opts == nil || !proto.HasExtension(opts, xt) {
		return nil
	}
	rule, _ := proto.GetExtension(opts, xt).(*visibility.VisibilityRule)
	var out []string
	for l := range strings.SplitSeq(rule.GetRestriction(), ",") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// methodRoles maps each procedure of the remote API's services
// ("/raycontrol.node.v1.NodeService/GetStatus") to the labels of its
// method_visibility; a method without one is ADMIN's. One table for the
// node's checks and the OpenAPI description (integrations-v1 §5.1).
var methodRoles = func() map[string][]string {
	out := map[string][]string{}
	for _, fd := range []protoreflect.FileDescriptor{nodev1.File_raycontrol_node_v1_node_proto, devicev1.File_raycontrol_device_v1_device_proto} {
		services := fd.Services()
		for i := range services.Len() {
			svc := services.Get(i)
			methods := svc.Methods()
			for j := range methods.Len() {
				m := methods.Get(j)
				labels := ruleLabels(m.Options(), visibility.E_MethodVisibility)
				if len(labels) == 0 {
					labels = []string{labelAdmin}
				}
				out["/"+string(svc.FullName())+"/"+string(m.Name())] = labels
			}
		}
	}
	return out
}()

// mayCall reports whether a device of role may call procedure through the
// remote API.
func mayCall(procedure, role string) bool {
	l := roleLabel(role)
	return l != "" && slices.Contains(methodRoles[procedure], l)
}

// fieldRules caches the labels of each field's field_visibility, nil for
// a field every caller of its method sees.
var fieldRules sync.Map // protoreflect.FullName → []string

func fieldLabels(fd protoreflect.FieldDescriptor) []string {
	if v, ok := fieldRules.Load(fd.FullName()); ok {
		return v.([]string)
	}
	l := ruleLabels(fd.Options(), visibility.E_FieldVisibility)
	fieldRules.Store(fd.FullName(), l)
	return l
}

// scrub clears in m, and in the messages, lists and maps in it, each field
// whose field_visibility names no label the caller has: the answer, not
// only its description, leaves them out (integrations-v1 §2.3).
func scrub(m protoreflect.Message, has func(label string) bool) {
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if l := fieldLabels(fd); l != nil && !slices.ContainsFunc(l, has) {
			m.Clear(fd) // the field Range is on: allowed
			return true
		}
		switch {
		case fd.IsMap():
			if fd.MapValue().Message() != nil {
				v.Map().Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
					scrub(mv.Message(), has)
					return true
				})
			}
		case fd.IsList():
			if fd.Message() != nil {
				list := v.List()
				for i := range list.Len() {
					scrub(list.Get(i).Message(), has)
				}
			}
		case fd.Message() != nil:
			scrub(v.Message(), has)
		}
		return true
	})
}

// callerRoleKey holds the role of the device calling through the remote
// API; the node's socket has none.
type callerRoleKey struct{}

// callerRole is the role of the calling device, "" on the node's socket.
func callerRole(ctx context.Context) string {
	r, _ := ctx.Value(callerRoleKey{}).(string)
	return r
}

// actorSuffix is how the audit names a device's calls by its role: an
// admin's "(remote)", as before integrations, an integration's by its
// role (integrations-v1 §2.5).
func actorSuffix(role string) string {
	if store.IntegrationRole(role) {
		return " (" + role + ")"
	}
	return " (remote)"
}

// deniedEvery is how often the audit takes a refusal by role of one
// device and method: the first, then one line a period at most with the
// count since the last, so that a broken integration does not fill the
// log (integrations-v1 §2.5).
const deniedEvery = 10 * time.Minute

type deniedKey struct{ device, procedure string }

type deniedMark struct {
	at     time.Time // of the last line
	missed int       // refusals since, not written
}

// denied writes an integration's refusal by role to the audit as
// api.denied, its target the method's name.
func (r *Remote) denied(ctx context.Context, d store.Device, procedure string) {
	if !store.IntegrationRole(d.Role) {
		return // a user's device, or an admin's at root's: as before
	}
	now := r.clock()
	k := deniedKey{d.ID, procedure}
	r.deniedMu.Lock()
	if r.deniedLog == nil {
		r.deniedLog = map[deniedKey]deniedMark{}
	}
	m, seen := r.deniedLog[k]
	if seen && now.Sub(m.at) < deniedEvery {
		m.missed++
		r.deniedLog[k] = m
		r.deniedMu.Unlock()
		return
	}
	r.deniedLog[k] = deniedMark{at: now}
	if len(r.deniedLog) > 4096 {
		for k, m := range r.deniedLog {
			if now.Sub(m.at) >= deniedEvery {
				delete(r.deniedLog, k)
			}
		}
	}
	r.deniedMu.Unlock()
	result := "refused"
	if m.missed > 0 {
		result = fmt.Sprintf("refused; %d more since the last line", m.missed)
	}
	method := procedure[strings.LastIndexByte(procedure, '/')+1:]
	if err := r.Server.Store.Audit(ctx, d.UserName+"/"+d.Name+actorSuffix(d.Role), "api.denied", method, result); err != nil {
		r.Log.Debug("audit api.denied", "err", err)
	}
}

// errNodeOnly refuses an admin device what root does on the node.
var errNodeOnly = errors.New("on the node only (rayctl as root)")

// roleGate lets a device call through the remote API what its role may
// (the proto's method_visibility), names it in the audit, keeps an
// integration to regular users (store.RegularOnly) and clears in its
// answers what it may not see (integrations-v1 §2).
func (r *Remote) roleGate() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			d, err := r.device(ctx)
			if err != nil {
				return nil, err
			}
			procedure := req.Spec().Procedure
			if !mayCall(procedure, d.Role) {
				r.denied(ctx, d, procedure)
				if d.Role == "admin" && slices.Contains(methodRoles[procedure], labelNode) {
					return nil, connect.NewError(connect.CodePermissionDenied, errNodeOnly)
				}
				return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("not for a device of role %s", d.Role))
			}
			ctx = context.WithValue(ctx, actorKey{}, d.UserName+"/"+d.Name+actorSuffix(d.Role))
			ctx = context.WithValue(ctx, callerRoleKey{}, d.Role)
			if store.IntegrationRole(d.Role) {
				ctx = store.RegularOnly(ctx)
			}
			resp, err := next(ctx, req)
			// The device once more after a call that answers with a secret:
			// one revoked while the call ran must not take away what the
			// call read or made after the revocation (its user's new
			// credentials in an export, a new device's bundle, an invite).
			// Whatever the call read after the revocation's commit, this
			// read comes later and sees it. The other answers say nothing
			// secret, and an admin may revoke the device it calls from or
			// disable its own user.
			if err == nil && secretAnswer[procedure] {
				if _, derr := r.device(ctx); derr != nil {
					return nil, derr
				}
			}
			if err == nil && d.Role != "admin" {
				if m, ok := resp.Any().(proto.Message); ok {
					label := roleLabel(d.Role)
					scrub(m.ProtoReflect(), func(l string) bool { return l == label })
				}
			}
			return resp, err
		}
	}
}
