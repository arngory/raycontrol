package api

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

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

// callerKey holds the device calling through the remote API; the node's
// socket has none.
type callerKey struct{}

// caller is the device calling through the remote API, false on the
// node's socket.
func caller(ctx context.Context) (store.Device, bool) {
	d, ok := ctx.Value(callerKey{}).(store.Device)
	return d, ok
}

// callerRole is the role of the calling device, "" on the node's socket.
func callerRole(ctx context.Context) string {
	d, _ := caller(ctx)
	return d.Role
}

// codeOf is an answer's code as the metrics name it: "ok" for none.
func codeOf(err error) string {
	if err == nil {
		return "ok"
	}
	return connect.CodeOf(err).String()
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
			method := methodName(procedure)
			integration := store.IntegrationRole(d.Role)
			now := r.clock()
			if !mayCall(procedure, d.Role) {
				if integration {
					r.Server.auditQuietly(ctx, d, "api.denied", method, now)
				}
				r.Server.countCall(d.Role, connect.CodePermissionDenied.String())
				if d.Role == "admin" && slices.Contains(methodRoles[procedure], labelNode) {
					return nil, connect.NewError(connect.CodePermissionDenied, errNodeOnly)
				}
				return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("not for a device of role %s", d.Role))
			}
			var labels []string
			if integration {
				release, err := r.Server.admit(ctx, d, method, now)
				if errors.Is(err, errLimited) {
					r.Server.auditQuietly(ctx, d, "api.limited", method, now)
					r.Server.countCall(d.Role, connect.CodeResourceExhausted.String())
					return nil, connect.NewError(connect.CodeResourceExhausted, err)
				}
				if err != nil {
					return nil, toConnect(err)
				}
				defer release()
				set, err := r.Server.integrationSettings(ctx)
				if err != nil {
					return nil, toConnect(err)
				}
				labels = []string{roleLabel(d.Role)}
				if d.Role == "support" && set.SupportNotes {
					labels = append(labels, labelNotes)
				}
				ctx = store.RegularOnly(ctx)
				if d.Role == "billing" {
					ctx = store.KeepCounting(ctx)
				}
			}
			ctx = context.WithValue(ctx, actorKey{}, d.UserName+"/"+d.Name+actorSuffix(d.Role))
			ctx = context.WithValue(ctx, callerKey{}, d)
			resp, err := next(ctx, req)
			r.Server.countCall(d.Role, codeOf(err))
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
					scrub(m.ProtoReflect(), func(l string) bool { return slices.Contains(labels, l) })
				}
			}
			return resp, err
		}
	}
}
