package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"slices"
	"strconv"

	"connectrpc.com/connect"
	"golang.org/x/sys/unix"
)

type peerKey struct{}

type actorKey struct{}

// connContext records the peer credentials of a unix socket connection.
func connContext(ctx context.Context, c net.Conn) context.Context {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return ctx
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return ctx
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credErr != nil {
		return ctx
	}
	return context.WithValue(ctx, peerKey{}, cred)
}

// PeerPolicy decides which local users may call the API: root, the daemon's
// own user, and members of Group, except the UIDs in Deny (rayspa: it only
// reads the perimeter feed). The socket itself is open to all local users;
// this check is the gate.
type PeerPolicy struct {
	Group string
	Deny  []int
}

func (p PeerPolicy) actor(ctx context.Context) (string, error) {
	cred, _ := ctx.Value(peerKey{}).(*unix.Ucred)
	if cred == nil {
		return "", errors.New("no peer credentials")
	}
	name := strconv.Itoa(int(cred.Uid))
	u, err := user.LookupId(name)
	if err == nil {
		name = u.Username
	}
	if slices.Contains(p.Deny, int(cred.Uid)) {
		return "", fmt.Errorf("uid %d may not use the node API", cred.Uid)
	}
	if cred.Uid == 0 || int(cred.Uid) == os.Getuid() {
		return name, nil
	}
	if p.Group == "" || u == nil {
		return "", fmt.Errorf("uid %d not allowed", cred.Uid)
	}
	g, err := user.LookupGroup(p.Group)
	if err != nil {
		return "", fmt.Errorf("uid %d not allowed: %w", cred.Uid, err)
	}
	ids, err := u.GroupIds()
	if err != nil || !slices.Contains(ids, g.Gid) {
		return "", fmt.Errorf("uid %d is not in group %s", cred.Uid, p.Group)
	}
	return name, nil
}

// interceptor rejects callers the policy does not allow and records the
// caller name for the audit log.
func (p PeerPolicy) interceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			actor, err := p.actor(ctx)
			if err != nil {
				return nil, connect.NewError(connect.CodePermissionDenied, err)
			}
			return next(context.WithValue(ctx, actorKey{}, actor), req)
		}
	}
}

func actorFrom(ctx context.Context) string {
	a, _ := ctx.Value(actorKey{}).(string)
	return a
}

// isLocal reports a caller on the node's own socket, not the remote API.
func isLocal(ctx context.Context) bool {
	cred, _ := ctx.Value(peerKey{}).(*unix.Ucred)
	return cred != nil
}

// isOwner reports a caller on the node's socket that is root or the
// daemon's own user, not a member of the group the policy lets in.
func isOwner(ctx context.Context) bool {
	cred, _ := ctx.Value(peerKey{}).(*unix.Ucred)
	return cred != nil && (cred.Uid == 0 || int(cred.Uid) == os.Getuid())
}

// isRoot reports a caller with UID 0.
func isRoot(ctx context.Context) bool {
	cred, _ := ctx.Value(peerKey{}).(*unix.Ucred)
	return cred != nil && cred.Uid == 0
}
