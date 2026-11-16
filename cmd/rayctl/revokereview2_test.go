package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
	"github.com/arngory/raycontrol/internal/store"
)

// A rollback that keeps the database renews the users of revocations with
// overlap when it goes to a rayd before v0.31.0, or a build that is no
// release, which runs without a period: no loop would finish their
// rotations. With a period, or to v0.31.0 and later, they stay (review 2,
// B1).
func TestRollbackRenewsOverlap(t *testing.T) {
	none := store.Rotation{Lead: store.DefaultRotation.Lead, Grace: store.DefaultRotation.Grace}
	for _, c := range []struct {
		target string
		rot    store.Rotation
		want   bool
	}{
		{"v0.30.2", none, true},
		{"v0.27.0", none, true},
		{"v0.30.2", store.DefaultRotation, false},
		{"v0.31.0", none, false},
		{"v0.32.1", none, false},
		{"dev", none, true},
		{"dev", store.DefaultRotation, false},
	} {
		if got := rollbackRenewsOverlap(c.target, c.rot); got != c.want {
			t.Errorf("to %s, period %v: %v", c.target, c.rot.Period, got)
		}
	}
}

// revokeStub is a node for device revoke: its version (or an error for
// GetStatus), its answer to RevokeDevice, its invites.
type revokeStub struct {
	nodev1connect.NodeServiceClient
	version   string
	statusErr error
	answer    *nodev1.RevokeDeviceResponse
	invites   []string
	revoked   []*nodev1.RevokeDeviceRequest
}

func (s *revokeStub) GetStatus(context.Context, *connect.Request[nodev1.GetStatusRequest]) (*connect.Response[nodev1.GetStatusResponse], error) {
	if s.statusErr != nil {
		return nil, s.statusErr
	}
	return connect.NewResponse(&nodev1.GetStatusResponse{Version: s.version}), nil
}

func (s *revokeStub) RevokeDevice(_ context.Context, req *connect.Request[nodev1.RevokeDeviceRequest]) (*connect.Response[nodev1.RevokeDeviceResponse], error) {
	s.revoked = append(s.revoked, req.Msg)
	return connect.NewResponse(s.answer), nil
}

func (s *revokeStub) ListDevices(context.Context, *connect.Request[nodev1.ListDevicesRequest]) (*connect.Response[nodev1.ListDevicesResponse], error) {
	r := &nodev1.ListDevicesResponse{Devices: []*nodev1.Device{{Id: "d2", User: "alice", Name: "laptop"}}}
	for _, id := range s.invites {
		r.Invites = append(r.Invites, &nodev1.Invite{Id: id, User: "alice", Name: "tablet"})
	}
	return connect.NewResponse(r), nil
}

// device revoke -overlap: a node whose version it cannot read gets no
// revocation; -json says on stderr what the text would beside the answer;
// an invite is withdrawn by a node before v0.31.0 too, a device not
// (review 2, R5, R6, nit 6).
func TestDeviceRevokeOverlapChecks(t *testing.T) {
	ctx := context.Background()
	run := func(c *cli, args ...string) (string, string, error) {
		t.Helper()
		return captureBoth(t, func() error { return c.run(ctx, append([]string{"device", "revoke"}, args...)) })
	}

	down := &revokeStub{statusErr: connect.NewError(connect.CodeUnavailable, errors.New("rayd is restarting"))}
	if _, _, err := run(&cli{c: down}, "-overlap", "d1"); err == nil || len(down.revoked) != 0 {
		t.Errorf("GetStatus failed: %v, revoked %v", err, down.revoked)
	}

	older := &revokeStub{version: "dev", answer: &nodev1.RevokeDeviceResponse{User: "alice", Device: "phone", Credentials: 2}}
	out, errOut, err := run(&cli{c: older, json: true}, "-overlap", "d1")
	if err != nil || !strings.Contains(errOut, "older than v0.31.0") || !strings.Contains(out, `"credentials"`) {
		t.Errorf("-json, revoked without overlap: %q %q %v", out, errOut, err)
	}

	until := time.Now().Add(time.Hour).Unix()
	overlapped := &revokeStub{version: "v0.31.0", answer: &nodev1.RevokeDeviceResponse{User: "alice", Device: "phone", Credentials: 2,
		SwitchAt: until - 1800, Until: until}}
	if out, errOut, err := run(&cli{c: overlapped, json: true}, "-overlap", "d1"); err != nil || errOut != "" || !strings.Contains(out, `"switchAt"`) || strings.Contains(out, `"0"`) {
		t.Errorf("-json, with overlap: %q %q %v", out, errOut, err)
	}

	invite := &revokeStub{version: "v0.30.2", invites: []string{"i1"}, answer: &nodev1.RevokeDeviceResponse{Invite: true}}
	if out, _, err := run(&cli{c: invite}, "-overlap", "i1"); err != nil || !strings.Contains(out, "invite i1 withdrawn") || len(invite.revoked) != 1 {
		t.Errorf("an invite on v0.30.2: %q %v", out, err)
	}
	if _, _, err := run(&cli{c: invite}, "-overlap", "d1"); err == nil || !strings.Contains(err.Error(), "Nothing revoked") || len(invite.revoked) != 1 {
		t.Errorf("a device on v0.30.2: %v, revoked %v", err, invite.revoked)
	}
}
