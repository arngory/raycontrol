package api

import (
	"bytes"
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
)

// hy2-obfs rotates its S only when the front takes salamander off with
// the devices' passwords (niko-server v0.19.3, spec/salamander-device-v1.md
// §3): the next one published, its switch a lead away, the current one
// accepted for the grace after; with now, at once. Before, as today: not
// a kind that rotates.
func TestRotateObfs(t *testing.T) {
	srv, sock, _ := startServer(t)
	srv.RealityLead, srv.CredGrace = 72*time.Hour, 48*time.Hour
	rotated := 0
	srv.Rotate = func() { rotated++ }
	ctx := context.Background()
	c := NewUnixClient(sock)
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "hy2-obfs", Name: "hy2o"})); err != nil {
		t.Fatal(err)
	}
	if !render.SalamanderDevice() {
		if _, err := c.RotateService(ctx, connect.NewRequest(&nodev1.RotateServiceRequest{Name: "hy2o"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("old mode: %v", err)
		}
	}
	defer render.UseNikoServer("v0.19.3")()
	svc, _ := srv.Store.ServiceByName(ctx, "hy2o")
	before, _ := srv.Store.ServiceSecrets(ctx, svc.ID)
	start := time.Now().Unix()
	r, err := c.RotateService(ctx, connect.NewRequest(&nodev1.RotateServiceRequest{Name: "hy2o"}))
	if err != nil || r.Msg.Kind != "hy2-obfs" || rotated != 1 || r.Msg.SwitchAt < start+72*3600 || r.Msg.SwitchAt > time.Now().Add(72*time.Hour).Unix() ||
		r.Msg.PrevUntil != r.Msg.SwitchAt+48*3600 {
		t.Fatalf("rotate: %v %v", r, err)
	}
	after, _ := srv.Store.ServiceSecrets(ctx, svc.ID)
	if !bytes.Equal(after[provision.SecretObfsPassword], before[provision.SecretObfsPassword]) ||
		len(after[provision.NextSecret(provision.SecretObfsPassword)]) != 32 {
		t.Fatal("no next S, or the current one changed")
	}
	if r, err = c.RotateService(ctx, connect.NewRequest(&nodev1.RotateServiceRequest{Name: "hy2o", Now: true})); err != nil || r.Msg.PrevUntil != 0 || r.Msg.SwitchAt > time.Now().Unix() {
		t.Fatalf("rotate now: %v %v", r, err)
	}
	now, _ := srv.Store.ServiceSecrets(ctx, svc.ID)
	if bytes.Equal(now[provision.SecretObfsPassword], before[provision.SecretObfsPassword]) || now[provision.NextSecret(provision.SecretObfsPassword)] != nil {
		t.Fatal("-now: S kept, or a next")
	}
}
