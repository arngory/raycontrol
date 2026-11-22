package api

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/clientver"
	devicev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/device/v1"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/spa"
)

// client-min-v1 §2, §4: the policy through the API, and a Register below the
// minimum refused before the invite is used, so that the same invite works
// after the update.
func TestClientPolicy(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "alice"})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "api", Name: "api"})); err != nil {
		t.Fatal(err)
	}
	r, err := c.GetClientPolicy(ctx, connect.NewRequest(&nodev1.GetClientPolicyRequest{}))
	if err != nil || len(r.Msg.Policy.GetMin()) != 0 {
		t.Fatalf("no policy: %+v %v", r, err)
	}
	for _, bad := range []*nodev1.ClientPolicy{{Min: map[string]string{"niko": "v1.59"}}, {Min: map[string]string{"Niko": "1.59.0"}}} {
		if _, err := c.SetClientPolicy(ctx, connect.NewRequest(&nodev1.SetClientPolicyRequest{Policy: bad})); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("%v: %v", bad, err)
		}
	}
	set, err := c.SetClientPolicy(ctx, connect.NewRequest(&nodev1.SetClientPolicyRequest{Policy: &nodev1.ClientPolicy{Min: map[string]string{"niko": "1.59.0"}}}))
	if err != nil || set.Msg.Policy.GetMin()["niko"] != "1.59.0" {
		t.Fatalf("set: %+v %v", set, err)
	}

	addr, pin := startRemote(t, srv)
	rd := newRemoteDevice(t, addr, pin)
	resp, err := c.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: "alice", Name: "phone"}))
	if err != nil {
		t.Fatal(err)
	}
	inv, err := node.DecodeInvite(resp.Msg.InviteCode)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := hex.DecodeString(inv.DeviceKey)
	register := func(client string) error {
		minute := time.Now().Unix() / 60
		req := connect.NewRequest(&devicev1.RegisterRequest{InviteId: inv.DeviceID, Minute: minute,
			Mac: RegisterMAC([spa.KeySize]byte(k), minute, CertPin(rd.cert.Leaf))})
		if client != "" {
			req.Header().Set(clientver.MetadataKey, client)
		}
		_, err := rd.dev.Register(ctx, req)
		return err
	}
	err = register("niko/1.58.0 (android; arm64-v8a)")
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "client too old: min niko 1.59.0") {
		t.Fatalf("below the minimum: %v", err)
	}
	if err := register("niko/1.59.0 (android; arm64-v8a)"); err != nil {
		t.Fatalf("the same invite after the update: %v", err)
	}
	// Taken away: no minimum.
	if r, err := c.SetClientPolicy(ctx, connect.NewRequest(&nodev1.SetClientPolicyRequest{Policy: &nodev1.ClientPolicy{}})); err != nil || len(r.Msg.Policy.GetMin()) != 0 {
		t.Fatalf("taken away: %+v %v", r, err)
	}
}

// docs/spec/dns-zone-length-v1.md: a dnstt zone of 100 characters, taken
// under a minimum of Niko 1.66.0, keeps a lower minimum out, and none; the
// status warns of a zone too long once the minimum is gone by other ways.
func TestClientPolicyZoneLength(t *testing.T) {
	_, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	zone := strings.Repeat("a", 60) + "." + strings.Repeat("b", 27) + ".example.net" // 100
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "dnstt", Name: "d",
		SettingsJson: `{"zone":"` + zone + `"}`})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("a dnstt zone of 100 with no minimum: %v", err)
	}
	set := func(min string) error {
		p := &nodev1.ClientPolicy{}
		if min != "" {
			p.Min = map[string]string{"niko": min}
		}
		_, err := c.SetClientPolicy(ctx, connect.NewRequest(&nodev1.SetClientPolicyRequest{Policy: p}))
		return err
	}
	if err := set("1.66.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "dnstt", Name: "d",
		SettingsJson: `{"zone":"` + zone + `"}`})); err != nil {
		t.Fatalf("a dnstt zone of 100 under niko 1.66.0: %v", err)
	}
	for _, min := range []string{"1.65.0", ""} {
		if err := set(min); connect.CodeOf(err) != connect.CodeInvalidArgument || !strings.Contains(err.Error(), "d "+zone) || !strings.Contains(err.Error(), "minimum of niko 1.66.0") {
			t.Errorf("minimum %q with the zone of 100: %v", min, err)
		}
	}
	if err := set("1.70.0"); err != nil {
		t.Errorf("a higher minimum: %v", err)
	}
	// A slipstream zone of 100 needs 1.67.0, and the refusal of a lower
	// minimum names it.
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "slipstream", Name: "s",
		SettingsJson: `{"zone":"s` + zone[1:] + `"}`})); err != nil {
		t.Fatalf("a slipstream zone of 100 under niko 1.70.0: %v", err)
	}
	if err := set("1.66.0"); connect.CodeOf(err) != connect.CodeInvalidArgument || !strings.Contains(err.Error(), "minimum of niko 1.67.0") {
		t.Errorf("minimum 1.66.0 with the slipstream zone of 100: %v", err)
	}
	if err := set("1.67.0"); err != nil {
		t.Errorf("minimum 1.67.0: %v", err)
	}
}
