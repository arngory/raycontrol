package api

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	devicev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/device/v1"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/spa"
)

// A Register repeated for an invite already used (api-v1 §4.1): the same
// certificate within the window gets the same device and bundle again,
// rcinv1 and rcinv2 alike, with the proofs checked again and nothing new
// made; another certificate, a wrong PIN, a revoked device or a later
// time get not_found as before. Duplicates sent at once all get the one
// device.
func TestRemoteRegisterReplay(t *testing.T) {
	var (
		mu   sync.Mutex
		skew time.Duration
	)
	at := func(d time.Duration) { mu.Lock(); skew = d; mu.Unlock() }
	srv, sock, _ := startServerWith(t, func(s *Server) []func() (string, http.Handler) {
		s.Store.SetClock(func() time.Time { mu.Lock(); defer mu.Unlock(); return time.Now().Add(skew) })
		return nil
	})
	ctx := context.Background()
	c := NewUnixClient(sock)
	if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "alice"})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "api", Name: "api"})); err != nil {
		t.Fatal(err)
	}
	addr, pin := startRemote(t, srv)
	now := time.Now().Unix() / 60
	invite := func(name string, withPIN bool) *nodev1.CreateInviteResponse {
		t.Helper()
		resp, err := c.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{User: "alice", Name: name, Role: "admin", Pin: withPIN}))
		if err != nil {
			t.Fatal(err)
		}
		return resp.Msg
	}
	devices := func() int {
		t.Helper()
		list, err := c.ListDevices(ctx, connect.NewRequest(&nodev1.ListDevicesRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return len(list.Msg.Devices)
	}
	audits := func(action string) int {
		t.Helper()
		a, err := c.ListAudit(ctx, connect.NewRequest(&nodev1.ListAuditRequest{Limit: 100}))
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range a.Msg.Entries {
			if e.Action == action {
				n++
			}
		}
		return n
	}

	for _, short := range []bool{false, true} {
		name := fmt.Sprintf("phone-%v", short)
		inv := invite(name, true)
		code := inv.InviteCode
		if short {
			code = inv.InviteCodeShort
		}
		d := newRemoteDevice(t, addr, pin)
		first, err := d.registerPIN(ctx, code, now, inv.Pin)
		if err != nil {
			t.Fatal(err)
		}
		n, registered := devices(), audits("device.register:admin")
		again, err := d.registerPIN(ctx, code, now, inv.Pin)
		if err != nil {
			t.Fatalf("%s: a repeated Register: %v", name, err)
		}
		if again.DeviceId != first.DeviceId || again.Role != first.Role || again.Bundle != first.Bundle {
			t.Fatalf("%s: a repeated Register: %+v, first %+v", name, again, first)
		}
		if devices() != n || audits("device.register:admin") != registered || audits("device.register-replay:admin") == 0 {
			t.Fatalf("%s: a repeated Register made records", name)
		}
		// The proofs still hold: a wrong PIN, none, a stale minute, another key.
		wrong := fmt.Sprintf("%06d", (mustAtoi(t, inv.Pin)+1)%1_000_000)
		if _, err := d.registerPIN(ctx, code, now, wrong); connect.CodeOf(err) != connect.CodeNotFound {
			t.Fatalf("%s: a repeat with a wrong PIN: %v", name, err)
		}
		if _, err := d.registerPIN(ctx, code, now, ""); connect.CodeOf(err) != connect.CodeNotFound {
			t.Fatalf("%s: a repeat without the PIN: %v", name, err)
		}
		if _, err := d.registerPIN(ctx, code, now-5, inv.Pin); connect.CodeOf(err) != connect.CodeNotFound {
			t.Fatalf("%s: a repeat with a stale minute: %v", name, err)
		}
		if _, err := newRemoteDevice(t, addr, pin).registerPIN(ctx, code, now, inv.Pin); connect.CodeOf(err) != connect.CodeNotFound {
			t.Fatalf("%s: the invite used again by another key: %v", name, err)
		}
	}

	// Duplicates at once: one device, the same answer to each.
	inv := invite("tablet", false)
	d := newRemoteDevice(t, addr, pin)
	n := devices()
	var wg sync.WaitGroup
	got := make([]*devicev1.RegisterResponse, 8)
	errs := make([]error, len(got))
	for i := range got {
		wg.Go(func() { got[i], errs[i] = d.register(ctx, inv.InviteCode, now) })
	}
	wg.Wait()
	for i := range got {
		if errs[i] != nil || got[i].DeviceId != got[0].DeviceId || got[i].Bundle != got[0].Bundle {
			t.Fatalf("duplicate %d: %v", i, errs[i])
		}
	}
	if devices() != n+1 {
		t.Fatalf("%d devices from duplicates", devices()-n)
	}
	invID := inv.Invite.Id
	inScope := func() bool {
		t.Helper()
		ds, err := srv.Store.SPADevices(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(ds, func(x spa.Device) bool { return x.ID == invID })
	}
	if !inScope() {
		t.Fatal("a used invite closes SPA before its replay window ends")
	}

	// After the window: not_found, and the invite's SPA is closed.
	at(16 * time.Minute)
	if _, err := d.register(ctx, inv.InviteCode, now); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("a repeat after the window: %v", err)
	}
	if inScope() {
		t.Fatal("a used invite passes SPA after its replay window")
	}

	// A revoked device: not_found at once, and no SPA either.
	at(0)
	inv = invite("watch", false)
	d = newRemoteDevice(t, addr, pin)
	reg, err := d.register(ctx, inv.InviteCode, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.RevokeDevice(ctx, connect.NewRequest(&nodev1.RevokeDeviceRequest{Id: reg.DeviceId})); err != nil {
		t.Fatal(err)
	}
	if _, err := d.register(ctx, inv.InviteCode, now); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("a repeat for a revoked device: %v", err)
	}
	invID = inv.Invite.Id
	if inScope() {
		t.Fatal("the invite of a revoked device passes SPA")
	}
}
