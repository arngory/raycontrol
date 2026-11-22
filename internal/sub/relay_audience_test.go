package sub_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
)

// relay-v1 §4.1 with traffic-limit-v1 §4 and client-min-v1 §4: a user over
// the limit gets no profiles and keeps the relays it may go through, so
// that its client can update through one (app-update-v1).
func TestRelayAudienceExhaustedKeepsRelays(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	srv := &sub.Server{Store: f.st, Keys: f.keys, Log: quiet()}
	reality, err := provision.CreateService(ctx, f.st, store.Service{Kind: "reality", Name: "reality", Enabled: true,
		Settings: `{"target":"www.example.org:443"}`})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.SetUserServices(ctx, "alice", []int64{reality.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.CreateRelay(ctx, "r1", netip.MustParseAddr("198.51.100.20")); err != nil {
		t.Fatal(err)
	}
	if err := f.st.SetRelayCertPin(ctx, "r1", "pin"); err != nil {
		t.Fatal(err)
	}
	build := func() sub.Payload {
		env, err := srv.BuildForDevice(ctx, "alice", f.key[:], netip.Addr{}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		p, err := sub.Verify(env, f.keys.PublicJSON())
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if p := build(); len(p.Relays) != 1 {
		t.Fatalf("under the limit: relays %+v", p.Relays)
	}
	limit := int64(1000)
	u, err := f.st.SetUserTraffic(ctx, "alice", store.TrafficChange{Limit: &limit})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.WriteTraffic(ctx, store.TrafficWrite{Adds: []store.TrafficAdd{{UserID: u.ID, Start: u.TrafficStart, Up: 700, Down: 300}}}); err != nil {
		t.Fatal(err)
	}
	p := build()
	if p.Traffic == nil || !p.Traffic.Exhausted {
		t.Fatalf("not exhausted: %+v", p.Traffic)
	}
	if len(p.Relays) != 1 {
		t.Errorf("a user over the limit: relays %+v, want them kept (traffic-limit-v1 §4)", p.Relays)
	}
}
