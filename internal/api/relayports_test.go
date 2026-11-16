package api

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/provision"
)

// A relay's ports (Relay.ports, IssueRelayBundleResponse.ports) are what
// its perimeter takes from outside, no more and no less: its SSH for its
// admin addresses, its SPA range, its probe endpoint, and the exit's
// ports it forwards (TCP and UDP 443, the subscription, the API), never
// the exit's SSH, a public DNS tunnel or a UDP rotation range. They follow
// the exit's services without a new bundle.
func TestRelayPorts(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := NewUnixClient(sock)
	for _, s := range []*nodev1.CreateServiceRequest{
		{Kind: "api", Name: "api"},
		{Kind: "reality", Name: "reality", SettingsJson: `{"target":"www.example.org:443"}`},
		{Kind: "hy2-masq", Name: "hy2"},
		{Kind: "dnstt", Name: "dns"},
		{Kind: "ssh", Name: "ssh", SettingsJson: `{"ports":["tcp/2222"]}`},
	} {
		if _, err := c.CreateService(ctx, connect.NewRequest(s)); err != nil {
			t.Fatal(s.Name, err)
		}
	}
	added, err := c.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: "r1", Address: "198.51.100.20"}))
	if err != nil {
		t.Fatal(err)
	}
	relayPorts := func() []*nodev1.RelayPort {
		t.Helper()
		r, err := c.ListRelays(ctx, connect.NewRequest(&nodev1.ListRelaysRequest{}))
		if err != nil || len(r.Msg.Relays) != 1 {
			t.Fatalf("list %v %v", r, err)
		}
		return r.Msg.Relays[0].Ports
	}
	show := func(ports []*nodev1.RelayPort) []string {
		var out []string
		for _, p := range ports {
			to := "relay"
			if p.Forwarded {
				to = "exit"
			}
			span := fmt.Sprint(p.From)
			if p.To != p.From {
				span = "range"
			}
			out = append(out, fmt.Sprintf("%s %s %s %s %s", p.Name, strings.Join(p.Protos, "+"), span, to, p.Access))
		}
		return out
	}
	sub, _ := srv.Store.ServiceByName(ctx, "subscription")
	subPorts, _ := sub.Ports()
	api, _ := srv.apiEndpoint(ctx)
	forwarded := []string{
		fmt.Sprintf("sub tcp+udp %d exit spa", subPorts[0].Num), fmt.Sprintf("api tcp %d exit spa", api.endpoint.Port),
		"reality tcp 443 exit spa", "hy2 udp 443 exit spa",
	}
	// Before a bundle: the relay host's SSH (22 at first) and what it
	// forwards; no SPA range or probe endpoint yet.
	before := show(relayPorts())
	if !slices.Equal(before, append([]string{"ssh tcp 22 relay admin"}, forwarded...)) {
		t.Fatalf("before the bundle %q", before)
	}
	if got := show(added.Msg.Relay.Ports); !slices.Equal(got, before) {
		t.Errorf("added %q", got)
	}

	issued, err := srv.issueRelayBundle(ctx, &nodev1.IssueRelayBundleRequest{Name: "r1", ExitAddress: "203.0.113.7", SshPort: 2200,
		Admin: []string{"192.0.2.7"}})
	if err != nil {
		t.Fatal(err)
	}
	got := show(issued.Ports)
	want := append([]string{"ssh tcp 2200 relay admin", "spa tcp+udp range relay everyone",
		fmt.Sprintf("probe tcp+udp %d relay spa", issued.ProbePort)}, forwarded...)
	if !slices.Equal(got, want) {
		t.Fatalf("with the bundle %q, want %q", got, want)
	}
	listed := relayPorts()
	if len(listed) != len(issued.Ports) || !slices.EqualFunc(listed, issued.Ports, func(a, b *nodev1.RelayPort) bool { return proto.Equal(a, b) }) {
		t.Fatalf("listed %q, bundle %q", show(listed), got)
	}
	params, err := provision.RelayParams(ctx, srv.Store, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if spa := issued.Ports[1]; spa.From != uint32(params.PortBase) || spa.To != uint32(params.PortBase)+uint32(params.PortRange)-1 {
		t.Fatalf("spa %v, params %d+%d", spa, params.PortBase, params.PortRange)
	}

	// No more and no less than the relay's perimeter: every port of its
	// snapshot is listed, and every port listed is in its snapshot.
	per := &PerimeterServer{Server: srv, DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour, TCPCarrier: true}
	snap, err := per.RelaySnapshot(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	inSnap := map[string]bool{}
	for _, s := range snap.Services {
		for _, p := range s.Ports {
			inSnap[fmt.Sprintf("%s/%d", p.Proto, p.Port)] = true
		}
	}
	for _, p := range snap.AdminPorts {
		inSnap[fmt.Sprintf("%s/%d", p.Proto, p.Port)] = true
	}
	for port := range snap.Spa.PortRange {
		for _, proto := range []string{"tcp", "udp"} {
			inSnap[fmt.Sprintf("%s/%d", proto, snap.Spa.PortBase+port)] = true
		}
	}
	inList := map[string]bool{}
	for _, p := range listed {
		for port := p.From; port <= p.To; port++ {
			for _, proto := range p.Protos {
				inList[fmt.Sprintf("%s/%d", proto, port)] = true
			}
		}
	}
	if !maps.Equal(inSnap, inList) {
		for k := range inSnap {
			if !inList[k] {
				t.Errorf("%s: in the relay's perimeter, not listed", k)
			}
		}
		for k := range inList {
			if !inSnap[k] {
				t.Errorf("%s: listed, not in the relay's perimeter", k)
			}
		}
	}

	// The exit's services change the forwarded ports, without a bundle.
	if _, err := c.SetServiceEnabled(ctx, connect.NewRequest(&nodev1.SetServiceEnabledRequest{Name: "hy2"})); err != nil {
		t.Fatal(err)
	}
	if got := show(relayPorts()); slices.Contains(got, "hy2 udp 443 exit spa") || !slices.Contains(got, "reality tcp 443 exit spa") ||
		!slices.Contains(got, "ssh tcp 2200 relay admin") {
		t.Fatalf("with hy2 off %q", got)
	}
}
