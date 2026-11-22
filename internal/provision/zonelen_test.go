package provision

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/clientver"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/store"
)

// zoneOf is a zone of n characters (16 or more) under example.net, in
// labels of 60 and the rest.
func zoneOf(n int) string {
	rest := n - len(".example.net")
	var parts []string
	for rest > 63 {
		parts = append(parts, strings.Repeat("a", 60))
		rest -= 61
	}
	parts = append(parts, strings.Repeat("a", rest))
	return strings.Join(parts, ".") + ".example.net"
}

func TestZoneOf(t *testing.T) {
	for _, n := range []int{20, 21, 29, 30, 72, 73, 116, 117, 120, 121, 134, 135} {
		if z := zoneOf(n); len(z) != n || !zoneName.MatchString(z) {
			t.Errorf("%d: %q (%d)", n, z, len(z))
		}
	}
}

// docs/spec/dns-zone-length-v1.md: the limits by kind, and the longer ones
// only while a minimum of Niko 1.66.0 or later holds.
func TestZoneMax(t *testing.T) {
	now := time.Now()
	long := clientver.Policy{Min: map[string]string{"niko": "1.66.0"}}
	for _, c := range []struct {
		p                      clientver.Policy
		dnstt, slip, md, other int
	}{
		{clientver.Policy{}, 72, 20, 116, 0},
		{clientver.Policy{Min: map[string]string{"niko": "1.65.9"}}, 72, 20, 116, 0},
		{long, 120, 29, 116, 0},
		{clientver.Policy{Min: map[string]string{"niko": "1.66.9"}}, 120, 29, 116, 0},
		{clientver.Policy{Min: map[string]string{"niko": "1.67.0"}}, 120, 134, 116, 0},
		{clientver.Policy{Min: map[string]string{"niko": "1.70.0"}}, 120, 134, 116, 0},
		{clientver.Policy{Min: map[string]string{"niko": "1.67.0"}, From: now.Add(time.Hour).Unix()}, 72, 20, 116, 0},
		{clientver.Policy{Min: map[string]string{"niko": "1.66.0-pre.1"}}, 72, 20, 116, 0}, // a pre-release comes before
		{clientver.Policy{Min: map[string]string{"other": "9.0.0"}}, 72, 20, 116, 0},
		{clientver.Policy{Min: map[string]string{"niko": "1.66.0"}, From: now.Add(time.Hour).Unix()}, 72, 20, 116, 0}, // not yet
	} {
		got := []int{ZoneMax("dnstt", c.p, now), ZoneMax("slipstream", c.p, now), ZoneMax("masterdns", c.p, now), ZoneMax("hy2-masq", c.p, now)}
		if got[0] != c.dnstt || got[1] != c.slip || got[2] != c.md || got[3] != c.other {
			t.Errorf("%+v: %v", c.p, got)
		}
	}
}

// A zone past its tunnel's limit is refused when the service is made, as a
// spare zone, and as the main zone a spare one becomes; under a minimum of
// Niko 1.66.0 dnstt and slipstream take longer ones.
func TestZoneLengthRefused(t *testing.T) {
	ctx, st := slipStore(t, "example.com")
	create := func(kind, name string, settings map[string]any) (store.Service, error) {
		b, _ := json.Marshal(settings)
		return CreateService(ctx, st, store.Service{Kind: kind, Name: name, Enabled: true, Settings: string(b)})
	}
	n := 0
	try := func(kind string, length int, ok bool) {
		t.Helper()
		n++
		name := fmt.Sprintf("%s%d", kind[:2], n)
		_, err := create(kind, name, map[string]any{"zone": zoneOf(length)})
		switch {
		case ok && err != nil:
			t.Errorf("%s zone of %d: %v", kind, length, err)
		case !ok && !errors.Is(err, store.ErrInvalid):
			t.Errorf("%s zone of %d: %v, want refused", kind, length, err)
		case !ok && !strings.Contains(err.Error(), "zone=") || !ok && !strings.Contains(err.Error(), "dns-zone-length"):
			t.Errorf("%s zone of %d: %v, want the limit and zone= named", kind, length, err)
		}
	}
	// zoneOf makes the same name for a length: one service per length.
	try("dnstt", 72, true)
	try("dnstt", 73, false)
	try("masterdns", 116, true)
	try("masterdns", 117, false)
	try("slipstream", 20, true)
	try("slipstream", 21, false)

	// A spare zone, given or made, the same.
	d, err := create("dnstt", "spare", map[string]any{"zone": "d.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SetServiceOption(ctx, st, d.Name, "spare_zones", "b"+zoneOf(72)[1:]+","+zoneOf(73)); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("a spare zone of 73: %v", err)
	}

	// Under a minimum of Niko 1.66.0: up to 120 and 29.
	if _, err := node.SetClientPolicy(ctx, st, clientver.Policy{Min: map[string]string{"niko": "1.66.0"}}); err != nil {
		t.Fatal(err)
	}
	try("dnstt", 120, true)
	try("dnstt", 121, false)
	try("slipstream", 29, true)
	try("slipstream", 30, false)
	try("masterdns", 117, false)
	if _, err := SetServiceOption(ctx, st, d.Name, "spare_zones", "c"+zoneOf(119)[1:]); err != nil {
		t.Errorf("a spare zone of 119 under the minimum: %v", err)
	}

	// The minimum taken away: the spare of 119 does not become the main zone.
	if _, err := node.SetClientPolicy(ctx, st, clientver.Policy{}); err != nil {
		t.Fatal(err)
	}
	if _, err := SetServiceOption(ctx, st, d.Name, "zone", "c"+zoneOf(119)[1:]); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("a spare of 119 made the main zone with no minimum: %v", err)
	}
	all, err := st.ListServices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	long := ZonesTooLong(all, clientver.Policy{}, time.Now())
	if len(long) != 3 { // dnstt 120 and the spare of 119, slipstream 29
		t.Errorf("too long with no minimum: %v", long)
	}
	if w := ZoneWarnings(all, clientver.Policy{}, time.Now()); len(w) != 4 { // the three, and masterdns 116 past 100
		t.Errorf("warnings: %v", w)
	}
}

// slipstream from Niko 1.67.0 (server-v0.3.0's picoquic): up to 134; the
// refusal names the oldest Niko that takes the zone, and a minimum that
// would let older clients back in is refused naming 1.67.0.
func TestZoneLengthSlipstreamLong(t *testing.T) {
	ctx, st := slipStore(t, "example.com")
	create := func(name string, length int) error {
		b, _ := json.Marshal(map[string]any{"zone": zoneOf(length)})
		_, err := CreateService(ctx, st, store.Service{Kind: "slipstream", Name: name, Enabled: true, Settings: string(b)})
		return err
	}
	if err := create("s1", 25); err == nil || !strings.Contains(err.Error(), "Niko 1.66.0 only") {
		t.Errorf("25 with no minimum: %v, want 1.66.0 named", err)
	}
	if err := create("s2", 100); err == nil || !strings.Contains(err.Error(), "Niko 1.67.0 only") || !strings.Contains(err.Error(), ", 134") {
		t.Errorf("100 with no minimum: %v, want 1.67.0 and 134 named", err)
	}
	if _, err := node.SetClientPolicy(ctx, st, clientver.Policy{Min: map[string]string{"niko": "1.66.0"}}); err != nil {
		t.Fatal(err)
	}
	if err := create("s3", 30); err == nil || !strings.Contains(err.Error(), "Niko 1.67.0 only") {
		t.Errorf("30 under 1.66.0: %v, want 1.67.0 named", err)
	}
	if _, err := node.SetClientPolicy(ctx, st, clientver.Policy{Min: map[string]string{"niko": "1.67.0"}}); err != nil {
		t.Fatal(err)
	}
	if err := create("s4", 134); err != nil {
		t.Errorf("134 under 1.67.0: %v", err)
	}
	if err := create("s5", 135); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("135 under 1.67.0: %v, want refused", err)
	}
	svc, err := st.ServiceByName(ctx, "s4")
	if err != nil {
		t.Fatal(err)
	}
	if ss, err := ParseSlipstream(svc); err != nil || len(ss.Zone) != 134 {
		t.Errorf("the zone of 134 read back: %q %v", ss.Zone, err)
	}
	all, err := st.ListServices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		min  string
		long int
	}{{"", 1}, {"1.66.0", 1}, {"1.67.0", 0}} {
		p := clientver.Policy{}
		if c.min != "" {
			p.Min = map[string]string{"niko": c.min}
		}
		if got := ZonesTooLong(all, p, time.Now()); len(got) != c.long {
			t.Errorf("too long under %q: %v", c.min, got)
		}
	}
	if v := ZoneClient("slipstream", 134); v != SlipstreamLongZoneClient {
		t.Errorf("ZoneClient 134: %q", v)
	}
	if v := ZoneClient("slipstream", 29); v != LongZoneClient {
		t.Errorf("ZoneClient 29: %q", v)
	}
	if v := ZoneClient("slipstream", 20); v != "" {
		t.Errorf("ZoneClient 20: %q", v)
	}
	if v := ZoneClient("dnstt", 120); v != LongZoneClient {
		t.Errorf("ZoneClient dnstt 120: %q", v)
	}
}

// A long node domain: the zone made under it is refused with the hint, for
// dnstt and masterdns as for slipstream.
func TestZoneLengthLongDomain(t *testing.T) {
	domain := zoneOf(69) // a zone under it: 4 more, 73
	ctx, st := slipStore(t, domain)
	if _, err := CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "d", Enabled: true}); !errors.Is(err, store.ErrInvalid) ||
		!strings.Contains(err.Error(), "zone=") {
		t.Errorf("dnstt under a domain of 69: %v", err)
	}
	if _, err := CreateService(ctx, st, store.Service{Kind: "masterdns", Name: "m", Enabled: true}); err != nil {
		t.Errorf("masterdns under a domain of 69: %v", err)
	}
}
