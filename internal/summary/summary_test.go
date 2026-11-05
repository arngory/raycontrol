package summary

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/asn"
	"github.com/arngory/raycontrol/internal/store"
)

type fakeASN map[string]asn.Info

func (f fakeASN) Lookup(_ context.Context, a netip.Addr) (asn.Info, bool) {
	i, ok := f[a.String()]
	return i, ok
}

func TestParse(t *testing.T) {
	good := `{"v":1,"net":"cellular","obs":[{"svc":3,"result":"works","tcp_stall_kib":16,"udp":"0-1","mbps":"5-20"},{"svc":4,"result":"fails"}]}`
	r, err := Parse(strings.NewReader(good))
	if err != nil || len(r.Obs) != 2 || r.Obs[0].TCPStallKiB != 16 || r.UDPMTU != "" {
		t.Fatalf("good report: %+v %v", r, err)
	}
	// The network's UDP MTU, a bucket, at the top (Niko §20).
	if r, err := Parse(strings.NewReader(`{"v":1,"net":"wifi","udp_mtu":"1350-1472","obs":[{"svc":1,"result":"works"}]}`)); err != nil || r.UDPMTU != "1350-1472" {
		t.Fatalf("udp_mtu: %+v %v", r, err)
	}
	for _, bad := range []string{
		`{"v":2,"net":"wifi","obs":[{"svc":1,"result":"works"}]}`,
		`{"v":1,"net":"satellite","obs":[{"svc":1,"result":"works"}]}`,
		`{"v":1,"net":"wifi","obs":[]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":1,"result":"great"}]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":1,"result":"works","tcp_stall_kib":17}]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":1,"result":"works","udp":"3"}]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":1,"result":"works","mbps":"7"}]}`,
		`{"v":1,"net":"wifi","udp_mtu":"1300","obs":[{"svc":1,"result":"works"}]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":1,"result":"works","udp_mtu":"<1200"}]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":1,"result":"works"},{"svc":1,"result":"fails"}]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":0,"result":"works"}]}`,
		`{"v":1,"net":"wifi","mcc_mnc":"25001","obs":[{"svc":1,"result":"works"}]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":1,"kind":"reality","result":"works"}]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":1,"result":"works","dns":"dnscrypt"}]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":1,"result":"works","dns":"8.8.8.8"}]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":1,"result":"fails","dns":"doh"}]}`,
		`{"v":1,"net":"wifi","obs":[` + strings.Repeat(`{"svc":1,"result":"works"},`, 2000) + `]}`,
	} {
		if _, err := Parse(strings.NewReader(bad)); !errors.Is(err, ErrInvalid) {
			t.Errorf("accepted %.80s: %v", bad, err)
		}
	}
}

func node(t *testing.T) (*store.Store, *Collector, []string) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	var ids []int64
	for _, n := range []string{"a", "b", "c"} {
		svc, err := st.CreateService(ctx, store.Service{Kind: "ssh", Name: n, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, svc.ID)
	}
	var devices []string
	for i := range 12 {
		name := fmt.Sprintf("user%d", i)
		if _, err := st.CreateUser(ctx, store.User{Name: name, Enabled: true}); err != nil {
			t.Fatal(err)
		}
		st.SetUserServices(ctx, name, ids)
		d, _, err := st.CreateDevice(ctx, name, "phone", "user")
		if err != nil {
			t.Fatal(err)
		}
		devices = append(devices, d.ID)
	}
	c := &Collector{Store: st, ASN: fakeASN{
		"203.0.113.10": {ASN: 64500, Name: "Mobile One", Country: "KZ"},
		"203.0.113.11": {ASN: 64500, Name: "Mobile One", Country: "KZ"},
		"198.51.100.5": {ASN: 64501, Name: "Small Net", Country: "UZ"},
		// A network behind a white list: a relay passes its /24.
		"192.0.2.0":  {ASN: 64502, Name: "White Net", Country: "RU"},
		"192.0.2.77": {ASN: 64502, Name: "White Net", Country: "RU"},
	}}
	return st, c, devices
}

func TestTakeAndHints(t *testing.T) {
	ctx := context.Background()
	st, c, devices := node(t)
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	mobile := netip.MustParseAddr("203.0.113.10")
	report := func(device string, addr netip.Addr, body string) error {
		return c.Take(ctx, device, addr, strings.NewReader(body))
	}
	r1 := `{"v":1,"net":"cellular","udp_mtu":"<1200","obs":[{"svc":1,"result":"fails","udp":"none"},{"svc":2,"result":"works","tcp_stall_kib":16},{"svc":3,"result":"degraded","tcp_stall_kib":16}]}`

	if err := report(devices[0], mobile, r1); !errors.Is(err, ErrDisabled) {
		t.Fatalf("taken while off: %v", err)
	}
	SetEnabled(ctx, st, true)
	if err := report(devices[0], mobile, r1); err != nil {
		t.Fatal(err)
	}
	// The same device from the same AS, another address of it: once a day.
	if err := report(devices[0], netip.MustParseAddr("203.0.113.11"), r1); !errors.Is(err, ErrRepeated) {
		t.Fatalf("second report of the day: %v", err)
	}
	// From another network the same day: fine.
	if err := report(devices[0], netip.MustParseAddr("198.51.100.5"), r1); err != nil {
		t.Fatal(err)
	}
	// A service the user cannot use.
	if err := report(devices[1], mobile, `{"v":1,"net":"wifi","obs":[{"svc":99,"result":"works"}]}`); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a foreign service: %v", err)
	}
	if err := report("no-such-device", mobile, r1); err == nil {
		t.Fatal("unknown device")
	}

	svcs := []uint16{1, 2, 3}
	// Nine reports from AS 64500: fewer than K, no hint for anyone.
	for _, d := range devices[1:9] {
		if err := report(d, mobile, r1); err != nil {
			t.Fatal(err)
		}
	}
	if h := c.Hints(ctx, mobile, svcs); h != nil {
		t.Fatalf("a hint from 9 reports: %+v", h)
	}
	if err := report(devices[9], mobile, r1); err != nil {
		t.Fatal(err)
	}
	h := c.Hints(ctx, mobile, svcs)
	if h == nil || h.Devices != 10 || h.Days != Window || !slices.Equal(h.Order, []uint16{2, 3, 1}) ||
		!slices.Equal(h.Avoid, []uint16{1}) || !h.UDPBlocked || h.TCPStallKiB != 16 || h.UDPMTU != "<1200" {
		t.Fatalf("hint %+v", h)
	}
	// Only the client's own services; nothing for a small network, a
	// private address, or when reports are off.
	if h := c.Hints(ctx, mobile, []uint16{2}); h == nil || !slices.Equal(h.Order, []uint16{2}) || h.Avoid != nil || h.UDPBlocked {
		t.Fatalf("hint for one service %+v", h)
	}
	if h := c.Hints(ctx, netip.MustParseAddr("198.51.100.5"), svcs); h != nil {
		t.Fatalf("hint for a network of 1: %+v", h)
	}
	if h := c.Hints(ctx, netip.MustParseAddr("10.0.0.1"), svcs); h != nil {
		t.Fatal("hint for a private address")
	}

	// The view shows AS 64500 and folds the small one into others.
	nets, others, err := c.View(ctx, 7)
	if err != nil || len(nets) != 1 || nets[0].ASN != 64500 || nets[0].Name != "Mobile One" || nets[0].Reports != 10 ||
		nets[0].Nets["cellular"] != 10 || nets[0].Services[1]["result"]["fails"] != 10 || nets[0].MTU["<1200"] != 10 || others != 1 {
		t.Fatalf("view %+v others %d %v", nets, others, err)
	}

	// A week later the hint is gone; after Keep days so are the counters.
	now = now.Add(8 * 24 * time.Hour)
	if h := c.Hints(ctx, mobile, svcs); h != nil {
		t.Fatalf("hint after the window: %+v", h)
	}
	if err := report(devices[0], mobile, r1); err != nil {
		t.Fatalf("a new day: %v", err)
	}
	now = now.Add(Keep * 24 * time.Hour)
	if n, err := c.Prune(ctx); err != nil || n == 0 {
		t.Fatalf("prune %d %v", n, err)
	}
	if rows, _ := st.SummaryCounts(ctx, 0, 0, true); len(rows) != 0 {
		t.Fatalf("rows after pruning: %v", rows)
	}
	if names, _ := st.SummaryAS(ctx); len(names) != 0 {
		t.Fatalf("AS names after pruning: %v", names)
	}

	SetEnabled(ctx, st, false)
	if h := c.Hints(ctx, mobile, svcs); h != nil {
		t.Fatal("hint while off")
	}
}

func TestSetAPI(t *testing.T) {
	ctx := context.Background()
	st, _, _ := node(t)
	if err := SetAPI(ctx, st, "maxmind", "x"); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("unknown provider: %v", err)
	}
	if err := SetAPI(ctx, st, "ipinfo", ""); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("no token: %v", err)
	}
	st.SetSetting(ctx, settingAPI, []byte("ipinfo"))
	st.SetSetting(ctx, settingToken, []byte("tok"))
	if p, tok := API(ctx, st); p != "ipinfo" || tok != "tok" {
		t.Fatalf("API %q %q", p, tok)
	}
	if err := SetAPI(ctx, st, "none", ""); err != nil {
		t.Fatal(err)
	}
	if p, tok := API(ctx, st); p != "" || tok != "" {
		t.Fatalf("API after none %q %q", p, tok)
	}
}

func TestMajority(t *testing.T) {
	for _, c := range []struct {
		m    map[string]int64
		want string
	}{
		{map[string]int64{"<1200": 6, "1472+": 4}, "<1200"},
		{map[string]int64{"<1200": 5, "1472+": 5}, ""},
		{map[string]int64{"1350-1472": 9}, ""}, // fewer than K
		{nil, ""},
	} {
		if got := majority(c.m); got != c.want {
			t.Errorf("%v: %q, want %q", c.m, got, c.want)
		}
	}
}

// The path a report came by (relay-v1 §9.3): a relay passes the client's
// network and the report says relay; those reports make via_relay and stay
// out of the network's direct hints.
func TestPathAndViaRelay(t *testing.T) {
	ctx := context.Background()
	st, c, devices := node(t)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	SetEnabled(ctx, st, true)
	white := netip.MustParsePrefix("192.0.2.77/24")
	direct := netip.MustParseAddr("192.0.2.77")
	relayed := `{"v":1,"net":"cellular","path":"relay","obs":[{"svc":1,"result":"fails"}]}`
	straight := `{"v":1,"net":"cellular","path":"direct","obs":[{"svc":1,"result":"works"}]}`

	// The path says how the report came.
	if err := c.TakeVia(ctx, devices[0], white, strings.NewReader(straight)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a relay's report saying direct: %v", err)
	}
	if err := c.TakeVia(ctx, devices[0], white, strings.NewReader(`{"v":1,"net":"cellular","obs":[{"svc":1,"result":"fails"}]}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a relay's report without a path: %v", err)
	}
	if err := c.Take(ctx, devices[0], direct, strings.NewReader(relayed)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a direct report saying relay: %v", err)
	}
	if err := c.TakeVia(ctx, devices[0], netip.Prefix{}, strings.NewReader(relayed)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no network: %v", err)
	}
	if _, err := Parse(strings.NewReader(`{"v":1,"net":"wifi","path":"tunnel","obs":[{"svc":1,"result":"works"}]}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an unknown path: %v", err)
	}

	// Ten through the relay: a network behind a white list, so start with
	// the relay; nothing about its direct path yet.
	for _, d := range devices[:10] {
		if err := c.TakeVia(ctx, d, white, strings.NewReader(relayed)); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.TakeVia(ctx, devices[0], white, strings.NewReader(relayed)); !errors.Is(err, ErrRepeated) {
		t.Fatalf("twice a day through the relay: %v", err)
	}
	h := c.Hints(ctx, direct, []uint16{1})
	if h == nil || !h.ViaRelay || h.Order != nil || h.Avoid != nil || h.Devices != 10 {
		t.Fatalf("hint behind a white list: %+v", h)
	}

	// Next day ten come directly, and it works: direct hints from them alone
	// (the relay's fails do not count), and no longer mostly through the
	// relay.
	now = now.Add(24 * time.Hour)
	for _, d := range devices[:10] {
		if err := c.Take(ctx, d, direct, strings.NewReader(straight)); err != nil {
			t.Fatal(err)
		}
	}
	h = c.Hints(ctx, direct, []uint16{1})
	if h == nil || h.ViaRelay || !slices.Equal(h.Order, []uint16{1}) || h.Avoid != nil || h.Devices != 10 {
		t.Fatalf("hint with direct reports: %+v", h)
	}
}

// A DNS tunnel's observation names the kind of resolver it works through;
// the network's hint gives, per tunnel kind, the resolver most of them work
// through: their queries differ, and so do the resolvers that pass them.
func TestResolverHint(t *testing.T) {
	ctx := context.Background()
	st, c, devices := node(t)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	SetEnabled(ctx, st, true)
	var tunnels []int64
	for _, k := range []string{"dnstt", "masterdns"} {
		svc, err := st.CreateService(ctx, store.Service{Kind: k, Name: k, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		tunnels = append(tunnels, svc.ID)
	}
	for i := range devices {
		st.SetUserServices(ctx, fmt.Sprintf("user%d", i), []int64{1, tunnels[0], tunnels[1]})
	}
	dnstt, mdns := tunnels[0], tunnels[1]
	mobile := netip.MustParseAddr("203.0.113.10")
	body := func(dns1, dns2 string) string {
		return fmt.Sprintf(`{"v":1,"net":"cellular","obs":[{"svc":1,"result":"works"},{"svc":%d,"result":"works","dns":%q},{"svc":%d,"result":"degraded","dns":%q}]}`,
			dnstt, dns1, mdns, dns2)
	}

	// Only a DNS tunnel names a resolver.
	if err := c.Take(ctx, devices[0], mobile, strings.NewReader(`{"v":1,"net":"cellular","obs":[{"svc":1,"result":"works","dns":"udp"}]}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a resolver for a service that is no DNS tunnel: %v", err)
	}
	// A failing tunnel names none: it may be reported without one.
	if err := c.Take(ctx, devices[0], netip.MustParseAddr("198.51.100.5"), strings.NewReader(fmt.Sprintf(`{"v":1,"net":"cellular","obs":[{"svc":%d,"result":"fails"}]}`, dnstt))); err != nil {
		t.Fatal(err)
	}
	// Ten reports: dnstt through DoH, masterdns through UDP but for two
	// through DoH (8 of 10).
	for i, d := range devices[:10] {
		m := "udp"
		if i < 2 {
			m = "doh"
		}
		if err := c.Take(ctx, d, mobile, strings.NewReader(body("doh", m))); err != nil {
			t.Fatal(err)
		}
	}
	h := c.Hints(ctx, mobile, []uint16{1, uint16(dnstt), uint16(mdns)})
	if h == nil || h.DNS["dnstt"] != "doh" || h.DNS["masterdns"] != "udp" || len(h.DNS) != 2 || h.Devices != 10 {
		t.Fatalf("hint %+v", h)
	}
	// Only the client's own tunnels; none without them.
	if h := c.Hints(ctx, mobile, []uint16{1, uint16(mdns)}); h == nil || len(h.DNS) != 1 || h.DNS["masterdns"] != "udp" {
		t.Fatalf("hint with masterdns only %+v", h)
	}
	if h := c.Hints(ctx, mobile, []uint16{1}); h == nil || h.DNS != nil {
		t.Fatalf("hint without tunnels %+v", h)
	}
	nets, _, err := c.View(ctx, 7)
	if err != nil || len(nets) != 1 || nets[0].Services[mdns]["dns"]["doh"] != 2 || nets[0].Services[dnstt]["dns"]["doh"] != 10 {
		t.Fatalf("view %+v %v", nets, err)
	}

	// No majority, no resolver: two kinds half and half.
	now = now.Add(8 * 24 * time.Hour)
	for i, d := range devices[:10] {
		m := "doh"
		if i%2 == 0 {
			m = "dot"
		}
		if err := c.Take(ctx, d, mobile, strings.NewReader(body(m, m))); err != nil {
			t.Fatal(err)
		}
	}
	if h := c.Hints(ctx, mobile, []uint16{1, uint16(dnstt), uint16(mdns)}); h == nil || h.DNS != nil {
		t.Fatalf("hint without a majority %+v", h)
	}
}

// Direct reports from before path (v0.10.1) have no path row: they count
// against via_relay all the same.
func TestViaRelayCountsOldReports(t *testing.T) {
	ctx := context.Background()
	st, c, devices := node(t)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	SetEnabled(ctx, st, true)
	day := now.Unix() / dayS
	if err := st.AddSummary(ctx, []store.SummaryCount{{Day: day - 1, ASN: 64502, Field: "reports", N: 50}}, "White Net", "ZZ"); err != nil {
		t.Fatal(err)
	}
	relayed := `{"v":1,"net":"cellular","path":"relay","obs":[{"svc":1,"result":"fails"}]}`
	for _, d := range devices[:10] {
		if err := c.TakeVia(ctx, d, netip.MustParsePrefix("192.0.2.0/24"), strings.NewReader(relayed)); err != nil {
			t.Fatal(err)
		}
	}
	if h := c.Hints(ctx, netip.MustParseAddr("192.0.2.77"), []uint16{1}); h != nil && h.ViaRelay {
		t.Fatalf("10 of 60 reports through a relay make via_relay: %+v", h)
	}
}

// countingASN counts its lookups.
type countingASN struct {
	asn.Source
	n int
}

func (c *countingASN) Lookup(ctx context.Context, addr netip.Addr) (asn.Info, bool) {
	c.n++
	return c.Source.Lookup(ctx, addr)
}

// A relay names the network of a report: past RelayTries a day a device's
// reports through relays are refused before any lookup.
func TestRelayTries(t *testing.T) {
	ctx := context.Background()
	st, c, devices := node(t)
	SetEnabled(ctx, st, true)
	src := &countingASN{Source: c.ASN}
	c.ASN = src
	relayed := `{"v":1,"net":"cellular","path":"relay","obs":[{"svc":1,"result":"fails"}]}`
	for i := range RelayTries + 3 {
		before := src.n
		err := c.TakeVia(ctx, devices[0], netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, byte(i), 0}), 24), strings.NewReader(relayed))
		if i >= RelayTries && (!errors.Is(err, ErrRepeated) || src.n != before) {
			t.Fatalf("report %d past the limit: %v, %d lookups", i, err, src.n-before)
		}
		if i < RelayTries && src.n == before {
			t.Fatalf("report %d within the limit not looked up: %v", i, err)
		}
	}
	// Another device has its own.
	if err := c.TakeVia(ctx, devices[1], netip.MustParsePrefix("198.51.200.0/24"), strings.NewReader(relayed)); errors.Is(err, ErrRepeated) {
		t.Fatalf("another device refused: %v", err)
	}
}
