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
	if err != nil || len(r.Obs) != 2 || r.Obs[0].TCPStallKiB != 16 {
		t.Fatalf("good report: %+v %v", r, err)
	}
	for _, bad := range []string{
		`{"v":2,"net":"wifi","obs":[{"svc":1,"result":"works"}]}`,
		`{"v":1,"net":"satellite","obs":[{"svc":1,"result":"works"}]}`,
		`{"v":1,"net":"wifi","obs":[]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":1,"result":"great"}]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":1,"result":"works","tcp_stall_kib":17}]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":1,"result":"works","udp":"3"}]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":1,"result":"works","mbps":"7"}]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":1,"result":"works"},{"svc":1,"result":"fails"}]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":0,"result":"works"}]}`,
		`{"v":1,"net":"wifi","mcc_mnc":"25001","obs":[{"svc":1,"result":"works"}]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":1,"kind":"reality","result":"works"}]}`,
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
	r1 := `{"v":1,"net":"cellular","obs":[{"svc":1,"result":"fails","udp":"none"},{"svc":2,"result":"works","tcp_stall_kib":16},{"svc":3,"result":"degraded","tcp_stall_kib":16}]}`

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
		!slices.Equal(h.Avoid, []uint16{1}) || !h.UDPBlocked || h.TCPStallKiB != 16 {
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
		nets[0].Nets["cellular"] != 10 || nets[0].Services[1]["result"]["fails"] != 10 || others != 1 {
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
