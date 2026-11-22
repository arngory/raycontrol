package provision

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/cloudflare"
	"github.com/arngory/raycontrol/internal/cloudflare/cftest"
	"github.com/arngory/raycontrol/internal/store"
)

// relayNode is a node with every kind a relay forwards beside a DNS
// tunnel, and relay r1 with its bundle (cert_pin) and r2 without.
func relayNode(t *testing.T) (context.Context, *store.Store) {
	t.Helper()
	ctx, st := rotationNode(t)
	for _, s := range []store.Service{
		{Kind: "reality", Name: "r", Enabled: true},
		{Kind: "reality", Name: "foreign", Enabled: true, Settings: `{"target":"www.example.org:443"}`},
		{Kind: "naive", Name: "nv", Enabled: true},
		{Kind: "doh", Name: "dh", Enabled: true},
		{Kind: "hy2-masq", Name: "hm", Enabled: true},
		{Kind: "hy2-obfs", Name: "ho", Enabled: true},
		{Kind: "dnstt", Name: "dns", Enabled: true},
	} {
		if _, err := CreateService(ctx, st, s); err != nil {
			t.Fatal(s.Name, err)
		}
	}
	for i, r := range []string{"r1", "r2"} {
		if _, err := st.CreateRelay(ctx, r, netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", 20+i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SetRelayCertPin(ctx, "r1", "pin1"); err != nil {
		t.Fatal(err)
	}
	return ctx, st
}

// relayNamesOf is RelayNames as "<relay> <service> <name>", by relay and
// service ID, failing the test on an error.
func relayNamesOf(t *testing.T, ctx context.Context, st *store.Store) map[string]string {
	t.Helper()
	names, err := RelayNames(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	all, _ := st.ListServices(ctx)
	out := map[string]string{}
	for _, rn := range names {
		i := slices.IndexFunc(all, func(s store.Service) bool { return s.ID == rn.Service })
		out[rn.Relay+" "+all[i].Name] = rn.Name
		if rn.Address != netip.MustParseAddr("198.51.100.20") && rn.Relay == "r1" {
			t.Errorf("%s: address %s", rn.Name, rn.Address)
		}
	}
	return out
}

// The node's other names: its own, the name zones are delegated to, every
// service's names and zones.
func otherNames(t *testing.T, ctx context.Context, st *store.Store) []string {
	t.Helper()
	own, err := NodeDNSName(ctx, st)
	if err != nil || own == "" {
		t.Fatalf("own name %q %v", own, err)
	}
	ns, err := NSName(ctx, st)
	if err != nil || ns == "" {
		t.Fatalf("ns %q %v", ns, err)
	}
	out := []string{own, ns}
	all, _ := st.ListServices(ctx)
	for _, s := range all {
		out = append(out, serverNames(s).all...)
		out = append(out, Zones(s)...)
	}
	return out
}

// relay-names-v1 §2, §3: a name for each service whose SNI is the node's
// (REALITY with self-steal, naive, DoH, hy2-masq) at each relay with its
// bundle that forwards it; one label under the domain, none another name
// of the node's nor another relay's; kept while the relay and the service
// are, a disabled service's too; none while the host is a name; none for a
// service the relay does not forward.
func TestRelayNames(t *testing.T) {
	ctx, st := relayNode(t)
	got := relayNamesOf(t, ctx, st)
	if keys := slices.Sorted(maps.Keys(got)); !slices.Equal(keys, []string{"r1 dh", "r1 hm", "r1 nv", "r1 r"}) {
		t.Fatalf("pairs %v", keys)
	}
	others := otherNames(t, ctx, st)
	seen := map[string]bool{}
	for pair, n := range got {
		if !oneLabelUnder(n, "example.com") || seen[n] || slices.Contains(others, n) {
			t.Errorf("%s: name %s (others %v)", pair, n, others)
		}
		seen[n] = true
	}
	if again := relayNamesOf(t, ctx, st); !maps.Equal(again, got) {
		t.Fatalf("names moved: %v, then %v", got, again)
	}

	// r2's bundle: names of its own, r1's as they were.
	if err := st.SetRelayCertPin(ctx, "r2", "pin2"); err != nil {
		t.Fatal(err)
	}
	both := relayNamesOf(t, ctx, st)
	if len(both) != 8 {
		t.Fatalf("with r2: %v", both)
	}
	for pair, n := range both {
		if strings.HasPrefix(pair, "r1 ") && got[pair] != n {
			t.Errorf("%s moved: %s, then %s", pair, got[pair], n)
		}
		if strings.HasPrefix(pair, "r2 ") && (seen[n] || slices.Contains(others, n)) {
			t.Errorf("%s: name %s taken already", pair, n)
		}
		seen[n] = true
	}

	// A disabled service has no name now, and gets its own back.
	if err := st.SetServiceEnabled(ctx, "nv", false); err != nil {
		t.Fatal(err)
	}
	if off := relayNamesOf(t, ctx, st); off["r1 nv"] != "" || len(off) != 6 {
		t.Fatalf("naive disabled: %v", off)
	}
	if err := st.SetServiceEnabled(ctx, "nv", true); err != nil {
		t.Fatal(err)
	}
	if on := relayNamesOf(t, ctx, st); !maps.Equal(on, both) {
		t.Fatalf("naive enabled again: %v, before %v", on, both)
	}

	// A relay that does not forward a service (its SSH on the service's
	// port): no name for that service there.
	if err := st.SetRelaySSHPort(ctx, "r2", 443); err != nil {
		t.Fatal(err)
	}
	ssh := relayNamesOf(t, ctx, st)
	if ssh["r2 r"] != "" || ssh["r2 hm"] != both["r2 hm"] {
		t.Fatalf("r2 with SSH on tcp/443: %v", ssh)
	}

	// The host a name: none, and the names come back with the address.
	if _, err := Init(ctx, st, Options{Host: "node.example.net"}); err != nil {
		t.Fatal(err)
	}
	if named := relayNamesOf(t, ctx, st); len(named) != 0 {
		t.Fatalf("the host a name: %v", named)
	}
	if _, err := Init(ctx, st, Options{Host: "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	if back := relayNamesOf(t, ctx, st); back["r1 r"] != both["r1 r"] {
		t.Fatalf("after the address: %v, before %v", back, both)
	}
}

// Names go with their relay and service, and under a new domain each pair
// gets a new one. A relay added again by its name gets new names.
func TestRelayNamesCleanup(t *testing.T) {
	ctx, st := relayNode(t)
	if err := st.SetRelayCertPin(ctx, "r2", "pin2"); err != nil {
		t.Fatal(err)
	}
	before := relayNamesOf(t, ctx, st)
	stored := func() map[string]map[int64]string {
		t.Helper()
		m, err := storedRelayNames(ctx, st)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	nv, _ := st.ServiceByName(ctx, "nv")
	if err := st.DeleteService(ctx, "nv"); err != nil {
		t.Fatal(err)
	}
	after := relayNamesOf(t, ctx, st)
	if len(after) != 6 || after["r1 r"] != before["r1 r"] {
		t.Fatalf("after naive: %v", after)
	}
	for r, svcs := range stored() {
		if _, ok := svcs[nv.ID]; ok {
			t.Errorf("%s keeps naive's name", r)
		}
	}
	if err := st.DeleteRelay(ctx, "r2"); err != nil {
		t.Fatal(err)
	}
	if after = relayNamesOf(t, ctx, st); len(after) != 3 {
		t.Fatalf("after r2: %v", after)
	}
	if _, ok := stored()["r2"]; ok {
		t.Fatal("r2's names stored after it went")
	}

	// r1 removed and added again before any render: ForgetRelayNames (the
	// API's removal and addition) drops its names at once.
	if err := ForgetRelayNames(ctx, st, "r1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := stored()["r1"]; ok {
		t.Fatal("r1's names stored after ForgetRelayNames")
	}
	renewed := relayNamesOf(t, ctx, st)
	if len(renewed) != 3 || renewed["r1 r"] == after["r1 r"] {
		t.Fatalf("r1 after its names were dropped: %v, before %v", renewed, after)
	}

	// A new domain: new names under it, none of the old ones kept.
	if _, err := Init(ctx, st, Options{Domain: "example.net"}); err != nil {
		t.Fatal(err)
	}
	moved := relayNamesOf(t, ctx, st)
	if len(moved) != 3 {
		t.Fatalf("under example.net: %v", moved)
	}
	for pair, n := range moved {
		if !oneLabelUnder(n, "example.net") {
			t.Errorf("%s: %s", pair, n)
		}
	}
	for _, svcs := range stored() {
		for _, n := range svcs {
			if !oneLabelUnder(n, "example.net") {
				t.Errorf("stored after the domain changed: %s", n)
			}
		}
	}
	// A stored value that does not read: made again, no error.
	if err := st.SetSetting(ctx, settingRelayNames, []byte("{")); err != nil {
		t.Fatal(err)
	}
	if again := relayNamesOf(t, ctx, st); len(again) != 3 {
		t.Fatalf("after a broken setting: %v", again)
	}
}

// No other name of the node takes a relay's, nor a relay's another's:
// newZone keeps clear of every relay name stored, and relay names of the
// rest. With most labels taken by relay names, a draw that did not look
// at them would land on one at once.
func TestRelayNamesApart(t *testing.T) {
	ctx, st := relayNode(t)
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	seeded := map[string]bool{}
	fake := map[int64]string{}
	for i := 0; len(fake) < 30000; i++ {
		label := string([]byte{alphabet[i%36], alphabet[i/36%36], alphabet[i/36/36%36]})
		fake[int64(i+1000)] = label + ".example.com"
		seeded[label+".example.com"] = true
	}
	b, _ := json.Marshal(map[string]map[int64]string{"gone": fake})
	if err := st.SetSetting(ctx, settingRelayNames, b); err != nil {
		t.Fatal(err)
	}
	all, _ := st.ListServices(ctx)
	for range 20 {
		z, err := newZone(ctx, st, all)
		if err != nil || seeded[z] {
			t.Fatalf("newZone %q %v: a relay's name", z, err)
		}
	}
	svc, err := CreateService(ctx, st, store.Service{Kind: "naive", Name: "nv2", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if n := serverNames(svc).all; slices.ContainsFunc(n, func(s string) bool { return seeded[s] }) {
		t.Fatalf("naive's names %v: a relay's", n)
	}
	others := otherNames(t, ctx, st)
	for pair, n := range relayNamesOf(t, ctx, st) {
		if seeded[n] || slices.Contains(others, n) {
			t.Errorf("%s: %s taken already", pair, n)
		}
	}
}

// relay-names-v1 §4: a DNS tunnel zone at, above or under a relay's name
// is refused, its service enabled or not; beside it, it is not.
func TestRelayNamesZones(t *testing.T) {
	ctx, st := relayNode(t)
	names := relayNamesOf(t, ctx, st)
	rn := names["r1 nv"]
	if err := st.SetServiceEnabled(ctx, "nv", false); err != nil {
		t.Fatal(err)
	}
	for i, bad := range []string{rn, "t." + rn} {
		_, err := CreateService(ctx, st, store.Service{Kind: "masterdns", Name: fmt.Sprint("m", i), Enabled: true, Settings: `{"zone":"` + bad + `"}`})
		if !errors.Is(err, store.ErrInvalid) || !strings.Contains(err.Error(), "the name of relay r1, "+rn) {
			t.Errorf("zone %s: %v", bad, err)
		}
		if _, err := SetServiceOption(ctx, st, "dns", "spare_zones", bad); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("spare zone %s: %v", bad, err)
		}
	}
	// Above: a name stored deeper than one label (a domain since moved up)
	// is taken with the zone that holds it.
	b, _ := json.Marshal(map[string]map[int64]string{"r1": {1: "abc.sub.example.com"}})
	if err := st.SetSetting(ctx, settingRelayNames, b); err != nil {
		t.Fatal(err)
	}
	all, _ := st.ListServices(ctx)
	if why, err := nodeNameClash(ctx, st, all, "sub.example.com"); err != nil || why != "the name of relay r1, abc.sub.example.com" {
		t.Errorf("a zone above a relay name: %q %v", why, err)
	}
	if why, err := nodeNameClash(ctx, st, all, "other.example.com"); err != nil || why != "" {
		t.Errorf("a zone beside: %q %v", why, err)
	}
}

// relay-names-v1 §4: a record of each relay name to its relay's address,
// beside the wildcard; Cloudflare's sync makes them and removes them with
// the relay.
func TestRelayNamesDNS(t *testing.T) {
	ctx, st := relayNode(t)
	names := relayNamesOf(t, ctx, st)
	records, warnings, err := DNSRecords(ctx, st)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("records %v %v", warnings, err)
	}
	for pair, n := range names {
		if !slices.Contains(records, cloudflare.Record{Type: "A", Name: n, Content: "198.51.100.20"}) {
			t.Errorf("%s: no record for %s in %+v", pair, n, records)
		}
	}
	if !slices.Contains(records, cloudflare.Record{Type: "A", Name: "*.example.com", Content: "203.0.113.7"}) {
		t.Errorf("no wildcard in %+v", records)
	}

	api, c := cftest.New(t)
	old := CloudflareAPI
	CloudflareAPI = c.BaseURL
	defer func() { CloudflareAPI = old }()
	if _, err := SetCloudflare(ctx, st, "good"); err != nil {
		t.Fatal(err)
	}
	if _, problems, err := SyncDNS(ctx, st); err != nil || len(problems) != 0 {
		t.Fatalf("sync %v %v", problems, err)
	}
	list := strings.Join(api.List(), "\n")
	for _, n := range names {
		if !strings.Contains(list, "A "+n+" 198.51.100.20 proxied=false ours=true") {
			t.Errorf("no record for %s in\n%s", n, list)
		}
	}
	if err := st.DeleteRelay(ctx, "r1"); err != nil {
		t.Fatal(err)
	}
	changes, _, err := SyncDNS(ctx, st)
	if err != nil || len(changes) != len(names) {
		t.Fatalf("after r1: %v %v", changes, err)
	}
	list = strings.Join(api.List(), "\n")
	for _, n := range names {
		if strings.Contains(list, n) {
			t.Errorf("record for %s left in\n%s", n, list)
		}
	}
}

// relay-names-v1 §3 since v0.36.0: a new name has a label of RelayLabelLen
// characters; one made before with 3 stays until -renew-names, and status
// says so, once a relay.
func TestRelayNameLabels(t *testing.T) {
	ctx, st := relayNode(t)
	got := relayNamesOf(t, ctx, st)
	for pair, n := range got {
		if label, _, _ := strings.Cut(n, "."); len(label) != RelayLabelLen {
			t.Errorf("%s: %s, a label of %d", pair, n, len(label))
		}
	}
	names, err := RelayNames(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if w := RelayNameWarnings(names); len(w) != 0 {
		t.Errorf("warnings for long labels: %v", w)
	}
	// Names stored as v0.35 made them: kept, and warned about once.
	stored := map[string]map[int64]string{}
	for i, rn := range names {
		if stored[rn.Relay] == nil {
			stored[rn.Relay] = map[int64]string{}
		}
		stored[rn.Relay][rn.Service] = fmt.Sprintf("s%02d.example.com", i)
	}
	b, _ := json.Marshal(stored)
	if err := st.SetSetting(ctx, settingRelayNames, b); err != nil {
		t.Fatal(err)
	}
	short := relayNamesOf(t, ctx, st)
	for pair, n := range short {
		if label, _, _ := strings.Cut(n, "."); len(label) != 3 {
			t.Errorf("%s: a stored short name made again: %s", pair, n)
		}
	}
	names, _ = RelayNames(ctx, st)
	if w := RelayNameWarnings(names); len(w) != 1 || !strings.Contains(w[0], "relay r1:") || !strings.Contains(w[0], "-renew-names r1") {
		t.Errorf("warnings %v", w)
	}
	// Forgotten (rayctl relay set -renew-names): long ones again.
	if err := ForgetRelayNames(ctx, st, "r1"); err != nil {
		t.Fatal(err)
	}
	for pair, n := range relayNamesOf(t, ctx, st) {
		if label, _, _ := strings.Cut(n, "."); len(label) != RelayLabelLen || n == short[pair] {
			t.Errorf("%s renewed: %s", pair, n)
		}
	}
}
