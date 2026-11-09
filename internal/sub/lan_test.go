package sub_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
)

// lanNode is a node with a Yggdrasil service and users' devices, its
// subscription endpoint, and a clock for the store the test moves.
type lanNode struct {
	t       *testing.T
	ctx     context.Context
	st      *store.Store
	srv     *sub.Server
	keys    provision.NodeKeys
	ygg     store.Service
	now     time.Time
	changed int
	devices map[string]lanDev // by "user/name"
}

type lanDev struct {
	store.Device
	key [spa.KeySize]byte
}

func newLANNode(t *testing.T) *lanNode {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	n := &lanNode{t: t, ctx: ctx, st: st, now: time.Now().Truncate(time.Second), devices: map[string]lanDev{}}
	st.SetClock(func() time.Time { return n.now })
	if _, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "reality", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if n.ygg, err = provision.CreateService(ctx, st, store.Service{Kind: "yggdrasil", Name: "ygg", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "hy2-masq", Name: "hy2", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if n.keys, err = provision.LoadNodeKeys(ctx, st); err != nil {
		t.Fatal(err)
	}
	n.srv = &sub.Server{Store: st, Keys: n.keys, Log: quiet(), Changed: func() { n.changed++ }}
	return n
}

func (n *lanNode) user(name string, services ...string) {
	n.t.Helper()
	if _, err := n.st.CreateUser(n.ctx, store.User{Name: name, Enabled: true}); err != nil {
		n.t.Fatal(err)
	}
	var ids []int64
	for _, s := range services {
		svc, err := n.st.ServiceByName(n.ctx, s)
		if err != nil {
			n.t.Fatal(err)
		}
		ids = append(ids, svc.ID)
	}
	if err := n.st.SetUserServices(n.ctx, name, ids); err != nil {
		n.t.Fatal(err)
	}
}

func (n *lanNode) device(user, name string) lanDev {
	n.t.Helper()
	n.now = n.now.Add(time.Second) // the order of adding
	d, key, err := n.st.CreateDevice(n.ctx, user, name, "user")
	if err != nil {
		n.t.Fatal(err)
	}
	n.devices[user+"/"+name] = lanDev{d, key}
	return n.devices[user+"/"+name]
}

// fetch asks the endpoint as the device, with the LAN header unless "".
func (n *lanNode) fetch(dev, lan string) (sub.Payload, string, int) {
	n.t.Helper()
	d := n.devices[dev]
	req := httptest.NewRequest(http.MethodGet, sub.Path, nil)
	req.Header.Set(sub.DeviceHeader, d.ID)
	req.Header.Set("Authorization", sub.AuthToken(d.key, time.Now().Unix()/60))
	if lan != "" {
		req.Header.Set(sub.LANHeader, lan)
	}
	rec := httptest.NewRecorder()
	n.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return sub.Payload{}, "", rec.Code
	}
	var env sub.Envelope
	if err := json.NewDecoder(rec.Body).Decode(&env); err != nil {
		n.t.Fatal(err)
	}
	p, err := sub.Verify(env, n.keys.PublicJSON())
	if err != nil {
		n.t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(env.Payload)
	return p, string(raw), rec.Code
}

// lanOf is fetch's lan field, failing without one.
func (n *lanNode) lanOf(dev, lan string) *sub.LAN {
	n.t.Helper()
	p, raw, code := n.fetch(dev, lan)
	if code != http.StatusOK || p.LAN == nil {
		n.t.Fatalf("%s: %d, no lan:\n%s", dev, code, raw)
	}
	return p.LAN
}

func ids(l *sub.LAN) []string {
	var out []string
	for _, d := range l.Devices {
		out = append(out, d.ID)
	}
	return out
}

// meshAddr is the address of the key in a profile's niko-ygg.
func meshAddr(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	_, keyHex, _ := strings.Cut(u.Query().Get("niko-ygg"), ";")
	seed, err := hex.DecodeString(keyHex)
	if err != nil || len(seed) != 32 {
		t.Fatalf("niko-ygg in %s", link)
	}
	return render.YggdrasilAddress(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)).String()
}

// The lan field and the X-Raycontrol-LAN header (lan-v1 §1): both consents;
// the password and the devices only for a device that shows itself; only
// the user's own devices, not revoked, not hidden, by ID; addresses as the
// devices' own links have them, and the next ones with the UUID's switch.
func TestLANInSubscription(t *testing.T) {
	n := newLANNode(t)
	ctx := n.ctx
	n.user("alice", "ygg", "hy2")
	n.user("bob", "ygg")
	n.user("carol", "hy2")
	phone := n.device("alice", "phone")
	laptop := n.device("alice", "work.laptop")
	tablet := n.device("alice", "tablet")
	watch := n.device("alice", "watch")
	bobPhone := n.device("bob", "phone")
	n.device("carol", "phone")

	// No consent of the administrator: no lan, whatever the device says;
	// the device's own is stored all the same.
	p, raw, _ := n.fetch("alice/phone", "on")
	if p.LAN != nil || strings.Contains(raw, `"lan"`) || n.changed != 1 {
		t.Fatalf("without the administrator: %s (changed %d)", raw, n.changed)
	}
	if _, err := n.st.SetUserLAN(ctx, "carol", true); err == nil {
		t.Fatal("LAN for a user without Yggdrasil")
	}
	if _, err := n.st.SetUserLAN(ctx, "alice", true); err != nil {
		t.Fatal(err)
	}
	ygg := uint16(n.ygg.ID)

	// The phone showed itself before: without a header it is in.
	l := n.lanOf("alice/phone", "")
	nodeID := p.NodeID
	if l.V != 1 || l.Svc != ygg || l.Relay != 20 || l.Label != "n-"+nodeID[:8] || len(l.Password) != 43 || l.Next != nil ||
		!slices.Equal(ids(l), []string{phone.ID}) || l.Devices[0].Name != "phone" || l.Devices[0].Label != "phone" || n.changed != 1 {
		t.Fatalf("the phone: %+v (changed %d)", l, n.changed)
	}
	// The laptop never said: it sees nothing (who is not seen does not see).
	p, raw, _ = n.fetch("alice/work.laptop", "")
	if p.LAN == nil || p.LAN.Password != "" || p.LAN.Devices != nil || strings.Contains(raw, `"password"`) || strings.Contains(raw, `"devices"`) {
		t.Fatalf("the laptop, hidden: %s", raw)
	}
	// It shows itself: in, both see both, by ID.
	l2 := n.lanOf("alice/work.laptop", "on")
	want := []string{phone.ID, laptop.ID}
	slices.Sort(want)
	if l2.Password != l.Password || !slices.Equal(ids(l2), want) || n.changed != 2 {
		t.Fatalf("the laptop, shown: %+v (changed %d)", l2, n.changed)
	}
	if l = n.lanOf("alice/phone", ""); !slices.Equal(ids(l), want) {
		t.Fatalf("the phone after the laptop: %v", ids(l))
	}
	for _, d := range l.Devices {
		if d.ID == laptop.ID && (d.Name != "work.laptop" || d.Label != "work-laptop") {
			t.Fatalf("the laptop: %+v", d)
		}
	}
	// The tablet hides itself, and a header that is neither changes
	// nothing: neither is in.
	n.lanOf("alice/tablet", "off")
	n.lanOf("alice/watch", "yes")
	if l = n.lanOf("alice/phone", "ON "); !slices.Equal(ids(l), want) || n.changed != 2 {
		t.Fatalf("hidden ones listed: %v (changed %d)", ids(l), n.changed)
	}
	if l := n.lanOf("alice/tablet", ""); l.Password != "" || l.Devices != nil {
		t.Fatalf("the tablet sees: %+v", l)
	}

	// Each device's address is the one of the key in its own link.
	for _, dev := range []string{"alice/phone", "alice/work.laptop"} {
		p, _, _ := n.fetch(dev, "")
		var link string
		for _, pr := range p.Profiles {
			if pr.Svc == ygg {
				link = pr.Link
			}
		}
		i := slices.IndexFunc(p.LAN.Devices, func(d sub.LANDevice) bool { return d.ID == n.devices[dev].ID })
		if link == "" || i < 0 || p.LAN.Devices[i].Addr != meshAddr(t, link) {
			t.Fatalf("%s: %+v, link %s", dev, p.LAN.Devices, link)
		}
	}

	// Another user: a list of its own, a password of its own; nothing of
	// alice's. No user's name anywhere in lan.
	if _, err := n.st.SetUserLAN(ctx, "bob", true); err != nil {
		t.Fatal(err)
	}
	lb := n.lanOf("bob/phone", "on")
	if !slices.Equal(ids(lb), []string{bobPhone.ID}) || lb.Password == l.Password {
		t.Fatalf("bob: %+v", lb)
	}
	if l = n.lanOf("alice/phone", ""); slices.Contains(ids(l), bobPhone.ID) {
		t.Fatal("bob's phone in alice's list")
	}
	for _, dev := range []string{"alice/phone", "bob/phone"} {
		_, raw, _ := n.fetch(dev, "")
		lan := raw[strings.Index(raw, `"lan"`):]
		if strings.Contains(lan, "alice") || strings.Contains(lan, "bob") {
			t.Fatalf("a user's name in lan: %s", lan)
		}
	}
	// The order of the JSON fields is the spec's.
	if _, raw, _ = n.fetch("alice/phone", ""); !strings.Contains(raw, `"lan":{"v":1,"svc":`) ||
		!strings.Contains(raw, `,"relay":20,"label":"n-`) || !strings.Contains(raw, `"password":"`) ||
		!strings.Contains(raw, `"devices":[{"id":"`) {
		t.Fatalf("lan: %s", raw)
	}

	// Revocation: the laptop goes from the list, and the password changes
	// for everyone at once.
	before := n.lanOf("alice/phone", "").Password
	if err := n.st.RevokeDevice(ctx, laptop.ID); err != nil {
		t.Fatal(err)
	}
	if l = n.lanOf("alice/phone", ""); slices.Contains(ids(l), laptop.ID) || l.Password == before || len(l.Password) != 43 {
		t.Fatalf("after the revocation: %+v", l)
	}
	if _, _, code := n.fetch("alice/work.laptop", "on"); code != http.StatusNotFound {
		t.Fatalf("the revoked laptop: %d", code)
	}

	// The UUID's rotation: the next password and each device's next
	// address, at the profile's from.
	n.lanOf("alice/watch", "on")
	day := 24 * time.Hour
	r := store.Rotation{Period: 30 * day, Lead: 3 * day, Grace: 2 * day}
	if c, err := n.st.RotateCredentials(ctx, time.Now().Add(28*day), r, render.NewUUID); err != nil || c == 0 {
		t.Fatalf("publish: %d %v", c, err)
	}
	p, _, _ = n.fetch("alice/phone", "")
	var prof sub.Profile
	for _, pr := range p.Profiles {
		if pr.Svc == ygg {
			prof = pr
		}
	}
	l = p.LAN
	if prof.Next == nil || l.Next == nil || l.Next.From != prof.Next.From || l.Next.Password == l.Password || len(l.Next.Password) != 43 {
		t.Fatalf("next: %+v, profile %+v", l.Next, prof.Next)
	}
	for _, d := range l.Devices {
		if d.Next == nil || d.Next.From != prof.Next.From || d.Next.Addr == d.Addr {
			t.Fatalf("a device's next: %+v", d)
		}
		if d.ID == phone.ID && d.Next.Addr != meshAddr(t, prof.Next.Link) {
			t.Fatalf("the phone's next address %s, its next link's %s", d.Next.Addr, meshAddr(t, prof.Next.Link))
		}
	}
	// The password is the user's key over the UUID: the watch's answer
	// agrees.
	if w := n.lanOf("alice/watch", ""); w.Password != l.Password || w.Next.Password != l.Next.Password {
		t.Fatalf("the watch: %+v", w)
	}
	_ = watch
	_ = tablet

	// The node's name gives its label; the relay ceiling its option.
	if _, err := node.SetName(ctx, n.st, "Амстердам 2"); err != nil {
		t.Fatal(err)
	}
	if _, err := provision.SetServiceOption(ctx, n.st, "ygg", "lan_relay", "0"); err != nil {
		t.Fatal(err)
	}
	if l = n.lanOf("alice/phone", ""); l.Label != "amsterdam-2" || l.Relay != 0 {
		t.Fatalf("label %q, relay %d", l.Label, l.Relay)
	}
	if _, raw, _ = n.fetch("alice/phone", ""); !strings.Contains(raw, `"relay":0,`) {
		t.Fatalf("relay 0 left out: %s", raw)
	}
	if _, err := provision.SetServiceOption(ctx, n.st, "ygg", "lan_relay", "50"); err != nil {
		t.Fatal(err)
	}
	if l = n.lanOf("alice/phone", ""); l.Relay != 50 {
		t.Fatalf("relay %d", l.Relay)
	}

	// Over the traffic limit: no profiles, no lan.
	limit := int64(1)
	u, err := n.st.SetUserTraffic(ctx, "alice", store.TrafficChange{Limit: &limit})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.st.WriteTraffic(ctx, store.TrafficWrite{Adds: []store.TrafficAdd{{UserID: u.ID, Start: u.TrafficStart, Up: 1}}}); err != nil {
		t.Fatal(err)
	}
	if p, raw, _ := n.fetch("alice/phone", ""); p.LAN != nil || len(p.Profiles) != 0 {
		t.Fatalf("over the limit: %s", raw)
	}
	zero := int64(0)
	if _, err := n.st.SetUserTraffic(ctx, "alice", store.TrafficChange{Limit: &zero}); err != nil {
		t.Fatal(err)
	}
	// Without the Yggdrasil service, or with the administrator's consent
	// taken back: no lan.
	if err := n.st.SetUserServices(ctx, "bob", nil); err != nil {
		t.Fatal(err)
	}
	if p, raw, _ := n.fetch("bob/phone", ""); p.LAN != nil {
		t.Fatalf("bob without Yggdrasil: %s", raw)
	}
	if _, err := n.st.SetUserLAN(ctx, "alice", false); err != nil {
		t.Fatal(err)
	}
	if p, raw, _ := n.fetch("alice/phone", ""); p.LAN != nil || len(p.Profiles) != 2 {
		t.Fatalf("off: %s", raw)
	}
	// The user's own subscription (no device): lan without the list.
	if _, err := n.st.SetUserLAN(ctx, "alice", true); err != nil {
		t.Fatal(err)
	}
	env, err := n.srv.Build(ctx, "alice", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p, err := sub.Verify(env, n.keys.PublicJSON()); err != nil || p.LAN == nil || p.LAN.Password != "" || p.LAN.Devices != nil {
		t.Fatalf("the user's own: %+v %v", p.LAN, err)
	}
}

// A device that shows itself again within a minute of its last change
// stays hidden until a request after it; hiding itself is never held back
// (lan-v1 §4.4). Each change is told once, none more.
func TestLANHeaderRate(t *testing.T) {
	n := newLANNode(t)
	n.user("alice", "ygg")
	n.device("alice", "phone")
	n.device("alice", "laptop")
	if _, err := n.st.SetUserLAN(n.ctx, "alice", true); err != nil {
		t.Fatal(err)
	}
	shown := func() bool {
		l := n.lanOf("alice/laptop", "on")
		return slices.Contains(ids(l), n.devices["alice/phone"].ID)
	}
	n.lanOf("alice/phone", "on")
	if !shown() || n.changed != 2 {
		t.Fatalf("on: changed %d", n.changed)
	}
	n.now = n.now.Add(time.Second)
	if l := n.lanOf("alice/phone", "off"); l.Password != "" || shown() || n.changed != 3 {
		t.Fatalf("off a second later: changed %d", n.changed)
	}
	n.now = n.now.Add(30 * time.Second)
	if l := n.lanOf("alice/phone", "on"); l.Password != "" || shown() || n.changed != 3 {
		t.Fatalf("on within the minute: changed %d", n.changed)
	}
	for range 5 {
		n.lanOf("alice/phone", "on")
	}
	if n.changed != 3 {
		t.Fatalf("repeated: changed %d", n.changed)
	}
	n.now = n.now.Add(30 * time.Second)
	if l := n.lanOf("alice/phone", "on"); l.Password == "" || !shown() || n.changed != 4 {
		t.Fatalf("on after the minute: changed %d", n.changed)
	}
	// The state is in the device list (rayctl device list).
	devs, err := n.st.ListDevices(n.ctx, "alice")
	if err != nil || len(devs) != 2 || !devs[0].LAN || !devs[1].LAN {
		t.Fatalf("%+v %v", devs, err)
	}
	// A request that fails its auth changes nothing.
	req := httptest.NewRequest(http.MethodGet, sub.Path, nil)
	req.Header.Set(sub.DeviceHeader, n.devices["alice/phone"].ID)
	req.Header.Set("Authorization", "RC1 1.AAAA")
	req.Header.Set(sub.LANHeader, "off")
	rec := httptest.NewRecorder()
	n.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || !shown() || n.changed != 4 {
		t.Fatalf("unauthenticated: %d, changed %d", rec.Code, n.changed)
	}
}
