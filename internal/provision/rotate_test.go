package provision

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

func rotationNode(t *testing.T) (context.Context, *store.Store) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := Init(ctx, st, Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	return ctx, st
}

// storeCert gives a site a certificate for names, as the manager would.
func storeCert(t *testing.T, ctx context.Context, st *store.Store, site string, names ...string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	svc, err := st.ServiceByName(ctx, site)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateService(ctx, svc.ID, store.ServiceUpdate{Set: map[string][]byte{
		SecretTLSChain: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), SecretTLSKey: keyDER,
	}}); err != nil {
		t.Fatal(err)
	}
}

func reload(t *testing.T, ctx context.Context, st *store.Store, name string) (store.Service, RealityState, map[string][]byte) {
	t.Helper()
	svc, err := st.ServiceByName(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := st.ServiceSecrets(ctx, svc.ID)
	if err != nil {
		t.Fatal(err)
	}
	return svc, ParseRealityState(svc), secrets
}

var epoch = RealityEpoch{Period: 90 * 24 * time.Hour, Lead: 3 * 24 * time.Hour, Prepare: 24 * time.Hour}

const day = 24 * time.Hour

func TestRealityRotationSelfSteal(t *testing.T) {
	ctx, st := rotationNode(t)
	svc, err := CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	created := svc.CreatedAt
	_, _, first := reload(t, ctx, st, "r")
	site, _ := st.ServiceByName(ctx, "site")
	oldName := SiteName(site)
	storeCert(t, ctx, st, "site", oldName)
	var asked []string
	resolves := func(_ context.Context, name string) error { asked = append(asked, name); return nil }
	rotate := func(at time.Time) int {
		t.Helper()
		n, err := RotateReality(ctx, st, at, epoch, resolves, nil)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}

	if n := rotate(created.Add(10 * day)); n != 0 {
		t.Fatalf("rotated after 10 days: %d", n)
	}

	// 86 days in (period - lead - preparation): next keys and a new name of
	// the node's own domain, waiting for its certificate.
	if n := rotate(created.Add(86 * day)); n != 1 {
		t.Fatalf("prepare: %d", n)
	}
	svc, state, secrets := reload(t, ctx, st, "r")
	if state.PreparedAt == 0 || state.NextFrom != 0 || state.SNINext == "" || state.SNINext == oldName ||
		!strings.HasSuffix(state.SNINext, ".example.com") || !slices.Equal(asked, []string{state.SNINext}) {
		t.Fatalf("prepared state %+v, asked %v", state, asked)
	}
	for _, name := range RealitySecrets {
		if len(secrets[NextSecret(name)]) == 0 || bytes.Equal(secrets[NextSecret(name)], secrets[name]) {
			t.Fatalf("next %s: %q", name, secrets[NextSecret(name)])
		}
	}
	all, _ := st.ListServices(ctx)
	if names, next := SiteNames(site, all); !slices.Equal(names, []string{oldName}) || !slices.Equal(next, []string{state.SNINext}) {
		t.Fatalf("site names %v, next %v", names, next)
	}
	if n := rotate(created.Add(86*day + time.Hour)); n != 0 {
		t.Fatal("published before the new name has a certificate")
	}

	// The certificate covers both names: published, switching on schedule.
	storeCert(t, ctx, st, "site", oldName, state.SNINext)
	if n := rotate(created.Add(86*day + 2*time.Hour)); n != 1 {
		t.Fatalf("publish: %d", n)
	}
	_, state, _ = reload(t, ctx, st, "r")
	if want := created.Add(90 * day).Unix(); state.NextFrom != want {
		t.Fatalf("switch at %d, want %d", state.NextFrom, want)
	}
	if n := rotate(created.Add(90*day - time.Minute)); n != 0 {
		t.Fatal("switched early")
	}

	newName := state.SNINext
	if n := rotate(created.Add(90 * day)); n != 1 {
		t.Fatalf("switch: %d", n)
	}
	svc, state, secrets = reload(t, ctx, st, "r")
	var settings struct{ SNI, Site string }
	_ = json.Unmarshal([]byte(svc.Settings), &settings)
	if state.RotatedAt != created.Add(90*day).Unix() || state.NextFrom != 0 || state.PreparedAt != 0 || state.SNINext != "" ||
		settings.SNI != newName || settings.Site != "site" {
		t.Fatalf("after the switch: %+v, settings %s", state, svc.Settings)
	}
	for _, name := range RealitySecrets {
		if _, ok := secrets[NextSecret(name)]; ok || bytes.Equal(secrets[name], first[name]) {
			t.Fatalf("%s after the switch", name)
		}
	}
	site, _ = st.ServiceByName(ctx, "site")
	all, _ = st.ListServices(ctx)
	if names, next := SiteNames(site, all); SiteName(site) != newName || !slices.Equal(names, []string{newName}) || next != nil {
		t.Fatalf("site follows: %s, names %v, next %v", SiteName(site), names, next)
	}

	// The next round counts from the switch.
	if n := rotate(created.Add(170 * day)); n != 0 {
		t.Fatal("prepared too early in the second round")
	}
	if n := rotate(created.Add(176 * day)); n != 1 {
		t.Fatal("second round not prepared")
	}
}

func TestRealityRotationKeysOnly(t *testing.T) {
	ctx, st := rotationNode(t)
	svc, err := CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	created := svc.CreatedAt
	_, _, before := reload(t, ctx, st, "r")
	oldSettings := svc.Settings

	// No wildcard record: the name stays, the keys are published at once.
	noDNS := func(context.Context, string) error { return errors.New("NXDOMAIN") }
	if n, err := RotateReality(ctx, st, created.Add(88*day), epoch, noDNS, nil); err != nil || n != 1 {
		t.Fatalf("rotate: %d %v", n, err)
	}
	_, state, _ := reload(t, ctx, st, "r")
	// Published at day 88: the switch is still a full lead away.
	if state.SNINext != "" || state.NextFrom != created.Add(91*day).Unix() {
		t.Fatalf("state %+v", state)
	}
	if n, _ := RotateReality(ctx, st, created.Add(91*day), epoch, noDNS, nil); n != 1 {
		t.Fatal("not switched")
	}
	svc, _, after := reload(t, ctx, st, "r")
	var a, b struct{ SNI string }
	_ = json.Unmarshal([]byte(oldSettings), &a)
	_ = json.Unmarshal([]byte(svc.Settings), &b)
	if a.SNI != b.SNI || bytes.Equal(before[SecretRealityKey], after[SecretRealityKey]) {
		t.Fatal("name changed or keys did not")
	}
}

func TestRealityRotationNameWithoutCertificate(t *testing.T) {
	ctx, st := rotationNode(t)
	svc, _ := CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true})
	created := svc.CreatedAt
	ok := func(context.Context, string) error { return nil }
	RotateReality(ctx, st, created.Add(86*day), epoch, ok, nil)
	// No certificate for the new name within a day: keys only.
	if n, _ := RotateReality(ctx, st, created.Add(86*day+23*time.Hour), epoch, ok, nil); n != 0 {
		t.Fatal("gave up early")
	}
	if n, _ := RotateReality(ctx, st, created.Add(87*day), epoch, ok, nil); n != 1 {
		t.Fatal("did not give up on the name")
	}
	_, state, _ := reload(t, ctx, st, "r")
	if state.SNINext != "" || state.NextFrom != created.Add(90*day).Unix() {
		t.Fatalf("state %+v", state)
	}
}

func TestRealityRotationRequest(t *testing.T) {
	ctx, st := rotationNode(t)
	// A foreign target: its name is not ours to change.
	svc, err := CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true, Settings: `{"target":"www.example.org:443"}`})
	if err != nil {
		t.Fatal(err)
	}
	now := svc.CreatedAt.Add(5 * day)
	ok := func(context.Context, string) error { return nil }

	if err := RequestRealityRotation(ctx, st, "r", now, epoch.Lead, false); err != nil {
		t.Fatal(err)
	}
	if n, _ := RotateReality(ctx, st, now, epoch, ok, nil); n != 1 {
		t.Fatal("request ignored")
	}
	_, state, _ := reload(t, ctx, st, "r")
	if state.SNINext != "" || state.NextFrom != now.Add(epoch.Lead).Unix() {
		t.Fatalf("state %+v", state)
	}
	// At once: moves the published switch to now.
	if err := RequestRealityRotation(ctx, st, "r", now.Add(time.Hour), epoch.Lead, true); err != nil {
		t.Fatal(err)
	}
	if n, _ := RotateReality(ctx, st, now.Add(time.Hour), epoch, ok, nil); n != 1 {
		t.Fatal("not switched at once")
	}
	_, state, _ = reload(t, ctx, st, "r")
	if state.RotatedAt != now.Add(time.Hour).Unix() || state.RotateAt != 0 || state.NextFrom != 0 {
		t.Fatalf("state %+v", state)
	}
	if err := RequestRealityRotation(ctx, st, "site", now, epoch.Lead, true); !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("site: %v", err)
	}
}

// With rotation off, only the operator's requests switch keys.
func TestRealityRotationOff(t *testing.T) {
	ctx, st := rotationNode(t)
	svc, _ := CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true, Settings: `{"target":"www.example.org:443"}`})
	off := RealityEpoch{Lead: 3 * day, Prepare: day}
	if n, _ := RotateReality(ctx, st, svc.CreatedAt.Add(400*day), off, nil, nil); n != 0 {
		t.Fatal("rotated with the period off")
	}
	now := svc.CreatedAt.Add(400 * day)
	if err := RequestRealityRotation(ctx, st, "r", now, off.Lead, true); err != nil {
		t.Fatal(err)
	}
	RotateReality(ctx, st, now, off, nil, nil)
	if n, _ := RotateReality(ctx, st, now.Add(time.Minute), off, nil, nil); n != 1 {
		t.Fatal("requested switch did not happen")
	}
	// A lost next set starts the round again instead of failing forever.
	RequestRealityRotation(ctx, st, "r", now.Add(time.Hour), off.Lead, false)
	RotateReality(ctx, st, now.Add(time.Hour), off, nil, nil)
	svc, _ = st.ServiceByName(ctx, "r")
	st.UpdateService(ctx, svc.ID, store.ServiceUpdate{Delete: []string{NextSecret(SecretRealityKey)}})
	if _, err := RotateReality(ctx, st, now.Add(time.Hour+off.Lead), off, nil, nil); err != nil {
		t.Fatal(err)
	}
	if n, err := RotateReality(ctx, st, now.Add(time.Hour+off.Lead+time.Minute), off, nil, nil); err != nil || n != 1 {
		t.Fatalf("not prepared again: %d %v", n, err)
	}
	if _, state, secrets := reload(t, ctx, st, "r"); state.NextFrom == 0 || len(secrets[NextSecret(SecretRealityKey)]) == 0 {
		t.Fatalf("state %+v", state)
	}
}

// With a grace period (R4-19) the switch comes a little early, the previous
// set and name stay for the grace period, the site's certificate keeps the
// previous name meanwhile, and then they go.
func TestRealityRotationGrace(t *testing.T) {
	ctx, st := rotationNode(t)
	svc, err := CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	created := svc.CreatedAt
	_, _, first := reload(t, ctx, st, "r")
	site, _ := st.ServiceByName(ctx, "site")
	oldName := SiteName(site)
	e := epoch
	e.Grace = 2 * day
	resolves := func(context.Context, string) error { return nil }
	rotate := func(at time.Time) int {
		t.Helper()
		n, err := RotateReality(ctx, st, at, e, resolves, nil)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := rotate(created.Add(86 * day)); n != 1 {
		t.Fatalf("prepare: %d", n)
	}
	_, state, _ := reload(t, ctx, st, "r")
	newName := state.SNINext
	storeCert(t, ctx, st, "site", oldName, newName)
	if n := rotate(created.Add(86*day + time.Hour)); n != 1 {
		t.Fatalf("publish: %d", n)
	}
	from := created.Add(90 * day)
	if n := rotate(from.Add(-RealityEarly - time.Second)); n != 0 {
		t.Fatal("switched too early")
	}
	if n := rotate(from.Add(-RealityEarly)); n != 1 {
		t.Fatal("not switched ahead of time")
	}
	svc, state, secrets := reload(t, ctx, st, "r")
	if state.PrevUntil != from.Add(2*day).Unix() || state.SNIPrev != oldName || state.RotatedAt != from.Unix() {
		t.Fatalf("after the switch: %+v", state)
	}
	for _, name := range RealitySecrets {
		if !bytes.Equal(secrets[PrevSecret(name)], first[name]) || bytes.Equal(secrets[name], first[name]) {
			t.Fatalf("previous %s", name)
		}
	}
	site, _ = st.ServiceByName(ctx, "site")
	all, _ := st.ListServices(ctx)
	if names, _ := SiteNames(site, all); !slices.Contains(names, oldName) || !slices.Contains(names, newName) {
		t.Fatalf("names while the previous one is accepted: %v", names)
	}

	if n := rotate(from.Add(2*day - time.Minute)); n != 0 {
		t.Fatal("previous keys dropped early")
	}
	if n := rotate(from.Add(2 * day)); n != 1 {
		t.Fatal("previous keys kept")
	}
	_, state, secrets = reload(t, ctx, st, "r")
	if state.PrevUntil != 0 || state.SNIPrev != "" {
		t.Fatalf("after the grace period: %+v", state)
	}
	for _, name := range RealitySecrets {
		if _, ok := secrets[PrevSecret(name)]; ok {
			t.Fatalf("previous %s kept", name)
		}
	}
	all, _ = st.ListServices(ctx)
	if names, _ := SiteNames(site, all); slices.Contains(names, oldName) {
		t.Fatalf("names after the grace period: %v", names)
	}
}

// rotate -now (leaked keys, a blocked name) keeps nothing of the old sets,
// grace period or not (R4-19).
func TestRealityRotationUrgent(t *testing.T) {
	ctx, st := rotationNode(t)
	svc, err := CreateService(ctx, st, store.Service{Kind: "reality", Name: "r", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	created := svc.CreatedAt
	e := epoch
	e.Grace = 2 * day
	noDNS := func(context.Context, string) error { return errors.New("NXDOMAIN") }
	rotate := func(at time.Time) int {
		t.Helper()
		n, err := RotateReality(ctx, st, at, e, noDNS, nil)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if rotate(created.Add(88*day)) != 1 || rotate(created.Add(91*day)) != 1 {
		t.Fatal("scheduled rotation")
	}
	if _, state, _ := reload(t, ctx, st, "r"); state.PrevUntil == 0 {
		t.Fatal("no grace period after a scheduled switch")
	}
	now := created.Add(91*day + time.Hour)
	if err := RequestRealityRotation(ctx, st, "r", now, e.Lead, true); err != nil {
		t.Fatal(err)
	}
	if rotate(now) != 1 || rotate(now) != 1 {
		t.Fatal("urgent rotation")
	}
	_, state, secrets := reload(t, ctx, st, "r")
	if state.PrevUntil != 0 || state.SNIPrev != "" || state.Urgent || state.RotateAt != 0 {
		t.Fatalf("after an urgent switch: %+v", state)
	}
	for _, name := range RealitySecrets {
		if _, ok := secrets[PrevSecret(name)]; ok {
			t.Fatalf("previous %s kept after an urgent switch", name)
		}
	}
}
