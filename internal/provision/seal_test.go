package provision

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

// The seal key switches at once; the previous one is accepted for the grace
// (spec/dnsseal-v1.md §8), then dropped; -now drops it at once.
func TestRotateSealKey(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := Init(ctx, st, Options{Domain: "example.com", Host: "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := SetServiceOption(ctx, st, "dns", "seal", "optional"); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	keys := func() (store.Service, map[string][]byte, [][]byte) {
		t.Helper()
		svc, err := st.ServiceByName(ctx, "dns")
		if err != nil {
			t.Fatal(err)
		}
		secrets, err := st.ServiceSecrets(ctx, svc.ID)
		if err != nil {
			t.Fatal(err)
		}
		return svc, secrets, SealKeys(svc, secrets)
	}
	_, s0, k := keys()
	first := s0[SecretSealKey]
	if len(k) != 1 || !bytes.Equal(k[0], first) || len(first) != 32 {
		t.Fatalf("keys before a switch: %x", k)
	}

	now := time.Unix(1_800_000_000, 0)
	grace := 48 * time.Hour
	checkBefore, err := st.DNSCheckKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state, err := RotateSealKey(ctx, st, "dns", now, grace, false)
	if err != nil {
		t.Fatal(err)
	}
	// The node's own check key is renewed with the seal key.
	if checkAfter, err := st.DNSCheckKey(ctx); err != nil || len(checkAfter) != 32 || bytes.Equal(checkAfter, checkBefore) {
		t.Fatalf("the node's check key not renewed: %v", err)
	}
	svc, s1, k := keys()
	if state.RotatedAt != now.Unix() || state.PrevUntil != now.Add(grace).Unix() || ParseSealState(svc) != state {
		t.Fatalf("state %+v, stored %+v", state, ParseSealState(svc))
	}
	if len(k) != 2 || bytes.Equal(k[0], first) || !bytes.Equal(k[1], first) || len(k[0]) != 32 {
		t.Fatalf("keys after a switch: %x (first %x)", k, first)
	}
	// The operator's other settings stay; theirs stay the rotation's.
	if _, err := SetServiceOption(ctx, st, "dns", "seal", "required"); err != nil {
		t.Fatal(err)
	}
	if svc, _, _ = keys(); ParseSealState(svc) != state {
		t.Fatalf("seal=required lost the rotation state: %s", svc.Settings)
	}

	// Within the grace nothing goes; after it the previous key does.
	if n, err := ExpireSealKeys(ctx, st, now.Add(grace-time.Second), log); n != 0 || err != nil {
		t.Fatalf("expire within the grace: %d %v", n, err)
	}
	if n, err := ExpireSealKeys(ctx, st, now.Add(grace), log); n != 1 || err != nil {
		t.Fatalf("expire after the grace: %d %v", n, err)
	}
	svc, s2, k := keys()
	if len(k) != 1 || !bytes.Equal(k[0], s1[SecretSealKey]) || s2[PrevSecret(SecretSealKey)] != nil {
		t.Fatalf("keys after the grace: %x, previous %x", k, s2[PrevSecret(SecretSealKey)])
	}
	if st := ParseSealState(svc); st.PrevUntil != 0 || st.RotatedAt != now.Unix() {
		t.Fatalf("state after the grace: %+v", st)
	}
	if mode := svc.Settings; !bytes.Contains([]byte(mode), []byte(`"seal":"required"`)) {
		t.Fatalf("settings after the grace: %s", mode)
	}

	// At once: no previous key, even with a grace.
	later := now.Add(72 * time.Hour)
	if state, err = RotateSealKey(ctx, st, "dns", later, grace, false); err != nil || state.PrevUntil == 0 {
		t.Fatalf("second switch: %+v %v", state, err)
	}
	if state, err = RotateSealKey(ctx, st, "dns", later.Add(time.Minute), grace, true); err != nil || state.PrevUntil != 0 {
		t.Fatalf("switch at once: %+v %v", state, err)
	}
	if svc, s3, k := keys(); len(k) != 1 || s3[PrevSecret(SecretSealKey)] != nil || ParseSealState(svc).PrevUntil != 0 {
		t.Fatalf("keys after a switch at once: %x, state %s", k, svc.Settings)
	}
	// A zero grace keeps nothing either.
	if state, err = RotateSealKey(ctx, st, "dns", later.Add(2*time.Minute), 0, false); err != nil || state.PrevUntil != 0 {
		t.Fatalf("switch with no grace: %+v %v", state, err)
	}

	// Only dnstt has a seal key.
	if _, err := CreateService(ctx, st, store.Service{Kind: "masterdns", Name: "mdns", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := RotateSealKey(ctx, st, "mdns", now, grace, false); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("masterdns: %v", err)
	}
	if _, err := RotateSealKey(ctx, st, "nope", now, grace, false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no such service: %v", err)
	}
}

// The expiry and the operator's options rewrite the same settings: neither
// may undo the other (settingsMu).
func TestSealKeysAndOptionsRace(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := Init(ctx, st, Options{Domain: "example.com", Host: "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	now := time.Unix(1_800_000_000, 0)
	for i := range 20 {
		if _, err := RotateSealKey(ctx, st, "dns", now, time.Hour, false); err != nil {
			t.Fatal(err)
		}
		mode := []string{"optional", "required"}[i%2]
		var wg sync.WaitGroup
		wg.Go(func() {
			if _, err := SetServiceOption(ctx, st, "dns", "seal", mode); err != nil {
				t.Error(err)
			}
		})
		wg.Go(func() {
			if _, err := ExpireSealKeys(ctx, st, now.Add(time.Hour), log); err != nil {
				t.Error(err)
			}
		})
		wg.Wait()
		svc, _ := st.ServiceByName(ctx, "dns")
		if !bytes.Contains([]byte(svc.Settings), []byte(`"seal":"`+mode+`"`)) || ParseSealState(svc).PrevUntil != 0 {
			t.Fatalf("round %d: %s", i, svc.Settings)
		}
	}
}

// A new DNS tunnel's modes: dnstt takes signed queries only, masterdns
// both kinds, and both seal for the clients that ask; given modes stay,
// unknown ones are refused, and a service from before reads as off.
// masterdns takes dnsauth only under AES-GCM (spec/dnsauth-masterdns.md
// §3).
func TestDNSTunnelModes(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := Init(ctx, st, Options{Domain: "example.com", Host: "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	mdnsMode := "off" // until niko-server v0.11.0 takes them (MasterDNSSealAuth)
	if MasterDNSSealAuth {
		mdnsMode = "optional"
	}
	for _, c := range []struct{ kind, name, settings, auth, seal string }{
		{"dnstt", "dns", "", "required", "optional"},
		{"masterdns", "mdns", "", mdnsMode, mdnsMode},
		{"dnstt", "dns2", `{"auth":"optional","seal":"off"}`, "optional", "off"},
		{"masterdns", "mdns2", `{"auth":"required","seal":"required"}`, "required", "required"},
		{"masterdns", "mdns3", `{"auth":"off","seal":"off"}`, "off", "off"},
	} {
		svc, err := CreateService(ctx, st, store.Service{Kind: c.kind, Name: c.name, Enabled: true, Settings: c.settings})
		if err != nil || DNSAuthMode(svc) != c.auth || DNSSealMode(svc) != c.seal {
			t.Errorf("%s %s: auth %s, seal %s, %v", c.kind, c.settings, DNSAuthMode(svc), DNSSealMode(svc), err)
		}
	}
	for i, bad := range []string{`{"auth":"on"}`, `{"seal":"strict"}`, `{"seal":true}`} {
		for _, kind := range []string{"dnstt", "masterdns"} {
			name := "bad" + string(rune('a'+i)) + kind
			if _, err := CreateService(ctx, st, store.Service{Kind: kind, Name: name, Enabled: true, Settings: bad}); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("%s %s: %v", kind, bad, err)
			}
		}
	}
	// A service from before keeps what it had: no mode reads as off. Other
	// kinds have none.
	for _, svc := range []store.Service{{Kind: "masterdns", Settings: `{"zone":"m.example.com"}`},
		{Kind: "reality", Settings: `{"auth":"required","seal":"required"}`}} {
		if DNSAuthMode(svc) != "off" || DNSSealMode(svc) != "off" {
			t.Errorf("%s %s: auth %s, seal %s", svc.Kind, svc.Settings, DNSAuthMode(svc), DNSSealMode(svc))
		}
	}

	// service set on masterdns: off removes the mode, the others set it.
	mode := map[string]func(store.Service) string{"auth": DNSAuthMode, "seal": DNSSealMode}
	for _, key := range []string{"auth", "seal"} {
		for _, v := range []string{"required", "off", "optional"} {
			svc, err := SetServiceOption(ctx, st, "mdns", key, v)
			if err != nil || mode[key](svc) != v || (v == "off") == strings.Contains(svc.Settings, `"`+key+`"`) {
				t.Fatalf("mdns %s=%s: %s %v", key, v, svc.Settings, err)
			}
		}
		if _, err := SetServiceOption(ctx, st, "mdns", key, "on"); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("mdns %s=on: %v", key, err)
		}
	}
	// dnsauth under a method that leaves the query unauthenticated (set by
	// hand): refused; off and the seal still go.
	mdns, _ := st.ServiceByName(ctx, "mdns")
	if err := st.UpdateService(ctx, mdns.ID, store.ServiceUpdate{Settings: strings.Replace(mdns.Settings, `"encryption_method":5`, `"encryption_method":2`, 1)}); err != nil {
		t.Fatal(err)
	}
	if _, err := SetServiceOption(ctx, st, "mdns", "auth", "required"); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("auth under method 2: %v", err)
	}
	for _, o := range [][2]string{{"auth", "off"}, {"seal", "required"}} {
		if _, err := SetServiceOption(ctx, st, "mdns", o[0], o[1]); err != nil {
			t.Fatalf("%s=%s under method 2: %v", o[0], o[1], err)
		}
	}
}
