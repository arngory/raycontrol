package sub_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/clientver"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/sub"
)

// client-min-v1 §4: a device below the node's minimum gets a signed 200
// with no profiles, refused, an hour at most and its way to update; the
// device keeps the client its request named (§5).
func TestClientMinimum(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	srv := &sub.Server{Store: f.st, Keys: f.keys, Log: quiet()}
	fetch := func(client string) (sub.Payload, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, sub.Path, nil)
		req.Header.Set(sub.DeviceHeader, f.device.ID)
		req.Header.Set("Authorization", sub.AuthToken(f.key, time.Now().Unix()/60))
		if client != "" {
			req.Header.Set(clientver.Header, client)
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%q: %d", client, rec.Code)
		}
		var env sub.Envelope
		if err := json.NewDecoder(rec.Body).Decode(&env); err != nil {
			t.Fatal(err)
		}
		p, err := sub.Verify(env, f.keys.PublicJSON())
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := base64.RawURLEncoding.DecodeString(env.Payload)
		return p, string(raw)
	}
	set := func(p clientver.Policy) {
		t.Helper()
		if _, err := node.SetClientPolicy(ctx, f.st, p); err != nil {
			t.Fatal(err)
		}
	}
	old, newer := "niko/1.58.0 (android; arm64-v8a)", "niko/1.59.0 (android; arm64-v8a)"

	// No policy: as before, and no field.
	if p, raw := fetch(old); len(p.Profiles) != 1 || p.Client != nil || strings.Contains(raw, `"client"`) {
		t.Fatalf("no policy: %+v\n%s", p.Client, raw)
	}
	devs, err := f.st.ListDevices(ctx, "alice")
	if err != nil || len(devs) != 1 || devs[0].Client != "niko/1.58.0" || devs[0].ClientAt == nil {
		t.Fatalf("the device's client: %+v %v", devs, err)
	}

	set(clientver.Policy{Min: map[string]string{"niko": "1.59.0"}})
	p, raw := fetch(old)
	if len(p.Profiles) != 0 || !strings.Contains(raw, `"profiles":[]`) || p.Client == nil || !p.Client.Refused ||
		p.Client.Min["niko"] != "1.59.0" || p.Expires-p.Issued > int64(sub.RefusedExpiry/time.Second) || p.SPA == nil {
		t.Fatalf("below: %+v %+v\n%s", p.Client, p, raw)
	}
	if strings.Contains(raw, `"next"`) || p.LAN != nil || p.DNSProbe != nil {
		t.Fatalf("below: what it must not carry\n%s", raw)
	}
	if p, _ := fetch(newer); len(p.Profiles) != 1 || p.Client == nil || p.Client.Refused || p.Expires-p.Issued != int64(sub.Lifetime/time.Second) {
		t.Fatalf("at the minimum: %+v", p.Client)
	}
	// Preview builds of the minimum are below it.
	if p, _ := fetch("niko/1.59.0-pre.20261120.1 (linux; amd64)"); len(p.Profiles) != 0 || !p.Client.Refused {
		t.Fatalf("preview of the minimum: %+v", p.Client)
	}
	// No header, unknown allowed: profiles. Unreadable is no header.
	for _, h := range []string{"", "niko/v1.0", "something else"} {
		if p, _ := fetch(h); len(p.Profiles) != 1 || p.Client == nil || p.Client.Refused {
			t.Fatalf("header %q, unknown allowed: %+v", h, p.Client)
		}
	}
	set(clientver.Policy{Min: map[string]string{"niko": "1.59.0"}, RefuseUnknown: true})
	if p, _ := fetch(""); len(p.Profiles) != 0 || !p.Client.Refused {
		t.Fatalf("no header, unknown refused: %+v", p.Client)
	}
	// A date ahead: everyone served, the field says when.
	from := time.Now().Add(48 * time.Hour).Unix()
	set(clientver.Policy{Min: map[string]string{"niko": "1.59.0"}, From: from, RefuseUnknown: true})
	if p, _ := fetch(old); len(p.Profiles) != 1 || p.Client == nil || p.Client.Refused || p.Client.From != from {
		t.Fatalf("ahead: %+v", p.Client)
	}
	// The user's own subscription (rayctl user export) is never refused.
	set(clientver.Policy{Min: map[string]string{"niko": "9.0.0"}, RefuseUnknown: true})
	env, err := srv.BuildForDevice(ctx, "alice", f.key[:], netip.Addr{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p, err := sub.Verify(env, f.keys.PublicJSON()); err != nil || len(p.Profiles) != 1 || p.Client.Refused {
		t.Fatalf("export: %+v %v", p.Client, err)
	}
	// Taken away: no field again.
	set(clientver.Policy{})
	if p, raw := fetch(old); len(p.Profiles) != 1 || strings.Contains(raw, `"client"`) {
		t.Fatalf("taken away:\n%s", raw)
	}
}
