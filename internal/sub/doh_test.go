package sub_test

import (
	"bytes"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
)

// testDevice is a device's SPA key for the tests that want a device's
// profiles (DoH's needs one).
var testDevice = bytes.Repeat([]byte{7}, 32)

// Each device gets its own DoH token in a line as before (R4-37): the
// same scheme, path shape and length, parameters and pins; the user's
// secret is in no line, and the next line carries the device's next
// token. Without a device (rayctl user export) there is no DoH line.
func TestDoHLinePerDevice(t *testing.T) {
	m := vectorModel(t, `{"sni":"s0p1.example.com"}`)
	const secret, next = "f3b1c0de-0000-4000-8000-000000000003", "f3b1c0de-0000-4000-8000-000000000004"
	m.Creds = map[int64]map[int64]string{7: {1: secret}}
	m.Sets = map[int64]map[int64]store.Credential{7: {1: {Current: secret, Next: next, NextFrom: time.Unix(1767268800, 0)}}}
	u := render.User{ID: 1, Name: "alice", Services: []int64{7}}
	other := bytes.Repeat([]byte{8}, 32)

	line := func(device []byte) sub.Profile {
		t.Helper()
		ps, err := sub.DeviceProfiles(m, u, device)
		if err != nil || len(ps) != 1 {
			t.Fatalf("profiles %+v, %v", ps, err)
		}
		return ps[0]
	}
	a, b := line(testDevice), line(other)
	if a.Link == b.Link {
		t.Fatal("two devices, one DoH line")
	}
	for _, p := range []sub.Profile{a, b} {
		if strings.Contains(p.Link, secret) || p.Next == nil || strings.Contains(p.Next.Link, next) {
			t.Fatalf("the user's secret in a line: %+v", p)
		}
	}
	tok := store.DoHDeviceToken(secret, testDevice)
	if want := sub.DoHLink(m, m.Services[3], tok); a.Link != want {
		t.Fatalf("line\n got %s\nwant %s", a.Link, want)
	}
	if want := sub.DoHLink(m, m.Services[3], store.DoHDeviceToken(next, testDevice)); a.Next.Link != want || a.Next.From != 1767268800 {
		t.Fatalf("next %+v", a.Next)
	}
	// As the user's line was, but for the token: its length too.
	user := sub.DoHLink(m, m.Services[3], secret)
	if len(a.Link) != len(user) || strings.Replace(a.Link, tok, secret, 1) != user {
		t.Fatalf("not the shape of the user's line:\n %s\n %s", a.Link, user)
	}
	pu, err := url.Parse(a.Link)
	if err != nil || pu.Scheme != "https" || pu.Path != "/dns-query/"+tok || pu.Query().Get("niko-pin") == "" {
		t.Fatalf("parsed %+v, %v", pu, err)
	}
	if ps, err := sub.Profiles(m, u); err != nil || len(ps) != 0 {
		t.Fatalf("export: %+v, %v", ps, err)
	}
}
