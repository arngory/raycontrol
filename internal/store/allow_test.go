package store

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/spa"
)

func TestCheckAllow(t *testing.T) {
	for _, tc := range []struct {
		in       []string
		want     string // the prefixes, comma-joined; "" with err
		warnings int
		err      string
	}{
		{in: []string{"198.51.100.7"}, want: "198.51.100.7/32"},
		{in: []string{" 198.51.100.7 ", "198.51.100.7/32", "2001:db8:7::/64"}, want: "198.51.100.7/32,2001:db8:7::/64"},
		{in: []string{"198.51.100.9/28"}, want: "198.51.100.0/28"}, // masked
		{in: []string{"::ffff:198.51.100.7"}, want: "198.51.100.7/32"},
		{in: []string{"::ffff:198.51.100.0/124"}, want: "198.51.100.0/28"},
		{in: []string{"2001:db8::1"}, want: "2001:db8::1/128"},
		{in: []string{"10.1.2.3", "fd00::1"}, want: "10.1.2.3/32,fd00::1/128", warnings: 2},
		{in: []string{"", " "}, want: ""},
		{in: []string{"198.51.100.0/27"}, err: "at most a /28"},
		{in: []string{"2001:db8::/63"}, err: "at most a /28"},
		{in: []string{"::ffff:0:0/95"}, err: "wider than /96"},
		{in: []string{"billing.example.net"}, err: "not a name"},
		{in: []string{"fe80::1%eth0"}, err: "not a name"},
		{in: []string{"127.0.0.1"}, err: "loopback"},
		{in: []string{"0.0.0.1"}, err: "loopback"},
		{in: []string{"169.254.1.1"}, err: "loopback"},
		{in: []string{"224.0.0.1"}, err: "loopback"},
		{in: []string{"255.255.255.255"}, err: "loopback"},
		{in: []string{"::1"}, err: "loopback"},
		{in: []string{"::"}, err: "loopback"},
		{in: []string{"fe80::1"}, err: "loopback"},
		{in: []string{"ff02::1"}, err: "loopback"},
		{in: strings.Split("198.51.100.1,198.51.100.2,198.51.100.3,198.51.100.4,198.51.100.5,198.51.100.6,198.51.100.7,198.51.100.8,198.51.100.9", ","), err: "at most 8"},
	} {
		got, warnings, err := CheckAllow(tc.in)
		if tc.err != "" {
			if err == nil || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%q: %v, want %q", tc.in, err, tc.err)
			}
			continue
		}
		var s []string
		for _, p := range got {
			s = append(s, p.String())
		}
		if err != nil || strings.Join(s, ",") != tc.want || len(warnings) != tc.warnings {
			t.Errorf("%q: %q %q %v, want %q", tc.in, s, warnings, err, tc.want)
		}
	}
}

func TestDeviceAllow(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	api, err := s.CreateService(ctx, Service{Kind: "api", Name: "api", Enabled: true, Settings: "{}"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"integrations", "ops"} {
		if _, err := s.CreateUser(ctx, User{Name: name, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	list := func(s ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, v := range s {
			out = append(out, netip.MustParsePrefix(v))
		}
		return out
	}
	// An invite with addresses: the device it becomes has them, and
	// neither knocks.
	inv, _, err := s.CreateInviteAllow(ctx, "integrations", "billing", "billing", time.Hour, list("198.51.100.7/32"), nil)
	if err != nil || len(inv.Allow) != 1 {
		t.Fatalf("invite: %+v %v", inv, err)
	}
	if _, _, err := s.CreateInviteAllow(ctx, "ops", "laptop", "admin", time.Hour, list("198.51.100.8/32"), nil); !errors.Is(err, ErrAllowRole) {
		t.Fatalf("an admin's invite with addresses: %v", err)
	}
	invites, _ := s.ListInvites(ctx)
	if len(invites) != 1 || !slices.Equal(invites[0].Allow, list("198.51.100.7/32")) {
		t.Fatalf("invites: %+v", invites)
	}
	spaHas := func(id string) bool {
		t.Helper()
		ds, err := s.SPADevices(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(ds, func(d spa.Device) bool { return d.ID == id })
	}
	if spaHas(inv.ID) {
		t.Fatal("an invite with addresses in the SPA snapshot")
	}
	entries, _ := s.AllowLists(ctx)
	if len(entries) != 1 || entries[0].InviteID != inv.ID || entries[0].Role != "billing" || entries[0].Name != "billing" {
		t.Fatalf("lists: %+v", entries)
	}
	d, _, err := s.UseInvite(ctx, inv.ID, "pin-billing")
	if err != nil || !slices.Equal(d.Allow, list("198.51.100.7/32")) {
		t.Fatalf("device: %+v %v", d, err)
	}
	if spaHas(d.ID) {
		t.Fatal("a device with addresses in the SPA snapshot")
	}
	entries, _ = s.AllowLists(ctx)
	if len(entries) != 1 || entries[0].DeviceID != d.ID || entries[0].CertPin != "pin-billing" {
		t.Fatalf("lists after the invite: %+v", entries)
	}
	if ps, _ := s.AllowPrefixes(ctx); !slices.Equal(ps, list("198.51.100.7/32")) {
		t.Fatalf("prefixes: %v", ps)
	}

	// Replaced, then cleared: it knocks again.
	got, err := s.SetDeviceAllow(ctx, d.ID, list("198.51.100.0/28", "2001:db8:7::/64"))
	if err != nil || len(got.Allow) != 2 || got.Role != "billing" {
		t.Fatalf("set: %+v %v", got, err)
	}
	if got, err = s.SetDeviceAllow(ctx, d.ID, nil); err != nil || got.Allow != nil || !spaHas(d.ID) {
		t.Fatalf("clear: %+v %v", got, err)
	}
	admin, _, err := s.CreateDevice(ctx, "ops", "laptop", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetDeviceAllow(ctx, admin.ID, list("198.51.100.9/32")); !errors.Is(err, ErrAllowRole) || !errors.Is(err, ErrPrecondition) {
		t.Fatalf("an admin's device: %v", err)
	}
	if _, err := s.SetDeviceAllow(ctx, "nope", list("198.51.100.9/32")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no device: %v", err)
	}

	// At most 64 on the node: invites count while they may register.
	var eight []netip.Prefix
	for i := range 8 {
		eight = append(eight, netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(16 + i)}), 32))
	}
	if _, err := s.SetDeviceAllow(ctx, d.ID, eight); err != nil {
		t.Fatal(err)
	}
	for i := range 7 {
		if _, _, err := s.CreateInviteAllow(ctx, "integrations", "b"+string(rune('a'+i)), "support", time.Hour, eight, nil); err != nil {
			t.Fatalf("invite %d: %v", i, err)
		}
	}
	if _, _, err := s.CreateInviteAllow(ctx, "integrations", "full", "support", time.Hour, list("198.51.100.40/32"), nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "over 64") {
		t.Fatalf("the 65th: %v", err)
	}
	if _, err := s.SetDeviceAllow(ctx, d.ID, eight); err != nil {
		t.Fatalf("a device's own list replaced in full: %v", err)
	}

	// Its last call, at most once an hour.
	now := time.Now().Truncate(time.Second)
	if err := s.SetLastCall(ctx, d.ID, now); err != nil {
		t.Fatal(err)
	}
	if err := s.SetLastCall(ctx, d.ID, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	ds, _ := s.ListDevices(ctx, "integrations")
	if len(ds) != 1 || ds[0].LastCall == nil || !ds[0].LastCall.Equal(now) || len(ds[0].Allow) != 8 {
		t.Fatalf("listed: %+v", ds)
	}

	// A revoked device's list is gone from the checks and the perimeter.
	if _, err := s.RevokeDevice(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	entries, _ = s.AllowLists(ctx)
	for _, e := range entries {
		if e.DeviceID == d.ID {
			t.Fatal("a revoked device's list")
		}
	}
	_ = api
}
