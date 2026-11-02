package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenTwiceAndMode(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sub", "rayd.db")
	for range 2 {
		s, err := Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		s.Close()
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
	}
}

func TestUsersServicesDevices(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	if _, err := s.CreateUser(ctx, User{Name: "Bad Name"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad name accepted: %v", err)
	}
	if _, err := s.CreateService(ctx, Service{Kind: "trojan", Name: "t"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown kind accepted: %v", err)
	}

	alice, err := s.CreateUser(ctx, User{Name: "alice", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	if _, err := s.CreateUser(ctx, User{Name: "bob", Enabled: true, ExpiresAt: &past}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, User{Name: "alice"}); err == nil {
		t.Fatal("duplicate user accepted")
	}

	reality, err := s.CreateService(ctx, Service{Kind: "reality", Name: "reality", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	dns, err := s.CreateService(ctx, Service{Kind: "dnstt", Name: "dns", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if reality.ID != 1 || dns.ID != 2 {
		t.Fatalf("ids %d %d", reality.ID, dns.ID)
	}
	// IDs are never reused.
	if err := s.DeleteService(ctx, "dns"); err != nil {
		t.Fatal(err)
	}
	dns, err = s.CreateService(ctx, Service{Kind: "dnstt", Name: "dns", Enabled: true})
	if err != nil || dns.ID != 3 {
		t.Fatalf("recreated id %d, err %v", dns.ID, err)
	}

	for _, u := range []string{"alice", "bob"} {
		if err := s.SetUserServices(ctx, u, []int64{reality.ID, dns.ID}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.UserByName(ctx, "alice")
	if err != nil || !slices.Equal(got.Services, []int64{reality.ID, dns.ID}) || got.ID != alice.ID {
		t.Fatalf("alice = %+v, %v", got, err)
	}

	phone, key, err := s.CreateDevice(ctx, "alice", "phone", "user")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateDevice(ctx, "bob", "phone", "user"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateDevice(ctx, "alice", "laptop", "root"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad role accepted: %v", err)
	}

	// Bob is expired, so only Alice's phone passes SPA.
	devs, err := s.SPADevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 1 || devs[0].ID != phone.ID || devs[0].Key != key || !slices.Equal(devs[0].Allowed, []uint16{1, 3}) {
		t.Fatalf("spa devices = %+v", devs)
	}

	if err := s.SetServiceEnabled(ctx, "reality", false); err != nil {
		t.Fatal(err)
	}
	devs, _ = s.SPADevices(ctx)
	if len(devs) != 1 || !slices.Equal(devs[0].Allowed, []uint16{3}) {
		t.Fatalf("after disabling reality: %+v", devs)
	}

	if err := s.SetUserEnabled(ctx, "alice", false); err != nil {
		t.Fatal(err)
	}
	if devs, _ = s.SPADevices(ctx); len(devs) != 0 {
		t.Fatalf("disabled user still passes SPA: %+v", devs)
	}
	if err := s.SetUserEnabled(ctx, "alice", true); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeDevice(ctx, phone.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeDevice(ctx, phone.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke: %v", err)
	}
	if devs, _ = s.SPADevices(ctx); len(devs) != 0 {
		t.Fatalf("revoked device still passes SPA: %+v", devs)
	}

	if err := s.DeleteUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListDevices(ctx, "")
	if err != nil || len(list) != 1 || list[0].UserName != "bob" {
		t.Fatalf("devices after delete = %+v, %v", list, err)
	}
	if err := s.DeleteUser(ctx, "alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

func TestSettingsAndAudit(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.GetSetting(ctx, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing setting: %v", err)
	}
	for _, v := range []string{"1", "2"} {
		if err := s.SetSetting(ctx, "x", []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	if v, _ := s.GetSetting(ctx, "x"); string(v) != "2" {
		t.Fatalf("setting = %q", v)
	}

	s.now = func() time.Time { return time.Unix(1000, 0) }
	s.Audit(ctx, "root", "user.create", "alice", "ok")
	s.now = func() time.Time { return time.Unix(2000, 0) }
	s.Audit(ctx, "root", "user.delete", "alice", "ok")
	entries, err := s.ListAudit(ctx, 10)
	if err != nil || len(entries) != 2 || entries[0].Action != "user.delete" {
		t.Fatalf("audit = %+v, %v", entries, err)
	}
	if err := s.PruneAudit(ctx, time.Unix(1500, 0)); err != nil {
		t.Fatal(err)
	}
	if entries, _ = s.ListAudit(ctx, 10); len(entries) != 1 {
		t.Fatalf("after prune: %+v", entries)
	}
}

func TestKindsHavePorts(t *testing.T) {
	if len(kindPorts) != len(ServiceKinds) {
		t.Fatalf("%d kinds with ports, %d kinds", len(kindPorts), len(ServiceKinds))
	}
	for _, k := range ServiceKinds {
		if _, ok := kindPorts[k]; !ok {
			t.Errorf("kind %s has no port entry", k)
		}
	}
}

func TestServicePorts(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	ssh, err := s.CreateService(ctx, Service{Kind: "ssh", Name: "ssh", Settings: `{"ports":["tcp/2222"]}`})
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := ssh.Ports(); len(p) != 1 || p[0] != (Port{"tcp", 2222}) {
		t.Fatalf("ssh ports = %v", p)
	}
	if _, err := s.CreateService(ctx, Service{Kind: "ssh", Name: "bad", Settings: `{"ports":["sctp/1"]}`}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad port accepted: %v", err)
	}
	dns := Service{Kind: "dnstt", Settings: "{}"}
	if p, _ := dns.Ports(); !dns.Public() || len(p) != 1 || p[0].String() != "udp/53" {
		t.Fatalf("dnstt = %v public=%v", p, dns.Public())
	}
}

func TestRotateCredentials(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Unix(1767225600, 0)
	s.now = func() time.Time { return now }
	u, _ := s.CreateUser(ctx, User{Name: "alice", Enabled: true})
	svc, err := s.CreateService(ctx, Service{Kind: "reality", Name: "r", Enabled: true, Settings: "{}"})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	gen := func() (string, error) { n++; return fmt.Sprintf("secret-%d", n), nil }
	r := Rotation{Period: 30 * 24 * time.Hour, Lead: 3 * 24 * time.Hour, Grace: 2 * 24 * time.Hour}
	day := 24 * time.Hour
	get := func() Credential {
		t.Helper()
		sets, err := s.CredentialSets(ctx, svc.ID, []int64{u.ID}, gen)
		if err != nil {
			t.Fatal(err)
		}
		return sets[u.ID]
	}
	if c := get(); c.Current != "secret-1" || c.Next != "" {
		t.Fatalf("new credential %+v", c)
	}
	// Nothing due at 26 days; the next one is published at 27, for day 30.
	if k, _ := s.RotateCredentials(ctx, now.Add(26*day), r, gen); k != 0 {
		t.Fatalf("rotated early: %d", k)
	}
	if k, _ := s.RotateCredentials(ctx, now.Add(27*day), r, gen); k != 1 {
		t.Fatalf("not published: %d", k)
	}
	c := get()
	if c.Next != "secret-2" || !c.NextFrom.Equal(now.Add(30*day)) || len(c.Accepted(now.Add(27*day))) != 2 {
		t.Fatalf("published %+v", c)
	}
	// The switch at day 30: the old one stays accepted for the grace.
	if k, _ := s.RotateCredentials(ctx, now.Add(30*day), r, gen); k != 1 {
		t.Fatalf("no switch: %d", k)
	}
	c = get()
	if c.Current != "secret-2" || c.Next != "" || c.Prev != "secret-1" || !c.PrevUntil.Equal(now.Add(32*day)) {
		t.Fatalf("switched %+v", c)
	}
	if acc := c.Accepted(now.Add(31 * day)); len(acc) != 2 || acc[0] != "secret-2" {
		t.Fatalf("accepted %v", acc)
	}
	if k, _ := s.RotateCredentials(ctx, now.Add(32*day), r, gen); k != 1 {
		t.Fatalf("previous kept: %d", k)
	}
	if c = get(); c.Prev != "" {
		t.Fatalf("after grace %+v", c)
	}
	// The next round counts from the switch, not from creation.
	if k, _ := s.RotateCredentials(ctx, now.Add(56*day), r, gen); k != 0 {
		t.Fatalf("second round early: %d", k)
	}
	if k, _ := s.RotateCredentials(ctx, now.Add(57*day), r, gen); k != 1 {
		t.Fatalf("second round: %d", k)
	}
	// A node that was off: the switch is a full lead after publication.
	s2 := openTest(t)
	s2.now = func() time.Time { return now }
	u2, _ := s2.CreateUser(ctx, User{Name: "bob", Enabled: true})
	svc2, _ := s2.CreateService(ctx, Service{Kind: "reality", Name: "r", Enabled: true, Settings: "{}"})
	s2.Credentials(ctx, svc2.ID, []int64{u2.ID}, gen)
	s2.RotateCredentials(ctx, now.Add(100*day), r, gen)
	sets, _ := s2.CredentialSets(ctx, svc2.ID, nil, gen)
	if !sets[u2.ID].NextFrom.Equal(now.Add(103 * day)) {
		t.Fatalf("switch after a pause at %v", sets[u2.ID].NextFrom)
	}
}
