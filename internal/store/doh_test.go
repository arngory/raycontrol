package store

import (
	"bytes"
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// A device's DoH token has the shape and length of the user's token (a
// version 4 UUID), is the same for the same secret and device, and
// differs for another device or another secret; no device, no token.
func TestDoHDeviceToken(t *testing.T) {
	secret, _ := NewUUID()
	a, b := []byte(strings.Repeat("a", 32)), []byte(strings.Repeat("b", 32))
	ta := DoHDeviceToken(secret, a)
	if !uuidV4.MatchString(ta) || len(ta) != len(secret) {
		t.Fatalf("token %q for secret %q", ta, secret)
	}
	if DoHDeviceToken(secret, a) != ta {
		t.Fatal("not the same twice")
	}
	other, _ := NewUUID()
	if tb := DoHDeviceToken(secret, b); tb == ta || tb == secret || DoHDeviceToken(other, a) == ta {
		t.Fatal("two devices or two secrets share a token")
	}
	if DoHDeviceToken(secret, nil) != "" || DoHDeviceToken("", a) != "" {
		t.Fatal("a token without a device or a secret")
	}
	// Pinned: the client never computes it, but a change would change
	// every device's line at the upgrade.
	if got := DoHDeviceToken("00000000-0000-4000-8000-000000000000", a); got != dohTokenVector {
		t.Fatalf("vector %q", got)
	}
}

// dohTokenVector was computed apart from this code (Python hmac).
const dohTokenVector = "04864674-3c16-4d07-a33e-e3fcdd148c96"

type dohFixture struct {
	s          *Store
	svc        int64
	alice, bob User
	a, b, c    Device // alice's a and b, bob's c
	keys       map[string][]byte
}

func newDoHFixture(t *testing.T) dohFixture {
	t.Helper()
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	f := dohFixture{s: s, keys: map[string][]byte{}}
	var ids []int64
	for _, k := range []string{"doh", "naive"} {
		svc, err := s.CreateService(ctx, Service{Kind: k, Name: k, Enabled: true, Settings: "{}"})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, svc.ID)
	}
	f.svc = ids[0]
	f.alice, _ = s.CreateUser(ctx, User{Name: "alice", Enabled: true, Services: ids})
	f.bob, _ = s.CreateUser(ctx, User{Name: "bob", Enabled: true, Services: ids})
	for _, svc := range ids {
		if _, err := s.Credentials(ctx, svc, []int64{f.alice.ID, f.bob.ID}, NewUUID); err != nil {
			t.Fatal(err)
		}
	}
	dev := func(user, name string) Device {
		d, k, err := s.CreateDevice(ctx, user, name, "user")
		if err != nil {
			t.Fatal(err)
		}
		f.keys[d.ID] = k[:]
		return d
	}
	f.a, f.b, f.c = dev("alice", "a"), dev("alice", "b"), dev("bob", "c")
	return f
}

func (f dohFixture) secret(t *testing.T, user int64) Credential {
	t.Helper()
	sets, err := f.s.CredentialSets(context.Background(), f.svc, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return sets[user]
}

func (f dohFixture) tokens(t *testing.T, now time.Time) map[string]bool {
	t.Helper()
	m, err := f.s.DoHTokens(context.Background(), f.svc, now)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Every device has its own token; the user's secret is none (a node made
// at schema 15 has no shared window). A revocation takes the revoked
// device's token away and leaves its siblings' and the user's DoH secret
// as they were, while the user's other credentials are new (R4-36,
// R4-37); a user disabled has none; rayctl user renew changes them all.
func TestDoHTokensPerDevice(t *testing.T) {
	ctx := context.Background()
	f := newDoHFixture(t)
	now := time.Now()
	if until, err := f.s.DoHSharedUntil(ctx); err != nil || !until.IsZero() {
		t.Fatalf("a new node has a shared window: %v %v", until, err)
	}
	as, bs := f.secret(t, f.alice.ID).Current, f.secret(t, f.bob.ID).Current
	ta, tb, tc := DoHDeviceToken(as, f.keys[f.a.ID]), DoHDeviceToken(as, f.keys[f.b.ID]), DoHDeviceToken(bs, f.keys[f.c.ID])
	got := f.tokens(t, now)
	if len(got) != 3 || !got[ta] || !got[tb] || !got[tc] || got[as] || got[bs] {
		t.Fatalf("tokens %v", got)
	}
	naive, _ := f.s.ServiceByName(ctx, "naive")
	naiveBefore, _ := f.s.Credentials(ctx, naive.ID, []int64{f.alice.ID}, nil)

	r, err := f.s.RevokeDevice(ctx, f.a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r.Credentials != 1 {
		t.Errorf("%d credentials new, want 1 (naive's; DoH's kept)", r.Credentials)
	}
	if f.secret(t, f.alice.ID).Current != as {
		t.Fatal("the revocation changed the user's DoH secret")
	}
	if c, _ := f.s.Credentials(ctx, naive.ID, []int64{f.alice.ID}, nil); c[f.alice.ID] == naiveBefore[f.alice.ID] {
		t.Fatal("the revocation left naive's password")
	}
	got = f.tokens(t, now)
	if got[ta] || !got[tb] || !got[tc] || len(got) != 2 {
		t.Fatalf("after the revocation: %v", got)
	}

	if err := f.s.SetUserEnabled(ctx, "bob", false); err != nil {
		t.Fatal(err)
	}
	if got = f.tokens(t, now); got[tc] || !got[tb] {
		t.Fatalf("bob disabled: %v", got)
	}

	if _, err := f.s.RenewUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	renewed := f.secret(t, f.alice.ID).Current
	if renewed == as {
		t.Fatal("rayctl user renew left the DoH secret")
	}
	if got = f.tokens(t, now); got[tb] || !got[DoHDeviceToken(renewed, f.keys[f.b.ID])] {
		t.Fatalf("after the renewal: %v", got)
	}
}

// The rotation goes on per device: a next secret published gives each
// device its next token, accepted with the current one; after the switch
// the previous one is accepted for its grace, and not after.
func TestDoHTokensRotation(t *testing.T) {
	ctx := context.Background()
	f := newDoHFixture(t)
	start := time.Now()
	r := Rotation{Period: 30 * 24 * time.Hour, Lead: 3 * 24 * time.Hour, Grace: 2 * 24 * time.Hour}
	cur := f.secret(t, f.alice.ID).Current
	at := start.Add(28 * 24 * time.Hour)
	if _, err := f.s.RotateCredentials(ctx, at, r, NewUUID); err != nil {
		t.Fatal(err)
	}
	next := f.secret(t, f.alice.ID).Next
	if next == "" {
		t.Fatal("no next secret")
	}
	key := f.keys[f.a.ID]
	got := f.tokens(t, at)
	if !got[DoHDeviceToken(cur, key)] || !got[DoHDeviceToken(next, key)] {
		t.Fatalf("current and next: %v", got)
	}
	switched := start.Add(31 * 24 * time.Hour)
	if _, err := f.s.RotateCredentials(ctx, switched, r, NewUUID); err != nil {
		t.Fatal(err)
	}
	if got = f.tokens(t, switched); !got[DoHDeviceToken(cur, key)] || !got[DoHDeviceToken(next, key)] {
		t.Fatalf("in the grace: %v", got)
	}
	if got = f.tokens(t, switched.Add(r.Grace+time.Minute)); got[DoHDeviceToken(cur, key)] || !got[DoHDeviceToken(next, key)] {
		t.Fatalf("past the grace: %v", got)
	}
}

// spaKey is a device's SPA key of 32 bytes n, as the seeds write it.
func spaKey(n byte) []byte { return bytes.Repeat([]byte{n}, 32) }

// A database at schema 14 with DoH (v0.26.0 and before gave every device
// the user's token): migrated to 15, the user's token is accepted beside
// the devices' own for DoHSharedWindow from the upgrade, and not after; a
// device revoked since the upgrade ends it for its user at once (it knew
// the shared token) and for no one else. One revoked before the upgrade
// changes nothing: its user's credentials were new then (R4-36, schema
// 14). A database at schema 14 without DoH has no window.
func TestMigration15SharedWindow(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "rayd.db")
	schemaAt(t, path, 14,
		`INSERT INTO services (id, kind, name, enabled, settings_json, created_at) VALUES (1, 'doh', 'doh', 1, '{}', 1)`,
		`INSERT INTO users (id, name, enabled, created_at) VALUES (1, 'alice', 1, 1), (2, 'bob', 1, 1)`,
		`INSERT INTO user_services (user_id, service_id) VALUES (1, 1), (2, 1)`,
		`INSERT INTO credentials (user_id, service_id, secret, created_at, rotated_at) VALUES (1, 1, 'a-tok', 1, 1), (2, 1, 'b-tok', 1, 1)`,
		`INSERT INTO devices (id, user_id, name, role, spa_key, created_at, revoked_at) VALUES
			('a000000000000001', 1, 'a', 'user', x'0101010101010101010101010101010101010101010101010101010101010101', 10, NULL),
			('a000000000000002', 1, 'b', 'user', x'0202020202020202020202020202020202020202020202020202020202020202', 10, NULL),
			('a000000000000003', 1, 'old', 'user', x'0303030303030303030303030303030303030303030303030303030303030303', 10, 20),
			('b000000000000001', 2, 'c', 'user', x'0404040404040404040404040404040404040404040404040404040404040404', 10, NULL)`)
	before := time.Now()
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	until, err := s.DoHSharedUntil(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d := until.Sub(before); d < DoHSharedWindow-time.Second || d > DoHSharedWindow+5*time.Second {
		t.Fatalf("the window ends %v after the upgrade, want %v", d, DoHSharedWindow)
	}
	tokens := func(now time.Time) map[string]bool {
		t.Helper()
		m, err := s.DoHTokens(ctx, 1, now)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	ta, tb := DoHDeviceToken("a-tok", spaKey(1)), DoHDeviceToken("a-tok", spaKey(2))
	got := tokens(time.Now())
	if !got["a-tok"] || !got["b-tok"] || !got[ta] || !got[tb] || got[DoHDeviceToken("a-tok", spaKey(3))] {
		t.Fatalf("in the window: %v", got)
	}
	if got = tokens(until); got["a-tok"] || got["b-tok"] || !got[ta] {
		t.Fatalf("at its end: %v", got)
	}
	if _, err := s.RevokeDevice(ctx, "a000000000000001"); err != nil {
		t.Fatal(err)
	}
	if got = tokens(time.Now()); got["a-tok"] || got[ta] || !got[tb] || !got["b-tok"] {
		t.Fatalf("a device of alice's revoked in the window: %v", got)
	}
	// A second start changes nothing.
	s.Close()
	if s, err = Open(ctx, path); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.DoHSharedUntil(ctx); !again.Equal(until) {
		t.Fatalf("a second start moved the window: %v, %v", again, until)
	}

	plain := filepath.Join(t.TempDir(), "rayd.db")
	schemaAt(t, plain, 14,
		`INSERT INTO services (id, kind, name, enabled, settings_json, created_at) VALUES (1, 'naive', 'naive', 1, '{}', 1)`,
		`INSERT INTO users (id, name, enabled, created_at) VALUES (1, 'alice', 1, 1)`,
		`INSERT INTO credentials (user_id, service_id, secret, created_at, rotated_at) VALUES (1, 1, 'a-pw', 1, 1)`)
	p, err := Open(ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if until, err := p.DoHSharedUntil(ctx); err != nil || !until.IsZero() {
		t.Fatalf("no DoH, a window: %v %v", until, err)
	}
}

// TestNewCredentialsHook: a user's first DoH secret is made when a model is
// first built for them (the data plane's apply, a subscription), after the
// change that added them woke the DoH handlers. The hook tells them it
// exists, so the device's token is known at once, not at the next load up
// to 30 s later (client interop, v0.27.0: a new device's token answered
// after 29.5 s). It runs only after a call that made one, once it is in.
func TestNewCredentialsHook(t *testing.T) {
	ctx := context.Background()
	f := newDoHFixture(t)
	calls := 0
	var seen map[string]bool
	f.s.OnNewCredentials(func() {
		calls++
		seen = f.tokens(t, time.Now()) // committed: a load from here has it
	})
	if _, err := f.s.Credentials(ctx, f.svc, []int64{f.alice.ID, f.bob.ID}, NewUUID); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("the hook ran %d times with no credential made", calls)
	}
	carol, err := f.s.CreateUser(ctx, User{Name: "carol", Enabled: true, Services: []int64{f.svc}})
	if err != nil {
		t.Fatal(err)
	}
	d, key, err := f.s.CreateDevice(ctx, "carol", "phone", "user")
	if err != nil {
		t.Fatal(err)
	}
	if got := f.tokens(t, time.Now()); len(got) != 3 {
		t.Fatalf("carol has a token before her secret exists: %v", got)
	}
	sets, err := f.s.CredentialSets(ctx, f.svc, []int64{f.alice.ID, f.bob.ID, carol.ID}, NewUUID)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("the hook ran %d times for one credential made, want 1", calls)
	}
	if want := DoHDeviceToken(sets[carol.ID].Current, key[:]); !seen[want] {
		t.Fatalf("device %s: its token is not in the tokens loaded from the hook: %v", d.ID, seen)
	}
	if _, err := f.s.CredentialSets(ctx, f.svc, []int64{carol.ID}, NewUUID); err != nil || calls != 1 {
		t.Fatalf("again with nothing new: %d calls, %v", calls, err)
	}
}
