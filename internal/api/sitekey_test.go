package api

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/sys/unix"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/testca"
)

// issueSite gives the site a certificate as the certificate manager does:
// for the key the plan picks, stored at the time at.
func issueSite(t *testing.T, st *store.Store, id int64, at time.Time) {
	t.Helper()
	ctx := context.Background()
	plan, err := provision.PlanSiteIssue(ctx, st, id, at, provision.SiteKeyPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(at.UnixNano()), DNSNames: []string{"site.example.com"},
		NotBefore: at.Add(-time.Hour), NotAfter: at.Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, plan.Key.Public(), plan.Key)
	if err != nil {
		t.Fatal(err)
	}
	if err := provision.StoreSiteCertificate(ctx, st, id, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), plan, at); err != nil {
		t.Fatal(err)
	}
}

// rayctl service rotate SITE (spec/cert-pin-v1.md §5): root on the node
// only; refused where rayd issues no certificates, before the site has
// one, and until the next key has been in subscriptions for the lead,
// unless forced. Accepted, it leaves the request the certificate manager
// carries out, and the audit log has it.
func TestRotateSiteKey(t *testing.T) {
	srv, _, changes := startServer(t)
	srv.SiteKeyLead = 14 * 24 * time.Hour
	ctx := context.Background()
	as := func(uid uint32) context.Context {
		return context.WithValue(context.WithValue(ctx, peerKey{}, &unix.Ucred{Uid: uid}), actorKey{}, "test")
	}
	remote := context.WithValue(ctx, actorKey{}, "admin/laptop (remote)")
	site, err := provision.CreateService(ctx, srv.Store, store.Service{Kind: "site", Name: "site", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	ask := func(ctx context.Context, force, fresh bool) (*nodev1.RotateServiceResponse, error) {
		r, err := srv.RotateService(ctx, connect.NewRequest(&nodev1.RotateServiceRequest{Name: "site", Force: force, Fresh: fresh}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	rotate := func(ctx context.Context, force bool) (*nodev1.RotateServiceResponse, error) {
		return ask(ctx, force, false)
	}
	state := func() provision.SiteKeyState {
		svc, err := srv.Store.ServiceByName(ctx, "site")
		if err != nil {
			t.Fatal(err)
		}
		return provision.ParseSiteKeyState(svc)
	}

	srv.Certificates = true
	for who, c := range map[string]context.Context{"the group": as(1000), "remote": remote} {
		if _, err := rotate(c, true); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("%s: %v", who, err)
		}
	}
	// No certificate manager (ACME off): nothing would make the switch.
	srv.Certificates = false
	if _, err := rotate(as(0), true); connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "issues no certificates") {
		t.Fatalf("without a certificate manager: %v", err)
	}
	srv.Certificates = true
	if _, err := rotate(as(0), true); connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "no certificate yet") {
		t.Fatalf("before the first certificate: %v", err)
	}

	// The next key in subscriptions for four days: too early.
	now := time.Now()
	issueSite(t, srv.Store, site.ID, now.Add(-4*24*time.Hour))
	before := changes.Load()
	_, err = rotate(as(0), false)
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "rayctl service rotate site -force") {
		t.Fatalf("four days in: %v", err)
	}
	if state().RotateAt != 0 || changes.Load() != before {
		t.Fatal("a refused switch changed the site")
	}
	// Anyway.
	r, err := rotate(as(0), true)
	if err != nil || r.Key != "tls" || r.SwitchAt < now.Unix() || r.Seal {
		t.Fatalf("forced: %+v %v", r, err)
	}
	if state().RotateAt == 0 || changes.Load() == before {
		t.Fatal("the forced switch left no request, or woke nobody")
	}
	entries, err := srv.Store.ListAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	var forced, refused bool
	for _, e := range entries {
		forced = forced || (e.Action == "service.rotate force" && e.Target == "site" && e.Result == "ok")
		refused = refused || (e.Action == "service.rotate" && e.Target == "site" && strings.HasPrefix(e.Result, "error"))
	}
	if !forced || !refused {
		t.Fatalf("audit: %+v", entries)
	}

	// The switch made (the certificate manager's part), its new next key
	// 15 days in subscriptions: no force needed.
	issueSite(t, srv.Store, site.ID, now.Add(-15*24*time.Hour))
	if s := state(); s.RotateAt != 0 || s.NextAt != now.Add(-15*24*time.Hour).Unix() {
		t.Fatalf("after the switch: %+v", s)
	}
	if r, err := rotate(as(0), false); err != nil || r.Key != "tls" {
		t.Fatalf("after the lead: %+v %v", r, err)
	}

	// That switch made now: the key in use is minutes old, and the one after
	// it too. Forced again it would land on a key that lists in use lack:
	// refused, with the way out named.
	issueSite(t, srv.Store, site.ID, now.Add(-time.Minute))
	if _, err := rotate(as(0), true); connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "rayctl service rotate site -fresh") {
		t.Fatalf("forced a minute after a switch: %v", err)
	}
	// A fresh key: root only, no lead and no age asked, audited as itself.
	for who, c := range map[string]context.Context{"the group": as(1000), "remote": remote} {
		if _, err := ask(c, false, true); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("a fresh key, %s: %v", who, err)
		}
	}
	if r, err := ask(as(0), false, true); err != nil || r.Key != "tls" {
		t.Fatalf("a fresh key: %+v %v", r, err)
	}
	if s := state(); s.RotateAt == 0 || s.RotateHow != provision.SiteSwitchFresh {
		t.Fatalf("the request for a fresh key: %+v", s)
	}
	entries, err = srv.Store.ListAudit(ctx, 5)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(entries, func(e store.AuditEntry) bool {
		return e.Action == "service.rotate fresh" && e.Target == "site" && e.Result == "ok"
	}) {
		t.Fatalf("audit: %+v", entries)
	}
}

// The operator's certificate replaces the key clients pin and takes the
// pins off every line: root's on the node, as the key switch is, not the
// API group's and not a remote admin's. And it is refused, unless forced,
// when it would cut the clients that hold the pins.
func TestSetCertificateIsRoots(t *testing.T) {
	srv, _, _ := startServer(t)
	srv.Certificates = true
	ctx := context.Background()
	as := func(uid uint32) context.Context {
		return context.WithValue(context.WithValue(ctx, peerKey{}, &unix.Ucred{Uid: uid}), actorKey{}, "test")
	}
	remote := context.WithValue(ctx, actorKey{}, "admin/laptop (remote)")
	site, err := provision.CreateService(ctx, srv.Store, store.Service{Kind: "site", Name: "site", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	issueSite(t, srv.Store, site.ID, now.Add(-30*24*time.Hour))
	pins := func() []string {
		svc, secrets, err := srv.Store.ServiceWithSecrets(ctx, site.ID)
		if err != nil {
			t.Fatal(err)
		}
		return provision.SiteKeyPins(svc, secrets, now)
	}
	pinned := pins()
	if len(pinned) != 2 {
		t.Fatalf("pins %v", pinned)
	}
	svc, _ := srv.Store.ServiceByName(ctx, "site")
	own, err := testca.New([]string{provision.SiteName(svc)}, now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	set := func(ctx context.Context, force bool) (*nodev1.SetCertificateResponse, error) {
		r, err := srv.SetCertificate(ctx, connect.NewRequest(&nodev1.SetCertificateRequest{Service: "site", ChainPem: own.ChainPEM,
			KeyPem: own.KeyPEM, Force: force}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
	}
	for who, c := range map[string]context.Context{"the group": as(1000), "remote": remote} {
		if _, err := set(c, true); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("%s replaced the pinned key: %v", who, err)
		}
	}
	if _, err := set(as(0), false); connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "-force") {
		t.Fatalf("root, another key under pins, without force: %v", err)
	}
	if got := pins(); !slices.Equal(got, pinned) {
		t.Fatalf("pins after the refusals: %v, were %v", got, pinned)
	}
	r, err := set(as(0), true)
	if err != nil || !r.Unpinned || pins() != nil {
		t.Fatalf("root with force: %+v %v, pins %v", r, err, pins())
	}
	entries, err := srv.Store.ListAudit(ctx, 5)
	if err != nil {
		t.Fatal(err)
	}
	var forced, refused bool
	for _, e := range entries {
		forced = forced || (e.Action == "service.cert force" && e.Target == "site" && e.Result == "ok")
		refused = refused || (e.Action == "service.cert" && e.Target == "site" && strings.HasPrefix(e.Result, "error"))
	}
	if !forced || !refused {
		t.Fatalf("audit: %+v", entries)
	}
}
