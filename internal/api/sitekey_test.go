package api

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/sys/unix"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
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
	rotate := func(ctx context.Context, force bool) (*nodev1.RotateServiceResponse, error) {
		r, err := srv.RotateService(ctx, connect.NewRequest(&nodev1.RotateServiceRequest{Name: "site", Force: force}))
		if err != nil {
			return nil, err
		}
		return r.Msg, nil
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

	// The next key in subscriptions for a day: too early.
	now := time.Now()
	issueSite(t, srv.Store, site.ID, now.Add(-24*time.Hour))
	before := changes.Load()
	_, err = rotate(as(0), false)
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "rayctl service rotate site -force") {
		t.Fatalf("a day in: %v", err)
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
}
