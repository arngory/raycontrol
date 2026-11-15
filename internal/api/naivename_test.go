package api

import (
	"context"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/testca"
)

// rayctl service rotate on naive (R4-42) asks for a switch of its server
// name, and ListServices shows the name in use and, once published only,
// the next one with its time: a next name chosen and routed ahead is no
// client's yet.
func TestRotateNaiveName(t *testing.T) {
	srv, sock, _ := startServer(t)
	srv.RealityLead = 72 * time.Hour
	rotated := 0
	srv.Rotate = func() { rotated++ }
	ctx := context.Background()
	c := NewUnixClient(sock)
	for _, s := range [][2]string{{"reality", "r"}, {"naive", "nv"}} {
		if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: s[0], Name: s[1]})); err != nil {
			t.Fatal(err)
		}
	}
	listed := func() *nodev1.Service {
		t.Helper()
		l, err := c.ListServices(ctx, connect.NewRequest(&nodev1.ListServicesRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range l.Msg.Services {
			if s.Name == "nv" {
				return s
			}
		}
		t.Fatal("no nv")
		return nil
	}
	nv, _ := srv.Store.ServiceByName(ctx, "nv")
	first := provision.ParseNaiveState(nv)
	if s := listed(); s.Sni != first.SNI || s.SniNext != "" || s.NextFrom != 0 || first.SNINext == "" {
		t.Fatalf("before the publication: %+v (next %s chosen)", s, first.SNINext)
	}

	start := time.Now()
	r, err := c.RotateService(ctx, connect.NewRequest(&nodev1.RotateServiceRequest{Name: "nv"}))
	if err != nil || r.Msg.Kind != "naive" || rotated != 1 || r.Msg.SwitchAt < start.Add(72*time.Hour).Unix() || r.Msg.Seal {
		t.Fatalf("rotate: %v %v", r, err)
	}
	// The round publishes it once the site's certificate covers it.
	site, _ := srv.Store.ServiceByName(ctx, "site")
	keyDER, certDER, _ := provision.SelfSigned("*.example.com")
	srv.Store.SetServiceSecret(ctx, site.ID, provision.SecretTLSChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	srv.Store.SetServiceSecret(ctx, site.ID, provision.SecretTLSKey, keyDER)
	e := provision.RealityEpoch{Lead: 72 * time.Hour, Prepare: 24 * time.Hour}
	if _, err := provision.RotateReality(ctx, srv.Store, time.Now(), e, nil, nil); err != nil {
		t.Fatal(err)
	}
	if s := listed(); s.Sni != first.SNI || s.SniNext != first.SNINext || s.NextFrom < start.Add(72*time.Hour).Unix() {
		t.Fatalf("published: %+v", s)
	}
	// -now: the response says naive; the switch is the round's.
	if r, err = c.RotateService(ctx, connect.NewRequest(&nodev1.RotateServiceRequest{Name: "nv", Now: true})); err != nil || r.Msg.Kind != "naive" ||
		r.Msg.SwitchAt > time.Now().Unix() {
		t.Fatalf("rotate -now: %v %v", r, err)
	}
	if _, err := provision.RotateReality(ctx, srv.Store, time.Now(), e, nil, nil); err != nil {
		t.Fatal(err)
	}
	if s := listed(); s.Sni != first.SNINext || s.SniNext != "" || s.NextFrom != 0 {
		t.Fatalf("after -now: %+v", s)
	}
	// rotate_sni on naive, through the API.
	if r, err := c.SetServiceOption(ctx, connect.NewRequest(&nodev1.SetServiceOptionRequest{Name: "nv", Key: "rotate_sni", Value: "on"})); err != nil ||
		provision.ParseNaiveState(srvService(t, srv, "nv")).RotateSNI == nil {
		t.Fatalf("rotate_sni=on: %v %v", r, err)
	}
}

// The client's interop stand (rayd serve -supervise -acme-directory "",
// test/supervise/run.sh): a wildcard certificate of the operator's
// (rayctl service cert site), a short lead (rayd serve -cred-lead 2m).
// rayctl service rotate naive publishes the next name at once, the
// switch a lead away, and -now switches in the same round; the previous
// name stays in the front's routes.
func TestRotateNaiveNameOnStand(t *testing.T) {
	srv, sock, _ := startServer(t)
	srv.RealityLead = 2 * time.Minute
	e := provision.RealityEpoch{Lead: srv.RealityLead, Prepare: 24 * time.Hour, Grace: 48 * time.Hour, NaivePeriod: 90 * 24 * time.Hour}
	ctx := context.Background()
	// rayd's rotation loop runs a round at each request.
	srv.Rotate = func() {
		if _, err := provision.RotateReality(ctx, srv.Store, time.Now(), e, nil, nil); err != nil {
			t.Error(err)
		}
	}
	c := NewUnixClient(sock)
	for _, s := range [][2]string{{"reality", "r"}, {"naive", "nv"}} {
		if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: s[0], Name: s[1]})); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "alice", Services: []string{"nv"}})); err != nil {
		t.Fatal(err)
	}
	ca, err := testca.New([]string{"*.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provision.SetCertificate(ctx, srv.Store, "site", ca.ChainPEM, ca.KeyPEM, time.Now(), false); err != nil {
		t.Fatal(err)
	}
	first := provision.ParseNaiveState(srvService(t, srv, "nv"))
	start := time.Now()
	if _, err := c.RotateService(ctx, connect.NewRequest(&nodev1.RotateServiceRequest{Name: "nv"})); err != nil {
		t.Fatal(err)
	}
	ns := provision.ParseNaiveState(srvService(t, srv, "nv"))
	if ns.SNI != first.SNI || ns.SNINext != first.SNINext || ns.NextFrom < start.Add(2*time.Minute).Unix() || ns.NextFrom > time.Now().Add(2*time.Minute).Unix() {
		t.Fatalf("published: %+v", ns)
	}
	// The user's export, as the subscription: the next line under the new
	// name from the switch's time.
	ex, err := c.ExportUser(ctx, connect.NewRequest(&nodev1.ExportUserRequest{Name: "alice"}))
	if err != nil || len(ex.Msg.Profiles) != 1 {
		t.Fatalf("export: %v %v", ex, err)
	}
	if p := ex.Msg.Profiles[0]; !strings.Contains(p.Link, "sni="+first.SNI) || !strings.Contains(p.NextLink, "sni="+first.SNINext) || p.NextFrom != ns.NextFrom {
		t.Fatalf("profile %+v", p)
	}
	if _, err := c.RotateService(ctx, connect.NewRequest(&nodev1.RotateServiceRequest{Name: "nv", Now: true})); err != nil {
		t.Fatal(err)
	}
	if sw := provision.ParseNaiveState(srvService(t, srv, "nv")); sw.SNI != first.SNINext || sw.SNIPrev != first.SNI || sw.NextFrom != 0 {
		t.Fatalf("after -now: %+v", sw)
	}
}

func srvService(t *testing.T, srv *Server, name string) store.Service {
	t.Helper()
	svc, err := srv.Store.ServiceByName(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}
