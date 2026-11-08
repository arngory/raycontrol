package api

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/deploy"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// hostileNode is a node whose services table has rows written past the
// store's rules (rayd owns the file; a restored copy is anyone's), then
// opened again as rayd opens it.
func hostileNode(t *testing.T, good []store.Service, rows func(context.Context, *sql.DB)) *Server {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "rayd.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provision.Init(ctx, st, provision.Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	for _, svc := range good {
		if _, err := provision.CreateService(ctx, st, svc); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	rows(ctx, db)
	db.Close()
	if st, err = store.Open(ctx, path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	params, err := node.LoadParams(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{Store: st, Params: params, Version: "test", Paths: render.DefaultPaths, Binaries: deploy.DefaultBinaries}
}

// rootPlan is the plan root builds from GetDeployInputs, as rayctl apply
// does: read back, checked, built with root's paths and binaries.
func rootPlan(t *testing.T, srv *Server) (*nodev1.GetDeployInputsResponse, deploy.Plan) {
	t.Helper()
	resp, err := srv.GetDeployInputs(context.Background(), connect.NewRequest(&nodev1.GetDeployInputsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	in, err := DeployInputs(resp.Msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Check(); err != nil {
		t.Fatal(err)
	}
	return resp.Msg, deploy.Build(in, render.DefaultPaths, deploy.DefaultBinaries)
}

// A hostile database (spec/apply-plan-v1.md §2.3, §4.2): rayd reports its
// rows as they are, and root's checks keep every one of them out of the
// plan; the other services are deployed.
func TestDeployInputsHostileDatabase(t *testing.T) {
	inject := "ExecStartPre=+/bin/sh -c id"
	hostile := []struct {
		kind, name, settings string
		uid                  int
	}{
		{"site", "evil-site", `{"answer":"404\n` + inject + `"}`, 9150},
		{"doh", "x 0755 root root -\nZ /etc 0777 rayd rayd -\nd /run/niko/y", "{}", 9151},
		{"reality", "r2", `{"site":"front,disk","target":"www.example.org:443"}`, 9152},
		{"dnstt", "a/../x", "{}", 9153},
		{"hy2-masq", "h0", "{}", 0},
		{"hy2-masq", "h9180", "{}", 9180},
		{"hy2-masq", "hdup", "{}", -1}, // the UID of dns
		{"evil", "e", "{}", 9154},
		{"olcrtc", "o\x1b[2J", "{}", 9155},
	}
	srv := hostileNode(t, []store.Service{
		{Kind: "ssh", Name: "ssh", Enabled: true},
		{Kind: "dnstt", Name: "dns", Enabled: true},
		{Kind: "reality", Name: "reality", Enabled: true, Settings: `{"target":"www.example.org:443"}`},
	}, func(ctx context.Context, db *sql.DB) {
		// The UID index too: the file is rayd's.
		if _, err := db.ExecContext(ctx, `DROP INDEX services_uid`); err != nil {
			t.Fatal(err)
		}
		for _, h := range hostile {
			uid := any(h.uid)
			if h.uid < 0 {
				uid = nil
			}
			q := `INSERT INTO services (kind, name, enabled, settings_json, uid, created_at) VALUES (?, ?, 1, ?, ?, 0)`
			if h.uid < 0 {
				q = `INSERT INTO services (kind, name, enabled, settings_json, uid, created_at) VALUES (?, ?, 1, ?, (SELECT uid FROM services WHERE name = 'dns'), 0)`
				if _, err := db.ExecContext(ctx, q, h.kind, h.name, h.settings); err != nil {
					t.Fatal(err)
				}
				continue
			}
			if _, err := db.ExecContext(ctx, q, h.kind, h.name, h.settings, uid); err != nil {
				t.Fatal(err)
			}
		}
	})
	resp, plan := rootPlan(t, srv)
	// rayd reports them as they are: it is root that checks.
	for _, h := range hostile {
		i := slices.IndexFunc(resp.Services, func(s *nodev1.DeployService) bool { return s.Name == h.name })
		if i < 0 || resp.Services[i].Kind != h.kind {
			t.Errorf("service %q not reported as it is", h.name)
		}
	}
	for _, u := range []string{"niko-dns.service", "niko-reality.service", "niko-inner.service", "niko-front.service"} {
		if !slices.Contains(plan.Units, u) {
			t.Errorf("good unit %s not deployed: %v", u, plan.Units)
		}
	}
	for _, f := range plan.Files {
		for _, bad := range []string{"/bin/sh", "Z /etc", "disk", "a/../x", "niko-h0", "h9180", "hdup", "niko-e.", "\x1b"} {
			if strings.Contains(string(f.Content), bad) || strings.Contains(f.Path, bad) {
				t.Errorf("%q in %s:\n%s", bad, f.Path, f.Content)
			}
		}
	}
	for _, u := range plan.Users {
		if !strings.HasPrefix(u.Name, "niko-") && u.Name != "rayd" && u.Name != "rayspa" || slices.Contains(u.ExtraGroups, "disk") ||
			strings.ContainsAny(u.Name, "/ \n") || u.UID == 0 || u.UID == 9180 {
			t.Errorf("user %+v", u)
		}
	}
	// Each one is said, once, in a form a terminal does not act on.
	left := 0
	for _, w := range plan.Warnings {
		if strings.Contains(w, "left out") || strings.Contains(w, "not deployed") {
			left++
		}
		if p := deploy.PrintableWarning(w); strings.ContainsAny(p, "\n\x1b") {
			t.Errorf("warning printed as %q", p)
		}
	}
	if left != len(hostile) {
		t.Errorf("%d services said left out, want %d:\n%s", left, len(hostile), strings.Join(plan.Warnings, "\n"))
	}
}

// 71 services with a process: one UID too many for the range. 70 are
// deployed.
func TestDeployInputs71Services(t *testing.T) {
	srv := hostileNode(t, nil, func(ctx context.Context, db *sql.DB) {
		if _, err := db.ExecContext(ctx, `DROP INDEX services_uid`); err != nil {
			t.Fatal(err)
		}
		for i := range 71 {
			if _, err := db.ExecContext(ctx, `INSERT INTO services (kind, name, enabled, settings_json, uid, created_at) VALUES ('hy2-masq', ?, 1, '{}', ?, 0)`,
				fmt.Sprintf("h%d", i), store.FirstServiceUID+i%70); err != nil {
				t.Fatal(err)
			}
		}
	})
	resp, plan := rootPlan(t, srv)
	n := 0
	for _, u := range plan.Units {
		if strings.HasPrefix(u, "niko-h") {
			n++
		}
	}
	reported := 0
	for _, s := range resp.Services {
		if s.Kind == "hy2-masq" {
			reported++
		}
	}
	if reported != 71 || n != 70 {
		t.Errorf("%d services reported, %d deployed", reported, n)
	}
}

// GetDeployInputs goes back into the same inputs, and the plan root builds
// from them is the one rayd builds for GetDeployment (on a node, both have
// the same paths and binaries).
func TestDeployInputsRoundTrip(t *testing.T) {
	srv := hostileNode(t, []store.Service{
		{Kind: "ssh", Name: "ssh", Enabled: true},
		{Kind: "dnstt", Name: "dns", Enabled: true},
		{Kind: "reality", Name: "reality", Enabled: true},
		{Kind: "naive", Name: "naive", Enabled: true},
		{Kind: "hy2-obfs", Name: "ho", Enabled: true},
		{Kind: "slipstream", Name: "slip", Enabled: true},
		{Kind: "yggdrasil", Name: "ygg", Enabled: true},
	}, func(context.Context, *sql.DB) {})
	ctx := context.Background()
	in, err := srv.deployInputs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DeployInputs(DeployInputsProto(in))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%+v", back) != fmt.Sprintf("%+v", in) {
		t.Errorf("round trip:\n%+v\n%+v", in, back)
	}
	_, plan := rootPlan(t, srv)
	dep, err := srv.GetDeployment(ctx, connect.NewRequest(&nodev1.GetDeploymentRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	plan.Files = append(plan.Files, deploy.FirewallFiles(in.HostPorts)...)
	if !slices.Equal(plan.Units, dep.Msg.Units) || !slices.Equal(plan.Warnings, dep.Msg.Warnings) || len(plan.Files) != len(dep.Msg.Files) {
		t.Fatalf("root's plan %v %v, rayd's %v %v", plan.Units, plan.Warnings, dep.Msg.Units, dep.Msg.Warnings)
	}
	for i, f := range plan.Files {
		if g := dep.Msg.Files[i]; g.Path != f.Path || g.Mode != f.Mode || string(g.Content) != string(f.Content) {
			t.Errorf("file %s differs", f.Path)
		}
	}
}

// Numbers that do not fit are refused, never cut down to fit.
func TestDeployInputsNumbers(t *testing.T) {
	for _, r := range []*nodev1.GetDeployInputsResponse{
		{HostPorts: []*nodev1.PortRange{{Proto: "tcp", From: 65536 + 22, To: 65536 + 22}}},
		{OutsidePorts: []*nodev1.PortRange{{Proto: "tcp", From: 1, To: 1 << 20}}},
		{Services: make([]*nodev1.DeployService, deploy.MaxInputServices+1)},
	} {
		if _, err := DeployInputs(r); err == nil {
			t.Errorf("accepted %v", r)
		}
	}
	in, err := DeployInputs(&nodev1.GetDeployInputsResponse{SubscriptionPort: 1 << 20,
		Services: []*nodev1.DeployService{{Kind: "slipstream", Name: "slip", Uid: 9110}}})
	if err != nil || in.Check() == nil || in.Services[0].SlipstreamError == "" {
		t.Errorf("%+v %v", in, err)
	}
}
