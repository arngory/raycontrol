package api

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/sys/unix"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/store"
)

func TestBackup(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: "alice"})); err != nil {
		t.Fatal(err)
	}

	// Through the socket: root gets it, anyone else is turned away.
	_, err := c.Backup(ctx, connect.NewRequest(&nodev1.BackupRequest{}))
	if os.Getuid() == 0 && err != nil {
		t.Fatalf("root: %v", err)
	}
	if os.Getuid() != 0 && connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("uid %d: %v", os.Getuid(), err)
	}

	as := func(uid uint32) context.Context {
		return context.WithValue(context.WithValue(ctx, peerKey{}, &unix.Ucred{Uid: uid}), actorKey{}, "test")
	}
	if _, err := srv.Backup(as(1000), connect.NewRequest(&nodev1.BackupRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("uid 1000: %v", err)
	}
	resp, err := srv.Backup(as(0), connect.NewRequest(&nodev1.BackupRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(resp.Msg.Database, []byte("SQLite format 3\x00")) || resp.Msg.NodeId == "" || resp.Msg.Version != "test" {
		t.Fatalf("backup: %d bytes, node %q, version %q", len(resp.Msg.Database), resp.Msg.NodeId, resp.Msg.Version)
	}
	path := filepath.Join(t.TempDir(), "restored.db")
	if err := os.WriteFile(path, resp.Msg.Database, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.UserByName(ctx, "alice"); err != nil {
		t.Fatalf("restored copy: %v", err)
	}
	entries, err := srv.Store.ListAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		found = found || e.Action == "node.backup"
	}
	if !found {
		t.Fatal("backup not audited")
	}
}

func TestMetrics(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	// rayd's loops report here (O-2).
	srv.Health = &health.Board{Now: func() time.Time { return time.Unix(1700000000, 0) }}
	srv.Health.Done("apply", nil)
	srv.Health.Done("acme site", errors.New("site.example.org does not resolve"))
	for _, svc := range [][3]string{{"reality", "reality", `{"target":"www.example.org:443"}`}, {"hy2-obfs", "hy2", ""}} {
		if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: svc[0], Name: svc[1], SettingsJson: svc[2]})); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range []string{"alice", "bob"} {
		if _, err := c.CreateUser(ctx, connect.NewRequest(&nodev1.CreateUserRequest{Name: u})); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.SetUserEnabled(ctx, connect.NewRequest(&nodev1.SetUserEnabledRequest{Name: "bob", Enabled: false})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateDevice(ctx, connect.NewRequest(&nodev1.CreateDeviceRequest{User: "alice", Name: "phone"})); err != nil {
		t.Fatal(err)
	}
	// Two dnstt services: the counters of the one whose backend gives them
	// on its stats socket; the other, without one, has none and no error.
	srv.Paths.Run = t.TempDir()
	for _, name := range []string{"dns", "dns2"} {
		if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: "dnstt", Name: name})); err != nil {
			t.Fatal(err)
		}
	}
	serveStats(t, srv.Paths.StatsSocket("dns"), `{"queries":5,"memo_hits":6,"sessions":1,"handshakes":0,"sessions_admitted":7,`+
		`"starts_refused_device":2,"auth_refused":3,"seal_opened":4,"unknown":9}`+"\n")
	resp, err := c.GetMetrics(ctx, connect.NewRequest(&nodev1.GetMetricsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	text := resp.Msg.Text
	for _, want := range []string{
		`raycontrol_info{version="test"} 1`,
		`raycontrol_users{state="active"} 1`,
		`raycontrol_users{state="disabled"} 1`,
		`raycontrol_users{state="expired"} 0`,
		`raycontrol_devices{role="user",state="active"} 1`,
		`raycontrol_devices{role="admin",state="active"} 0`,
		`raycontrol_services{kind="reality",enabled="true"} 1`,
		`raycontrol_services{kind="hy2-obfs",enabled="true"} 1`,
		`raycontrol_certificate_not_after_seconds{service="hy2",kind="hy2-obfs"} `,
		`raycontrol_reality_next_from_seconds{service="reality"} 0`,
		"# TYPE raycontrol_dns_problems gauge\nraycontrol_dns_problems ",
		`raycontrol_loop_last_success_seconds{loop="apply"} 1700000000`,
		`raycontrol_loop_last_error_seconds{loop="acme site"} 1700000000`,
		`raycontrol_loop_last_success_seconds{loop="acme site"} 0`,
		`raycontrol_loop_errors_total{loop="acme site"} 1`,
		`raycontrol_dnstt_queries_total{service="dns"} 5`,
		`raycontrol_dnstt_memo_hits_total{service="dns"} 6`,
		`raycontrol_dnstt_sessions{service="dns"} 1`,
		`raycontrol_dnstt_handshakes{service="dns"} 0`,
		`raycontrol_dnstt_sessions_admitted_total{service="dns"} 7`,
		`raycontrol_dnstt_starts_refused_total{service="dns",reason="full"} 0`,
		`raycontrol_dnstt_starts_refused_total{service="dns",reason="device"} 2`,
		`raycontrol_dnstt_auth_total{service="dns",result="refused"} 3`,
		`raycontrol_dnstt_seal_total{service="dns",result="opened"} 4`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in\n%s", want, text)
		}
	}
	if strings.Contains(text, "alice") || strings.Contains(text, "phone") || strings.Contains(text, "does not resolve") {
		t.Errorf("names of users or devices, or error text, in the metrics:\n%s", text)
	}
	if strings.Contains(text, `service="dns2"`) {
		t.Errorf("counters of a dnstt service without a stats socket:\n%s", text)
	}
	st, err := c.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if l := st.Msg.Loops; len(l) != 2 || l[0].Name != "acme site" || l[0].Error != "site.example.org does not resolve" || l[0].LastOk != 0 ||
		l[1].Name != "apply" || l[1].LastOk != 1700000000 {
		t.Fatalf("status loops %v", l)
	}
	// Each family is one block: its samples follow its TYPE line.
	family := ""
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if name, ok := strings.CutPrefix(line, "# TYPE "); ok {
			family = strings.Fields(name)[0]
			if seen[family] {
				t.Errorf("family %s twice", family)
			}
			seen[family] = true
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		if name := strings.FieldsFunc(line, func(r rune) bool { return r == '{' || r == ' ' })[0]; name != family {
			t.Errorf("sample %q outside its family (%s)", line, family)
		}
	}
}

// serveStats gives line to each connection on a unix socket at path, as a
// dnstt backend's stats socket does.
func serveStats(t *testing.T, path, line string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte(line))
			c.Close()
		}
	}()
}
