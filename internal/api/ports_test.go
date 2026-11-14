package api

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// GetPorts names every port the perimeter has: SPA and each rotating range
// with the port of this slot, the subscription, the API, SSH for the admin
// addresses, the front's 443 behind the knock, DNS tunnels for everyone,
// TCP 80 while certificates come through HTTP-01. A disabled service has
// none.
func TestGetPorts(t *testing.T) {
	srv, sock, _ := startServer(t)
	ctx := context.Background()
	c := NewUnixClient(sock)
	for _, s := range []struct{ kind, name, settings string }{
		{"ssh", "ssh", `{"ports":["tcp/2222"]}`}, {"api", "api", ""}, {"reality", "reality", ""}, {"hy2-masq", "hy2", ""},
		{"dnstt", "dns", ""}, {"naive", "off", ""},
	} {
		if _, err := c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: s.kind, Name: s.name, SettingsJson: s.settings})); err != nil {
			t.Fatal(s.name, err)
		}
	}
	if _, err := c.SetServiceEnabled(ctx, connect.NewRequest(&nodev1.SetServiceEnabledRequest{Name: "off", Enabled: false})); err != nil {
		t.Fatal(err)
	}
	r, err := c.GetPorts(ctx, connect.NewRequest(&nodev1.GetPortsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	byName := map[string]*nodev1.NodePort{}
	for _, p := range r.Msg.Ports {
		got = append(got, p.Name+" "+strings.Join(p.Protos, "+")+" "+p.Source+" "+p.Access)
		byName[p.Name] = p
	}
	for _, want := range []string{"spa tcp+udp random everyone", "sub tcp+udp random spa", "api tcp random spa", "ssh tcp sshd admin",
		"reality tcp fixed spa", "hy2 udp fixed spa", "hy2 rotation udp random spa", "dns udp fixed everyone", "acme tcp fixed acme"} {
		if !slices.Contains(got, want) {
			t.Errorf("no %q in %q", want, got)
		}
	}
	if byName["off"] != nil {
		t.Error("a disabled service has ports")
	}
	p := srv.Params
	spa := byName["spa"]
	if spa.From != uint32(p.PortBase) || spa.To != uint32(p.PortBase)+uint32(p.PortRange)-1 || spa.Current < spa.From || spa.Current > spa.To {
		t.Errorf("spa %+v", spa)
	}
	if !slices.Contains(p.ActivePorts(time.Now()), uint16(spa.Current)) || spa.CurrentUntil <= time.Now().Unix() ||
		spa.CurrentUntil > time.Now().Add(p.SlotLen).Unix() {
		t.Errorf("spa now %d until %d", spa.Current, spa.CurrentUntil)
	}
	rot := byName["hy2 rotation"]
	if rot.Current < rot.From || rot.Current > rot.To || rot.CurrentUntil != spa.CurrentUntil {
		t.Errorf("rotation %+v", rot)
	}
	if byName["ssh"].From != 2222 || byName["reality"].From != 443 || byName["dns"].From != 53 {
		t.Errorf("ports %v", got)
	}
	// Ports chosen at install say so (provision.Ports).
	srv.Store.SetSetting(ctx, "ports_chosen", []byte(fmt.Sprintf("sub=%d,api=%d", byName["sub"].From, byName["api"].From)))
	r, err = c.GetPorts(ctx, connect.NewRequest(&nodev1.GetPortsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range r.Msg.Ports {
		if want := map[string]string{"sub": "chosen", "api": "chosen", "spa": "random"}[p.Name]; want != "" && p.Source != want {
			t.Errorf("%s: %s, want %s", p.Name, p.Source, want)
		}
	}
}
