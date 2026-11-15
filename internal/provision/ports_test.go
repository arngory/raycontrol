package provision

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/store"
)

// -ports: names once each, ports from 1024, ranges that do not overlap
// each other or sshd's port; the choice reads back as it was given.
func TestParsePorts(t *testing.T) {
	c, err := ParsePorts(" spa=40000-40099, sub=40100,api=40101,rotation=41000-41999")
	if err != nil {
		t.Fatal(err)
	}
	want := PortChoice{SPA: Span{40000, 100}, Sub: 40100, API: 40101, Rotation: Span{41000, 1000}}
	if c != want || c.String() != "spa=40000-40099,sub=40100,api=40101,rotation=41000-41999" {
		t.Fatalf("%+v %q", c, c)
	}
	if back, err := ParsePorts(c.String()); err != nil || back != c {
		t.Fatalf("read back %+v %v", back, err)
	}
	if c, err := ParsePorts("spa=40000,rotation=off"); err != nil || c.SPA != (Span{40000, 1}) || !c.NoRotate || c.String() != "spa=40000,rotation=off" {
		t.Fatalf("one knock port, no rotation: %+v %v", c, err)
	}
	if c, err := ParsePorts(""); err != nil || !c.Zero() {
		t.Fatalf("none: %+v %v", c, err)
	}
	for in, msg := range map[string]string{
		"spa=443":                        "privileged",
		"sub=80":                         "privileged",
		"api=1023":                       "privileged",
		"spa=40000-39999":                "a port or first-last",
		"spa=40000-70000":                "a port or first-last",
		"sub=40000-40001":                "one port",
		"api=x":                          "a port or first-last",
		"rotation=on":                    "a port or first-last",
		"dns=5353":                       "not one of",
		"sub=40000,sub=40001":            "once each",
		"sub":                            "once each",
		"spa=40000-40099,sub=40050":      "overlap",
		"api=41000,rotation=41000-41999": "overlap",
		"spa=2000-2999":                  "SSH listens on",
	} {
		if _, err := ParsePorts(in, 2222); err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("%q: %v, want %q", in, err, msg)
		}
	}
}

// The first install takes the chosen ports: the SPA range, the
// subscription's, the API's when its service is made, the rotation pool
// carved for the services; what was not chosen stays random and clear of
// them. A node that exists takes only its own ports again.
func TestInitPorts(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	c, _ := ParsePorts("spa=40000-40099,sub=40100,api=40101,rotation=41000-41399")
	p, err := Init(ctx, st, Options{Host: "203.0.113.7", Domain: "example.com", Ports: c})
	if err != nil {
		t.Fatal(err)
	}
	if p.PortBase != 40000 || p.PortRange != 100 {
		t.Fatalf("SPA %d+%d", p.PortBase, p.PortRange)
	}
	sub, _ := st.ServiceByName(ctx, SubscriptionService)
	if ps, _ := sub.Ports(); len(ps) != 2 || ps[0] != (store.Port{Proto: "tcp", Num: 40100}) || ps[1] != (store.Port{Proto: "udp", Num: 40100}) {
		t.Fatalf("subscription %v", ps)
	}
	if got, _ := Ports(ctx, st); got != c {
		t.Fatalf("kept %+v", got)
	}
	api, err := CreateService(ctx, st, store.Service{Kind: "api", Name: "api", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if ps, _ := api.Ports(); len(ps) != 1 || ps[0] != (store.Port{Proto: "tcp", Num: 40101}) {
		t.Fatalf("api %v", ps)
	}
	// Four quarters of the pool, then no more.
	for i, name := range []string{"h1", "h2", "h3", "h4"} {
		s, err := CreateService(ctx, st, store.Service{Kind: "hy2-masq", Name: name, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		if rot, ok := ServiceRotation(s); !ok || rot.Base != uint16(41000+100*i) || rot.Range != 100 {
			t.Fatalf("%s rotation %+v", name, rot)
		}
	}
	if _, err := CreateService(ctx, st, store.Service{Kind: "hy2-masq", Name: "h5", Enabled: true}); !errors.Is(err, store.ErrInvalid) ||
		!strings.Contains(err.Error(), "41000-41399") {
		t.Fatalf("a fifth rotation: %v", err)
	}
	// The ACME responder's random port keeps clear of the chosen ones.
	acme, err := ACMEPort(ctx, st)
	if err != nil || acme >= 40000 && acme <= 41399 {
		t.Fatalf("acme %d %v", acme, err)
	}

	// Again: the same ports, a part of them, or none are taken; others
	// are refused before anything changes.
	for _, again := range []string{"", "spa=40000-40099", "sub=40100,api=40101", c.String()} {
		ac, _ := ParsePorts(again)
		if _, err := Init(ctx, st, Options{Ports: ac}); err != nil {
			t.Errorf("again with %q: %v", again, err)
		}
	}
	for _, other := range []string{"spa=40000-40199", "sub=40102", "api=40102", "rotation=42000-42999", "rotation=off"} {
		oc, _ := ParsePorts(other)
		if err := CheckPorts(ctx, st, oc); !errors.Is(err, store.ErrInvalid) || !strings.Contains(err.Error(), "first install only") {
			t.Errorf("again with %q: %v", other, err)
		}
		if _, err := Init(ctx, st, Options{Ports: oc}); err == nil {
			t.Errorf("init again with %q", other)
		}
	}
	if p2, _ := node.LoadParams(ctx, st); p2.PortBase != 40000 || p2.PortRange != 100 {
		t.Fatalf("SPA moved: %d+%d", p2.PortBase, p2.PortRange)
	}
}

// Chosen ports with the SPA range left random: the range is drawn clear
// of them; rotation=off gives the UDP services none, on 443 as before; a
// node made without -ports takes none later.
func TestInitPortsRandomSPA(t *testing.T) {
	ctx := context.Background()
	for range 20 {
		st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
		if err != nil {
			t.Fatal(err)
		}
		c, _ := ParsePorts("sub=30000,api=40000,rotation=off")
		p, err := Init(ctx, st, Options{Host: "203.0.113.7", Domain: "example.com", Ports: c})
		if err != nil {
			t.Fatal(err)
		}
		spaSpan := Span{p.PortBase, p.PortRange}
		if spaSpan.overlaps(Span{30000, 1}) || spaSpan.overlaps(Span{40000, 1}) {
			t.Fatalf("SPA %s holds a chosen port", spaSpan)
		}
		s, err := CreateService(ctx, st, store.Service{Kind: "hy2-masq", Name: "hy2", Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := ServiceRotation(s); ok {
			t.Fatal("rotation=off: a rotation")
		}
		st.Close()
	}
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := Init(ctx, st, Options{Host: "203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	if err := CheckPorts(ctx, st, PortChoice{API: 40000}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("a choice after the first install: %v", err)
	}
}

// A node made without -ports, installed again naming its own random SPA
// range (CheckPorts lets that through): nothing is stored, and its ports
// stay random, as rayctl ports says.
func TestInitAgainKeepsRandom(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p, err := Init(ctx, st, Options{Host: "203.0.113.7", Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	c := PortChoice{SPA: Span{p.PortBase, p.PortRange}}
	if _, err := Init(ctx, st, Options{Host: "203.0.113.7", Domain: "example.com", Ports: c}); err != nil {
		t.Fatal(err)
	}
	if got, err := Ports(ctx, st); err != nil || !got.Zero() {
		t.Fatalf("kept %+v %v, want none", got, err)
	}
}

// rayd init's -ssh-ports, and sshd -T's output.
func TestSSHPorts(t *testing.T) {
	if ps, err := ParseSSHPorts("22, 2222,22"); err != nil || len(ps) != 2 || ps[0] != 22 || ps[1] != 2222 {
		t.Fatalf("%v %v", ps, err)
	}
	if ps, err := ParseSSHPorts("none"); err != nil || ps != nil {
		t.Fatalf("none: %v %v", ps, err)
	}
	for _, bad := range []string{"", "0", "70000", "ssh"} {
		if _, err := ParseSSHPorts(bad); err == nil {
			t.Errorf("%q taken", bad)
		}
	}
	if SSHPortsArg(nil) != "none" || SSHPortsArg([]uint16{22, 2222}) != "22,2222" {
		t.Error("SSHPortsArg")
	}
	ps, err := SSHDPorts("port 22\nlistenaddress [::]:2222\nlistenaddress 0.0.0.0:2222 rdomain red\n")
	if err != nil || len(ps) != 1 || ps[0] != 2222 {
		t.Fatalf("%v %v", ps, err)
	}
	c, err := ParsePorts("spa=2200-2299", ps...)
	if err == nil || !strings.Contains(err.Error(), "SSH") {
		t.Fatalf("over sshd's port: %+v %v", c, err)
	}
}
