package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/api"
	"github.com/arngory/raycontrol/internal/deploy"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
)

// fakeRayd answers GetDeployment with a plan of its own, root's undoing,
// and GetDeployInputs with inputs, unless they are nil: then it has no
// such call, as a rayd before v0.21.0.
type fakeRayd struct {
	inputs      *nodev1.GetDeployInputsResponse
	deployments atomic.Int32 // GetDeployment calls
}

func (f *fakeRayd) client(t *testing.T) nodev1connect.NodeServiceClient {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(nodev1connect.NodeServiceGetDeploymentProcedure, connect.NewUnaryHandler(nodev1connect.NodeServiceGetDeploymentProcedure,
		func(context.Context, *connect.Request[nodev1.GetDeploymentRequest]) (*connect.Response[nodev1.GetDeploymentResponse], error) {
			f.deployments.Add(1)
			return connect.NewResponse(&nodev1.GetDeploymentResponse{
				Users: []*nodev1.SystemUser{{Name: "rayd", Uid: 9190, ExtraGroups: []string{"docker", "disk"}}},
				Files: []*nodev1.DeployFile{
					{Path: "/etc/sudoers.d/rayd", Mode: 0o644, Content: []byte("rayd ALL=(ALL) NOPASSWD: ALL\n")},
					{Path: "/usr/local/bin/rootshell", Mode: uint32(os.ModeSetuid) | 0o755, Content: []byte("#!/bin/sh\n")},
				},
				Units: []string{"debug-shell.service"},
			}), nil
		}))
	if f.inputs != nil {
		mux.Handle(nodev1connect.NodeServiceGetDeployInputsProcedure, connect.NewUnaryHandler(nodev1connect.NodeServiceGetDeployInputsProcedure,
			func(context.Context, *connect.Request[nodev1.GetDeployInputsRequest]) (*connect.Response[nodev1.GetDeployInputsResponse], error) {
				return connect.NewResponse(f.inputs), nil
			}))
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return api.NewNodeClient(srv.Client(), srv.URL, api.MaxAnswer)
}

// testHost is a host in a directory, its commands recorded.
func testHost(t *testing.T) (*deploy.Host, string, *[]string, *bytes.Buffer) {
	t.Helper()
	root := t.TempDir()
	var cmds []string
	out := &bytes.Buffer{}
	return &deploy.Host{Root: root, Out: out,
		Run: func(name string, args ...string) ([]byte, error) {
			cmds = append(cmds, name+" "+strings.Join(args, " "))
			return nil, nil
		},
		LookupUser:  func(string) (int, error) { return 0, errors.New("unknown") },
		LookupGroup: func(string) (int, error) { return 0, errors.New("unknown") },
	}, root, &cmds, out
}

// nodeInputs are a node's inputs as rayd reports them.
func nodeInputs() deploy.Inputs {
	return deploy.Inputs{FrontTCP: true, Front: true, FrontDNS: true, DNSProbeKey: true,
		HostPorts: []deploy.PortRange{{Proto: "tcp", From: 22, To: 22}, {Proto: "udp", From: 53, To: 53}},
		Services: []deploy.ServiceInput{
			{Kind: "inner", Name: "inner", UID: 9110}, {Kind: "dnstt", Name: "dns", UID: 9111}, {Kind: "ssh", Name: "ssh"},
		}}
}

// A rayd before GetDeployInputs (a binary replaced by hand, not yet
// restarted): apply refuses, says what to do, and changes nothing. It does
// not go back to rayd's own plan (spec/apply-plan-v1.md §3.5).
func TestApplyOldRayd(t *testing.T) {
	f := &fakeRayd{}
	h, root, cmds, _ := testHost(t)
	err := (&cli{c: f.client(t)}).deploy(context.Background(), h)
	if !errors.Is(err, errOldRayd) || !strings.Contains(err.Error(), "systemctl restart rayd") {
		t.Fatalf("an old rayd: %v", err)
	}
	if left, _ := os.ReadDir(root); len(left) != 0 || len(*cmds) != 0 {
		t.Errorf("changed the host: %v, ran %v", left, *cmds)
	}
	if f.deployments.Load() != 0 {
		t.Error("asked rayd for its plan")
	}
}

// apply installs the plan it builds from rayd's inputs, never rayd's own:
// what rayd's GetDeployment says is not even asked for.
func TestApplyBuildsItsOwnPlan(t *testing.T) {
	f := &fakeRayd{inputs: api.DeployInputsProto(nodeInputs())}
	h, root, _, _ := testHost(t)
	c := &cli{c: f.client(t)}
	if err := c.deploy(context.Background(), h, "rayd.service"); err != nil {
		t.Fatal(err)
	}
	want, _, err := c.deployPlan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range want.Files {
		if _, err := os.Stat(filepath.Join(root, file.Path)); err != nil && file.Path != deploy.FirewalldService && file.Path != deploy.UFWProfile {
			t.Errorf("%s not written: %v", file.Path, err)
		}
	}
	for _, p := range []string{"/etc/sudoers.d/rayd", "/usr/local/bin/rootshell"} {
		if _, err := os.Stat(filepath.Join(root, p)); !os.IsNotExist(err) {
			t.Errorf("rayd's file %s written", p)
		}
	}
	if f.deployments.Load() != 0 {
		t.Error("asked rayd for its plan")
	}
	b, _ := os.ReadFile(filepath.Join(root, "/etc/systemd/system/niko-dns.service"))
	if !strings.Contains(string(b), "ExecStartPre=+/usr/local/bin/rayd credential /var/lib raycontrol/rendered/dns/noise.key rayd niko-dns /run/niko/dns/noise.key\n") {
		t.Errorf("dns unit:\n%s", b)
	}
}

// Inputs that cannot be a node's fail the apply whole; a service that
// cannot be one is left out, said in a form a terminal does not act on.
func TestApplyHostileInputs(t *testing.T) {
	for name, f := range map[string]func(*nodev1.GetDeployInputsResponse){
		"a port past 65535": func(r *nodev1.GetDeployInputsResponse) { r.HostPorts[0].From, r.HostPorts[0].To = 65536+22, 65536+22 },
		"a protocol": func(r *nodev1.GetDeployInputsResponse) {
			r.HostPorts[0].Proto = `tcp"/><port protocol="tcp" port="1-65535`
		},
		"subscription port": func(r *nodev1.GetDeployInputsResponse) { r.SubscriptionPort = 70000 },
	} {
		r := api.DeployInputsProto(nodeInputs())
		f(r)
		h, root, cmds, _ := testHost(t)
		err := (&cli{c: (&fakeRayd{inputs: r}).client(t)}).deploy(context.Background(), h)
		if err == nil || !strings.Contains(err.Error(), "nothing was changed") {
			t.Errorf("%s: %v", name, err)
		}
		if left, _ := os.ReadDir(root); len(left) != 0 || len(*cmds) != 0 {
			t.Errorf("%s: changed the host: %v, ran %v", name, left, *cmds)
		}
	}

	in := nodeInputs()
	in.Services = append(in.Services, deploy.ServiceInput{Kind: "site", Name: "evil", UID: 9150, Answer: "404\nExecStartPre=+/bin/sh -c id"})
	in.Warnings = []string{"not rendered: \x1b]0;owned\x07\x1b[2J"}
	h, root, _, out := testHost(t)
	if err := (&cli{c: (&fakeRayd{inputs: api.DeployInputsProto(in)}).client(t)}).deploy(context.Background(), h, "rayd.service"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "/etc/systemd/system/niko-evil.service")); !os.IsNotExist(err) {
		t.Error("the bad site deployed")
	}
	if !strings.Contains(out.String(), "warning: service evil (site) left out") || strings.Contains(out.String(), "\x1b") {
		t.Errorf("output:\n%q", out)
	}
}
