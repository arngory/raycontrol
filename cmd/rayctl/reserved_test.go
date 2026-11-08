package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/api"
	"github.com/arngory/raycontrol/internal/deploy"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/hostcheck"
)

// rayctl check says whether the node's ports are reserved (in CI rayspa
// could not listen on a slot an outgoing connection held), which are not,
// and what reserves them; nothing without rayd.
func TestReservedResults(t *testing.T) {
	in := nodeInputs()
	in.HostPorts = append(in.HostPorts, deploy.PortRange{Proto: "tcp", From: 42000, To: 43023}, deploy.PortRange{Proto: "udp", From: 42000, To: 43023},
		deploy.PortRange{Proto: "tcp", From: 60718, To: 60718})
	c := raydAnswering(t, func() (*nodev1.GetDeployInputsResponse, error) { return api.DeployInputsProto(in), nil })
	saved := reservedPortsFile
	t.Cleanup(func() { reservedPortsFile = saved })
	reservedPortsFile = filepath.Join(t.TempDir(), "ip_local_reserved_ports")
	for _, x := range []struct{ live, missing string }{
		{"8080,42000-43023,60718\n", ""},
		{"\n", "42000-43023,60718"},
		{"42000-42999\n", "43000-43023,60718"},
	} {
		os.WriteFile(reservedPortsFile, []byte(x.live), 0o644)
		rs := c.reservedResults(context.Background())
		if len(rs) != 1 || rs[0].Level != hostcheck.Advised || rs[0].Name != "reserved ports" || rs[0].OK != (x.missing == "") ||
			(x.missing != "" && (!strings.Contains(rs[0].Detail, "lacks "+x.missing+":") || !strings.Contains(rs[0].Fix, "rayctl apply"))) {
			t.Errorf("%q: %+v", x.live, rs)
		}
	}
	if rs := (&cli{c: api.NewUnixClient(filepath.Join(t.TempDir(), "none.sock"))}).reservedResults(context.Background()); rs != nil {
		t.Errorf("no rayd: %+v", rs)
	}
}
