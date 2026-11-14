package render_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// The front remembers a UDP flow for longer than a QUIC server behind it
// keeps a silent connection: otherwise a connection quiet for the time
// between the two is lost in the middle with both ends alive. rayd's
// servers take render.QUICIdle (cmd/rayd checks its side), Hysteria2 is
// niko-server's.
func TestFrontOutlastsQUICIdle(t *testing.T) {
	m := render.Model{FrontTCP: true, FrontUDP: true, Now: time.Unix(1767225600, 0),
		Services: []render.Service{
			{Service: store.Service{ID: 1, Kind: "site", Name: "www", Enabled: true, Settings: `{}`},
				Secrets: map[string][]byte{provision.SecretTLSChain: []byte("chain"), provision.SecretTLSKey: []byte("key")}},
			{Service: store.Service{ID: 2, Kind: "naive", Name: "nv", Enabled: true, Settings: `{"site":"www","sni":"n.example.com"}`}},
		},
	}
	files, _, err := render.Render(m, render.DefaultPaths)
	if err != nil {
		t.Fatal(err)
	}
	var front struct {
		UDP struct {
			Idle string `json:"idle"`
		} `json:"udp"`
	}
	for _, f := range files {
		if f.Path == render.DefaultPaths.Rendered+"/front/front.json" {
			if err := json.Unmarshal(f.Content, &front); err != nil {
				t.Fatal(err)
			}
		}
	}
	idle, err := time.ParseDuration(front.UDP.Idle)
	if err != nil {
		t.Fatalf("the front's udp.idle %q: %v", front.UDP.Idle, err)
	}
	if idle != render.FrontUDPIdle {
		t.Errorf("the front's udp.idle is %v, not render.FrontUDPIdle (%v)", idle, render.FrontUDPIdle)
	}
	// niko-server's Hysteria2 listener (hysteriaIdle).
	const hysteriaIdle = 60 * time.Second
	for name, quic := range map[string]time.Duration{"rayd's QUIC servers": render.QUICIdle, "Hysteria2": hysteriaIdle} {
		if idle < quic+10*time.Second {
			t.Errorf("the front forgets a flow after %v, %s a connection after %v: a quiet one is lost in between", idle, name, quic)
		}
	}
	// What niko-server takes (FrontUDP.validate).
	if idle < 5*time.Second || idle > 10*time.Minute {
		t.Errorf("udp.idle %v: niko-server takes 5 s to 10 min", idle)
	}
}
