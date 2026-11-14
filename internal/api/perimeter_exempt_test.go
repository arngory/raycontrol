package api

import (
	"testing"

	"github.com/arngory/raycontrol/internal/store"
)

// The snapshot's exemptions of the local part (spec/egress-policy-v1.md
// §10): each enabled REALITY service with a target on a local address, by
// that address, TCP and port, for the service's UID; nothing else.
func TestLocalExempt(t *testing.T) {
	services := []store.Service{
		{Kind: "reality", Name: "steal", Enabled: true, UID: 9120, Settings: `{"target":"127.0.0.1:8443","sni":"www.example.org"}`},
		{Kind: "reality", Name: "lan", Enabled: true, UID: 9121, Settings: `{"target":"[fd00::7]:443","sni":"www.example.org"}`},
		{Kind: "reality", Name: "public", Enabled: true, UID: 9122, Settings: `{"target":"www.example.org:443"}`},
		{Kind: "reality", Name: "off", Enabled: false, UID: 9123, Settings: `{"target":"127.0.0.1:9443","sni":"www.example.org"}`},
		{Kind: "reality", Name: "nouid", Enabled: true, Settings: `{"target":"127.0.0.1:9443","sni":"www.example.org"}`},
		{Kind: "naive", Name: "naive", Enabled: true, UID: 9124, Settings: `{"target":"127.0.0.1:9443"}`},
	}
	got := localExempt(services)
	if len(got) != 2 || got[0].Addr != "127.0.0.1" || got[0].Port.Port != 8443 || got[0].Port.Proto != "tcp" || got[0].Uid != 9120 ||
		got[1].Addr != "fd00::7" || got[1].Port.Port != 443 || got[1].Uid != 9121 {
		t.Fatalf("%v", got)
	}
}
