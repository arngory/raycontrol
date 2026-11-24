package api

import (
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
)

// TestSalamanderListWarnings: a hy2-obfs service warns once the devices
// allowed on it could put the front's list past nine tenths of its most in
// a rotation; another service's devices, a disabled service and another
// kind do not count.
func TestSalamanderListWarnings(t *testing.T) {
	services := []store.Service{
		{ID: 1, Kind: "hy2-obfs", Name: "big", Enabled: true},
		{ID: 2, Kind: "hy2-obfs", Name: "small", Enabled: true},
		{ID: 3, Kind: "hy2-obfs", Name: "off", Enabled: false},
		{ID: 4, Kind: "hy2-masq", Name: "masq", Enabled: true},
	}
	var devices []spa.Device
	for range 20000 {
		devices = append(devices, spa.Device{Allowed: []uint16{1, 3, 4}})
	}
	devices = append(devices, spa.Device{Allowed: []uint16{2}})
	got := salamanderListWarnings(services, devices)
	if len(got) != 1 || !strings.Contains(got[0], "service big (hy2-obfs): 20000 devices") {
		t.Fatalf("warnings %q", got)
	}
	if got := salamanderListWarnings(services, devices[:19000]); len(got) != 0 {
		t.Fatalf("19000 devices (57002 lines) warned: %q", got)
	}
}
