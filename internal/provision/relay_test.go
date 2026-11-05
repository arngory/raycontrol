package provision

import (
	"errors"
	"testing"

	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
)

// A relay's probe port keeps clear of its SPA range and of every port it
// forwards or serves, of either protocol.
func TestRelayProbePort(t *testing.T) {
	// The SPA range leaves 59999 alone of 10000..59999.
	p := spa.Params{PortBase: 10000, PortRange: 49999}
	for range 20 {
		port, err := RelayProbePort(nil, p)
		if err != nil || port != 59999 {
			t.Fatalf("port %d %v, want 59999", port, err)
		}
	}
	// Taken by UDP: not for TCP either.
	if port, err := RelayProbePort([]store.Port{{Proto: "udp", Num: 59999}}, p); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("a port the relay serves: %d %v", port, err)
	}
}
