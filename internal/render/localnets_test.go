package render

import (
	"slices"
	"testing"

	"github.com/arngory/raycontrol/internal/perimeter"
)

// Xray's routing keeps out what the perimeter refuses the data plane
// (R4-38): one list, so that neither lets through what the other holds.
func TestPrivateNetsArePerimeters(t *testing.T) {
	if !slices.Equal(privateNets, perimeter.LocalNets) {
		t.Fatalf("Xray's private networks\n%v\nthe perimeter's local networks\n%v", privateNets, perimeter.LocalNets)
	}
}
