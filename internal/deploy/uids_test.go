package deploy_test

import (
	"fmt"
	"testing"

	"github.com/arngory/raycontrol/internal/perimeter"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// The perimeter keeps the data plane off the node by UID (S-2): the front
// and every service UID the allocator hands out.
func TestDataPlaneUIDs(t *testing.T) {
	want := fmt.Sprintf("%d-%d", render.FrontUID, store.LastServiceUID)
	if perimeter.DataPlaneUIDs != want || render.FrontUID >= store.FirstServiceUID || render.RaydUID <= store.LastServiceUID {
		t.Fatalf("perimeter.DataPlaneUIDs = %s, want %s, rayd outside", perimeter.DataPlaneUIDs, want)
	}
}
