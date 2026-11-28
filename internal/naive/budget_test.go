package naive_test

import (
	"testing"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/memlimit"
	"github.com/arngory/raycontrol/internal/naive"
)

// naive's budget for its tunnels in a data unit as rayctl apply sizes it
// (deploy.MemoryOf, MemoryHigh 7/8 of MemoryMax): half the less of
// memory.high and 15/16 of memory.max, that is 7/16 of MemoryMax, and a
// user's fair share an eighth of it at least.
func TestMemoryBudgetUnits(t *testing.T) {
	for _, c := range []struct {
		host             int64
		budgetMiB, share int64 // MiB, KiB
	}{
		{512 << 20, 58, 7526}, {1 << 30, 137, 17561}, {4 << 30, 714, 91392},
	} {
		unit := deploy.MemoryOf(c.host).Unit
		l := memlimit.Limits{Max: unit, High: deploy.MemoryHigh(unit), MemTotal: c.host}
		b := naive.MemoryBudget(l)
		if b != deploy.MemoryHigh(unit)/2 || b>>20 != c.budgetMiB || b/8>>10 != c.share {
			t.Errorf("host %d MiB, unit %.1f MiB: budget %.1f MiB (%d KiB a share), want %d MiB and %d KiB",
				c.host>>20, float64(unit)/(1<<20), float64(b)/(1<<20), b/8>>10, c.budgetMiB, c.share)
		}
	}
}
