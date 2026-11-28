package naive

import (
	"testing"
	"time"
)

// The scanner's look at 10^5 tunnels without pressure, a hundred a
// connection, a tenth of them blocked on their upload: it holds the
// registry's lock about all its time (the readings are the test's).
func BenchmarkTick(b *testing.B) {
	tn, _ := testTunnels(1 << 40)
	conns := make([]*int, 1000)
	for i := range conns {
		conns[i] = new(int)
	}
	for i := range 100_000 {
		tm := tn.admit("u"+string(rune('a'+i%26)), conns[i%len(conns)], false, func(error) {})
		tn.run(tm, nil)
		if i%10 == 0 {
			tm.up.Store(mono() - int64(time.Second))
		}
	}
	b.ReportAllocs()
	for b.Loop() {
		tn.tick()
	}
}
