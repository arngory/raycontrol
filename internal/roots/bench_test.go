package roots_test

import (
	"path/filepath"
	"testing"

	"github.com/arngory/raycontrol/internal/roots"
)

// BenchmarkPool: what each outbound request pays to learn its pool, with
// a settings file on disk (rayd's case), from many goroutines at once.
func BenchmarkPool(b *testing.B) {
	dir := b.TempDir()
	settings := filepath.Join(dir, "tls-roots.json")
	if err := roots.WriteSettings(settings, roots.Settings{System: true}); err != nil {
		b.Fatal(err)
	}
	tr := &roots.Trust{Path: settings}
	tr.Pool()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if tr.Pool() == nil {
				b.Fatal("no pool")
			}
		}
	})
}
