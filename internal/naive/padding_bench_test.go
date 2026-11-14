package naive

import (
	"io"
	"testing"
)

// The hot path of every tunnel: a write and a read of 32 KiB (io.Copy's
// buffer) past the padded first frames, which must take no allocation.
func BenchmarkPaddedStream(b *testing.B) {
	payload := make([]byte, 32<<10)
	b.Run("write", func(b *testing.B) {
		s := &paddedStream{w: io.Discard}
		for range paddingFrames {
			_, _ = s.Write(payload)
		}
		b.SetBytes(int64(len(payload)))
		b.ReportAllocs()
		for b.Loop() {
			if _, err := s.Write(payload); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("read", func(b *testing.B) {
		s := &paddedStream{r: zeros{}, readFrames: paddingFrames}
		buf := make([]byte, len(payload))
		b.SetBytes(int64(len(buf)))
		b.ReportAllocs()
		for b.Loop() {
			if _, err := s.Read(buf); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// zeros reads as an endless stream of zero bytes.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
