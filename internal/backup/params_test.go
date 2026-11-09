package backup

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// A header that asks for more scrypt work than Seal writes, plus a step,
// is refused before any key is derived: the tag is checked only after,
// and a crafted file must not cost gigabytes or minutes. What Seal writes
// still opens.
func TestOpenBoundsKeyParameters(t *testing.T) {
	sealed, err := Seal([]byte("data"), "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ n, r, p byte }{{logN + 2, r, p}, {logN, r + 1, p}, {logN, r, p + 2}, {22, 32, 16}} {
		crafted := bytes.Clone(sealed)
		crafted[len(Magic)], crafted[len(Magic)+1], crafted[len(Magic)+2] = c.n, c.r, c.p
		start := time.Now()
		_, err := Open(crafted, "correct horse battery")
		if err == nil || errors.Is(err, ErrPassphrase) || time.Since(start) > time.Second {
			t.Fatalf("logN %d, r %d, p %d: %v after %v", c.n, c.r, c.p, err, time.Since(start))
		}
	}
	if _, err := Open(sealed, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
}
