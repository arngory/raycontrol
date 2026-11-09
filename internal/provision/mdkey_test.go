package provision

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/store"
)

// A masterdns service's key (spec/masterdns-key-rotation.md §2): the new
// one at once, the previous one taken for the grace; one previous key at
// most; -now takes none; the grace's end drops it.
func TestRotateMasterDNSKey(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := Init(ctx, st, Options{Host: "203.0.113.7", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	svc, err := CreateService(ctx, st, store.Service{Kind: "masterdns", Name: "mdns", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	keys := func() [][]byte {
		t.Helper()
		s, _ := st.ServiceByName(ctx, "mdns")
		secrets, _ := st.ServiceSecrets(ctx, s.ID)
		return MasterDNSKeys(s, secrets)
	}
	first := keys()
	if len(first) != 1 || len(first[0]) != 32 {
		t.Fatalf("a new service's keys %q", first)
	}
	now := time.Unix(1_800_000_000, 0)
	state, err := RotateMasterDNSKey(ctx, st, "mdns", now, 48*time.Hour, false, false)
	if err != nil || state.PrevUntil != now.Add(48*time.Hour).Unix() || state.RotatedAt != now.Unix() {
		t.Fatalf("rotate: %+v %v", state, err)
	}
	second := keys()
	if len(second) != 2 || bytes.Equal(second[0], first[0]) || !bytes.Equal(second[1], first[0]) || len(second[0]) != 32 {
		t.Fatalf("after a switch: %q", second)
	}
	// A second switch within the grace (a retry): refused, nothing changes,
	// since it would drop the first key for clients still on it.
	if _, err := RotateMasterDNSKey(ctx, st, "mdns", now.Add(time.Hour), 48*time.Hour, false, false); !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("a second switch within the grace: %v", err)
	}
	if again := keys(); !slices.EqualFunc(again, second, bytes.Equal) {
		t.Fatalf("after a refused switch: %q, before %q", again, second)
	}
	// Forced: the key before the previous goes.
	if _, err := RotateMasterDNSKey(ctx, st, "mdns", now.Add(time.Hour), 48*time.Hour, false, true); err != nil {
		t.Fatal(err)
	}
	if third := keys(); len(third) != 2 || !bytes.Equal(third[1], second[0]) {
		t.Fatalf("after a second switch: %q", third)
	}
	// The grace ends: the previous key leaves the file.
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if n, err := ExpireSealKeys(ctx, st, now.Add(50*time.Hour), log); err != nil || n != 1 {
		t.Fatalf("expire: %d %v", n, err)
	}
	if k := keys(); len(k) != 1 {
		t.Fatalf("after the grace: %q", k)
	}
	// -now: none taken but the new one.
	if state, _ := RotateMasterDNSKey(ctx, st, "mdns", now.Add(51*time.Hour), 48*time.Hour, true, false); state.PrevUntil != 0 || len(keys()) != 1 {
		t.Fatalf("-now: %+v, %d keys", state, len(keys()))
	}
	if _, err := RotateMasterDNSKey(ctx, st, "nope", now, time.Hour, false, false); err == nil {
		t.Fatal("an unknown service")
	}
	dns, _ := CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true})
	if _, err := RotateMasterDNSKey(ctx, st, dns.Name, now, time.Hour, false, false); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("a dnstt service: %v", err)
	}
	_ = svc
}
