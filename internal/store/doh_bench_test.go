package store

import (
	"context"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// dohBenchStore is a node with a DoH service and n users on it, each with
// one device and a DoH secret with a next one published (two tokens a
// device).
func dohBenchStore(b *testing.B, n int) (*Store, int64) {
	b.Helper()
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(b.TempDir(), "rayd.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { s.Close() })
	svc, err := s.CreateService(ctx, Service{Kind: "doh", Name: "doh", Enabled: true, Settings: "{}"})
	if err != nil {
		b.Fatal(err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		b.Fatal(err)
	}
	for i := 1; i <= n; i++ {
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		sec, _ := NewUUID()
		next, _ := NewUUID()
		for _, q := range []struct {
			q    string
			args []any
		}{
			{`INSERT INTO users (id, name, enabled, created_at) VALUES (?, ?, 1, 1)`, []any{i, fmt.Sprintf("u%d", i)}},
			{`INSERT INTO user_services (user_id, service_id) VALUES (?, ?)`, []any{i, svc.ID}},
			{`INSERT INTO credentials (user_id, service_id, secret, created_at, rotated_at, next_secret, next_from) VALUES (?, ?, ?, 1, 1, ?, ?)`,
				[]any{i, svc.ID, sec, next, time.Now().Add(time.Hour).Unix()}},
			{`INSERT INTO devices (id, user_id, name, role, spa_key, created_at) VALUES (?, ?, 'phone', 'user', ?, 1)`,
				[]any{fmt.Sprintf("d%015d", i), i, key}},
		} {
			if _, err := tx.Exec(q.q, q.args...); err != nil {
				b.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	return s, svc.ID
}

// The load of a DoH handler's tokens (rayd: every 30 s and after each
// change), at 5 000 and 50 000 devices.
func BenchmarkDoHTokens(b *testing.B) {
	for _, n := range []int{5000, 50000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s, svc := dohBenchStore(b, n)
			ctx := context.Background()
			if _, err := s.DoHTokens(ctx, svc, time.Now()); err != nil { // as rayd after its first load
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				m, err := s.DoHTokens(ctx, svc, time.Now())
				if err != nil || len(m) != 2*n {
					b.Fatal(len(m), err)
				}
			}
		})
	}
}
