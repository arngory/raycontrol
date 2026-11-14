package doh_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/doh"
	"github.com/arngory/raycontrol/internal/store"
)

// handler is what the benchmark drives.
type handler interface {
	http.Handler
	Forget()
}

func newHandler(tokens func(context.Context) (map[string]bool, error), cacheFor time.Duration) handler {
	return &doh.Handler{Tokens: tokens, CacheFor: cacheFor}
}

// benchNode is a node with a DoH service and n users on it, one device
// each; it returns the store, the service and a token of one device.
func benchNode(b *testing.B, n int) (*store.Store, int64, string) {
	b.Helper()
	ctx := context.Background()
	path := filepath.Join(b.TempDir(), "rayd.db")
	st, err := store.Open(ctx, path)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { st.Close() })
	svc, err := st.CreateService(ctx, store.Service{Kind: "doh", Name: "doh", Enabled: true, Settings: "{}"})
	if err != nil {
		b.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	key := func(i int) []byte { return []byte(fmt.Sprintf("%032d", i)) }
	secret := func(i int) string { return fmt.Sprintf("%08x-0000-4000-8000-000000000000", i) }
	for i := 1; i <= n; i++ {
		for _, q := range []struct {
			q    string
			args []any
		}{
			{`INSERT INTO users (id, name, enabled, created_at) VALUES (?, ?, 1, 1)`, []any{i, fmt.Sprintf("u%d", i)}},
			{`INSERT INTO user_services (user_id, service_id) VALUES (?, ?)`, []any{i, svc.ID}},
			{`INSERT INTO credentials (user_id, service_id, secret, created_at, rotated_at) VALUES (?, ?, ?, 1, 1)`,
				[]any{i, svc.ID, secret(i)}},
			{`INSERT INTO devices (id, user_id, name, role, spa_key, created_at) VALUES (?, ?, 'phone', 'user', ?, 1)`,
				[]any{fmt.Sprintf("d%015d", i), i, key(i)}},
		} {
			if _, err := tx.Exec(q.q, q.args...); err != nil {
				b.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	return st, svc.ID, store.DoHDeviceToken(secret(n/2), key(n/2))
}

// Requests with a good token, one after another for 3 s at least, while
// the tokens load, at 5 000 and 50 000 devices: "refresh" with a CacheFor
// of 100 ms (rayd: 30 s), "forget" with a Forget every 10 ms (an API
// mutation, as rayd's serveDoH makes on each). It reports the mean, the
// 99th percentile and the longest request, and how many loads ran. Run
// it with -benchtime 1x: the window, not b.N, sets the length.
func BenchmarkRequestDuringReload(b *testing.B) {
	for _, n := range []int{5000, 50000} {
		for _, mode := range []string{"refresh", "forget"} {
			b.Run(fmt.Sprintf("%d/%s", n, mode), func(b *testing.B) {
				st, svc, token := benchNode(b, n)
				var loads atomic.Int64
				tokens := func(ctx context.Context) (map[string]bool, error) {
					loads.Add(1)
					return st.DoHTokens(ctx, svc, time.Now())
				}
				cacheFor := time.Hour
				if mode == "refresh" {
					cacheFor = 100 * time.Millisecond
				}
				h := newHandler(tokens, cacheFor)
				req := httptest.NewRequest(http.MethodPut, "/dns-query/"+token, nil)
				serve := func() int {
					w := httptest.NewRecorder()
					h.ServeHTTP(w, req)
					return w.Code
				}
				if c := serve(); c != http.StatusMethodNotAllowed {
					b.Fatalf("the token: %d", c)
				}
				stop := make(chan struct{})
				done := make(chan struct{})
				go func() {
					defer close(done)
					for {
						select {
						case <-stop:
							return
						case <-time.After(10 * time.Millisecond):
						}
						if mode == "forget" {
							h.Forget()
						}
					}
				}()
				var took []time.Duration
				b.ResetTimer()
				for t0 := time.Now(); len(took) < b.N || time.Since(t0) < 3*time.Second; {
					t0 := time.Now()
					if c := serve(); c != http.StatusMethodNotAllowed {
						b.Fatalf("the token during a load: %d", c)
					}
					took = append(took, time.Since(t0))
				}
				b.StopTimer()
				close(stop)
				<-done
				var sum time.Duration
				for _, d := range took {
					sum += d
				}
				b.ReportMetric(float64(sum.Microseconds())/float64(len(took)), "mean-µs")
				slices.Sort(took)
				b.ReportMetric(float64(took[len(took)*99/100].Microseconds()), "p99-µs")
				b.ReportMetric(float64(took[len(took)-1].Microseconds()), "max-µs")
				b.ReportMetric(float64(loads.Load()), "loads")
			})
		}
	}
}
