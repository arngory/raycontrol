package sub_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/sub"
	"github.com/arngory/raycontrol/internal/summary"
)

// The device is read once more after build, and that read fails closed:
// a request whose context ends, a store that fails, or a revocation that
// commits after every read of build (Hints is its last callback before
// Sign) gets what a revoked device gets, a plain 404. Without any of
// them the same request gets its subscription. A check before build
// instead of after it lets the revocation through.
func TestRecheckAfterBuildFailsClosed(t *testing.T) {
	for _, mode := range []string{"cancel", "revoke", "store-closed", "none"} {
		t.Run(mode, func(t *testing.T) {
			n := newLANNode(t)
			n.user("alice", "hy2", "reality")
			phone := n.device("alice", "phone")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			hit := false
			n.srv.Hints = func(context.Context, netip.Addr, []uint16) *summary.Hints {
				hit = true
				switch mode {
				case "cancel":
					cancel()
				case "revoke":
					if _, err := n.st.RevokeDevice(context.Background(), phone.ID); err != nil {
						t.Error(err)
					}
				case "store-closed":
					n.st.Close()
				}
				return nil
			}
			req := httptest.NewRequest(http.MethodGet, sub.Path, nil).WithContext(ctx)
			req.RemoteAddr = "198.51.100.9:4444"
			req.Header.Set(sub.DeviceHeader, phone.ID)
			req.Header.Set("Authorization", sub.AuthToken(phone.key, time.Now().Unix()/60))
			rec := httptest.NewRecorder()
			n.srv.ServeHTTP(rec, req)
			if !hit {
				t.Fatal("build did not reach Hints")
			}
			want := http.StatusNotFound
			if mode == "none" {
				want = http.StatusOK
			}
			if rec.Code != want {
				t.Fatalf("%d %q, want %d", rec.Code, rec.Body.String(), want)
			}
			if want == http.StatusNotFound && rec.Body.String() != "404 page not found\n" {
				t.Fatalf("not the answer a revoked device gets: %q", rec.Body.String())
			}
		})
	}
}
