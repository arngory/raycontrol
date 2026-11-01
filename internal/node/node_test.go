package node

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/arngory/raycontrol/internal/store"
)

func TestInitIsStable(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	first, err := Init(ctx, st, "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	again, err := Init(ctx, st, "")
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Fatal("second Init changed the parameters")
	}
	if h, _ := Host(ctx, st); h != "203.0.113.7" {
		t.Fatalf("host = %q", h)
	}
}

func TestBundleRoundTrip(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p, err := Init(ctx, st, "")
	if err != nil {
		t.Fatal(err)
	}
	b := Bundle{Version: 1, Host: "n.example.com", SPA: FromParams(p), DeviceID: "ab", DeviceKey: "00",
		Services: []BundleService{{ID: 1, Kind: "reality", Name: "reality"}}}
	s, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeBundle(s)
	if err != nil {
		t.Fatal(err)
	}
	gp, err := got.SPA.Params()
	if err != nil || gp != p || got.Services[0] != b.Services[0] || got.Host != b.Host {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
	if _, err := DecodeBundle("rcdev2:xx"); err == nil {
		t.Fatal("wrong prefix accepted")
	}
}
