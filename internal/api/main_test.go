package api

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// No test resolves the node's -host in real DNS (spa-v3 own addresses).
	ownLookup = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no DNS in tests") }
	os.Exit(m.Run())
}
