package deploy

import "net/netip"

// LegacyBuild is Build before Inputs (legacy_build_test.go).
var LegacyBuild = legacyBuild

// SetOwnAddrs makes the host's addresses these, until the returned func.
func SetOwnAddrs(m map[netip.Addr]bool) func() {
	saved := ownAddrs
	ownAddrs = func() map[netip.Addr]bool { return m }
	return func() { ownAddrs = saved }
}
