package deploy

import "net/netip"

// SetOwnAddrs makes the host's addresses these, until the returned func.
func SetOwnAddrs(m map[netip.Addr]bool) func() {
	saved := ownAddrs
	ownAddrs = func() map[netip.Addr]bool { return m }
	return func() { ownAddrs = saved }
}
