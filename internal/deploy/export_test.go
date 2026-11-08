package deploy

import (
	"net/netip"

	"golang.org/x/sys/unix"
)

// LegacyBuild is Build before Inputs (legacy_build_test.go).
var LegacyBuild = legacyBuild

// OpenBeneath is openBeneath.
var OpenBeneath = openBeneath

// NoOpenat2 makes openat2 missing, as on a kernel before 5.6, until the
// returned func.
func NoOpenat2() func() {
	saved := openat2
	openat2 = func(int, string, *unix.OpenHow) (int, error) { return -1, unix.ENOSYS }
	return func() { openat2 = saved }
}

// Openat2Err makes openat2 fail with err until the returned func: EPERM
// is a container's seccomp filter, ELOOP or ENOENT a refusal of the path.
func Openat2Err(err error) func() {
	saved := openat2
	openat2 = func(int, string, *unix.OpenHow) (int, error) { return -1, err }
	return func() { openat2 = saved }
}

// SetOwnAddrs makes the host's addresses these, until the returned func.
func SetOwnAddrs(m map[netip.Addr]bool) func() {
	saved := ownAddrs
	ownAddrs = func() map[netip.Addr]bool { return m }
	return func() { ownAddrs = saved }
}
