//go:build !linux

package render

import "golang.org/x/sys/unix"

// HostIPv6 reports whether this host can open IPv6 sockets. The model is
// a node's, and a node is Linux; elsewhere the package builds for rayctl
// (no SOCK_CLOEXEC there: the socket is closed at once).
func HostIPv6() bool {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		return false
	}
	_ = unix.Close(fd)
	return true
}
