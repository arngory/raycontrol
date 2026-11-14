package render

import "golang.org/x/sys/unix"

// HostIPv6 reports whether this host can open IPv6 sockets.
func HostIPv6() bool {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return false
	}
	_ = unix.Close(fd)
	return true
}
