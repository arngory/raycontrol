package naive

import (
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// lowat and setLowat read and set a TCP socket's TCP_NOTSENT_LOWAT.
func lowat(fd uintptr) (int, error) {
	return unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT)
}

func setLowat(fd uintptr, n int) error {
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, n)
}

// setUserTimeout sets a TCP socket's TCP_USER_TIMEOUT: unacknowledged
// data that long ends the connection.
func setUserTimeout(fd uintptr, d time.Duration) error {
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(d/time.Millisecond))
}

// sockMemory is what the kernel holds for a socket (SO_MEMINFO): received
// and unread, queued to send, allocated ahead, and the backlog.
func sockMemory(fd uintptr) (int64, error) {
	var m [unix.SK_MEMINFO_VARS]uint32
	n := uint32(unsafe.Sizeof(m))
	// x/sys has no getsockopt of SO_MEMINFO's array.
	if _, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.SOL_SOCKET, unix.SO_MEMINFO,
		uintptr(unsafe.Pointer(&m[0])), uintptr(unsafe.Pointer(&n)), 0); errno != 0 { //nolint:gosec // G103: the kernel's u32 array into one of its size
		return 0, errno
	}
	return int64(m[unix.SK_MEMINFO_RMEM_ALLOC]) + int64(m[unix.SK_MEMINFO_WMEM_QUEUED]) +
		int64(m[unix.SK_MEMINFO_FWD_ALLOC]) + int64(m[unix.SK_MEMINFO_BACKLOG]), nil
}
