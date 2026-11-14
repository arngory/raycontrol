package naive

import "golang.org/x/sys/unix"

// lowat and setLowat read and set a TCP socket's TCP_NOTSENT_LOWAT.
func lowat(fd uintptr) (int, error) {
	return unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT)
}

func setLowat(fd uintptr, n int) error {
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, n)
}
