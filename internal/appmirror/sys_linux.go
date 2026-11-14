package appmirror

import "golang.org/x/sys/unix"

// statfsFree is the room an unprivileged process has in dir's file system.
func statfsFree(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Frsize), nil
}

// setLowat sets a TCP socket's TCP_NOTSENT_LOWAT (pace).
func setLowat(fd uintptr, n int) error {
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, n)
}
