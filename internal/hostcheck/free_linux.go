package hostcheck

import "syscall"

// statfsFree is the room an unprivileged process has in path's file
// system (Host.Free).
func statfsFree(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil //nolint:gosec // G115: block sizes are positive
}
