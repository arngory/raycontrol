package deploy

import "golang.org/x/sys/unix"

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
