package live

import "syscall"

// procAttr ends the data plane with rayd: no processes left behind when a
// test kills it.
func procAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}
