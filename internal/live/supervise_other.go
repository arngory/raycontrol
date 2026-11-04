//go:build !linux

package live

import "syscall"

func procAttr() *syscall.SysProcAttr { return nil }
