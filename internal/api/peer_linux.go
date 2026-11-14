package api

import "golang.org/x/sys/unix"

// ucred is the peer of a connection on rayd's socket, as the kernel
// vouches for it (SO_PEERCRED).
type ucred = unix.Ucred

func peerCred(fd uintptr) (*ucred, error) {
	return unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
}
