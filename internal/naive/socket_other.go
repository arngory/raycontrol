//go:build !linux

package naive

import "errors"

// lowat, setLowat: the bound on a connection's unsent bytes is set on a
// node's sockets, and a node is Linux. The package builds elsewhere for
// rayctl.
var errLowat = errors.New("naive: TCP_NOTSENT_LOWAT is set on a Linux node only")

func lowat(uintptr) (int, error) { return 0, errLowat }

func setLowat(uintptr, int) error { return errLowat }
