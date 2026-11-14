//go:build !linux

package hostcheck

import "errors"

// statfsFree: the host that is checked is a node's, and a node is Linux
// (rayctl check refuses elsewhere).
func statfsFree(string) (uint64, error) {
	return 0, errors.New("hostcheck: a host is checked on a Linux node only")
}
