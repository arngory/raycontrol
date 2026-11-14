//go:build !linux

package naive

import "errors"

// openPing: ICMP goes through a node, and a node is Linux (its ping
// sockets and their error queue). The package builds elsewhere for rayctl.
func openPing(bool) (icmpConn, error) {
	return nil, errors.New("naive: ICMP sockets are opened on a Linux node only")
}
