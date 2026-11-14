//go:build !linux

package probe

import (
	"context"
	"errors"
	"net/netip"
)

// The server's side reads the kernel's sock_diag and TCP_INFO: it runs on
// a node, and a node is Linux. The package builds elsewhere for rayctl,
// whose probe is the client's side (client.go).

type tcpConn struct{}

func tcpConnections() ([]tcpConn, error) {
	return nil, errors.New("probe: the host's TCP connections are listed on a Linux node only")
}

func aggregate(_ []tcpConn, addr netip.Addr, _ []uint16) LinkStats {
	return LinkStats{Address: addr.String()}
}

func tcpInfo(context.Context) *TCPInfo { return nil }
