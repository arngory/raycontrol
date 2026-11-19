package xrayapi_test

import (
	"math/rand/v2"
	"net"
	"strconv"
	"testing"
)

// subPort is a port for a test node's subscription endpoint: below the
// kernel's range for outgoing connections (32768–60999 by default), free
// on 127.0.0.1 for TCP and UDP (the probe's echo). A node reserves its
// ports in that range (ip_local_reserved_ports, v0.21.0); a test cannot,
// and a port drawn there was now and then taken by an outgoing connection
// of the test itself ("bind: address already in use").
func subPort(t *testing.T) uint16 {
	t.Helper()
	for range 200 {
		p := 20000 + rand.IntN(32768-20000)
		addr := "127.0.0.1:" + strconv.Itoa(p)
		tl, err := net.Listen("tcp", addr)
		if err != nil {
			continue
		}
		ul, err := net.ListenPacket("udp", addr)
		tl.Close()
		if err != nil {
			continue
		}
		ul.Close()
		return uint16(p)
	}
	t.Fatal("no free port for the subscription below 32768")
	return 0
}
