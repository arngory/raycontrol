// Command listen holds ports until it is killed, for the install test: a
// host whose port 443 is taken must be refused.
//
//	listen tcp:443 udp:443
package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	for _, a := range os.Args[1:] {
		proto, port, _ := strings.Cut(a, ":")
		var err error
		switch proto {
		case "tcp":
			_, err = net.Listen("tcp", ":"+port)
		case "udp":
			_, err = net.ListenPacket("udp", ":"+port)
		default:
			err = fmt.Errorf("%s: tcp:PORT or udp:PORT", a)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "listen:", err)
			os.Exit(1)
		}
	}
	// Until killed: a bare select{} is a deadlock to the runtime when no
	// goroutine runs.
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
	<-c
}
