package deploy_test

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/arngory/raycontrol/internal/deploy"
)

// In a network namespace of its own, with ten ephemeral ports
// (42000-42009): outgoing connections, TCP and UDP, never take a port
// apply reserved (42005), so a listen on it always binds; without the
// reservation one of them takes it and the listen fails (EADDRINUSE), as
// rayspa's did in CI. Root only.
func TestReservedPortsNetns(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: a network namespace")
	}
	for _, reserve := range []bool{true, false} {
		done := make(chan netnsResult, 1)
		go func() {
			// Never unlocked: the thread ends with the goroutine, and the
			// namespace with it.
			runtime.LockOSThread()
			done <- reservedPortsIn(reserve)
		}()
		r := <-done
		if r.skip != nil {
			t.Skip(r.skip)
		}
		if r.err != nil {
			t.Fatalf("reserved %v: %v", reserve, r.err)
		}
		for _, proto := range []string{"tcp", "udp"} {
			got := r.ports[proto]
			switch {
			case reserve && (len(got) != 9 || slices.Contains(got, 42005)):
				t.Errorf("reserved, %s took %v", proto, got)
			case !reserve && (len(got) != 10 || !slices.Contains(got, 42005)):
				t.Errorf("not reserved, %s took %v", proto, got)
			}
		}
		if reserve != (r.listen == nil) || (!reserve && !errors.Is(r.listen, unix.EADDRINUSE)) {
			t.Errorf("reserved %v: a listen on 42005 with every port taken: %v", reserve, r.listen)
		}
	}
}

type netnsResult struct {
	ports     map[string][]int // the source ports outgoing sockets took, each round
	listen    error            // a listen on 42005 with all of them open
	err, skip error
}

// reservedPortsIn runs on a locked thread: it moves it to a new network
// namespace, so it is to be ended, not given back.
func reservedPortsIn(reserve bool) (r netnsResult) {
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return netnsResult{skip: err}
	}
	if err := loUp(); err != nil {
		return netnsResult{err: err}
	}
	write := func(key, v string) error {
		return os.WriteFile("/proc/sys/net/ipv4/"+key, []byte(v+"\n"), 0o644)
	}
	if err := write("ip_local_port_range", "42000 42009"); err != nil {
		return netnsResult{err: err}
	}
	if reserve {
		v, _, err := deploy.ReservedValue("", "", []deploy.PortRange{{Proto: "tcp", From: 42005, To: 42005}})
		if err == nil {
			err = write("ip_local_reserved_ports", v)
		}
		if err != nil {
			return netnsResult{err: err}
		}
	}
	lfd, err := listenOn(unix.SOCK_STREAM, 41000)
	if err != nil {
		return netnsResult{err: err}
	}
	defer unix.Close(lfd)
	ufd, err := listenOn(unix.SOCK_DGRAM, 41000)
	if err != nil {
		return netnsResult{err: err}
	}
	defer unix.Close(ufd)
	r.ports = map[string][]int{}
	// Rounds: each takes every port it can, the reserved one never; each
	// socket closes with a reset (no TIME_WAIT keeps its port).
	for round := range 5 {
		var fds []int
		for _, typ := range []int{unix.SOCK_STREAM, unix.SOCK_DGRAM} {
			proto := map[int]string{unix.SOCK_STREAM: "tcp", unix.SOCK_DGRAM: "udp"}[typ]
			var ports []int
			for range 11 {
				fd, port, err := connectOut(typ)
				if err != nil {
					break // the range is taken
				}
				fds = append(fds, fd)
				ports = append(ports, port)
			}
			slices.Sort(ports)
			if round == 0 {
				r.ports[proto] = ports
			} else if !slices.Equal(ports, r.ports[proto]) {
				r.err = fmt.Errorf("round %d: %s took %v, then %v", round, proto, r.ports[proto], ports)
			}
		}
		if round == 0 {
			fd, err := listenOn(unix.SOCK_STREAM, 42005)
			if err == nil {
				unix.Close(fd)
			}
			r.listen = err
		}
		for _, fd := range fds {
			_ = unix.SetsockoptLinger(fd, unix.SOL_SOCKET, unix.SO_LINGER, &unix.Linger{Onoff: 1, Linger: 0})
			unix.Close(fd)
		}
		if r.err != nil {
			return r
		}
	}
	return r
}

// loUp brings the namespace's loopback up.
func loUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

// listenOn binds a socket on all addresses as Go's net.Listen does
// (SO_REUSEADDR), and listens if it is TCP.
func listenOn(typ, port int) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, typ|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if err == nil {
		err = unix.Bind(fd, &unix.SockaddrInet4{Port: port})
	}
	if err == nil && typ == unix.SOCK_STREAM {
		err = unix.Listen(fd, 128)
	}
	if err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// connectOut connects a socket to the listener on 127.0.0.1:41000 (the
// kernel picks its port) and says which port it took.
func connectOut(typ int) (int, int, error) {
	fd, err := unix.Socket(unix.AF_INET, typ|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, 0, err
	}
	if err := unix.Connect(fd, &unix.SockaddrInet4{Port: 41000, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		unix.Close(fd)
		return -1, 0, err
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		unix.Close(fd)
		return -1, 0, err
	}
	return fd, sa.(*unix.SockaddrInet4).Port, nil
}
