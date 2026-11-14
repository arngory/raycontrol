package nikoipc

import (
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// What quic-go asks of a PacketConn that is no UDP socket before it sizes
// its buffers (sys_conn_buffers.go): without these methods it warns at
// every start that the connection cannot be sized.
var _ interface {
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
} = (*PacketConn)(nil)

func sockBuf(t *testing.T, c *net.UnixConn, opt int) int {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var serr error
	if err := rc.Control(func(fd uintptr) { v, serr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, opt) }); err != nil || serr != nil {
		t.Fatal(err, serr)
	}
	return v
}

// Mode packet both ways, and the buffers a QUIC server asks for: they are
// the front's connection's, the one there is and the next.
func TestPacketConn(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "quic.sock")
	pc, err := ListenPacket(sock, os.Getuid(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	// Asked before the front is there: kept for its connection.
	if err := pc.SetReadBuffer(7 << 20); err != nil {
		t.Fatal(err)
	}
	if err := pc.SetWriteBuffer(7 << 20); err != nil {
		t.Fatal(err)
	}
	front, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: sock, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()

	client, local := netip.MustParseAddrPort("203.0.113.7:51000"), netip.MustParseAddrPort("198.51.100.1:443")
	if err := Front(front, client, local, []byte("initial")); err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, from, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "initial" || from.String() != client.String() {
		t.Fatalf("read %q from %v: %v", buf[:n], from, err)
	}
	if _, err := pc.WriteTo([]byte("answer"), from); err != nil {
		t.Fatal(err)
	}
	_ = front.SetReadDeadline(time.Now().Add(5 * time.Second))
	msg := make([]byte, 256)
	n, err = front.Read(msg)
	if err != nil {
		t.Fatal(err)
	}
	to, src, payload, err := Answer(msg[:n])
	if err != nil || to != client || src != local || string(payload) != "answer" {
		t.Fatalf("answer %q to %v from %v: %v", payload, to, src, err)
	}

	// The connection the front made has the buffers asked for, as far as
	// the host grants them: no smaller than a socket that asks for the
	// same itself.
	pc.mu.Lock()
	served := pc.front
	pc.mu.Unlock()
	probe, peer, err := unixPair()
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	defer peer.Close()
	_ = probe.SetReadBuffer(7 << 20)
	_ = probe.SetWriteBuffer(7 << 20)
	if got, want := sockBuf(t, served, unix.SO_RCVBUF), sockBuf(t, probe, unix.SO_RCVBUF); got < want {
		t.Errorf("receive buffer %d, a socket that asks for 7 MiB gets %d", got, want)
	}
	if got, want := sockBuf(t, served, unix.SO_SNDBUF), sockBuf(t, probe, unix.SO_SNDBUF); got < want {
		t.Errorf("send buffer %d, a socket that asks for 7 MiB gets %d", got, want)
	}
	// Asked again while the front is there: its connection's at once.
	if err := pc.SetReadBuffer(1 << 20); err != nil {
		t.Fatal(err)
	}
	_ = probe.SetReadBuffer(frontBuffer)
	if got, want := sockBuf(t, served, unix.SO_RCVBUF), sockBuf(t, probe, unix.SO_RCVBUF); got != want {
		t.Errorf("receive buffer %d after a smaller request, want the least %d", got, want)
	}
}

// unixPair is a connected pair of SOCK_SEQPACKET sockets.
func unixPair() (*net.UnixConn, *net.UnixConn, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	conns := make([]*net.UnixConn, 0, 2)
	for _, fd := range fds {
		f := os.NewFile(uintptr(fd), "pair")
		c, err := net.FileConn(f)
		f.Close()
		if err != nil {
			return nil, nil, err
		}
		conns = append(conns, c.(*net.UnixConn))
	}
	return conns[0], conns[1], nil
}
