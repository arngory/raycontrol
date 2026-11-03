package nikoipc

import (
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHandoff(t *testing.T) {
	h := Handoff{Route: "naive", Src: netip.MustParseAddrPort("203.0.113.7:51000"),
		Dst: netip.MustParseAddrPort("[2001:db8::1]:443"), SNI: "n.example.com", Prefetch: []byte{0x16, 3, 1}}
	got, err := DecodeHandoff(h.Encode())
	if err != nil || got.Route != h.Route || got.Src != h.Src || got.Dst != h.Dst || got.SNI != h.SNI || string(got.Prefetch) != string(h.Prefetch) {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := DecodeHandoff(h.Encode()[:30]); err == nil {
		t.Fatal("a cut message decoded")
	}
}

func TestListenFD(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	sock := filepath.Join(t.TempDir(), "fd.sock")
	ln, err := ListenFD(sock, os.Getuid(), log)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode: %v %v", fi, err)
	}
	front, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: sock, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()

	// A client connection the front accepted and read a little of.
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	client, err := net.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted, err := tcp.Accept()
	if err != nil {
		t.Fatal(err)
	}
	src := netip.MustParseAddrPort(client.LocalAddr().String())
	if err := Pass(front, accepted.(*net.TCPConn), Handoff{Route: "doh", Src: src, Dst: src, SNI: "d.example.com", Prefetch: []byte("hello ")}); err != nil {
		t.Fatal(err)
	}
	accepted.Close() // the backend has its own copy

	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.RemoteAddr().String() != src.String() || conn.(*Conn).ServerName() != "d.example.com" {
		t.Fatalf("remote %v, name %q", conn.RemoteAddr(), conn.(*Conn).ServerName())
	}
	io.WriteString(client, "world")
	got := make([]byte, 11)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "hello world" {
		t.Fatalf("read %q %v", got, err)
	}
	io.WriteString(conn, "back")
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	answer := make([]byte, 4)
	if _, err := io.ReadFull(client, answer); err != nil || string(answer) != "back" {
		t.Fatalf("answer %q %v", answer, err)
	}
}

func TestListenFDOtherUID(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "fd.sock")
	ln, err := ListenFD(sock, os.Getuid()+1, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	front, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: sock, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	front.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := front.Read(make([]byte, 1)); err == nil || os.IsTimeout(err) {
		t.Fatalf("a peer that is not the front stayed connected: %v", err)
	}
}
