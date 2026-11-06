package dnscheck

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// The host's network on loopback: a stray datagram is skipped, TCP has its
// length prefix, a server that keeps quiet ends with the context.
func TestNetExchange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	q, err := newQuery("example.com", dnsmessage.TypeSOA, true)
	if err != nil {
		t.Fatal(err)
	}
	answer := respond(q, dnsmessage.RCodeSuccess, true, []dnsmessage.Resource{rrSOA("example.com", "ns1.example.net", 60)}, nil, nil)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1500)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		stray := respond(buf[:n], dnsmessage.RCodeRefused, false, nil, nil, nil)
		stray[1]++ // another ID
		_, _ = pc.WriteTo(stray, from)
		_, _ = pc.WriteTo(answer, from)
	}()
	r, err := Net{}.Exchange(ctx, "udp", netip.MustParseAddrPort(pc.LocalAddr().String()), q)
	if err != nil {
		t.Fatal(err)
	}
	if x, err := parseReply(q, r); err != nil || x.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("udp answer %v %v", x, err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		got := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, got); err != nil {
			return
		}
		_, _ = c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(answer))), answer...))
	}()
	if r, err := (Net{}).Exchange(ctx, "tcp", netip.MustParseAddrPort(ln.Addr().String()), q); err != nil || !isReplyTo(q, r) {
		t.Fatalf("tcp answer %v", err)
	}

	quiet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer quiet.Close()
	short, cancelShort := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancelShort()
	if _, err := (Net{}).Exchange(short, "udp", netip.MustParseAddrPort(quiet.LocalAddr().String()), q); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("quiet server: %v", err)
	}
}
