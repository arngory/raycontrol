package naive

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"testing"

	"github.com/arngory/raycontrol/internal/probe"
)

// FuzzUDPUpstream: a sequence of a client's HTTP datagrams, each as a QUIC
// datagram or a capsule, through upstream as a request has them, with
// everything on 127.0.0.3 allowed and every name resolving there (after an
// address that is not allowed): parseUDP, the probe name, resolve and the
// request's names, quicLong, the QUIC rule, reach and the socket. Each
// datagram is sent or dropped, once, and what is sent is what a model of
// the rules says: an allowed destination, and the QUIC rule on capsules
// held against a model of the pairs.
//
// The input is entries of [u8 flags (bit 0: a capsule)][u16 length][the
// datagram], 150 at most. Each run sends real datagrams over loopback,
// which makes the fuzzer's minimizing slow: fuzz it with
// -fuzzminimizetime 5s. Its seeds run with every go test, as CI's.
func FuzzUDPUpstream(f *testing.F) {
	sinkAddr := netip.MustParseAddr("127.0.0.3")
	sink, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(sinkAddr, 0)))
	if err != nil {
		f.Fatal(err) // loopback is all of 127/8 here, as udpTrap has it
	}
	sinkAt := sink.LocalAddr().(*net.UDPAddr).AddrPort()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { sink.Close(); conn.Close() })
	s := &Server{Allow: func(a netip.Addr) bool { return a == sinkAddr }, Log: slog.New(slog.DiscardHandler)}
	s.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.1"), sinkAddr}, nil
	}
	// No limit of pairs, and a lookup token for every name: what the
	// model does not have does not drop a datagram. Each input is a user
	// of its own, with a full bucket of new destinations (200).
	s.SetConnLimit(false)
	s.lim.lookupBurst = 1e6
	s.Probe = sinkAt.String()

	entry := func(flags byte, dg []byte) []byte {
		return append(binary.BigEndian.AppendUint16([]byte{flags}, uint16(len(dg))), dg...) //nolint:gosec // G115: the seeds'
	}
	to := udpDest(sinkAt)
	f.Add(append(entry(0, udpDatagram(to, quicInitial(100))), entry(1, udpDatagram(to, quicInitial(1300)))...))
	f.Add(append(entry(1, udpDatagram(to, quicInitial(1300))), entry(0, udpDatagram(to, []byte("x")))...))
	f.Add(entry(1, udpDatagram(udpDestName("a.test", sinkAt.Port()), make([]byte, 1400))))
	f.Add(entry(0, udpDatagram(udpDestName(probe.Name, sinkAt.Port()), []byte("p"))))
	f.Add(entry(0, udpDatagram(udpDestName(probe.Name, sinkAt.Port()+1), []byte("p"))))
	f.Add(append(entry(1, udpDatagram(udpDest(netip.MustParseAddrPort("127.0.0.1:9")), nil)), entry(0, []byte{0, 4})...))
	users := 0
	f.Fuzz(func(t *testing.T, in []byte) {
		users++
		d := &udpRequest{s: s, conn: conn, n: new(udpCounts), u: &uotStream{s: s, ctx: context.Background(),
			slot: &uotSlot{user: "u" + strconv.Itoa(users)}, names: map[string]uotResolved{}, peers: map[netip.AddrPort]pairTimes{}}}
		quicPairs := map[netip.AddrPort]bool{} // the model's pairs: whether each is QUIC's
		var wantIn int64
		for k := 0; len(in) >= 3 && k < 150; k++ {
			flags, n := in[0], int(binary.BigEndian.Uint16(in[1:3]))
			in = in[3:]
			n = min(n, len(in))
			b := in[:n]
			in = in[n:]
			capsule := flags&1 != 0
			// The model: what upstream is to do with it.
			dest, data, why := parseUDP(b)
			sent := false
			if why < 0 {
				var at netip.AddrPort
				ok := false
				switch {
				case dest.name == probe.Name:
					at, ok = sinkAt, dest.port == sinkAt.Port()
				case dest.name != "":
					at, ok = netip.AddrPortFrom(sinkAddr, dest.port), domainName(dest.name)
				default:
					at, ok = netip.AddrPortFrom(dest.ip, dest.port), dest.ip == sinkAddr
				}
				if ok {
					marked, has := quicPairs[at]
					q := quicLong(data)
					ruled := capsule && len(data) > quicCapsuleMax && (marked || (!has && q))
					if !ruled {
						if !has {
							quicPairs[at] = q
						}
						sent = true
					}
				}
			}
			before := d.n.in.Load()
			var dropsBefore int64
			for i := range d.n.dropped {
				dropsBefore += d.n.dropped[i].Load()
			}
			d.upstream(b, capsule)
			var drops int64
			for i := range d.n.dropped {
				drops += d.n.dropped[i].Load()
			}
			went := d.n.in.Load() - before
			if went+drops-dropsBefore != 1 {
				t.Fatalf("a datagram sent %d times and dropped %d times", went, drops-dropsBefore)
			}
			if sent {
				wantIn++
			}
			if (went == 1) != sent {
				t.Fatalf("datagram %d (capsule %v, %d bytes, why %d, dest %+v): sent %v, the model says %v", k, capsule, len(data), why, dest, went == 1, sent)
			}
		}
		if d.n.in.Load() != wantIn {
			t.Fatalf("%d sent, the model %d", d.n.in.Load(), wantIn)
		}
	})
}
