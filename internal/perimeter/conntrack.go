package perimeter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// A small ctnetlink client (linux/netfilter/nfnetlink_conntrack.h): a dump
// of the table filtered by mark in the kernel, and the deletion of an entry
// by its original tuple and ID. Only what the guard's sweep needs
// (spec/conn-limit-v1.md §6.3), over github.com/mdlayher/netlink, which
// the module had already (go-nflog). rayspa has CAP_NET_ADMIN and
// AF_NETLINK.
const (
	nfnlSubsysCTNetlink = 1
	ctMsgGet            = 1 // IPCTNL_MSG_CT_GET
	ctMsgDelete         = 2 // IPCTNL_MSG_CT_DELETE

	ctaTupleOrig = 1
	ctaStatus    = 3
	ctaProtoinfo = 4
	ctaMark      = 8
	ctaID        = 12
	ctaZone      = 18
	ctaMarkMask  = 21
	ctaFilter    = 25 // Linux 5.8

	ctaFilterOrigFlags = 1
	// ctaFilterProtoNum: the filter matches the original tuple's protocol.
	ctaFilterProtoNum = 1 << 3

	ctaTupleIP    = 1
	ctaTupleProto = 2

	ctaIPv4Src = 1
	ctaIPv4Dst = 2
	ctaIPv6Src = 3
	ctaIPv6Dst = 4

	ctaProtoNum     = 1
	ctaProtoSrcPort = 2
	ctaProtoDstPort = 3

	ctaProtoinfoTCP      = 1
	ctaProtoinfoTCPState = 1

	// ipsSrcNAT and ipsDstNAT are status bits: a NATed entry's socket has
	// another tuple.
	ipsSrcNAT = 1 << 4
	ipsDstNAT = 1 << 5
)

// TCP states of conntrack (nf_conntrack_tcp.h).
const (
	tcpNone = iota
	tcpSynSent
	tcpSynRecv
	tcpEstablished
	tcpFinWait
	tcpCloseWait
	tcpLastAck
	tcpTimeWait
	tcpClose
	tcpSynSent2
)

// ctTuple is one direction of an entry.
type ctTuple struct {
	Src, Dst netip.AddrPort
	Proto    uint8
}

// ctEntry is an entry as the sweep needs it.
type ctEntry struct {
	Family   uint8
	Orig     ctTuple
	Status   uint32
	Mark     uint32
	ID       uint32
	Zone     uint16
	TCPState uint8
	hasState bool
}

// ctConn is a ctnetlink socket.
type ctConn struct {
	c *netlink.Conn
	// noFilter: the kernel refused the protocol's filter; dumps go
	// without it.
	noFilter bool
}

func dialConntrack() (*ctConn, error) {
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, fmt.Errorf("ctnetlink: %w", err)
	}
	return &ctConn{c: c}, nil
}

func (c *ctConn) Close() error { return c.c.Close() }

// nfgen is the nfnetlink header: the family, version 0, resource 0.
func nfgen(family uint8) []byte { return []byte{family, unix.NFNETLINK_V0, 0, 0} }

// dump lists the entries of a family whose mark, masked, is value, and of
// protocol proto (0: any): the kernel filters (ctnetlink_filter_match).
// The protocol's filter (CTA_FILTER) is Linux 5.8's: an older kernel
// ignores it and one that refuses it is asked again without; the caller
// looks at the protocol itself all the same. The whole dump is in memory
// at once (the library gathers a multipart answer): the filter keeps it to
// what the sweep may remove.
func (c *ctConn) dump(family uint8, value, mask uint32, proto uint8) ([]ctEntry, error) {
	msgs, err := c.dumpMsgs(family, value, mask, proto)
	if err != nil && proto != 0 && !c.noFilter && (errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP)) {
		c.noFilter = true
		msgs, err = c.dumpMsgs(family, value, mask, proto)
	}
	if err != nil {
		return nil, fmt.Errorf("ctnetlink dump: %w", err)
	}
	out := make([]ctEntry, 0, len(msgs))
	for _, m := range msgs {
		e, err := parseEntry(m.Data)
		if err != nil {
			continue // one entry we cannot read is not swept
		}
		out = append(out, e)
	}
	return out, nil
}

func (c *ctConn) dumpMsgs(family uint8, value, mask uint32, proto uint8) ([]netlink.Message, error) {
	ae := netlink.NewAttributeEncoder()
	ae.ByteOrder = binary.BigEndian
	ae.Uint32(ctaMark, value)
	ae.Uint32(ctaMarkMask, mask)
	if proto != 0 && !c.noFilter {
		ae.Nested(ctaTupleOrig, func(nae *netlink.AttributeEncoder) error {
			nae.Nested(ctaTupleProto, func(pae *netlink.AttributeEncoder) error {
				pae.Uint8(ctaProtoNum, proto)
				return nil
			})
			return nil
		})
		ae.Nested(ctaFilter, func(nae *netlink.AttributeEncoder) error {
			// The flags in the host's order (nla_get_u32), not the network's.
			nae.Bytes(ctaFilterOrigFlags, binary.NativeEndian.AppendUint32(nil, ctaFilterProtoNum))
			return nil
		})
	}
	attrs, err := ae.Encode()
	if err != nil {
		return nil, err
	}
	return c.c.Execute(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(nfnlSubsysCTNetlink<<8 | ctMsgGet), Flags: netlink.Request | netlink.Dump},
		Data:   append(nfgen(family), attrs...),
	})
}

// delete removes an entry by its original tuple, and only that one: the
// ID must match too. An entry already gone is no error.
func (c *ctConn) delete(e ctEntry) error {
	ae := netlink.NewAttributeEncoder()
	ae.ByteOrder = binary.BigEndian
	ae.Nested(ctaTupleOrig, func(nae *netlink.AttributeEncoder) error {
		encodeTuple(nae, e.Orig)
		return nil
	})
	ae.Uint32(ctaID, e.ID)
	if e.Zone != 0 {
		ae.Uint16(ctaZone, e.Zone)
	}
	attrs, err := ae.Encode()
	if err != nil {
		return err
	}
	_, err = c.c.Execute(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(nfnlSubsysCTNetlink<<8 | ctMsgDelete), Flags: netlink.Request | netlink.Acknowledge},
		Data:   append(nfgen(e.Family), attrs...),
	})
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func encodeTuple(ae *netlink.AttributeEncoder, t ctTuple) {
	ae.Nested(ctaTupleIP, func(nae *netlink.AttributeEncoder) error {
		if t.Src.Addr().Is4() {
			nae.Bytes(ctaIPv4Src, t.Src.Addr().AsSlice())
			nae.Bytes(ctaIPv4Dst, t.Dst.Addr().AsSlice())
		} else {
			nae.Bytes(ctaIPv6Src, t.Src.Addr().AsSlice())
			nae.Bytes(ctaIPv6Dst, t.Dst.Addr().AsSlice())
		}
		return nil
	})
	ae.Nested(ctaTupleProto, func(nae *netlink.AttributeEncoder) error {
		nae.Uint8(ctaProtoNum, t.Proto)
		nae.Uint16(ctaProtoSrcPort, t.Src.Port())
		nae.Uint16(ctaProtoDstPort, t.Dst.Port())
		return nil
	})
}

// parseEntry reads a dumped entry: the nfnetlink header, then attributes.
func parseEntry(b []byte) (ctEntry, error) {
	var e ctEntry
	if len(b) < 4 {
		return e, errors.New("ctnetlink: short message")
	}
	e.Family = b[0]
	ad, err := netlink.NewAttributeDecoder(b[4:])
	if err != nil {
		return e, err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaTupleOrig:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				var err error
				e.Orig, err = parseTuple(nad)
				return err
			})
		case ctaStatus:
			e.Status = ad.Uint32()
		case ctaMark:
			e.Mark = ad.Uint32()
		case ctaID:
			e.ID = ad.Uint32()
		case ctaZone:
			e.Zone = ad.Uint16()
		case ctaProtoinfo:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					if nad.Type() != ctaProtoinfoTCP {
						continue
					}
					nad.Nested(func(tad *netlink.AttributeDecoder) error {
						for tad.Next() {
							if tad.Type() == ctaProtoinfoTCPState {
								e.TCPState, e.hasState = tad.Uint8(), true
							}
						}
						return nil
					})
				}
				return nil
			})
		}
	}
	if err := ad.Err(); err != nil {
		return e, err
	}
	if !e.Orig.Src.IsValid() || !e.Orig.Dst.IsValid() {
		return e, errors.New("ctnetlink: no original tuple")
	}
	return e, nil
}

func parseTuple(ad *netlink.AttributeDecoder) (ctTuple, error) {
	var t ctTuple
	var src, dst netip.Addr
	var sport, dport uint16
	for ad.Next() {
		switch ad.Type() {
		case ctaTupleIP:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					a, ok := netip.AddrFromSlice(nad.Bytes())
					if !ok {
						continue
					}
					switch nad.Type() {
					case ctaIPv4Src, ctaIPv6Src:
						src = a
					case ctaIPv4Dst, ctaIPv6Dst:
						dst = a
					}
				}
				return nil
			})
		case ctaTupleProto:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					switch nad.Type() {
					case ctaProtoNum:
						t.Proto = nad.Uint8()
					case ctaProtoSrcPort:
						sport = nad.Uint16()
					case ctaProtoDstPort:
						dport = nad.Uint16()
					}
				}
				return nil
			})
		}
	}
	if !src.IsValid() || !dst.IsValid() {
		return t, errors.New("ctnetlink: a tuple without addresses")
	}
	t.Src, t.Dst = netip.AddrPortFrom(src, sport), netip.AddrPortFrom(dst, dport)
	return t, ad.Err()
}
