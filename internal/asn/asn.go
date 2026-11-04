// Package asn finds the autonomous system (and the country) of an address,
// for the client summaries (docs/08-decisions.md, R4-21): the node keeps
// counts by AS and never the address. Sources, first match wins:
//
//   - a database the operator imported (MMDB, rayctl summary db);
//   - IPinfo Lite shipped in the release, under its signature
//     (CC BY-SA 4.0, attribution in the archive's NOTICE);
//   - an API, only when the administrator turns it on: asked by network
//     (/24, /48), never by address, and only when the databases miss.
//
// The node fetches nothing on a schedule of its own (R4-5).
package asn

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
)

// Info is the AS and the country of an address.
type Info struct {
	ASN     uint32
	Name    string // the AS organization
	Country string // ISO 3166-1 alpha-2, may be empty
}

// Source finds the AS of an address; ok is false when it does not know.
type Source interface {
	Lookup(ctx context.Context, addr netip.Addr) (info Info, ok bool)
}

// Chain asks its sources in order.
type Chain []Source

// Lookup returns the first answer.
func (c Chain) Lookup(ctx context.Context, addr netip.Addr) (Info, bool) {
	for _, s := range c {
		if s == nil {
			continue
		}
		if info, ok := s.Lookup(ctx, addr); ok {
			return info, true
		}
	}
	return Info{}, false
}

// ParseASN reads "AS13335" or "13335".
func ParseASN(s string) (uint32, bool) {
	s = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "AS"), "as")
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err == nil && n > 0
}

// Public reports whether an address can have an AS worth asking about: not
// private, loopback, link-local or otherwise special.
func Public(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsGlobalUnicast() && !addr.IsPrivate()
}

// Network is what an API is asked about instead of the address: its /24
// (IPv4) or /48 (IPv6).
func Network(addr netip.Addr) netip.Prefix {
	addr = addr.Unmap()
	bits := 48
	if addr.Is4() {
		bits = 24
	}
	p, _ := addr.Prefix(bits)
	return p
}
