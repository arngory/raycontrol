package dnscheck

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// ednsSize is the UDP size every query advertises: dnsprobe-v1's (§3), and
// what a client of the tunnel sends.
const ednsSize = 1232

// newQuery builds a query of one question with a random ID, RD as asked,
// and an OPT record of ednsSize without the DO bit.
func newQuery(name string, t dnsmessage.Type, rd bool) ([]byte, error) {
	n, err := dnsmessage.NewName(canonical(name) + ".")
	if err != nil {
		return nil, err
	}
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: binary.BigEndian.Uint16(id[:]), RecursionDesired: rd})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: t, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	if err := b.StartAdditionals(); err != nil {
		return nil, err
	}
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(ednsSize, dnsmessage.RCodeSuccess, false); err != nil {
		return nil, err
	}
	if err := b.OPTResource(opt, dnsmessage.OPTResource{}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// reply is a parsed answer to a query.
type reply struct {
	dnsmessage.Header
	answers, authorities, additionals []dnsmessage.Resource
}

var errNotReply = errors.New("not an answer to the query")

// parseReply parses r as the answer to q: the same ID and question (the
// name in any case), QR set. Of a truncated answer only the header is read.
func parseReply(q, r []byte) (*reply, error) {
	var qp, rp dnsmessage.Parser
	qh, err := qp.Start(q)
	if err != nil {
		return nil, err
	}
	qq, err := qp.Question()
	if err != nil {
		return nil, err
	}
	h, err := rp.Start(r)
	if err != nil {
		return nil, err
	}
	if h.ID != qh.ID || !h.Response {
		return nil, errNotReply
	}
	rq, err := rp.Question()
	if err != nil || !strings.EqualFold(rq.Name.String(), qq.Name.String()) || rq.Type != qq.Type || rq.Class != qq.Class {
		return nil, errNotReply
	}
	out := &reply{Header: h}
	if h.Truncated {
		return out, nil
	}
	if err := rp.SkipAllQuestions(); err != nil {
		return nil, err
	}
	if out.answers, err = rp.AllAnswers(); err != nil {
		return nil, err
	}
	if out.authorities, err = rp.AllAuthorities(); err != nil {
		return nil, err
	}
	if out.additionals, err = rp.AllAdditionals(); err != nil {
		return nil, err
	}
	return out, nil
}

// isReplyTo reports whether r answers q (ID, QR and question), for the
// network to skip stray datagrams.
func isReplyTo(q, r []byte) bool {
	var qp, rp dnsmessage.Parser
	qh, err := qp.Start(q)
	if err != nil {
		return false
	}
	h, err := rp.Start(r)
	if err != nil || h.ID != qh.ID || !h.Response {
		return false
	}
	qq, err := qp.Question()
	if err != nil {
		return false
	}
	rq, err := rp.Question()
	return err == nil && strings.EqualFold(rq.Name.String(), qq.Name.String()) && rq.Type == qq.Type && rq.Class == qq.Class
}

// nameOf is a record's owner in lower case without the final dot.
func nameOf(n dnsmessage.Name) string { return canonical(n.String()) }

// txt is the TXT data of the first TXT record of name among the answers,
// its strings joined.
func (r *reply) txt(name string) ([]byte, bool) {
	for _, rr := range r.answers {
		if t, ok := rr.Body.(*dnsmessage.TXTResource); ok && nameOf(rr.Header.Name) == canonical(name) {
			var data []byte
			for _, s := range t.TXT {
				data = append(data, s...)
			}
			return data, true
		}
	}
	return nil, false
}

// soaIn finds the first SOA record: its owner and the primary server it
// names (MNAME).
func soaIn(rs []dnsmessage.Resource) (owner, mname string, ok bool) {
	for _, rr := range rs {
		if s, isSOA := rr.Body.(*dnsmessage.SOAResource); isSOA {
			return nameOf(rr.Header.Name), nameOf(s.NS), true
		}
	}
	return "", "", false
}

// nsIn returns the names of the NS records of owner and their smallest TTL.
func nsIn(rs []dnsmessage.Resource, owner string) (names []string, ttl uint32) {
	for _, rr := range rs {
		if ns, ok := rr.Body.(*dnsmessage.NSResource); ok && nameOf(rr.Header.Name) == owner {
			if n := nameOf(ns.NS); !contains(names, n) {
				names = append(names, n)
			}
			if ttl == 0 || rr.Header.TTL < ttl {
				ttl = rr.Header.TTL
			}
		}
	}
	return names, ttl
}

// addrsIn returns the addresses (A and AAAA) of name.
func addrsIn(rs []dnsmessage.Resource, name string) []netip.Addr {
	var out []netip.Addr
	for _, rr := range rs {
		if nameOf(rr.Header.Name) != name {
			continue
		}
		switch b := rr.Body.(type) {
		case *dnsmessage.AResource:
			out = append(out, netip.AddrFrom4(b.A))
		case *dnsmessage.AAAAResource:
			out = append(out, netip.AddrFrom16(b.AAAA))
		}
	}
	return out
}

func contains[T comparable](s []T, v T) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
