package dnscheck

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"time"
)

// A dnstt poll is what a client sends with nothing to send: a ClientID and
// padding, no packets (spec/dnsauth-v1.md §3, spec/dnsseal-v1.md §3). The
// backend answers it with TXT after about a second (dnstt waits that long
// for data) when it takes the query, and with NODATA when it does not: no
// valid dnsauth-v1 tag under auth=required, an open query under
// seal=required. A ClientID of its own opens no session: the answer
// carries no packets.
const (
	clientIDLen = 8
	authTagLen  = 8
	authEpoch   = 600 // seconds (dnsauth-v1 §3)
	pollPadding = 8   // dnstt pads a poll with 8 random bytes
	paddingByte = 0xe0
)

// Poll is one poll query.
type Poll struct {
	Name   string // the query name: the payload's labels, then the zone
	Sealed bool
	key    []byte // the seal key, when sealed
}

// NewPoll makes a poll of zone: sealed with sealKey unless it is nil, and
// with a device's tag when authKey is not nil (its key for the service,
// spa.DNSAuthKey): dnsauth-v2 with v2, otherwise dnsauth-v1.
func NewPoll(zone string, sealKey, authKey []byte, v2 bool, now time.Time) (Poll, error) {
	pad := pollPadding
	if sealKey != nil {
		// Under the seal a padding frame of random length (0 to 31 bytes):
		// N makes the name unique (dnsseal-v1 §3).
		pad = randN(32)
	}
	payload := make([]byte, clientIDLen+1+pad)
	if _, err := rand.Read(payload); err != nil {
		return Poll{}, err
	}
	payload[clientIDLen] = paddingByte + byte(pad)
	if authKey != nil {
		tag := authTag
		if v2 {
			tag = authTag2
		}
		payload = append(tag(authKey, uint32(now.Unix()/authEpoch), payload), payload...)
	}
	if sealKey != nil {
		var n [sealNonceLen]byte
		if _, err := rand.Read(n[:]); err != nil {
			return Poll{}, err
		}
		payload = sealQuery(sealKey, n, payload)
	}
	encoded := strings.ToLower(base32NoPad.EncodeToString(payload))
	var labels []string
	for encoded != "" {
		n := 63
		if sealKey != nil {
			n = 32 + randN(32) // random lengths, 32 to 63 (dnsseal-v1 §3)
		}
		n = min(n, len(encoded))
		labels, encoded = append(labels, encoded[:n]), encoded[n:]
	}
	return Poll{Name: strings.Join(labels, ".") + "." + canonical(zone), Sealed: sealKey != nil, key: sealKey}, nil
}

// Open checks the TXT data of the poll's answer and returns how many
// packets it carries. A sealed answer must carry the zone key's tag.
func (p Poll) Open(data []byte) (int, error) {
	if p.Sealed {
		plain, err := openAnswer(p.key, data)
		if err != nil {
			return 0, err
		}
		data = plain
	}
	packets := 0
	for len(data) >= 2 {
		n := int(binary.BigEndian.Uint16(data))
		if n == 0 && p.Sealed {
			return packets, nil // the end of the packets; zeros follow
		}
		if n == 0 || 2+n > len(data) {
			return packets, errors.New("the answer's frames do not parse")
		}
		data, packets = data[2+n:], packets+1
	}
	if len(data) != 0 {
		return packets, errors.New("the answer's frames do not parse")
	}
	return packets, nil
}

// authTag is the dnsauth-v1 tag of a query's payload (its ClientID and what
// follows) in an epoch.
func authTag(key []byte, epoch uint32, payload []byte) []byte {
	var e [4]byte
	binary.BigEndian.PutUint32(e[:], epoch)
	return mac(key, []byte("dnsauth1"), e[:], payload)[:authTagLen]
}

// authTag2 is the dnsauth-v2 field of a payload in an epoch
// (spec/dnsauth-v2.md §2): the key's hint for the epoch, then the tag.
func authTag2(key []byte, epoch uint32, payload []byte) []byte {
	var e [4]byte
	binary.BigEndian.PutUint32(e[:], epoch)
	hint := mac(key, []byte("dnsauth2-hint"), e[:])[:2]
	return append(hint, mac(key, []byte("dnsauth2-tag"), e[:], payload)[:authTagLen-2]...)
}

// randN is a random number below n (at most 256), for lengths.
func randN(n int) int {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return int(b[0]) % n
}
