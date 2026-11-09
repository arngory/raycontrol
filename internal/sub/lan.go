package sub

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
)

// LANHeader carries a device's consent to its user's LAN (lan-v1 §1.1):
// "on" shows it to the user's other devices, "off" hides it; without the
// header nothing changes.
const LANHeader = "X-Raycontrol-LAN"

// LAN is the lan field of a device's subscription (spec/lan-v1.md §1.2):
// the user's devices seeing each other over Yggdrasil, through the core of
// service Svc. Password and Devices only go to a device that shows itself
// (lan-v1 §1.1, symmetry).
type LAN struct {
	V int `json:"v"`
	// Svc is the Yggdrasil service whose profile carries the network.
	Svc uint16 `json:"svc"`
	// Relay is the ceiling of device-to-device traffic through the node,
	// Mbit/s a user; 0: directly in one Wi-Fi only.
	Relay int `json:"relay"`
	// Label is the node's DNS label (lan-v1 §1.3): a device is
	// <device label>.<node label>.niko.internal.
	Label string `json:"label"`
	// Password is the multicast password, base64url of 32 bytes; Next the
	// one of the next inner UUID, from its switch (R4-1).
	Password string       `json:"password,omitempty"`
	Next     *LANPassword `json:"next,omitempty"`
	// Devices are the user's devices that show themselves and are not
	// revoked, this one too, by ID.
	Devices []LANDevice `json:"devices,omitempty"`
}

// LANPassword is the multicast password from a switch on.
type LANPassword struct {
	Password string `json:"password"`
	From     int64  `json:"from"`
}

// LANDevice is one device of the user's LAN: its ID (as in
// X-Raycontrol-Device), its name, its DNS label and its mesh address, with
// the address of its next key from the switch on.
type LANDevice struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Label string   `json:"label"`
	Addr  string   `json:"addr"`
	Next  *LANAddr `json:"next,omitempty"`
}

// LANAddr is a device's mesh address from a switch on.
type LANAddr struct {
	Addr string `json:"addr"`
	From int64  `json:"from"`
}

const lanPasswordLabel = "raycontrol-lan-v1 password\x00"

// LANPassword is a user's multicast password for an inner UUID (lan-v1 §3):
// base64url (no padding) of HMAC-SHA256 under the user's LAN key of a label
// and the UUID. 43 characters: yggdrasil-go takes 64 bytes at most.
func LANPasswordFor(key []byte, uuid string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(lanPasswordLabel + uuid))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// lanTranslit is the Cyrillic of lan-v1 §1.3 in Latin, ICAO 9303: ь is
// nothing; a Cyrillic letter not here is "everything else".
var lanTranslit = map[rune]string{
	'а': "a", 'б': "b", 'в': "v", 'г': "g", 'ґ': "g", 'д': "d", 'е': "e", 'є': "ie", 'ё': "e", 'ж': "zh",
	'з': "z", 'и': "i", 'і': "i", 'ї': "i", 'й': "i", 'к': "k", 'л': "l", 'м': "m", 'н': "n", 'о': "o",
	'п': "p", 'р': "r", 'с': "s", 'т': "t", 'у': "u", 'ў': "u", 'ф': "f", 'х': "kh", 'ц': "ts", 'ч': "ch",
	'ш': "sh", 'щ': "shch", 'ъ': "ie", 'ы': "y", 'ь': "", 'э': "e", 'ю': "iu", 'я': "ia",
}

// lanLabelMax is the longest label from a name, which leaves room for a
// suffix -<id[:4]> under DNS's 63.
const lanLabelMax = 58

// LANLabel is the DNS label of a name (lan-v1 §1.3, steps 1-5), "" when
// nothing is left: composed (NFC, so that a letter typed as a base and a
// mark is the letter), Unicode lower case, Cyrillic in Latin, a-z and 0-9
// kept and anything else a dash, dashes collapsed and trimmed, at most 58
// characters. Only letters, digits and single dashes inside: never xn--.
func LANLabel(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(norm.NFC.String(name)) {
		lat, ok := lanTranslit[r]
		switch {
		case ok:
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			lat = string(r)
		default:
			dash = true
			continue
		}
		if lat == "" {
			continue // ь: nothing, not a dash
		}
		if dash && b.Len() > 0 {
			b.WriteByte('-')
		}
		dash = false
		b.WriteString(lat)
	}
	label := b.String()
	if len(label) > lanLabelMax {
		label = strings.TrimRight(label[:lanLabelMax], "-")
	}
	return label
}

// NodeLabel is the node's DNS label (lan-v1 §1.3): from its name, or
// n-<node_id[:8]> for none or nothing left.
func NodeLabel(name, nodeID string) string {
	if l := LANLabel(name); l != "" {
		return l
	}
	return "n-" + prefix(nodeID, 8)
}

// LANLabels are the DNS labels of a user's devices (lan-v1 §1.3), given in
// the order they were added: from the name, d-<id[:8]> for nothing left; a
// label an earlier device has gets -<id[:4]>, and if that is taken too,
// d-<id>.
func LANLabels(devices []store.LANDevice) map[string]string {
	out := make(map[string]string, len(devices))
	taken := map[string]bool{}
	for _, d := range devices {
		l := LANLabel(d.Name)
		if l == "" {
			l = "d-" + prefix(d.ID, 8)
		}
		if taken[l] {
			l += "-" + prefix(d.ID, 4)
		}
		if taken[l] {
			l = "d-" + d.ID
		}
		taken[l] = true
		out[d.ID] = l
	}
	return out
}

func prefix(s string, n int) string {
	if len(s) > n && utf8.ValidString(s[:n]) {
		return s[:n]
	}
	return s
}

// lanAddr is the mesh address of a device's key for an inner UUID.
func lanAddr(uuid string, key []byte) string {
	return render.YggdrasilAddress(render.YggdrasilDeviceKey(uuid, key).Public().(ed25519.PublicKey)).String()
}

// lanConsent reads a request's LANHeader: on, and whether it says either.
func lanConsent(h http.Header) (on, said bool) {
	switch strings.ToLower(strings.TrimSpace(h.Get(LANHeader))) {
	case "on":
		return true, true
	case "off":
		return false, true
	}
	return false, false
}

// lanHint is the lan field for a user's device (device: its ID, "" for
// none), nil without it: the administrator's consent and a Yggdrasil
// profile in profiles (the first by ID), whose core carries the network.
// Its password and the devices only when the device shows itself: who is
// not seen does not see (lan-v1 §1.1). Never the user's name, the user's
// own key, revoked or hidden devices, invites, or another user's.
func (s *Server) lanHint(ctx context.Context, m render.Model, u store.User, profiles []Profile, device, nodeName string) (*LAN, error) {
	if !u.LAN {
		return nil, nil
	}
	var ygg, inner *render.Service
	for i := range m.Services {
		svc := &m.Services[i]
		switch {
		case svc.Kind == "inner":
			inner = svc
		case svc.Kind == "yggdrasil" && ygg == nil &&
			slices.ContainsFunc(profiles, func(p Profile) bool { return int64(p.Svc) == svc.ID }):
			ygg = svc
		}
	}
	if ygg == nil || inner == nil || m.Inner[u.ID] == "" {
		return nil, nil
	}
	lan := &LAN{V: 1, Svc: uint16(ygg.ID), Relay: provision.LANRelay(ygg.Service), Label: NodeLabel(nodeName, m.NodeID)}
	if device == "" {
		return lan, nil
	}
	key, devices, err := s.Store.LANDevices(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	if len(key) != store.LANKeySize || !slices.ContainsFunc(devices, func(d store.LANDevice) bool { return d.ID == device }) {
		return lan, nil
	}
	uuid, set := m.Inner[u.ID], m.Sets[inner.ID][u.ID]
	lan.Password = LANPasswordFor(key, uuid)
	if set.Next != "" {
		lan.Next = &LANPassword{Password: LANPasswordFor(key, set.Next), From: set.NextFrom.Unix()}
	}
	labels := LANLabels(devices)
	slices.SortFunc(devices, func(a, b store.LANDevice) int { return strings.Compare(a.ID, b.ID) })
	for _, d := range devices {
		ld := LANDevice{ID: d.ID, Name: d.Name, Label: labels[d.ID], Addr: lanAddr(uuid, d.Key[:])}
		if set.Next != "" {
			ld.Next = &LANAddr{Addr: lanAddr(set.Next, d.Key[:]), From: set.NextFrom.Unix()}
		}
		lan.Devices = append(lan.Devices, ld)
	}
	return lan, nil
}
