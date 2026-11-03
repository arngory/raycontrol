package render

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"maps"
	"net/netip"
	"path"
	"slices"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
)

// Yggdrasil (docs/08-decisions.md, R4-15): a niko-server backend behind
// tcpmux. Clients peer with the node directly over a TLS link under a name
// of the node's domain; the node's mesh address leads to inner on its exit
// port. The node's key and the site's certificate key go through systemd's
// copy (Paths.Credential); the users are keys derived from their inner
// UUIDs.
const (
	YggdrasilUsers   = "users.json"
	YggdrasilChain   = "chain.pem"
	YggdrasilTLSKey  = "key.pem"
	YggdrasilNodeKey = "node.key"
)

// YggdrasilSettings are the settings of a Yggdrasil service.
type YggdrasilSettings struct {
	SNI      string `json:"sni"`
	Site     string `json:"site"`
	ExitPort int    `json:"exit_port"`
	// Peers are public peers (P-14, R4-18): the node peers with them and
	// becomes reachable through the mesh, and clients get them as a
	// fallback path. None by default: clients peer with the node directly.
	Peers []string `json:"peers,omitempty"`
}

// YggdrasilKey is a user's Yggdrasil key, derived from their inner UUID: it
// rotates with it (R4-1), and one link carries both.
func YggdrasilKey(uuid string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("raycontrol-yggdrasil-v1\x00" + uuid))
	return ed25519.NewKeyFromSeed(seed[:])
}

// YggdrasilNode returns a Yggdrasil service's settings and the node's public
// key in the mesh.
func YggdrasilNode(s Service) (YggdrasilSettings, ed25519.PublicKey, error) {
	var st YggdrasilSettings
	_ = json.Unmarshal([]byte(s.Settings), &st)
	seed := s.Secrets[provision.SecretYggdrasilSeed]
	if len(seed) != ed25519.SeedSize || st.ExitPort < 1 || st.ExitPort > 65535 || st.SNI == "" {
		return st, nil, fmt.Errorf("service %s has no node key, name or exit port", s.Name)
	}
	return st, ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), nil
}

// YggdrasilAddress is the mesh address of a key, as yggdrasil-go's
// address.AddrForKey makes it: 0x02, the number of leading ones of the
// inverted key, then its bits after the first zero.
func YggdrasilAddress(key ed25519.PublicKey) netip.Addr {
	var a [16]byte
	a[0] = 0x02
	ones, done := byte(0), false
	var bits byte
	n, at := 0, 2
	for i := 0; i < 8*len(key) && at < len(a); i++ {
		bit := (^key[i/8] >> (7 - uint(i%8))) & 1
		if !done {
			if bit == 1 {
				ones++
			} else {
				done = true
			}
			continue
		}
		bits = bits<<1 | bit
		if n++; n == 8 {
			a[at], at, n, bits = bits, at+1, 0, 0
		}
	}
	a[1] = ones
	return netip.AddrFrom16(a)
}

// yggdrasilUsers are the keys of the users of a Yggdrasil service: from the
// current inner UUID of each, and the next and previous while they rotate.
func yggdrasilUsers(m Model, s Service, inner Service) []map[string]any {
	now := m.Now
	if now.IsZero() {
		now = time.Now()
	}
	keys := map[string]string{}
	add := func(name, uuid string) {
		keys[name] = hex.EncodeToString(YggdrasilKey(uuid).Public().(ed25519.PublicKey))
	}
	for _, u := range m.Users {
		if !slices.Contains(u.Services, s.ID) || m.Inner[u.ID] == "" {
			continue
		}
		add(InnerEmail(u.ID), m.Inner[u.ID])
		set := m.Sets[inner.ID][u.ID]
		if set.Next != "" {
			add(InnerEmail(u.ID)+"-n", set.Next)
		}
		if set.Prev != "" && now.Before(set.PrevUntil) {
			add(InnerEmail(u.ID)+"-p", set.Prev)
		}
	}
	users := []map[string]any{}
	for _, name := range slices.Sorted(maps.Keys(keys)) {
		users = append(users, map[string]any{"name": name, "enabled": true, "yggdrasil": map[string]string{"public_key": keys[name]}})
	}
	return users
}

func yggdrasilFiles(s Service, m Model, inner Service, p Paths) ([]File, error) {
	st, _, err := YggdrasilNode(s)
	if err != nil {
		return nil, err
	}
	var chain, keyDER []byte
	for _, x := range m.Services {
		if x.Kind == "site" && x.Name == provision.SiteOf(s.Service) {
			chain, keyDER = x.Secrets[provision.SecretTLSChain], x.Secrets[provision.SecretTLSKey]
		}
	}
	dir := path.Join(p.Rendered, s.Name)
	options := map[string]any{
		"private_key_file": p.Credential(s.Name, YggdrasilNodeKey),
		"exit_ports":       []int{st.ExitPort},
	}
	if len(st.Peers) > 0 {
		options["peers"] = st.Peers
	}
	b, err := jsonFile(map[string]any{
		"schema": Schema, "role": "backend", "kind": "yggdrasil", "log": map[string]string{"level": "warn"},
		"socket": p.socket(s.Name, "fd"), "front_uid": FrontUID,
		"users_file": path.Join(dir, YggdrasilUsers),
		"tls": map[string]any{
			"certificate_file": path.Join(dir, YggdrasilChain),
			"key_file":         p.Credential(s.Name, YggdrasilTLSKey),
			"curves":           []string{"X25519MLKEM768"},
		},
		"options": options,
		"inner":   p.InnerSocket(inner.Name),
	})
	if err != nil {
		return nil, err
	}
	u, err := jsonFile(map[string]any{"users": yggdrasilUsers(m, s, inner)})
	if err != nil {
		return nil, err
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	node := []byte(hex.EncodeToString(s.Secrets[provision.SecretYggdrasilSeed]) + "\n")
	return []File{
		{Path: path.Join(dir, "backend.json"), Mode: 0o640, Group: GroupName(s.Name), Content: b, Service: s.Name},
		{Path: path.Join(dir, YggdrasilUsers), Mode: 0o640, Group: GroupName(s.Name), Content: u, Service: s.Name, Reload: true},
		{Path: path.Join(dir, YggdrasilChain), Mode: 0o640, Group: GroupName(s.Name), Content: chain, Service: s.Name},
		{Path: path.Join(dir, YggdrasilTLSKey), Mode: 0o600, Content: key, Service: s.Name},
		{Path: path.Join(dir, YggdrasilNodeKey), Mode: 0o600, Content: node, Service: s.Name},
	}, nil
}
