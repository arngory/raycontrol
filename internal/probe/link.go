package probe

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// PathLink gives the server's view of the requester's current connections.
const PathLink = "/probe/v1/link"

// LinkStats are the server's numbers for the TCP connections from the
// requester's address to the node's tunnel port (443): aggregates only, as
// several people may share an address behind carrier-grade NAT.
type LinkStats struct {
	Address     string  `json:"address"` // as the node sees the requester
	Connections int     `json:"connections"`
	RTTus       Spread  `json:"rtt_us"`
	MinRTTus    uint32  `json:"min_rtt_us"`
	Retrans     uint64  `json:"retrans"`  // segments retransmitted, all connections
	SegsOut     uint64  `json:"segs_out"` // segments sent, all connections
	RetransRate float64 `json:"retrans_rate"`
	DeliveryBps Spread  `json:"delivery_bps"`
	// Hysteria2: the sessions of the address on each Hysteria2 service, by
	// service ID (niko-server's session stats).
	Hysteria2 map[string]json.RawMessage `json:"hysteria2,omitempty"`
}

// Spread is the minimum, median and maximum over the connections.
type Spread struct {
	Min    uint64 `json:"min"`
	Median uint64 `json:"median"`
	Max    uint64 `json:"max"`
}

// link answers with the stats of the requester's address. Through a tunnel
// the request comes from the node itself, which says nothing of the
// channel: 409.
func (s *Server) link(w http.ResponseWriter, r *http.Request, device string) {
	// A dump of the host's sockets: once in 5 s per device.
	s.mu.Lock()
	if s.lastLink == nil {
		s.lastLink = map[string]time.Time{}
	}
	now := s.clock()
	if now.Sub(s.lastLink[device]) < 5*time.Second {
		s.mu.Unlock()
		w.Header().Set("Retry-After", "5")
		http.Error(w, "once in 5 seconds", http.StatusTooManyRequests)
		return
	}
	s.lastLink[device] = now
	s.mu.Unlock()
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	addr := ap.Addr().Unmap()
	if addr.IsLoopback() {
		http.Error(w, "the link of a tunnel is measured directly, not through it", http.StatusConflict)
		return
	}
	ports := s.LinkPorts
	if len(ports) == 0 {
		ports = []uint16{443}
	}
	conns, err := tcpConnections()
	if err != nil {
		s.Log.Warn("probe: sock_diag", "err", err)
		http.Error(w, "no connection data", http.StatusServiceUnavailable)
		return
	}
	st := aggregate(conns, addr, ports)
	if s.Hysteria != nil {
		account := ""
		if s.Account != nil {
			if name, err := s.Account(r.Context(), device); err == nil {
				account = name
			}
		}
		for id, path := range s.Hysteria() {
			if raw, err := sessionStats(path, addr, account); err == nil {
				if st.Hysteria2 == nil {
					st.Hysteria2 = map[string]json.RawMessage{}
				}
				st.Hysteria2[id] = raw
			} else {
				s.Log.Debug("probe: hysteria2 stats", "service", id, "err", err)
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

// sessionStats asks a Hysteria2 backend for the sessions of addr and the
// account's own ones; a backend before niko-server v0.7 answers nothing to
// a name, so it gets the address alone.
func sessionStats(path string, addr netip.Addr, account string) (json.RawMessage, error) {
	raw, err := hysteriaStats(path, addr, account)
	if err != nil && account != "" {
		raw, err = hysteriaStats(path, addr, "")
	}
	return raw, err
}

// hysteriaStats asks a Hysteria2 backend for the sessions of addr: the
// address (and the account whose own sessions to list) on a line in, its
// JSON out.
func hysteriaStats(path string, addr netip.Addr, account string) (json.RawMessage, error) {
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	line := addr.String()
	if account != "" {
		line += " " + account
	}
	if _, err := c.Write([]byte(line + "\n")); err != nil {
		return nil, err
	}
	var raw json.RawMessage
	err = json.NewDecoder(io.LimitReader(c, 1<<16)).Decode(&raw)
	return raw, err
}
