package store

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Port is a transport port a service listens on.
type Port struct {
	Proto string // tcp | udp
	Num   uint16
}

func (p Port) String() string { return p.Proto + "/" + strconv.Itoa(int(p.Num)) }

// ParsePort parses "tcp/443".
func ParsePort(s string) (Port, error) {
	proto, num, ok := strings.Cut(s, "/")
	n, err := strconv.ParseUint(num, 10, 16)
	if !ok || err != nil || n == 0 || (proto != "tcp" && proto != "udp") {
		return Port{}, fmt.Errorf("%w port %q: use tcp/N or udp/N", ErrInvalid, s)
	}
	return Port{proto, uint16(n)}, nil
}

// kindPorts are the ports each kind uses on the node (docs/03-protocols.md).
// Public kinds are reachable without SPA; all others only after SPA.
// Kinds with a process run as their own system user with a fixed UID.
var kindPorts = map[string]struct {
	ports   []Port
	public  bool
	process bool
}{
	"reality":      {ports: []Port{{"tcp", 443}}, process: true},
	"naive":        {ports: []Port{{"tcp", 443}, {"udp", 443}}, process: true},
	"doh":          {ports: []Port{{"tcp", 443}, {"udp", 443}}, process: true},
	"yggdrasil":    {ports: []Port{{"tcp", 443}}, process: true},
	"hy2-masq":     {ports: []Port{{"udp", 443}}, process: true},
	"hy2-obfs":     {ports: []Port{{"udp", 443}}, process: true},
	"dnstt":        {ports: []Port{{"udp", 53}}, public: true, process: true},
	"masterdns":    {ports: []Port{{"udp", 53}}, public: true, process: true},
	"ssh":          {ports: []Port{{"tcp", 22}}},
	"subscription": {}, // served by rayd; port chosen at install, in settings
	"api":          {},
	"olcrtc":       {process: true}, // outbound only
	"openflux":     {process: true},
	"inner":        {process: true}, // unix socket only
}

// UID range of data-plane service processes (docs/08-decisions.md, R1-6).
const (
	FirstServiceUID = 9110
	LastServiceUID  = 9179
)

// HasProcess reports whether services of the kind run their own process.
func HasProcess(kind string) bool { return kindPorts[kind].process }

// Ports returns the ports of a service: settings {"ports": ["tcp/2222"]}
// override the kind's defaults.
func (svc Service) Ports() ([]Port, error) {
	var s struct {
		Ports []string `json:"ports"`
	}
	if err := json.Unmarshal([]byte(svc.Settings), &s); err != nil {
		return nil, fmt.Errorf("%w settings of %s: %w", ErrInvalid, svc.Name, err)
	}
	if len(s.Ports) == 0 {
		return kindPorts[svc.Kind].ports, nil
	}
	out := make([]Port, 0, len(s.Ports))
	for _, p := range s.Ports {
		port, err := ParsePort(p)
		if err != nil {
			return nil, err
		}
		out = append(out, port)
	}
	return out, nil
}

// Public reports whether the service is reachable without SPA.
func (svc Service) Public() bool { return kindPorts[svc.Kind].public }
