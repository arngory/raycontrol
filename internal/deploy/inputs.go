package deploy

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/site"
	"github.com/arngory/raycontrol/internal/store"
)

// Inputs are what Build makes the deployment from (spec/apply-plan-v1.md
// §3.3). rayd reports them (InputsOf, GetDeployInputs); rayctl apply, as
// root, checks them and builds the plan itself with its own paths and
// binaries. Short and typed: no secrets, no file contents, nothing root
// installs as rayd wrote it.
type Inputs struct {
	// Services are the enabled services, in the database's order.
	Services []ServiceInput
	// FrontTCP: TCP 443 is behind the front (render.Model.FrontTCP).
	FrontTCP bool
	// Front: rayd rendered the front's config. FrontDNS: the front answers
	// DNS tunnels on UDP 53. DNSProbeKey: the front's dnsprobe-v1 key was
	// rendered.
	Front, FrontDNS, DNSProbeKey bool
	// SubscriptionPort is the subscription endpoint's port, 0 without one:
	// the channel probes of naive and Hysteria2 go there.
	SubscriptionPort int
	// HostPorts are the ports clients reach (host firewalls), OutsidePorts
	// the same as they arrive from outside (a provider's firewall).
	HostPorts, OutsidePorts []PortRange
	// Warnings are rayd's own: what it could not render, and why. Text for
	// a person, nothing else (PrintableWarning).
	Warnings []string
}

// ServiceInput is a service as Build needs it.
type ServiceInput struct {
	Kind string
	Name string
	UID  int // the user of its process, 0 without one
	// Answer is what a site answers (site.Answers).
	Answer string
	// Site is the node's site REALITY steals from, or naive answers as.
	Site string
	// Slipstream are a slipstream service's settings, or SlipstreamError
	// why rayd could not read them: the service is left out.
	Slipstream      provision.SlipstreamSettings
	SlipstreamError string
	// PublicPeers: a Yggdrasil service dials public peers.
	PublicPeers bool
	// Salamander: the front's copy of a hy2-obfs service's salamander
	// password was rendered.
	Salamander bool
}

// MaxInputServices bounds the services of Inputs: the 70 UIDs of the
// service range for those with a process, and a few without (ssh, api,
// subscription).
const MaxInputServices = 128

// maxPortRanges bounds the port ranges of Inputs.
const maxPortRanges = 1024

// InputsOf are the inputs of the rendered model: m the model, files what
// Render wrote of it, p where. HostPorts, OutsidePorts and Warnings are
// the caller's (they are not the model's).
func InputsOf(m render.Model, files []render.File, p render.Paths) Inputs {
	in := Inputs{FrontTCP: m.FrontTCP, SubscriptionPort: m.SubscriptionPort()}
	rendered := map[string]bool{}
	for _, f := range files {
		rendered[f.Path] = true
	}
	// The front's config, not any file of the front's: a slipstream service
	// that failed to render still refreshes its keys file there (review).
	front := path.Join(p.Rendered, "front", "front.json")
	in.Front = rendered[front]
	in.DNSProbeKey = rendered[path.Join(p.Rendered, "front", render.DNSProbeKeyFile)]
	// The front answers the DNS tunnels on UDP 53 when its rendered config
	// listens there (a tunnel that did not render is not there).
	for _, f := range files {
		if f.Path == front {
			var c struct {
				DNS *struct {
					Listen []string `json:"listen"`
				} `json:"dns"`
			}
			in.FrontDNS = json.Unmarshal(f.Content, &c) == nil && c.DNS != nil && len(c.DNS.Listen) > 0
		}
	}
	for _, s := range m.Services {
		si := ServiceInput{Kind: s.Kind, Name: s.Name, UID: s.UID}
		switch s.Kind {
		case "site":
			si.Answer = provision.SiteAnswer(s.Service)
		case "reality", "naive":
			si.Site = provision.SiteOf(s.Service)
		case "slipstream":
			ss, err := provision.ParseSlipstream(s.Service)
			if err != nil {
				si.SlipstreamError = fmt.Sprintf("service %s: %v", s.Name, err)
			} else {
				si.Slipstream = ss
			}
		case "yggdrasil":
			st, _, err := render.YggdrasilNode(s)
			si.PublicPeers = err == nil && len(st.Peers) > 0
		case "hy2-obfs":
			// Only what this render wrote: a service that could not be
			// rendered leaves none, and an install of a missing file would
			// keep the whole front down (Q-1).
			si.Salamander = rendered[path.Join(p.Rendered, "front", s.Name+".salamander")]
		}
		in.Services = append(in.Services, si)
	}
	return in
}

// CheckService checks a service by the store's write rules: its kind, its
// name and UID, and what goes from its settings into the units. One that
// fails is left out with a warning, as Render leaves out a broken one
// (Q-1). The database is not to be trusted any more than rayd: a copy
// restored from elsewhere is one (spec/apply-plan-v1.md §2.3). What needs
// the other services (a name or UID taken twice, REALITY's site) Build
// checks.
func CheckService(s ServiceInput) error {
	if !slices.Contains(store.ServiceKinds, s.Kind) {
		return fmt.Errorf("service %q (%q) is not known to this version: left out", s.Name, s.Kind)
	}
	if !store.HasProcess(s.Kind) {
		if err := store.CheckServiceName(s.Name); err != nil {
			return fmt.Errorf("service left out: %w", err)
		}
		if s.UID != 0 {
			return fmt.Errorf("service %s (%s) left out: UID %d, but it has no process", s.Name, s.Kind, s.UID)
		}
		return nil
	}
	if err := store.CheckProcessName(s.Name); err != nil {
		return fmt.Errorf("service left out: %w", err)
	}
	if s.UID < store.FirstServiceUID || s.UID > store.LastServiceUID {
		return fmt.Errorf("service %s (%s) left out: UID %d is outside %d-%d", s.Name, s.Kind, s.UID, store.FirstServiceUID, store.LastServiceUID)
	}
	switch s.Kind {
	case "site":
		if !slices.Contains(site.Answers, s.Answer) {
			return fmt.Errorf("service %s (site) left out: answer %q: want one of %s", s.Name, s.Answer, strings.Join(site.Answers, ", "))
		}
	case "reality":
		// Its user joins the site's group (Build checks that it is a site).
		if s.Site != "" {
			if err := store.CheckProcessName(s.Site); err != nil {
				return fmt.Errorf("service %s (reality) left out: its site: %w", s.Name, err)
			}
		}
	}
	return nil
}

// checked are the services Build deploys: each passed CheckService, its
// name and UID are its own, and REALITY's site is among them. The others
// are left out, with the warnings.
func (in Inputs) checked() (out []ServiceInput, warnings []string) {
	names, uids := map[string]bool{}, map[int]bool{}
	for _, s := range in.Services {
		err := CheckService(s)
		switch {
		case err != nil:
		case names[s.Name]:
			err = fmt.Errorf("service %s (%s) left out: another service has its name", s.Name, s.Kind)
		case s.UID != 0 && uids[s.UID]:
			err = fmt.Errorf("service %s (%s) left out: another service has its UID %d", s.Name, s.Kind, s.UID)
		}
		if err != nil {
			warnings = append(warnings, err.Error())
			continue
		}
		names[s.Name], uids[s.UID] = true, true
		out = append(out, s)
	}
	sites := map[string]bool{}
	for _, s := range out {
		if s.Kind == "site" {
			sites[s.Name] = true
		}
	}
	out = slices.DeleteFunc(out, func(s ServiceInput) bool {
		if s.Kind != "reality" || s.Site == "" || sites[s.Site] {
			return false
		}
		warnings = append(warnings, fmt.Sprintf("service %s (reality) left out: its site %s is not one of the node's", s.Name, s.Site))
		return true
	})
	return out, warnings
}

// Check checks what is the node's rather than a service's. A bad value
// here fails the whole apply before anything changes (spec/apply-plan-v1.md
// §6, 1).
func (in Inputs) Check() error {
	if len(in.Services) > MaxInputServices {
		return fmt.Errorf("%d services: at most %d", len(in.Services), MaxInputServices)
	}
	if in.SubscriptionPort < 0 || in.SubscriptionPort > 65535 {
		return fmt.Errorf("subscription port %d", in.SubscriptionPort)
	}
	if len(in.HostPorts) > maxPortRanges || len(in.OutsidePorts) > maxPortRanges {
		return fmt.Errorf("%d host and %d outside port ranges: at most %d", len(in.HostPorts), len(in.OutsidePorts), maxPortRanges)
	}
	for _, r := range slices.Concat(in.HostPorts, in.OutsidePorts) {
		if err := r.Check(); err != nil {
			return err
		}
	}
	return nil
}

// Check checks a port range: tcp or udp, ports 1-65535, from no more than
// to.
func (r PortRange) Check() error {
	if (r.Proto != "tcp" && r.Proto != "udp") || r.From == 0 || r.From > r.To {
		return fmt.Errorf("port range %q %d-%d: want tcp or udp, 1-65535", r.Proto, r.From, r.To)
	}
	return nil
}

// errNotPort is a port number out of range.
var errNotPort = errors.New("not a port")

// Port is n as a port, 1-65535.
func Port(n uint32) (uint16, error) {
	if n == 0 || n > 65535 {
		return 0, fmt.Errorf("%w: %d", errNotPort, n)
	}
	return uint16(n), nil
}

// maxWarning bounds a warning as printed.
const maxWarning = 512

// PrintableWarning is a warning as a terminal may show it: without what it
// would act on (control characters, invalid UTF-8), cut to a length. rayd's
// warnings come from its database, which root does not trust.
func PrintableWarning(w string) string {
	w = nodeupdate.Printable(w)
	if len(w) <= maxWarning {
		return w
	}
	n := maxWarning
	for n > 0 && !utf8.RuneStart(w[n]) {
		n--
	}
	return w[:n] + "…"
}
