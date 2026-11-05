package api

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/provision"
)

// GetMetrics describes the node in the Prometheus text format (R4-14):
// counts and times only, no user names, addresses or traffic of anyone.
// Nothing is sent anywhere; rayctl writes the text where the operator's
// collector reads it.
func (s *Server) GetMetrics(ctx context.Context, _ *connect.Request[nodev1.GetMetricsRequest]) (*connect.Response[nodev1.GetMetricsResponse], error) {
	text, err := s.metrics(ctx, time.Now())
	if err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&nodev1.GetMetricsResponse{Text: text}), nil
}

// Metrics collects samples in the text format, each family in one block
// whatever order they come in.
type Metrics struct {
	names    []string
	help     map[string]string
	families map[string]*strings.Builder
}

// Add records one sample; labels go as name, value pairs. A name ending in
// _total is a counter, the rest are gauges.
func (m *Metrics) Add(name, help string, value float64, labels ...string) {
	if m.families == nil {
		m.help, m.families = map[string]string{}, map[string]*strings.Builder{}
	}
	b := m.families[name]
	if b == nil {
		b = &strings.Builder{}
		m.families[name], m.help[name] = b, help
		m.names = append(m.names, name)
	}
	b.WriteString(name)
	if len(labels) > 0 {
		b.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(labels[i] + `="` + escapeLabel(labels[i+1]) + `"`)
		}
		b.WriteByte('}')
	}
	b.WriteString(" " + strconv.FormatFloat(value, 'f', -1, 64) + "\n")
}

func (m *Metrics) String() string {
	var out strings.Builder
	for _, name := range m.names {
		typ := "gauge"
		if strings.HasSuffix(name, "_total") {
			typ = "counter"
		}
		fmt.Fprintf(&out, "# HELP %s %s\n# TYPE %s %s\n%s", name, m.help[name], name, typ, m.families[name].String())
	}
	return out.String()
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// escapeLabel escapes a label value as the text format wants.
func escapeLabel(v string) string { return labelEscaper.Replace(v) }

func (s *Server) metrics(ctx context.Context, now time.Time) (string, error) {
	var m Metrics
	m.Add("raycontrol_info", "The node's version.", 1, "version", s.Version)

	users, err := s.Store.ListUsers(ctx)
	if err != nil {
		return "", err
	}
	byState := map[string]int{"active": 0, "disabled": 0, "expired": 0}
	for _, u := range users {
		switch {
		case !u.Enabled:
			byState["disabled"]++
		case u.ExpiresAt != nil && !u.ExpiresAt.After(now):
			byState["expired"]++
		default:
			byState["active"]++
		}
	}
	for _, k := range sortedKeys(byState) {
		m.Add("raycontrol_users", "Users by state.", float64(byState[k]), "state", k)
	}

	devices, err := s.Store.ListDevices(ctx, "")
	if err != nil {
		return "", err
	}
	byDev := map[[2]string]int{{"user", "active"}: 0, {"admin", "active"}: 0}
	for _, d := range devices {
		state := "active"
		if d.RevokedAt != nil {
			state = "revoked"
		}
		byDev[[2]string{d.Role, state}]++
	}
	devKeys := make([][2]string, 0, len(byDev))
	for k := range byDev {
		devKeys = append(devKeys, k)
	}
	sort.Slice(devKeys, func(i, j int) bool {
		return devKeys[i][0]+devKeys[i][1] < devKeys[j][0]+devKeys[j][1]
	})
	for _, k := range devKeys {
		m.Add("raycontrol_devices", "Enrolled devices by role and state.", float64(byDev[k]), "role", k[0], "state", k[1])
	}

	services, err := s.Store.ListServices(ctx)
	if err != nil {
		return "", err
	}
	byKind := map[[2]string]int{}
	for _, svc := range services {
		byKind[[2]string{svc.Kind, fmt.Sprint(svc.Enabled)}]++
	}
	kindKeys := make([][2]string, 0, len(byKind))
	for k := range byKind {
		kindKeys = append(kindKeys, k)
	}
	sort.Slice(kindKeys, func(i, j int) bool {
		return kindKeys[i][0]+kindKeys[i][1] < kindKeys[j][0]+kindKeys[j][1]
	})
	for _, k := range kindKeys {
		m.Add("raycontrol_services", "Services by kind.", float64(byKind[k]), "kind", k[0], "enabled", k[1])
	}

	// Certificates: the end of validity of each service's own certificate.
	for _, svc := range services {
		if !svc.Enabled {
			continue
		}
		secrets, err := s.Store.ServiceSecrets(ctx, svc.ID)
		if err != nil {
			return "", err
		}
		if notAfter, ok := certNotAfter(secrets); ok {
			m.Add("raycontrol_certificate_not_after_seconds", "When the service's certificate expires (Unix time).",
				float64(notAfter.Unix()), "service", svc.Name, "kind", svc.Kind)
		} else if svc.Kind == "site" {
			// A site still without one: 0, so that an alert on "expires
			// soon" fires for it too (O-2).
			m.Add("raycontrol_certificate_not_after_seconds", "When the service's certificate expires (Unix time).",
				0, "service", svc.Name, "kind", svc.Kind)
		}
	}

	// rayd's loops (O-2): the last success and failure of each; the error
	// itself is in rayctl status.
	for _, l := range s.Health.Loops() {
		m.Add("raycontrol_loop_last_success_seconds", "When the loop last succeeded (Unix time, 0 when never).",
			float64(unixOf(l.LastOK)), "loop", l.Name)
		m.Add("raycontrol_loop_last_error_seconds", "When the loop last failed (Unix time, 0 when never).",
			float64(unixOf(l.LastErr)), "loop", l.Name)
		m.Add("raycontrol_loop_runs_total", "Rounds of the loop since rayd started.", float64(l.Runs), "loop", l.Name)
		m.Add("raycontrol_loop_errors_total", "Failed rounds of the loop since rayd started.", float64(l.Errors), "loop", l.Name)
		failing := 0.0
		if l.Failing() {
			failing = 1
		}
		m.Add("raycontrol_loop_failing", "1 when the loop's last round failed.", failing, "loop", l.Name)
	}

	// REALITY rotation (R4-7).
	for _, svc := range services {
		if svc.Kind != "reality" || !svc.Enabled {
			continue
		}
		st := provision.ParseRealityState(svc)
		m.Add("raycontrol_reality_rotated_at_seconds", "Last switch of the REALITY key set (Unix time).",
			float64(st.RotatedAt), "service", svc.Name)
		m.Add("raycontrol_reality_next_from_seconds", "Switch time of the published next key set (Unix time, 0 when none).",
			float64(st.NextFrom), "service", svc.Name)
	}

	// DNS: problems only, the records themselves are in "rayctl dns".
	_, problems, err := provision.DNSRecords(ctx, s.Store)
	if err != nil {
		return "", err
	}
	m.Add("raycontrol_dns_problems", "Problems with the DNS records the node needs.", float64(len(problems)))

	m.Add("raycontrol_spa_ports", "SPA ports open now.", float64(len(s.Params.ActivePorts(now))))
	return m.String(), nil
}

// certNotAfter reads the end of validity of a service's certificate: the
// ACME chain (PEM) or a self-signed certificate (DER).
func certNotAfter(secrets map[string][]byte) (time.Time, bool) {
	if chain := secrets[provision.SecretTLSChain]; len(chain) > 0 {
		if b, _ := pem.Decode(chain); b != nil {
			if c, err := x509.ParseCertificate(b.Bytes); err == nil {
				return c.NotAfter, true
			}
		}
	}
	if der := secrets[provision.SecretTLSCert]; len(der) > 0 {
		if c, err := x509.ParseCertificate(der); err == nil {
			return c.NotAfter, true
		}
	}
	return time.Time{}, false
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
