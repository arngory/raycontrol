package api

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/dnsstats"
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

	// Invites: those waiting, and the wrong PINs (api-v1 §4) since rayd
	// started; a run of them is someone trying PINs of an invite they hold.
	invites, err := s.Store.ListInvites(ctx)
	if err != nil {
		return "", err
	}
	byInvite := map[string]int{"active": 0, "expired": 0}
	for _, inv := range invites {
		if inv.ExpiresAt.After(now) {
			byInvite["active"]++
		} else {
			byInvite["expired"]++
		}
	}
	for _, k := range sortedKeys(byInvite) {
		m.Add("raycontrol_invites", "Invites not yet used, by state.", float64(byInvite[k]), "state", k)
	}
	m.Add("raycontrol_invite_pin_wrong_total", "Wrong invite PINs since rayd started.", float64(s.pinWrong.Load()))
	m.Add("raycontrol_invite_pin_withdrawn_total", "Invites withdrawn by their last wrong PIN since rayd started.", float64(s.pinWithdrawn.Load()))

	// The DNS path: each enabled dnstt service's counters, from its
	// backend's stats socket (niko-server v0.11.0), and the DNS front's;
	// none from one that has none. Read at once: a stopped backend's
	// socket may still take the connection and hold it to the deadline.
	type read struct {
		name string
		st   dnsstats.Snapshot
		err  error
	}
	var reads []*read
	var front dnsstats.Front
	var frontErr error
	var wg sync.WaitGroup
	for _, svc := range services {
		if svc.Kind != "dnstt" || !svc.Enabled {
			continue
		}
		r := &read{name: svc.Name}
		reads = append(reads, r)
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.st, r.err = dnsstats.Read(ctx, s.Paths.StatsSocket(r.name))
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		front, frontErr = dnsstats.ReadFront(ctx, s.Paths.FrontStats())
	}()
	wg.Wait()
	for _, r := range reads {
		if r.err == nil {
			addDNSTTStats(&m, r.name, r.st)
		}
	}
	// The front's: queries by zone (load: anyone can send a zone's name;
	// which zone clients reach is dnstt's zone_tagged), probes, refusals,
	// answers lost.
	if frontErr == nil {
		owner := map[string]string{}
		for _, svc := range services {
			for _, z := range provision.Zones(svc) {
				owner[z] = svc.Name
			}
		}
		addFrontStats(&m, front, owner)
	}
	return m.String(), nil
}

// addDNSTTStats adds a dnstt service's counters, labelled by service.
func addDNSTTStats(m *Metrics, service string, st dnsstats.Snapshot) {
	add := func(name, help string, v uint64, labels ...string) {
		m.Add(name, help, float64(v), append([]string{"service", service}, labels...)...)
	}
	add("raycontrol_dnstt_queries_total", "DNS queries the dnstt backend parsed.", st.Queries)
	add("raycontrol_dnstt_memo_hits_total", "Resolvers' retries answered from the memo.", st.MemoHits)
	m.Add("raycontrol_dnstt_sessions", "dnstt sessions now.", float64(st.Sessions), "service", service)
	m.Add("raycontrol_dnstt_handshakes", "dnstt sessions in their Noise handshake now.", float64(st.Handshakes), "service", service)
	add("raycontrol_dnstt_sessions_admitted_total", "New dnstt sessions admitted.", st.SessionsAdmitted)
	type sample struct {
		label string
		v     uint64
	}
	for _, r := range []sample{{"full", st.RefusedFull}, {"rate", st.RefusedRate}, {"device", st.RefusedDevice}} {
		add("raycontrol_dnstt_starts_refused_total", "dnstt session starts refused, by reason; a client's retries count again.", r.v, "reason", r.label)
	}
	add("raycontrol_dnstt_sessions_evicted_total", "A device's silent dnstt session closed for its new one.", st.SessionsEvicted)
	add("raycontrol_dnstt_handshake_timeouts_total", "dnstt sessions closed with the Noise handshake undone.", st.HandshakeTimeouts)
	add("raycontrol_dnstt_streams_refused_total", "Streams over a dnstt session's bound.", st.StreamsRefused)
	// niko-server counts a throttled query as refused too: refused here
	// is the rest, so the results add up (clamped: the two are read apart).
	refused := st.AuthRefused - min(st.AuthThrottled, st.AuthRefused)
	for _, r := range []sample{{"valid", st.AuthValid}, {"untagged", st.AuthUntagged}, {"refused", refused}, {"throttled", st.AuthThrottled}} {
		add("raycontrol_dnstt_auth_total", "dnsauth-v1 checks of queries, by result; throttled ones are refused unscanned.", r.v, "result", r.label)
	}
	for _, r := range []sample{{"opened", st.SealOpened}, {"unsealed", st.SealUnsealed}, {"refused", st.SealRefused}} {
		add("raycontrol_dnstt_seal_total", "dnsseal-v1 queries, by result.", r.v, "result", r.label)
	}
	// Which zones of the tunnel clients reach (dnszones-v1): queries with
	// a device's valid tag. A hint: the tag does not cover the zone, and
	// whoever sees a device's query can send it again in another zone.
	for _, z := range sortedKeys(st.Zones) {
		add("raycontrol_dnstt_zone_tagged_total", "dnstt queries with a device's valid dnsauth tag, by zone.", st.Zones[z], "zone", z)
	}
}

// addFrontStats adds the DNS front's counters; a zone's queries labelled by
// the zone and the service it is of (owner).
func addFrontStats(m *Metrics, f dnsstats.Front, owner map[string]string) {
	for _, z := range sortedKeys(f.Queries) {
		m.Add("raycontrol_dns_front_queries_total", "DNS queries in a zone of the node's, by zone: load, not reach.", float64(f.Queries[z]), "zone", z, "service", owner[z])
	}
	for _, c := range []struct {
		name, help string
		v          uint64
		labels     []string
	}{
		{"raycontrol_dns_front_refused_total", "DNS queries outside the node's zones, refused.", f.Refused, nil},
		{"raycontrol_dns_front_malformed_total", "Datagrams on port 53 that are no query the front reads.", f.Malformed, nil},
		{"raycontrol_dns_front_apex_total", "Queries the front answered at a zone's apex (SOA, NS).", f.Apex, nil},
		{"raycontrol_dns_front_probes_total", "dnsprobe-v1 probes, by result.", f.Probes, []string{"result", "answered"}},
		{"raycontrol_dns_front_probes_total", "dnsprobe-v1 probes, by result.", f.ProbesOverRate, []string{"result", "over_rate"}},
		{"raycontrol_dns_front_forwarded_total", "Queries passed to a tunnel's backend.", f.Forwarded, nil},
		{"raycontrol_dns_front_backend_away_total", "Queries not passed on: the backend away or its queue full.", f.BackendAway, nil},
		{"raycontrol_dns_front_answers_total", "Backends' answers sent on, truncated ones included.", f.Answers, nil},
		{"raycontrol_dns_front_truncated_total", "Answers over the requester's size, sent with TC and no records.", f.Truncated, nil},
		{"raycontrol_dns_front_unmatched_total", "Backends' answers no query waited for, dropped.", f.Unmatched, nil},
		{"raycontrol_dns_front_dropped_total", "Backends' messages not sent on: unreadable, no question to truncate to, a failed write.", f.Dropped, nil},
	} {
		m.Add(c.name, c.help, float64(c.v), c.labels...)
	}
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

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
