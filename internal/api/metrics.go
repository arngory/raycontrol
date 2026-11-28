package api

import (
	"cmp"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"maps"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/connlimit"
	"github.com/arngory/raycontrol/internal/dnsstats"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/naive"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/stats"
	"github.com/arngory/raycontrol/internal/store"
)

// GetMetrics describes the node in the Prometheus text format (R4-14):
// counts and times only, no user names, addresses or traffic of anyone.
// Nothing is sent anywhere; rayctl writes the text where the operator's
// collector reads it.
func (s *Server) GetMetrics(ctx context.Context, _ *connect.Request[nodev1.GetMetricsRequest]) (*connect.Response[nodev1.GetMetricsResponse], error) {
	// The node's numbers, whoever asks.
	m, err := s.collect(store.AllUsers(ctx), time.Now())
	if err != nil {
		return nil, toConnect(err)
	}
	if store.IntegrationRole(callerRole(ctx)) {
		services, err := s.Store.ListServices(ctx)
		if err != nil {
			return nil, toConnect(err)
		}
		m = m.relabel(integrationLabels(services))
	}
	return connect.NewResponse(&nodev1.GetMetricsResponse{Text: m.String()}), nil
}

// integrationLabels hides from an integration's metrics what names a
// zone or a site: a zone as its service's kind#n and its number, a loop by
// its kind; the rest as it is (integrations-v1 §2.3).
func integrationLabels(services []store.Service) stats.Clean {
	ids := serviceIDs(services)
	zones := map[string]string{}
	for _, svc := range services {
		for i, z := range provision.Zones(svc) {
			zones[z] = fmt.Sprintf("%s/zone%d", ids[svc.Name], i+1)
		}
	}
	return func(_ string, raw []string) ([]string, bool) {
		labels := slices.Clone(raw)
		for i := 0; i+1 < len(labels); i += 2 {
			switch labels[i] {
			case "zone":
				labels[i+1] = cmp.Or(zones[labels[i+1]], "other")
			case "loop":
				labels[i+1], _, _ = strings.Cut(labels[i+1], " ")
			}
		}
		return labels, true
	}
}

// relabel is m with each sample's labels as clean has them. Samples that
// come out alike are summed when they are counters (_total), the highest
// kept when they are levels or times, and for a last success the lowest:
// a stale loop among them still shows.
func (m *Metrics) relabel(clean stats.Clean) *Metrics {
	type series struct {
		name   string
		labels []string
		value  float64
	}
	var order []string
	sum := map[string]*series{}
	for _, p := range m.points {
		labels, ok := clean(p.Name, p.Labels)
		if !ok {
			continue
		}
		key := stats.Point{Name: p.Name, Labels: labels}.Key()
		if e, ok := sum[key]; ok {
			switch {
			case strings.HasSuffix(p.Name, "_total"):
				e.value += p.Value
			case strings.Contains(p.Name, "last_success"):
				e.value = min(e.value, p.Value)
			default:
				e.value = max(e.value, p.Value)
			}
			continue
		}
		sum[key] = &series{p.Name, labels, p.Value}
		order = append(order, key)
	}
	var out Metrics
	for _, k := range order {
		e := sum[k]
		out.Add(e.name, m.help[e.name], e.value, e.labels...)
	}
	return &out
}

// Metrics collects samples in the text format, each family in one block
// whatever order they come in.
type Metrics struct {
	names    []string
	help     map[string]string
	families map[string]*strings.Builder
	points   []stats.Point // the same samples, for rayctl stats
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
	m.points = append(m.points, stats.Point{Name: name, Labels: slices.Clone(labels), Value: value})
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

// collect gathers the node's metrics (GetMetrics, StatsPoints).
func (s *Server) collect(ctx context.Context, now time.Time) (*Metrics, error) {
	var m Metrics
	m.Add("raycontrol_info", "The node's version.", 1, "version", s.Version)

	users, err := s.Store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	// One state each, in this order: active is store.User.Active.
	byState := map[string]int{"active": 0, "disabled": 0, "expired": 0, "over_limit": 0}
	limited := 0
	for _, u := range users {
		if u.Limited() {
			limited++
		}
		switch {
		case !u.Enabled:
			byState["disabled"]++
		case !u.Live(now):
			byState["expired"]++
		case !u.Active(now):
			byState["over_limit"]++
		default:
			byState["active"]++
		}
	}
	for _, k := range sortedKeys(byState) {
		m.Add("raycontrol_users", "Users by state.", float64(byState[k]), "state", k)
	}
	// Numbers only (traffic-limit-v1 §6): how many users have a limit.
	m.Add("raycontrol_users_limited", "Users with a traffic limit.", float64(limited))

	devices, err := s.Store.ListDevices(ctx, "")
	if err != nil {
		return nil, err
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
	// By the client they last named in the last 30 days (client-min-v1 §5):
	// product and version, no device or user.
	clients, err := s.Store.ClientCounts(ctx, now.Add(-ClientWindow))
	if err != nil {
		return nil, err
	}
	for _, c := range clients {
		product, version, _ := strings.Cut(c.Client, "/")
		// "-" is no product's name: devices that never named one.
		m.Add("raycontrol_client_devices", "Devices not revoked by the client they last named (30 days); product -: never named one.",
			float64(c.Devices), "product", cmp.Or(product, "-"), "version", version)
	}

	services, err := s.Store.ListServices(ctx)
	if err != nil {
		return nil, err
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
			return nil, err
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
	// naive's server name (R4-42).
	for _, svc := range services {
		if svc.Kind != "naive" || !svc.Enabled {
			continue
		}
		st := provision.ParseNaiveState(svc)
		m.Add("raycontrol_naive_name_rotated_at_seconds", "Last switch of the naive server name (Unix time; the service's creation before the first).",
			float64(st.RotatedAt), "service", svc.Name)
		m.Add("raycontrol_naive_name_next_from_seconds", "Switch time of the published next naive server name (Unix time, 0 when none).",
			float64(st.NextFrom), "service", svc.Name)
	}

	// DNS: problems only, the records themselves are in "rayctl dns".
	_, problems, err := provision.DNSRecords(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	m.Add("raycontrol_dns_problems", "Problems with the DNS records the node needs.", float64(len(problems)))

	m.Add("raycontrol_spa_ports", "SPA ports open now.", float64(len(s.Params.ActivePorts(now))))

	// Invites: those waiting, and the wrong PINs (api-v1 §4) since rayd
	// started; a run of them is someone trying PINs of an invite they hold.
	invites, err := s.Store.ListInvites(ctx)
	if err != nil {
		return nil, err
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

	// The remote API's calls by role and answer, and the integrations' rate
	// limits and mass actions (integrations-v1 §11), since rayd started.
	s.integrationMetrics(&m)

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
	// naive's datagram requests (spec/naive-udp-v1.md §7): the udp of its
	// stats socket's line, on a service with udp=on; and its TCP tunnels'
	// memory (spec/memory-v1.md §5), on every one.
	type naiveRead struct {
		name string
		udp  *naive.UDPStats
		mem  *naive.MemoryStats
	}
	var naives []*naiveRead
	var wg sync.WaitGroup
	for _, svc := range services {
		if !svc.Enabled {
			continue
		}
		switch svc.Kind {
		case "dnstt":
			r := &read{name: svc.Name}
			reads = append(reads, r)
			wg.Add(1)
			go func() {
				defer wg.Done()
				r.st, r.err = dnsstats.Read(ctx, s.Paths.StatsSocket(r.name))
			}()
		case "naive":
			// One read of its line: the datagrams only with udp=on (the
			// line of one without has none), the tunnels' memory from any;
			// its users' bytes are the traffic loop's to read.
			if s.NaiveStats == nil {
				continue
			}
			r := &naiveRead{name: svc.Name}
			naives = append(naives, r)
			udp := provision.NaiveUDP(svc)
			wg.Add(1)
			go func() {
				defer wg.Done()
				if u, m, err := s.NaiveStats(ctx, r.name); err == nil {
					if udp {
						r.udp = u
					}
					r.mem = m
				}
			}()
		}
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
	for _, r := range naives {
		if r.udp != nil {
			addNaiveUDP(&m, r.name, *r.udp)
		}
		if r.mem != nil {
			addNaiveMemory(&m, r.name, *r.mem)
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
	// The subscription's answers since rayd started, by outcome.
	if q := s.SubRequests; q != nil {
		for _, o := range []struct {
			outcome string
			n       uint64
		}{{"ok", q.OK.Load()}, {"client_refused", q.ClientRefused.Load()}, {"traffic_exhausted", q.TrafficExhausted.Load()}, {"denied", q.Denied.Load()}} {
			m.Add("raycontrol_sub_requests_total", "Subscription requests since rayd started, by outcome: denied is a 404 (unknown or revoked device, wrong Authorization, user off).",
				float64(o.n), "outcome", o.outcome)
		}
	}
	if s.ConnLimit != nil {
		addConnLimit(&m, s.ConnLimit.Snapshot())
	}
	return &m, nil
}

// addConnLimit adds the connection limits, the table and the guard
// (spec/conn-limit-v1.md §7): numbers only, never users.
func addConnLimit(m *Metrics, s connlimit.Snapshot) {
	for _, svc := range s.Services {
		for _, kind := range connlimit.Kinds {
			m.Add("raycontrol_conn_limit_refused_total", "Connections, streams and packets refused by a per-user limit, by service and kind.",
				float64(s.Refused[[2]string{svc, kind}]), "service", svc, "kind", kind)
		}
	}
	at := map[string]int{}
	for _, svc := range s.Services {
		at[svc] = 0
	}
	for _, u := range s.Users {
		at[u.Service]++
	}
	for _, svc := range sortedKeys(at) {
		m.Add("raycontrol_conn_limit_users", "Users who met a per-user limit in the last 15 minutes, by service.", float64(at[svc]), "service", svc)
	}
	if ct := s.Conntrack; ct != nil {
		m.Add("raycontrol_conntrack_entries", "Entries in the conntrack table.", float64(ct.Count))
		m.Add("raycontrol_conntrack_max", "The conntrack table's size (nf_conntrack_max).", float64(ct.Max))
		m.Add("raycontrol_conntrack_dropped_total", "New connections the kernel dropped: the table was full.", float64(ct.Dropped))
		m.Add("raycontrol_conntrack_early_dropped_total", "Unconfirmed entries the kernel pushed out for new ones.", float64(ct.EarlyDropped))
	}
	if g := s.Guard; g != nil {
		on := 0.0
		if g.On {
			on = 1
		}
		m.Add("raycontrol_conn_guard_on", "1 while the conntrack guard refuses new data-plane connections.", on)
		m.Add("raycontrol_conn_guard_switches_total", "Times the guard switched, on or off, since rayspa started.", float64(g.Switches))
		m.Add("raycontrol_conn_guard_refused_total", "New data-plane connections the guard refused since rayspa started.", float64(g.Refused))
		for _, k := range []struct {
			kind string
			v    uint64
		}{{"udp", g.SweptUDP}, {"tcp-out", g.SweptTCPOut}, {"tcp-in", g.SweptTCPIn}} {
			m.Add("raycontrol_conn_guard_swept_total", "Conntrack entries without a socket the guard removed, by kind.", float64(k.v), "kind", k.kind)
		}
	}
}

// addNaiveUDP adds a naive service's datagram requests since its process
// started (spec/naive-udp-v1.md §7), labelled by service: counts only,
// never who or where. The datagrams dropped go by reason, every reason
// naive has with its zero; what its reasons do not cover (a naive of
// another version) as "other", so that they add up to its dropped.
func addNaiveUDP(m *Metrics, service string, u naive.UDPStats) {
	add := func(name, help string, v int64, labels ...string) {
		m.Add(name, help, float64(v), append([]string{"service", service}, labels...)...)
	}
	add("raycontrol_naive_udp_requests_total", "naive's datagram requests answered 200 (connect-udp over HTTP/3) since naive started.", u.Requests)
	add("raycontrol_naive_udp_refused_total", "naive's datagram requests refused (429: no place; 503: no socket) since naive started.", u.Refused)
	for _, d := range []struct {
		dir           string
		all, capsules int64
	}{{"in", u.In, u.CapsulesIn}, {"out", u.Out, u.CapsulesOut}} {
		add("raycontrol_naive_udp_datagrams_total", "naive's datagrams since it started: in, sent on to destinations; out, passed to clients.", d.all,
			"direction", d.dir)
		add("raycontrol_naive_udp_capsules_total", "Of naive's datagrams, those that went as capsules in the request's stream, by direction.", d.capsules,
			"direction", d.dir)
	}
	// naive's reasons in its order, then any other it gave; what they do
	// not cover is "other".
	reasons := naive.DropReasons()
	byReason := maps.Clone(u.DroppedBy)
	if byReason == nil {
		byReason = map[string]int64{}
	}
	// Saturating: the line is a data-plane process's, whose counts may
	// add up past int64 (traffic-limit-v1 §6).
	var sum int64
	for _, r := range sortedKeys(byReason) {
		sum = addSaturating(sum, byReason[r])
		if !slices.Contains(reasons, r) {
			reasons = append(reasons, r)
		}
	}
	if u.Dropped > sum {
		if !slices.Contains(reasons, "other") {
			reasons = append(reasons, "other")
		}
		byReason["other"] = addSaturating(byReason["other"], u.Dropped-sum)
	}
	for _, r := range reasons {
		add("raycontrol_naive_udp_dropped_total", "naive's datagrams dropped, either way, by reason (spec/naive-udp-v1.md §7).", max(byReason[r], 0), "reason", r)
	}
}

// addNaiveMemory adds a naive service's TCP tunnels' memory
// (spec/memory-v1.md §5), labelled by service: counts only.
func addNaiveMemory(m *Metrics, service string, st naive.MemoryStats) {
	pressure := 0.0
	if st.Pressure {
		pressure = 1
	}
	m.Add("raycontrol_naive_tunnels_budget_bytes", "naive's budget for its TCP tunnels' memory.", float64(st.Budget), "service", service)
	m.Add("raycontrol_naive_tunnels_charge_bytes", "naive's TCP tunnels' memory as charged now.", float64(st.Charge), "service", service)
	m.Add("raycontrol_naive_tunnels_pressure", "1 while naive resets TCP tunnels that hold memory and do not move.", pressure, "service", service)
	m.Add("raycontrol_naive_tunnels_refused_total", "naive's CONNECTs refused 429 at the memory budget since naive started.", float64(st.Refused), "service", service)
	m.Add("raycontrol_naive_tunnels_evicted_total", "naive's TCP tunnels reset under memory pressure since naive started.", float64(st.Evicted), "service", service)
}

// addSaturating is a + b for counts: below zero is zero, past
// math.MaxInt64 is math.MaxInt64.
func addSaturating(a, b int64) int64 {
	a, b = max(a, 0), max(b, 0)
	if b > math.MaxInt64-a {
		return math.MaxInt64
	}
	return a + b
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
		{"raycontrol_dns_front_probes_total", "dnsprobe-v1 probes, by result.", f.ProbesOverLabel, []string{"result", "over_label"}},
		{"raycontrol_dns_front_forwarded_total", "Queries passed to a tunnel's backend.", f.Forwarded, nil},
		{"raycontrol_dns_front_backend_away_total", "Queries not passed on: the backend away or its queue full.", f.BackendAway, nil},
		{"raycontrol_dns_front_answers_total", "Backends' answers sent on, truncated ones included.", f.Answers, nil},
		{"raycontrol_dns_front_truncated_total", "Answers over the requester's size, sent with TC and no records.", f.Truncated, nil},
		{"raycontrol_dns_front_unmatched_total", "Backends' answers no query waited for, dropped.", f.Unmatched, nil},
		{"raycontrol_dns_front_dropped_total", "Backends' messages not sent on: unreadable, no question to truncate to, a failed write.", f.Dropped, nil},
		{"raycontrol_dns_front_untagged_total", "Queries of a slipstream zone without a device's valid tag: NOERROR, the server sees none.", f.Untagged, nil},
		{"raycontrol_dns_front_replayed_total", "Queries of a slipstream zone whose tag passed before (copies): the server sees none.", f.Replayed, nil},
		{"raycontrol_dns_front_replay_turns_total", "Generations of the front's memory of tags started early under load: older copies reach the server, which drops them.", f.ReplayTurns, nil},
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
