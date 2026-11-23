// Command rayd is the raycontrol node daemon: it owns the node state and
// serves the node API.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/arngory/raycontrol/internal/api"
	"github.com/arngory/raycontrol/internal/appmirror"
	"github.com/arngory/raycontrol/internal/asn"
	"github.com/arngory/raycontrol/internal/certfile"
	"github.com/arngory/raycontrol/internal/certs"
	"github.com/arngory/raycontrol/internal/cloudflare"
	"github.com/arngory/raycontrol/internal/connlimit"
	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/dnscheck"
	"github.com/arngory/raycontrol/internal/doh"
	"github.com/arngory/raycontrol/internal/health"
	"github.com/arngory/raycontrol/internal/live"
	"github.com/arngory/raycontrol/internal/logx"
	"github.com/arngory/raycontrol/internal/naive"
	"github.com/arngory/raycontrol/internal/nikoipc"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/pprofx"
	"github.com/arngory/raycontrol/internal/probe"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/quiccid"
	"github.com/arngory/raycontrol/internal/quiccid/cidkey"
	"github.com/arngory/raycontrol/internal/relayprobe"
	"github.com/arngory/raycontrol/internal/release"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/roots"
	"github.com/arngory/raycontrol/internal/site"
	"github.com/arngory/raycontrol/internal/stats"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
	"github.com/arngory/raycontrol/internal/summary"
	"github.com/arngory/raycontrol/internal/traffic"
	"github.com/arngory/raycontrol/internal/xrayapi"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const (
	defaultDB     = "/var/lib/raycontrol/rayd.db"
	defaultSocket = "/run/raycontrol/rayd.sock"
	auditKeep     = 90 * 24 * time.Hour
)

func usage() {
	fmt.Fprintf(os.Stderr, `usage: rayd <command> [flags]

commands:
  init     create the node state and its random parameters (safe to repeat)
  serve    serve the node API on the local socket
  site     serve the decoy site on a unix socket (run by its own unit)
  naive    serve NaiveProxy (HTTP/2) behind the niko-server front (its own unit)
  relay    serve a relay host's probe endpoint (relay-v1 §9.1; its own unit there)
  version  print the version
`)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	// Profiles under real load (O-3): off unless RAYD_PPROF is set.
	if err := pprofx.Start(logx.New(os.Stderr, slog.LevelInfo)); err != nil {
		fmt.Fprintln(os.Stderr, "rayd:", err)
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "site":
		err = cmdSite(os.Args[2:])
	case "naive":
		err = cmdNaive(os.Args[2:])
	case "relay":
		err = cmdRelay(os.Args[2:])
	case deploy.CredentialCommand:
		// Not in the usage: systemd runs it, as root, from the units.
		err = cmdCredential(os.Args[2:])
	case "version":
		fmt.Println(version)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "rayd:", err)
		os.Exit(1)
	}
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	db := fs.String("db", defaultDB, "database path")
	host := fs.String("host", "", "public address clients use (IP or domain)")
	domain := fs.String("domain", "", "base domain for service subdomains and DNS tunnel zones")
	seqClock := fs.Bool("seq-clock", false, "the subscription's seq goes on from the clock at once (rayctl restore: the database is older than "+
		"what clients have seen, and they drop answers with a lower seq)")
	ports := fs.String("ports", "", "ports chosen at the node's first install (rayctl install -ports): spa=A-B,sub=N,api=N,rotation=A-B|off")
	checkPorts := fs.Bool("check-ports", false, "only check -ports against the node in -db, changing nothing (read-only, no migration)")
	sshPorts := fs.String("ssh-ports", "", "the ports sshd listens on, which -ports keeps clear of: N[,N...] or none (rayctl install passes "+
		"them); empty: sshd -T says, and -ports is refused when it cannot")
	fs.Parse(args)

	var taken []uint16
	if *ports != "" {
		var err error
		if taken, err = initSSHPorts(*sshPorts); err != nil {
			return err
		}
	}
	choice, err := provision.ParsePorts(*ports, taken...)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if *checkPorts {
		// Beside the node's rayd, on its live database: read only, and no
		// migration of a database this rayd would migrate.
		if _, err := os.Stat(*db); errors.Is(err, os.ErrNotExist) {
			return nil // a new node: any choice
		}
		st, err := store.OpenReadOnly(ctx, *db)
		if err != nil {
			return err
		}
		defer st.Close()
		return provision.CheckPorts(ctx, st, choice)
	}
	st, err := store.Open(ctx, *db)
	if err != nil {
		return err
	}
	defer st.Close()
	p, err := provision.Init(ctx, st, provision.Options{Host: *host, Domain: *domain, Ports: choice})
	if err != nil {
		return err
	}
	if *seqClock {
		if err := sub.SeqToClock(ctx, st, time.Now()); err != nil {
			return err
		}
	}
	fmt.Printf("node %x initialised in %s\n", p.NodeID, *db)
	return nil
}

// minCredGrace is the shortest overlap after a credential switch.
const minCredGrace = 12 * time.Hour

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	db := fs.String("db", defaultDB, "database path")
	socket := fs.String("socket", defaultSocket, "API socket path")
	group := fs.String("group", "raycontrol", "group whose members may use the API besides root")
	rayspaUser := fs.String("rayspa-user", "rayspa", "system user of rayspa, the only one besides root that receives the perimeter feed")
	spaTTL := fs.Duration("spa-ttl", 10*time.Minute, "access granted by SPA when the packet asks for the default")
	spaMaxTTL := fs.Duration("spa-max-ttl", time.Hour, "longest access a SPA packet may ask for")
	spaTCP := fs.Bool("spa-tcp", true, "also accept SPA v2 over TCP on the slot ports")
	rendered := fs.String("rendered", render.DefaultPaths.Rendered, "directory for rendered data-plane files")
	run := fs.String("run", render.DefaultPaths.Run, "runtime directory of the data plane: its sockets and credentials")
	liveApply := fs.Bool("live", true, "render and apply data-plane files while serving")
	supervise := fs.Bool("supervise", false, "run the data plane as child processes, without systemd (tests, containers): no users, groups or sandbox")
	xrayBin := fs.String("xray", deploy.DefaultBinaries.Xray, "Xray binary for -supervise")
	nikoBin := fs.String("niko-server", deploy.DefaultBinaries.NikoServer, "niko-server binary for -supervise")
	slipBin := fs.String("slipstream-server", deploy.DefaultBinaries.Slipstream, "slipstream-server binary for -supervise")
	acmeDir := fs.String("acme-directory", certs.LetsEncrypt, "ACME directory for the sites' certificates (empty: none); "+
		"a private CA's root goes in the node's roots (rayctl roots file)")
	tlsRoots := fs.String("tls-roots", roots.SettingsFile, "settings of the roots the node's own outbound TLS trusts besides "+
		"its embedded list (rayctl roots; a stand may name a file of its own)")
	credPeriod := fs.Duration("cred-period", store.DefaultRotation.Period, "how long a user credential stays current (0: no scheduled rotation; "+
		"rayctl device revoke -overlap still starts one of its user's credentials)")
	credLead := fs.Duration("cred-lead", store.DefaultRotation.Lead, "the next credential is in the subscription this long before the switch, "+
		"a scheduled one and the one rayctl device revoke -overlap publishes")
	probeDaily := fs.Int("probe-daily-mib", probe.DefaultDaily>>20, "channel probes: MiB per device and UTC day, both directions")
	credGrace := fs.Duration("cred-grace", store.DefaultRotation.Grace, "the previous credential (and REALITY key set) is accepted this long after the switch (12h at least); "+
		"after rayctl device revoke -overlap, what the device knew works -cred-lead + -cred-grace")
	realityPeriod := fs.Duration("reality-period", 90*24*time.Hour, "how long REALITY keys stay current; their next set is published -cred-lead ahead (0: no rotation)")
	realityPrepare := fs.Duration("reality-prepare", 24*time.Hour, "how long a new server name (REALITY's, naive's) may wait for its certificate")
	naiveSNIPeriod := fs.Duration("naive-sni-period", provision.DefaultNaiveSNIPeriod, "how long a naive server name stays current: the next one is published -cred-lead ahead, "+
		"under a wildcard certificate only unless rayctl service set NAME rotate_sni=on (0: only by rayctl service rotate NAME); "+
		"a name left at a switch stays accepted until a switch this long after (90 days with 0), 3 previous names at most")
	siteKeyPeriod := fs.Duration("site-key-period", provision.DefaultSiteKeyPeriod, "how long the key of a site's certificate stays in use: at an issuance after that the next key takes over (0: only by rayctl service rotate SITE)")
	siteKeyLead := fs.Duration("site-key-lead", provision.DefaultSiteKeyLead, "the next key of a site's certificate is in the subscription (niko-pin) this long before a switch to it")
	debug := fs.Bool("debug", false, "log at debug level: refused subscription requests with their addresses (personal data: turn it off after use)")
	updateCheck := fs.Duration("update-check", 0, "look for a newer raycontrol release this often, an hour or more, ±10 % (0: never; release builds only): the node fetches the latest SHA256SUMS and its signature from github.com, which sees the node's address; rayctl status says what it found")
	dnsCheck := fs.Duration("dns-check", time.Hour, "check the DNS tunnel zones from the node this often, ±10 %: the delegation, the front and the backend, the zones through public resolvers (0: only on demand, rayctl dns check -now)")
	dnsCheckResolvers := fs.String("dns-check-resolvers", strings.Join(dnscheck.DefaultResolvers, ","),
		"resolvers the DNS check asks: "+strings.Join(dnscheck.ResolverNames(), ", ")+", udp:IP or tcp:IP")
	dnsCheckPrivate := fs.Bool("dns-check-private", false,
		"the DNS check asks the parent zone's servers at private, shared or reserved addresses too (a lab's own parent zone)")
	fs.Parse(args)
	epoch := provision.RealityEpoch{Period: *realityPeriod, Lead: *credLead, Prepare: *realityPrepare, Grace: *credGrace, NaivePeriod: *naiveSNIPeriod}
	if err := epoch.Check(); err != nil {
		return err
	}
	// The keys of the sites' certificates (spec/cert-pin-v1.md §5).
	siteKeys := provision.SiteKeyPolicy{Period: *siteKeyPeriod, Lead: *siteKeyLead}
	if err := siteKeys.Check(); err != nil {
		return fmt.Errorf("-site-key-period, -site-key-lead: %w", err)
	}
	// A grant of 0 would be an element with no timeout at all; the gate
	// gives a second at least all the same.
	if *spaTTL < time.Second || *spaMaxTTL < time.Second {
		return fmt.Errorf("-spa-ttl %v, -spa-max-ttl %v: a second at least", *spaTTL, *spaMaxTTL)
	}
	dnsResolvers, err := dnscheck.ParseResolvers([]string{*dnsCheckResolvers})
	if err != nil {
		return fmt.Errorf("-dns-check-resolvers: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// -debug always; otherwise while the debug window is open (followDebug).
	level := new(slog.LevelVar)
	if *debug {
		level.Set(slog.LevelDebug)
	}
	log := logx.New(os.Stderr, level)
	// Interop (the client's CI): a stand that walks through a switch to the
	// next key and a fresh one in minutes. Only without systemd, where no
	// node in use runs.
	if err := unsafeStand(*supervise, os.Getenv, log); err != nil {
		return err
	}

	st, err := store.Open(ctx, *db)
	if err != nil {
		return err
	}
	defer st.Close()
	params, err := node.LoadParams(ctx, st)
	if errors.Is(err, store.ErrNotFound) {
		return errors.New("node is not initialised: run rayd init")
	}
	if err != nil {
		return err
	}

	// Where the loops below report: rayctl status and the metrics (O-2).
	hb := &health.Board{}
	// The roots of the node's own outbound TLS (R4-41): which, and the
	// connections they refused, in rayctl status.
	rr := &rootsReporter{hb: hb, log: log}
	roots.Node.Path, roots.Node.Report = *tlsRoots, rr.report
	roots.Node.Status() // builds the pool: reported
	go rr.run(ctx, roots.Node)
	go pruneAudit(ctx, st, hb, log)
	paths := render.Paths{Rendered: *rendered, Run: *run, Supervised: *supervise}
	rotateNow := make(chan struct{}, 1)
	srv := &api.Server{Store: st, Params: params, Version: version, Paths: paths, Binaries: deploy.DefaultBinaries,
		CheckRealityTarget: provision.CheckRealityTarget, RealityLead: *credLead, NaivePeriod: *naiveSNIPeriod, CredGrace: *credGrace, SiteKeyLead: *siteKeyLead, Health: hb,
		Rotate: func() {
			select {
			case rotateNow <- struct{}{}:
			default:
			}
		},
		DNSCheck: dnsMonitor(ctx, st, dnsResolvers, hb, log)}
	srv.DNSCheck.Checker.Private = *dnsCheckPrivate
	// The client's releases (spec/app-update-v1.md), beside the database:
	// only while the administrator has the mirror on (rayctl app-mirror).
	srv.AppMirror = &appmirror.Mirror{Store: st, Dir: filepath.Join(filepath.Dir(*db), "app"), Conn: probe.Conn, Log: log}
	// The update by request (spec/node-update-v1.md): the latest release
	// rayd's checks saw, and the newest patch release of this version, for
	// GetUpdateStatus.
	var latestSeen, patchSeen atomic.Value
	srv.NodeUpdate = &api.NodeUpdate{Latest: func() string { v, _ := latestSeen.Load().(string); return v },
		LatestPatch: func() string { v, _ := patchSeen.Load().(string); return v }}
	// Interop (the client's CI): releases from a server of the test's,
	// signed with its key. Never on a node in use: anything that key signs
	// would go to its devices.
	if api := os.Getenv("RAYCONTROL_UNSAFE_APP_MIRROR_API"); api != "" {
		srv.AppMirror.API, srv.AppMirror.AllowHTTP = strings.TrimSuffix(api, "/"), true
		log.Warn("UNSAFE: the client's releases come from a test source, plain HTTP allowed", "api", api)
	}
	if key := os.Getenv("RAYCONTROL_UNSAFE_APP_MIRROR_KEY"); key != "" {
		srv.AppMirror.PubKey = key
		log.Warn("UNSAFE: the client's releases are checked with a test key, not the client's", "key", key)
	}
	go srv.AppMirror.Run(ctx, func() time.Duration { return mrand.N(appmirror.Jitter) }) //nolint:gosec // G404: when to look, no secret
	// The connection limits (spec/conn-limit-v1.md §7): the refusals of
	// naive, Hysteria2 and Xray by user every 15 s, the conntrack table,
	// the guard as rayspa reports it.
	srv.ConnLimit = &connlimit.Monitor{Sources: connLimitSources(st, paths), Off: st.ConnLimitOff, Health: hb, Log: log}
	go srv.ConnLimit.Run(ctx)
	// naive's datagram requests for rayctl metrics (naive-udp-v1 §7): the
	// same line as its bytes and refusals, read when the metrics are asked.
	srv.NaiveUDP = func(ctx context.Context, service string) (*naive.UDPStats, error) {
		r, err := traffic.ReadLine(ctx, paths.StatsSocket(service))
		return r.UDP, err
	}
	// rayctl stats (spec/stats-v1.md): the metrics without names and the
	// host, a sample a minute, two hours of them in memory.
	srv.SubRequests, srv.Started = &sub.Requests{}, processStart
	srv.Stats = &stats.Sampler{Collect: srv.StatsPoints, ReadHost: stats.HostReader(filepath.Dir(*db)), Log: log}
	go srv.Stats.Run(ctx)
	per := &api.PerimeterServer{Server: srv, RayspaUID: -1, DefaultTTL: *spaTTL, MaxTTL: *spaMaxTTL, TCPCarrier: *spaTCP, Refresh: time.Minute}
	policy := api.PeerPolicy{Group: *group}
	if u, err := user.Lookup(*rayspaUser); err == nil {
		per.RayspaUID, _ = strconv.Atoi(u.Uid)
		policy.Deny = []int{per.RayspaUID}
	} else {
		log.Warn("rayspa user not found; only root receives the perimeter feed", "user", *rayspaUser)
	}

	if !*supervise {
		// rayspa away: rayctl status's "perimeter" line, and the journal
		// at error (R4-40). A supervised node has no rayspa.
		go per.MonitorRayspa(ctx, log)
	}
	if *supervise && !*liveApply {
		return errors.New("-supervise needs -live: the processes read the rendered files")
	}
	// Each user's bytes for the traffic limit (traffic-limit-v1 §2.4),
	// read from the processes while a user has a limit; one wakes apply
	// when it crosses it.
	acct := &traffic.Accountant{Store: st, Sources: traffic.Processes(paths), Health: hb, Log: log, Notify: srv.Notify}
	if *liveApply {
		applier := &live.Applier{Store: st, Paths: paths, Log: log, Report: func(err error) { hb.Done("apply", err) },
			BeforeRestart: acct.Flush, FrontUnit: deploy.UnitPath(render.UnitName("front"))}
		var sup *live.Supervisor
		if *supervise {
			sup, err = supervisor(paths, deploy.Binaries{Xray: *xrayBin, NikoServer: *nikoBin, Slipstream: *slipBin}, st, log)
			if err != nil {
				return err
			}
			applier.Restart = sup.Restart
			applier.FrontUnit = ""
		}
		// The socket opens after the first render: rayctl apply waits for it
		// before it starts the data-plane units that read these files.
		err := applier.Apply(ctx)
		hb.Done("apply", err)
		if err != nil {
			log.Error("apply", "err", err)
		}
		if sup != nil {
			// The processes run on a context of their own: they stop after
			// the traffic loop's last round has read them (its deferred wait
			// below runs first), and before rayd returns.
			supCtx, supStop := context.WithCancel(context.WithoutCancel(ctx))
			done := make(chan struct{})
			go func() { sup.Run(supCtx); close(done) }()
			defer func() { supStop(); <-done }()
		}
		go applier.Run(ctx, srv.Changes)
	}
	if *updateCheck > 0 && *updateCheck < time.Hour {
		return errors.New("-update-check must be an hour or more: each check asks github.com from the node")
	}
	r, err := credRotation(store.Rotation{Period: *credPeriod, Lead: *credLead, Grace: *credGrace}, log)
	if err != nil {
		return err
	}
	if err := startCredentialRotation(ctx, st, r, func() { srv.Notify() }, hb, log); err != nil {
		return err
	}
	// The relays' names clients may be given (relay-names-v1 §4, §5),
	// checked again as soon as the DNS sync changed records; without a DNS
	// provider, those the sites' certificates take (§6).
	relayNames := newRelayNameCheck(st, net.DefaultResolver.LookupNetIP)
	relayNames.acmeForward = srv.RelayACMEForward
	srv.RelayNameStatus = relayNames.Status
	var cm *certs.Manager
	var is *certs.Issuer
	if *acmeDir != "" {
		if cm, is, err = startCertificates(ctx, st, srv, *acmeDir, siteKeys, relayNames, hb, log); err != nil {
			log.Error("certificates not managed", "err", err)
		}
	}
	if cm != nil {
		relayNames.ordering, relayNames.resolved = true, cm.Wake
	}
	go rotateReality(ctx, st, epoch, is, cm, rotateNow, func() { srv.Notify() }, paths.FrontConfig(), hb, log)
	go relayNames.run(ctx, srv.Changes, log)
	go syncDNS(ctx, st, srv.Changes, relayNames.Wake, hb, log)
	go checkRealityTargets(ctx, st, srv.Changes, hb, log)
	if *dnsCheck > 0 {
		go checkDNSZones(ctx, srv.DNSCheck, st, srv.Changes, *dnsCheck, hb, log)
	}
	if *updateCheck > 0 {
		if release.IsRelease(version) {
			// GitHub only: a mirror would learn the node's address too,
			// for a question the operator can ask by hand.
			f := &release.Fetcher{Log: fetchLog(log)}
			latest := func(ctx context.Context) (string, error) {
				v, err := f.Latest(ctx, release.PubKey)
				if err == nil {
					latestSeen.Store(v)
				}
				return v, err
			}
			patch := func(ctx context.Context, latest string) (string, error) {
				v, err := f.NewestPatch(ctx, release.PubKey, version, latest)
				patchSeen.Store(v)
				return v, err
			}
			go checkUpdates(ctx, latest, patch, version, *updateCheck, hb, log)
		} else {
			log.Info("no update check: this build is no release", "version", version)
		}
	}
	// The auto update of patch releases, once root turns it on (rayctl
	// update auto patch); a root unit runs what it asks for, which a node
	// without systemd does not have.
	if !*supervise {
		f := &release.Fetcher{Log: fetchLog(log)}
		latest := func(ctx context.Context) (string, error) { return f.Latest(ctx, release.PubKey) }
		patch := func(ctx context.Context, latest string) (string, error) {
			return f.NewestPatch(ctx, release.PubKey, version, latest)
		}
		a := &autoUpdater{st: st, running: version, latest: latest, patch: patch, seen: &latestSeen, seenPatch: &patchSeen, request: nodeupdate.RequestFile,
			status: nodeupdate.StatusFile, policy: nodeupdate.PolicyFile, now: nodeupdate.LocalNow, tick: 10 * time.Minute, hb: hb, log: log}
		go a.run(ctx)
	}
	frontUID := render.FrontUID
	if *supervise {
		frontUID = os.Getuid() // the front is a child of rayd's
	}
	go checkPort53(ctx, st, &deploy.Host{}, frontUID, hb, log)
	// The DNS path's events (dnstt's counters, an hour of them).
	go watchDNSTT(ctx, st, paths, hb)
	// The traffic loop writes its last poll as rayd stops: before the
	// database closes, and before the supervised processes stop (their
	// context ends in a deferred call made earlier, which runs after this
	// one). The Xray API's connections close after the last round.
	defer xrayapi.Close()
	trafficDone := make(chan struct{})
	go func() { acct.Run(ctx); close(trafficDone) }()
	defer func() { stop(); <-trafficDone }()
	go checkResolver(ctx, hb, log)
	go followDebug(ctx, st, level, *debug, srv.Changes, srv.Notify, log)
	go serveDoH(ctx, st, paths, srv.Changes, srv.AfterChange, log)
	// Client summaries (R4-21): reports in, from devices and through relays
	// (relay-v1 §9.3), hints out; only while the administrator has them on
	// (rayctl summary on). One collector: a device's network counts once a
	// day whichever way its report came.
	sum := &summary.Collector{Store: st, ASN: summary.Sources(st, &asn.DB{Path: summary.OperatorDB}, &asn.DB{Path: summary.ReleaseDB})}
	go pruneSummary(ctx, sum, log)
	remote := &api.Remote{Server: srv, Log: log, Perimeter: per, RelayReport: sum.TakeVia}
	go serveRemote(ctx, remote, srv.Changes)
	if err := startSubscription(ctx, st, paths, log, sum, remote.RelayProbeUp, remote.RelaySPA, srv.SPAVersions, relayNames.Ready, *probeDaily, *spaTCP, srv.AppMirror, srv.Notify, srv.SubRequests); err != nil {
		log.Error("subscription endpoint not started", "err", err)
	}
	log.Info("serving", "socket", *socket, "node", fmt.Sprintf("%x", params.NodeID))
	return srv.ServeUnix(ctx, *socket, policy, per.Handler)
}

// supervisor runs the data plane without systemd (-supervise): the plan
// rayctl apply would install, as child processes.
func supervisor(paths render.Paths, bins deploy.Binaries, st *store.Store, log *slog.Logger) (*live.Supervisor, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	bins.Rayd = self
	for _, b := range []string{bins.Xray, bins.NikoServer, bins.Slipstream} {
		if _, err := os.Stat(b); err != nil {
			log.Warn("supervise: binary missing; its services will not start", "err", err)
		}
	}
	return &live.Supervisor{Log: log, Plan: func(ctx context.Context) (deploy.Plan, error) {
		m, err := render.CollectForRender(ctx, st)
		if err != nil {
			return deploy.Plan{}, err
		}
		files, _, err := render.Render(m, paths)
		if err != nil && !render.Partial(err) {
			return deploy.Plan{}, err
		}
		// The applier reports the broken services; the rest runs (Q-1).
		return deploy.Build(deploy.InputsOf(m, files, paths), paths, bins), nil
	}}, nil
}

// startCertificates issues and renews the sites' certificates through ACME
// HTTP-01, opening the perimeter window for each order (R2-11). A site
// keeps its key from one certificate to the next and changes it by keys or
// when root asks (spec/cert-pin-v1.md §4, §5).
func startCertificates(ctx context.Context, st *store.Store, srv *api.Server, directory string, keys provision.SiteKeyPolicy,
	relayNames *relayNameCheck, hb *health.Board, log *slog.Logger) (*certs.Manager, *certs.Issuer, error) {
	key, err := certs.AccountKey(ctx, st)
	if err != nil {
		return nil, nil, err
	}
	host, err := node.Host(ctx, st)
	if err != nil {
		return nil, nil, err
	}
	port, err := provision.ACMEPort(ctx, st)
	if err != nil {
		return nil, nil, err
	}
	is := &certs.Issuer{Directory: directory, AccountKey: key, Window: srv.SetACMEWindow, NodeHost: host, Log: log,
		Listen: ":" + strconv.Itoa(int(port)), RelayAddrs: relayAddrs(st)}
	// With Cloudflare: DNS-01 and one wildcard certificate, no window on
	// TCP 80 (R4-10).
	is.DNS = func(ctx context.Context) (certs.DNSSolver, error) {
		c, zone, err := provision.Cloudflare(ctx, st)
		if err != nil || c == nil {
			return nil, err
		}
		return &cloudflare.Solver{Client: c, Zone: zone}, nil
	}
	m := &certs.Manager{Store: st, Issue: is.Issue, Keys: keys, Notify: srv.Notify, Log: log,
		// No pins from a node that may still roll its update back, and no
		// certificate the site process would refuse to load.
		NextKeyFrom: time.Now().Add(pinSettle),
		Check:       func(chainPEM, keyPEM []byte) error { _, err := siteCertificate(chainPEM, keyPEM); return err },
		Report:      func(site string, err error) { hb.Done("acme "+site, err) },
		Wildcard: func(ctx context.Context) string {
			if c, _, err := provision.Cloudflare(ctx, st); err != nil || c == nil {
				return ""
			}
			d, _ := provision.Domain(ctx, st)
			return d
		},
		// Without a DNS provider, the relays' names that resolve to their
		// relay, through relays that forward TCP 80 (relay-names-v1 §6).
		// The relays' feeds come back within relayFeedsBack of a start:
		// until then a certificate with their names is not renewed
		// without them.
		RelayNames: relayNames.RelayNamesFor, RelayReport: relayNames.Ordered, RelayHoldUntil: processStart.Add(relayFeedsBack)}
	// The operator's DNS change may be the fix of a failure: try now.
	srv.DNSChanged = m.Retry
	srv.SiteKeyAsked = m.RetrySite
	// A site's switch to its next key is an order of this manager's.
	srv.Certificates = true
	go m.Run(ctx)
	// A new site (rayctl service add reality) gets its certificate now, not
	// at the next hourly check; failures keep their back-off.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-srv.Changes():
				m.Wake()
			}
		}
	}()
	return m, is, nil
}

// relayAddrs gives the relays' names and their relays' addresses
// (certs.Issuer.RelayAddrs): those names resolve to the relay, not the
// node, and their challenges come through it (relay-names-v1 §6).
func relayAddrs(st *store.Store) func(ctx context.Context) (map[string]netip.Addr, error) {
	return func(ctx context.Context) (map[string]netip.Addr, error) {
		names, err := provision.RelayNames(ctx, st)
		if err != nil {
			return nil, err
		}
		out := make(map[string]netip.Addr, len(names))
		for _, rn := range names {
			out[rn.Name] = rn.Address
		}
		return out, nil
	}
}

// dohListener is a running DoH endpoint and the certificate it serves.
type dohListener struct {
	srv  *http.Server
	h3   context.CancelFunc // DoH3
	cert [32]byte
	// certs is what its handshakes answer with, TCP and QUIC.
	certs *certfile.Holder
	// h answers the queries; it forgets its tokens at every change.
	h *doh.Handler
	// mode is the site's answer that answer gives strangers (dohAnswer).
	mode   string
	answer *swapHandler
}

// swapHandler serves with the handler it was last given.
type swapHandler struct{ h atomic.Pointer[http.Handler] }

func (s *swapHandler) set(h http.Handler) { s.h.Store(&h) }

func (s *swapHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	(*s.h.Load()).ServeHTTP(w, r)
}

// dohAnswer is what DoH answers whoever has no token, from its site's
// settings: the site's answer, as naive has it (internal/deploy), but an
// empty 404 for a site of pages, whose files are the site's own. Without
// it a site that answered 403 or nothing had a DoH name beside it that
// answered 404: told from the site, and from naive, without a token.
func dohAnswer(siteSettings string) (string, http.Handler) {
	var st struct {
		Answer string `json:"answer"`
	}
	_ = json.Unmarshal([]byte(siteSettings), &st)
	mode := st.Answer
	if mode == "" || mode == site.AnswerPages {
		mode = site.Answer404
	}
	h, err := site.Responder(mode, "")
	if err != nil {
		mode = site.Answer404
		h, _ = site.Responder(mode, "")
	}
	return mode, h
}

// serveDoH keeps rayd's TLS listener on the socket of every enabled DoH
// service whose site has a certificate (R3-2); the front passes the
// connections for the DoH name to it (R2-15). A new certificate (a
// renewal, the site's next key) goes to the listener as it runs: new
// handshakes get it, the connections that are open go on
// (spec/cert-pin-v1.md §6). One that does not parse leaves the one in use.
//
// A change may have taken tokens away (a revoked device's, R4-37): each
// handler forgets its tokens in the call that made the change (afterChange,
// api.Server.AfterChange), so that when the API has answered no query with
// a token is answered from those of before (doh.Handler.Forget). The
// listeners follow the changes in the background, as the data plane does.
func serveDoH(ctx context.Context, st *store.Store, p render.Paths, changes func() <-chan struct{},
	afterChange func(func()), log *slog.Logger) {
	forgets := &dohForgets{}
	afterChange(forgets.forget)
	// A user's first secret is made after the change that added them woke
	// the handlers: they load again once it is (store.OnNewCredentials).
	st.OnNewCredentials(forgets.forget)
	running := map[string]*dohListener{}
	stop := func(name string) {
		if l := running[name]; l != nil {
			_ = l.srv.Close()
			l.h3()
			forgets.remove(l.h)
			delete(running, name)
		}
	}
	defer func() {
		for name := range running {
			stop(name)
		}
	}()
	for {
		wake := changes()
		services, err := st.ListServices(ctx)
		if err != nil {
			log.Error("doh", "err", err)
		}
		want := map[string]bool{}
		for _, svc := range services {
			if svc.Kind != "doh" || !svc.Enabled {
				continue
			}
			site, err := st.ServiceByName(ctx, provision.SiteOf(svc))
			if err != nil {
				continue
			}
			secrets, err := st.ServiceSecrets(ctx, site.ID)
			if err != nil || len(secrets[provision.SecretTLSChain]) == 0 {
				continue
			}
			want[svc.Name] = true
			sum := sha256.Sum256(append(slices.Clone(secrets[provision.SecretTLSChain]), secrets[provision.SecretTLSKey]...))
			mode, answer := dohAnswer(site.Settings)
			l := running[svc.Name]
			if l != nil && l.mode != mode {
				// The connections that are open take it at their next request.
				l.answer.set(answer)
				l.mode = mode
				log.Info("doh answer changed", "service", svc.Name, "answer", mode)
			}
			if l != nil && l.cert == sum {
				continue
			}
			keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: secrets[provision.SecretTLSKey]})
			cert, err := tls.X509KeyPair(secrets[provision.SecretTLSChain], keyPEM)
			if err != nil {
				log.Error("doh certificate", "service", svc.Name, "err", err)
				continue
			}
			if l != nil {
				l.certs.Set(cert)
				l.cert = sum
				log.Info("doh certificate reloaded", "service", svc.Name)
				continue
			}
			certs := &certfile.Holder{}
			certs.Set(cert)
			// The front passes the sockets of the DoH name here (R2-15).
			ln, err := nikoipc.ListenFD(p.DoHSocket(svc.Name), p.PeerUID(render.FrontUID), log)
			if err != nil {
				log.Error("doh socket", "service", svc.Name, "err", err)
				continue
			}
			id := svc.ID
			sw := &swapHandler{}
			sw.set(answer)
			h := dohHandler(st, id, sw, log.With("service", svc.Name))
			forgets.add(h) // before it answers a query
			srv := dohHTTPServer(h, certs.GetCertificate, log)
			go func() { _ = srv.ServeTLS(ln, "", "") }()
			// DoH3: the same handler over QUIC, datagrams from the front (R3-5).
			h3ctx, h3stop := context.WithCancel(ctx)
			if pc, err := nikoipc.ListenPacket(p.DoH3Socket(svc.Name), p.PeerUID(render.FrontUID), log); err != nil {
				log.Error("doh3 socket", "service", svc.Name, "err", err)
			} else {
				// The service's key of stateless resets, as naive-quic has
				// its own (provision.EnsureQUICResetKey): after rayd starts
				// anew a DoH3 client learns at its next packet that its
				// connection is gone. Without the key the service serves
				// as it did before it had one; why is said, the key never.
				var o quicOptions
				if own, err := st.ServiceSecrets(ctx, svc.ID); err != nil {
					log.Warn("doh3: no key of stateless resets; serving without them", "service", svc.Name, "err", err)
				} else if key, err := provision.EnsureQUICResetKey(ctx, st, svc, own); err != nil || len(key) != len(quic.StatelessResetKey{}) {
					log.Warn("doh3: no key of stateless resets; serving without them", "service", svc.Name, "err", err)
				} else {
					o.resetKey = (*quic.StatelessResetKey)(key)
				}
				// The service's label and its key, from the node's secret,
				// as the front has them (spec/quic-cid-route-v1.md); without
				// them, random IDs. rayd takes the secret at the service's
				// start: a database restored with another one restarts rayd.
				label := render.CIDLabel(svc.ID)
				if secret, err := st.QUICCIDKey(ctx); err != nil {
					log.Warn("doh3: connection IDs without a label", "service", svc.Name, "err", err)
				} else if key, err := cidkey.LabelKey(secret, label); err != nil {
					log.Warn("doh3: connection IDs without a label", "service", svc.Name, "err", err)
				} else if o.connIDs, err = connIDs(key, label); err != nil {
					log.Warn("doh3: connection IDs without a label", "service", svc.Name, "err", err)
				}
				go func() {
					if err := serveHTTP3(h3ctx, pc, certs.GetCertificate, h, o); err != nil {
						log.Error("doh3", "service", svc.Name, "err", err)
					}
				}()
			}
			running[svc.Name] = &dohListener{srv: srv, h3: h3stop, cert: sum, certs: certs, h: h, mode: mode, answer: sw}
			log.Info("doh serving", "service", svc.Name)
		}
		for name := range running {
			if !want[name] {
				stop(name)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-time.After(10 * time.Minute):
		}
	}
}

// dohForgets are the handlers serveDoH runs, for the change hook to make
// each forget its tokens.
type dohForgets struct {
	mu sync.Mutex
	hs map[*doh.Handler]bool
}

func (f *dohForgets) add(h *doh.Handler) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hs == nil {
		f.hs = map[*doh.Handler]bool{}
	}
	f.hs[h] = true
}

func (f *dohForgets) remove(h *doh.Handler) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.hs, h)
}

// forget is the change hook: Forget does not block.
func (f *dohForgets) forget() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for h := range f.hs {
		h.Forget()
	}
}

// serveRemote keeps the remote API (R3-3) on the port of the enabled api
// service; a new port or certificate restarts it.
func serveRemote(ctx context.Context, r *api.Remote, changes func() <-chan struct{}) {
	st, log := r.Server.Store, r.Log
	var stop func()
	var running [32]byte
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	for {
		wake := changes()
		var want [32]byte
		var cfg *tls.Config
		var addr string
		services, err := st.ListServices(ctx)
		if err != nil {
			log.Error("remote api", "err", err)
		}
		for _, svc := range services {
			if svc.Kind != "api" || !svc.Enabled {
				continue
			}
			ports, err := svc.Ports()
			secrets, serr := st.ServiceSecrets(ctx, svc.ID)
			if err != nil || serr != nil || len(ports) == 0 {
				log.Error("remote api", "service", svc.Name, "err", errors.Join(err, serr))
				break
			}
			if cfg, err = api.RemoteTLSConfig(secrets[provision.SecretTLSCert], secrets[provision.SecretTLSKey]); err != nil {
				log.Error("remote api", "service", svc.Name, "err", err)
				break
			}
			addr = ":" + strconv.Itoa(int(ports[0].Num))
			want = sha256.Sum256(append([]byte(addr), secrets[provision.SecretTLSCert]...))
		}
		if want != running {
			if stop != nil {
				stop()
				stop = nil
			}
			running = [32]byte{}
			if cfg != nil {
				ln, err := net.Listen("tcp", addr)
				if err != nil {
					log.Error("remote api", "addr", addr, "err", err)
				} else {
					sctx, cancel := context.WithCancel(ctx)
					stop = cancel
					go func() {
						if err := r.Serve(sctx, ln, cfg); err != nil {
							log.Error("remote api", "err", err)
						}
					}()
					running = want
					log.Info("remote api", "addr", addr)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-time.After(10 * time.Minute):
		}
	}
}

// dohHandler is the handler of a DoH service: the tokens are those of
// the devices not revoked of active users (store.User.Active: over the
// traffic limit is out too) with access to the service, with their
// rotation (R4-1, R4-37: store.DoHTokens), and strangers get answer.
func dohHandler(st *store.Store, service int64, answer http.Handler, log *slog.Logger) *doh.Handler {
	return &doh.Handler{Tokens: func(ctx context.Context) (map[string]bool, error) {
		return st.DoHTokens(ctx, service, time.Now())
	}, Answer: answer, Log: log,
		// The upstreams through the node's roots: the queries are the users',
		// a root planted in the image's store must not read them.
		HTTP: roots.Node.Client(5 * time.Second)}
}

// syncDNS keeps the node's records in its DNS provider's zone: when the
// records it needs change (a DNS tunnel added or removed) and every hour
// against drift (R4-10). synced is called after a sync that changed some.
func syncDNS(ctx context.Context, st *store.Store, changes func() <-chan struct{}, synced func(), hb *health.Board, log *slog.Logger) {
	last := ""
	next := time.Time{}
	for {
		wake := changes()
		records, _, err := provision.DNSRecords(ctx, st)
		key := fmt.Sprint(records)
		if c, _, perr := provision.Cloudflare(ctx, st); err == nil && perr == nil && c != nil && (key != last || time.Now().After(next)) {
			done, problems, err := provision.SyncDNS(ctx, st)
			if err == nil && len(problems) > 0 {
				hb.Done("dns", fmt.Errorf("%d records not as they should be: %s", len(problems), strings.Join(problems, "; ")))
			} else {
				hb.Done("dns", err)
			}
			switch {
			case err != nil:
				log.Warn("DNS records not synced", "err", err)
			default:
				last, next = key, time.Now().Add(time.Hour)
				if len(done) > 0 {
					log.Info("DNS records synced", "changes", len(done))
					synced()
				}
				for _, p := range problems {
					log.Warn("DNS record", "problem", p)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-time.After(10 * time.Minute):
		}
	}
}

// rotateReality advances the REALITY key rotation (R4-7) and naive's
// server names (R4-42) every minute, in one round, so the switch lands
// within a minute of the time clients have, and at once on an operator
// request. A new server name needs a certificate first: the manager is
// woken for it. Without certificate management REALITY's names stay, and
// naive's move only under a certificate that covers them already.
func rotateReality(ctx context.Context, st *store.Store, e provision.RealityEpoch, is *certs.Issuer, cm *certs.Manager,
	now <-chan struct{}, notify func(), frontConfig string, hb *health.Board, log *slog.Logger) {
	var resolves func(context.Context, string) error
	if is != nil && cm != nil {
		resolves = func(ctx context.Context, name string) error { return is.CheckDNS(ctx, []string{name}) }
	}
	for {
		n, err := provision.RotateReality(ctx, st, time.Now(), e, resolves, log)
		hb.Done("reality-rotation", err)
		if err != nil {
			log.Error("REALITY rotation", "err", err)
		}
		if n > 0 { // the services that rotated, with or without another's error
			notify()
			if cm != nil {
				cm.Wake()
			}
		}
		// A published naive name the front does not serve (docs/research/naive-sni-rotation.md §8.4).
		if naive, err := naiveServed(ctx, st, frontConfig); naive || err != nil {
			hb.Done(naiveNamesLoop, err)
		}
		// The previous seal keys of dnstt services past their grace
		// (spec/dnsseal-v1.md §8): the key files lose them.
		if n, err := provision.ExpireSealKeys(ctx, st, time.Now(), log); err != nil {
			log.Error("seal keys", "err", err)
		} else if n > 0 {
			notify()
		}
		select {
		case <-ctx.Done():
			return
		case <-now:
		case <-time.After(time.Minute):
		}
	}
}

// startSubscription serves the subscription endpoint on the port of the
// subscription service, if it is enabled. changed wakes apply: a device's
// LAN consent changed (lan-v1 §1.1).
func startSubscription(ctx context.Context, st *store.Store, paths render.Paths, log *slog.Logger, sum *summary.Collector, relayProbe func(string) bool, relaySPA func(string) []int, spaVersions func(context.Context) []int, relayNameReady func(string) bool, probeDailyMiB int, tcpCarrier bool, app *appmirror.Mirror, changed func(), requests *sub.Requests) error {
	svc, err := st.ServiceByName(ctx, provision.SubscriptionService)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !svc.Enabled) {
		log.Info("subscription service disabled")
		return nil
	}
	if err != nil {
		return err
	}
	ports, err := svc.Ports()
	if err != nil || len(ports) == 0 {
		return fmt.Errorf("subscription service has no port: %w", err)
	}
	secrets, err := st.ServiceSecrets(ctx, svc.ID)
	if err != nil {
		return err
	}
	tlsCfg, err := sub.TLSConfig(secrets[provision.SecretTLSCert], secrets[provision.SecretTLSKey])
	if err != nil {
		return err
	}
	keys, err := provision.LoadNodeKeys(ctx, st)
	if err != nil {
		return err
	}
	s := &sub.Server{Store: st, Keys: keys, Log: log, TCPCarrier: tcpCarrier, RelayProbe: relayProbe, RelaySPA: relaySPA, SPAVersions: spaVersions,
		ClockSeqAfter: time.Now().Add(settleAfterStart), PinsSince: processStart, PinsAfter: time.Now().Add(pinSettle), App: app, Changed: changed,
		Requests: requests, RelayNameReady: relayNameReady}
	port := int(ports[0].Num)
	addr := ":" + strconv.Itoa(port)
	// Channel probes (R4-16) on the same endpoint, and their UDP echo on
	// the same port number, which SPA opens with the TCP one.
	s.Probe = &probe.Server{Auth: s.Device, Daily: int64(probeDailyMiB) << 20, Log: log,
		// The session stats of the Hysteria2 backends, for link (R4-16).
		Hysteria: func() map[string]string {
			out := map[string]string{}
			services, err := st.ListServices(ctx)
			if err != nil {
				return out
			}
			for _, svc := range services {
				if svc.Enabled && render.IsHysteria(svc.Kind) {
					out[strconv.FormatInt(svc.ID, 10)] = paths.StatsSocket(svc.Name)
				}
			}
			return out
		},
		// The device's user's base name, u<id>: niko-server lists the
		// sessions of every name under it, u<id>-*, the user's credentials
		// in the Hysteria2 users file, one by one (niko-server v0.7).
		Account: func(ctx context.Context, device string) (string, error) {
			d, _, err := st.ActiveDevice(ctx, device)
			if err != nil {
				return "", err
			}
			u, err := st.UserByName(ctx, d.UserName)
			if err != nil {
				return "", err
			}
			return render.InnerEmail(u.ID), nil
		}}
	s.Probe.Report = sum.Take
	s.Probe.Relayed = s.FromRelay
	s.Hints = sum.Hints
	if err := provision.SubscriptionUDP(ctx, st); err != nil {
		log.Warn("probe: the subscription service has no UDP port", "err", err)
	} else if pc, err := net.ListenPacket("udp", addr); err != nil {
		log.Warn("probe: no UDP echo", "err", err)
	} else {
		s.Probe.UDPPort = port
		go func() {
			<-ctx.Done()
			_ = pc.Close()
		}()
		go func() { _ = s.Probe.ServeUDP(pc) }()
	}
	go func() {
		if err := s.Serve(ctx, addr, tlsCfg); err != nil {
			log.Error("subscription endpoint", "err", err)
		}
	}()
	log.Info("subscription endpoint", "addr", addr, "probe_udp", s.Probe.UDPPort != 0)
	return nil
}

// checkPort53 looks every few minutes for sockets on UDP 53 besides the
// front's and systemd-resolved's stub while the node has DNS tunnels: the
// front shares the port with SO_REUSEADDR, so a DNS server that binds it
// the same way takes the queries to its address without a sound (rayctl
// status shows it).
func checkPort53(ctx context.Context, st *store.Store, h *deploy.Host, frontUID int, hb *health.Board, log *slog.Logger) {
	for {
		services, err := st.ListServices(ctx)
		tunnels := err == nil && slices.ContainsFunc(services, func(s store.Service) bool {
			return s.Enabled && provision.DNSTunnel(s.Kind)
		})
		if tunnels {
			var others []string
			for _, o := range h.OthersOn53(frontUID) {
				others = append(others, o.Addr+" ("+o.Owner+")")
			}
			if len(others) > 0 {
				err = fmt.Errorf("UDP 53 is held beside the front by %s: the DNS tunnels' queries there do not reach it", strings.Join(others, ", "))
				log.Warn("port 53", "err", err)
			}
			hb.Done("port53", err)
		} else {
			hb.Retain("port53", nil) // no tunnels, nothing to say
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Minute):
		}
	}
}

// followDebug keeps rayd's level on the debug window (rayctl debug), and
// renders the data plane again when the window ends by itself: its level
// follows the window, as rayspa's does through its snapshot.
func followDebug(ctx context.Context, st *store.Store, level *slog.LevelVar, always bool, changes func() <-chan struct{}, notify func(), log *slog.Logger) {
	open := false
	for {
		// The channel before the store: a change between the two wakes
		// the loop instead of going unseen.
		wake := changes()
		now, until := time.Now(), st.DebugUntil(ctx)
		on := now.Before(until)
		switch {
		case on && !open:
			log.Warn("debug window open: client addresses go to the journal", "until", until.UTC().Format(time.RFC3339))
		case !on && open:
			log.Info("debug window closed")
			notify()
		}
		open = on
		if on || always {
			level.Set(slog.LevelDebug)
		} else {
			level.Set(slog.LevelInfo)
		}
		wait := time.Hour
		if on {
			wait = until.Sub(now)
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-time.After(wait):
		}
	}
}

// checkResolver looks every few minutes whether rayd can resolve names
// with the host's resolv.conf (rayctl status: resolver): unreadable to it
// or without a server, every lookup goes to localhost, and certificates
// and DNS records fail with "lookup … on [::1]:53".
func checkResolver(ctx context.Context, hb *health.Board, log *slog.Logger) {
	last := ""
	for {
		p := deploy.ResolverProblem("")
		var err error
		if p != "" {
			err = errors.New(p)
			if p != last {
				log.Warn("resolver", "err", err)
			}
		}
		last = p
		hb.Done("resolver", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Minute):
		}
	}
}

// pruneSummary drops the summary counters past their 30 days, daily.
func pruneSummary(ctx context.Context, c *summary.Collector, log *slog.Logger) {
	for {
		if n, err := c.Prune(ctx); err != nil {
			log.Warn("summary: prune", "err", err)
		} else if n > 0 {
			log.Info("summary: old counters dropped", "rows", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(6 * time.Hour):
		}
	}
}

// rotateCredentials advances the rotation of user credentials every ten
// minutes (R4-1); a change re-renders, which adds and removes UUIDs through
// the Xray API without a restart.
// checkRealityTargets checks what a REALITY service with a foreign target
// needs from it (TLS 1.3, X25519MLKEM768, a chain longer than REALITY's
// ML-DSA-65 certificate): a new or changed target at once, all of them every
// 6 hours, since a site that moves to a short chain breaks REALITY. The loop
// "reality-target <service>" in rayctl status says so (RAYCONTROL.md
// §22.2.1). On every change it also forgets the health of deleted services
// and sites.
func checkRealityTargets(ctx context.Context, st *store.Store, changes func() <-chan struct{}, hb *health.Board, log *slog.Logger) {
	checked := map[string]string{} // service: the target and name last checked
	all := time.Now()
	for {
		wake := changes()
		full := !time.Now().Before(all)
		if full {
			all = time.Now().Add(6 * time.Hour)
		}
		services, err := st.ListServices(ctx)
		if err == nil {
			var targets, sites []string
			for _, svc := range services {
				if svc.Kind == "site" {
					sites = append(sites, svc.Name)
				}
				if svc.Kind != "reality" || !svc.Enabled {
					continue
				}
				target, sni, err := provision.RealityTargetFromJSON(svc.Settings)
				if err != nil || target == "" || strings.HasPrefix(target, "/") || strings.HasPrefix(target, "site:") {
					continue // self-steal: the node's own site, checked when its certificate loads
				}
				targets = append(targets, svc.Name)
				if !full && checked[svc.Name] == target+" "+sni {
					continue
				}
				cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
				// A target the data plane does not reach says what fixes it
				// (rayctl status shows the loop).
				err = provision.ForService(svc.Name, provision.CheckRealityTarget(cctx, target, sni))
				cancel()
				if ctx.Err() != nil {
					return
				}
				checked[svc.Name] = target + " " + sni
				hb.Done("reality-target "+svc.Name, err)
				if err != nil {
					log.Warn("REALITY target no longer fits", "service", svc.Name, "err", err)
				}
			}
			hb.Retain("reality-target ", targets)
			hb.Retain("acme ", sites)
			for name := range checked {
				if !slices.Contains(targets, name) {
					delete(checked, name)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-time.After(time.Until(all)):
		}
	}
}

// dnsZoneLoop names a zone's loop in rayctl status after "dns-zone ": the
// main zone by its service, as before; a spare one by its service and
// itself (spec/dnszones-v1.md).
func dnsZoneLoop(z dnscheck.Zone) string {
	if z.Spare {
		return z.Service + " " + z.Name
	}
	return z.Service
}

// dnsMonitor checks the node's DNS tunnel zones (internal/dnscheck): every
// full check with rayd's resolvers goes to the health board, a loop per
// zone ("dns-zone <service>" in rayctl status), and a zone's failure to
// the log when it changes. The checks send queries to the parent's servers
// and to public resolvers from the node's address: no key, nothing about
// users (docs/design/observability.md).
func dnsMonitor(ctx context.Context, st *store.Store, resolvers []dnscheck.Resolver, hb *health.Board, log *slog.Logger) *dnscheck.Monitor {
	var mu sync.Mutex
	logged := map[string]string{} // service: the failure last logged
	return &dnscheck.Monitor{Checker: &dnscheck.Checker{}, Resolvers: resolvers, Base: ctx,
		Targets: func(ctx context.Context) ([]dnscheck.Zone, error) { return provision.DNSCheckTargets(ctx, st) },
		Done: func(rep dnscheck.Report) {
			mu.Lock()
			defer mu.Unlock()
			var services []string
			for _, z := range rep.Zones {
				svc := z.Zone.Service
				loop := dnsZoneLoop(z.Zone)
				services = append(services, loop)
				err := z.Err()
				hb.Report("dns-zone "+loop, z.Summary(), err)
				msg := ""
				if err != nil {
					msg = err.Error()
				}
				switch {
				case msg == logged[loop]:
				case err != nil:
					log.Warn("DNS zone check failed", "service", svc, "zone", z.Zone.Name, "err", err)
				default:
					log.Info("DNS zone check passes again", "service", svc, "zone", z.Zone.Name)
				}
				logged[loop] = msg
			}
			hb.Retain("dns-zone ", services)
		}}
}

// Pace of the DNS zone check after a change of zones or of the node's
// address: the parent from 30 s on (the front takes a new zone first),
// every 30 s for up to 10 minutes. Variables for the tests.
var (
	dnsParentEvery = 30 * time.Second
	dnsParentFor   = 10 * time.Minute
)

// checkDNSZones checks the DNS tunnel zones from the node every period,
// ±10 % (internal/dnscheck; rayctl status: dns-zone <service>). After a
// change of the zones or of the node's address it asks only the parent
// until it delegates them, and the resolvers then: a resolver asked before
// the delegation keeps the zone's absence in its cache, and clients with
// it. On every change it also forgets the loops of zones that went.
func checkDNSZones(ctx context.Context, mon *dnscheck.Monitor, st *store.Store, changes func() <-chan struct{}, period time.Duration,
	hb *health.Board, log *slog.Logger) {
	defer mon.SetNext(time.Time{})
	var key string
	var changed, next time.Time
	waiting := false
	for {
		wake := changes()
		zones, err := provision.DNSCheckTargets(ctx, st)
		now := time.Now()
		var retry time.Time // a read again sooner than next, after an error
		if err == nil {
			services := make([]string, 0, len(zones))
			for _, z := range zones {
				services = append(services, dnsZoneLoop(z))
			}
			hb.Retain("dns-zone ", services)
		}
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			log.Warn("DNS zone check: the zones not read", "err", err)
			// Read again in dnsParentEvery: a change that woke the loop
			// is not left to the plan, an hour away (review 10). Never
			// sooner, or a database that keeps failing spins the loop
			// (review 8); the plan itself stays (review 9).
			if !next.After(now) {
				next = now.Add(dnsParentEvery)
			}
			retry = now.Add(dnsParentEvery)
		case len(zones) == 0:
			key, next, waiting = "", time.Time{}, false
		case dnsZonesKey(zones) != key:
			key, changed, next, waiting = dnsZonesKey(zones), now, now.Add(dnsParentEvery), true
		case now.Before(next):
		case waiting && now.Sub(changed) < dnsParentFor:
			rep, err := mon.Run(ctx, dnscheck.RunOptions{ParentOnly: true})
			if err == nil && !slices.ContainsFunc(rep.Zones, func(z dnscheck.ZoneResult) bool { return !z.Delegated }) {
				waiting = false
				continue // the whole check now
			}
			next = time.Now().Add(dnsParentEvery)
		default:
			waiting = false
			if _, err := mon.Run(ctx, dnscheck.RunOptions{}); err != nil && ctx.Err() == nil {
				log.Warn("DNS zone check", "err", err)
			}
			next = time.Now().Add(jitter(period, 10))
		}
		mon.SetNext(next)
		at := next
		if !retry.IsZero() && retry.Before(at) {
			at = retry
		}
		var timer <-chan time.Time
		if !at.IsZero() {
			timer = time.After(time.Until(at))
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-timer:
		}
	}
}

// checkUpdates looks for a newer release every period, ±10 % (rayd
// -update-check, off unless asked: github.com or a mirror sees the node's
// address). The loop "update" in rayctl status says what it found; a
// check that fails is said there too, never as a failure of the node, and
// a new release goes to the log once. Unless latest is a patch release of
// the running one, patch (nil: none) looks for the newest one (newestPatch:
// latest may be a backport of an older minor version).
func checkUpdates(ctx context.Context, fetch func(context.Context) (string, error), patch func(context.Context, string) (string, error),
	running string, period time.Duration, hb *health.Board, log *slog.Logger) {
	said := ""
	for {
		cctx, cancel := context.WithTimeout(ctx, time.Minute)
		latest, err := fetch(cctx)
		newest := ""
		if err == nil && !nodeupdate.Patch(latest, running) {
			newest, _ = newestPatch(cctx, latest, running, patch)
		}
		cancel()
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			hb.Report("update", "not checked: "+err.Error(), nil)
		case release.Newer(latest, running):
			d := latest + " is out, this node runs " + running + ": rayctl update"
			if newest != "" {
				d += " (" + newest + ", a patch release of this minor version: rayctl update -version " + newest + ")"
			}
			hb.Report("update", d, nil)
			if latest != said {
				said = latest
				log.Info("a newer release is out", "latest", latest, "running", running)
			}
		case newest != "":
			hb.Report("update", newest+" is out, a patch release of "+running+" (GitHub's latest, "+latest+", is not newer): rayctl update -version "+newest, nil)
			if newest != said {
				said = newest
				log.Info("a newer release is out", "patch", newest, "latest", latest, "running", running)
			}
		default:
			hb.Report("update", "up to date ("+running+")", nil)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter(period, 10)):
		}
	}
}

// dnsZonesKey names what the delegation depends on: the zones, the name
// they are delegated to and the node's host.
func dnsZonesKey(zones []dnscheck.Zone) string {
	keys := make([]string, 0, len(zones))
	for _, z := range zones {
		keys = append(keys, z.Service+" "+z.Kind+" "+z.Name+" "+z.NS+" "+z.Host)
	}
	slices.Sort(keys)
	return strings.Join(keys, "\n")
}

// jitter is d, give or take percent %, at random: nodes started together
// do not ask the same resolvers at the same moment.
func jitter(d time.Duration, percent int64) time.Duration {
	spread := int64(d) * percent / 100
	if spread <= 0 {
		return d
	}
	n, err := rand.Int(rand.Reader, big.NewInt(2*spread+1))
	if err != nil {
		return d
	}
	return time.Duration(int64(d) - spread + n.Int64())
}

func rotateCredentials(ctx context.Context, st *store.Store, r store.Rotation, notify func(), hb *health.Board, log *slog.Logger) {
	for {
		n, err := st.RotateCredentials(ctx, time.Now(), r, render.NewUUID)
		hb.Done("credential-rotation", err)
		if err != nil {
			log.Error("credential rotation", "err", err)
		} else if n > 0 {
			log.Info("credentials rotated", "changed", n)
			notify()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Minute):
		}
	}
}

func pruneAudit(ctx context.Context, st *store.Store, hb *health.Board, log *slog.Logger) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		aerr := st.PruneAudit(ctx, time.Now().Add(-auditKeep))
		if aerr != nil && ctx.Err() == nil {
			log.Warn("audit prune failed", "err", aerr)
		}
		// Invites used or expired a week ago: their key opens nothing anymore.
		ierr := st.PruneInvites(ctx, time.Now().Add(-7*24*time.Hour))
		if ierr != nil && ctx.Err() == nil {
			log.Warn("invite prune failed", "err", ierr)
		}
		if ctx.Err() == nil {
			hb.Done("prune", errors.Join(aerr, ierr))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// cmdSite serves the decoy site: TLS 1.3 with h2 on a unix socket, the
// self-steal target of REALITY (docs/decisions.md, R2-12).
func cmdSite(args []string) error {
	fs := flag.NewFlagSet("site", flag.ExitOnError)
	answer := fs.String("answer", site.Answer404, "what requests get: "+strings.Join(site.Answers, ", "))
	root := fs.String("root", "", "site content directory (answer pages)")
	chain := fs.String("chain", "", "certificate chain (PEM, leaf first)")
	key := fs.String("key", "", "private key (PEM)")
	socket := fs.String("socket", "", "unix socket to listen on")
	fs.Parse(args)
	if *chain == "" || *key == "" || *socket == "" {
		return errors.New("site needs -chain, -key and -socket")
	}
	handler, err := site.Responder(*answer, *root)
	if err != nil {
		return err
	}
	log := logx.New(os.Stderr, slog.LevelInfo)
	certs, err := loadCertificate(*chain, *key, siteCertificate, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go certs.Watch(ctx)
	_ = os.Remove(*socket)
	ln, err := net.Listen("unix", *socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(*socket, 0o660); err != nil { //nolint:gosec // G302: the REALITY process connects through the group
		return err
	}
	log.Info("serving the site", "socket", *socket, "chain", len(certs.Current().Certificate), "answer", *answer)
	return site.ServeCertificates(ctx, ln, handler, certs.GetCertificate, log)
}

// cmdNaive serves NaiveProxy (R2-14): the site's TLS, tunnels over
// X25519MLKEM768 only, and HTTP/2 on the connections the front passes for
// the service's name (R2-15).
func cmdNaive(args []string) error {
	fs := flag.NewFlagSet("naive", flag.ExitOnError)
	answer := fs.String("answer", site.Answer404, "what other requests get: 404, 403 or silent")
	users := fs.String("users", "", "JSON object of the passwords' SHA-256 hashes and the names their bytes count under (or a list of hashes), "+
		"read again when it changes: a password it no longer has loses its streams")
	statsSocket := fs.String("stats-socket", "", "unix socket where the line \"traffic\" gets each name's bytes (traffic-limit-v1 §2.3), for rayd")
	chain := fs.String("chain", "", "certificate chain (PEM, leaf first)")
	key := fs.String("key", "", "private key (PEM)")
	socket := fs.String("socket", "", "SOCK_SEQPACKET socket the front passes connections to (niko-server IPC, mode fd)")
	quicSocket := fs.String("quic-socket", "", "SOCK_SEQPACKET socket the front sends QUIC datagrams to (naive-quic; IPC mode packet)")
	frontUID := fs.Int("front-uid", render.FrontUID, "UID of the niko-server front, the only peer accepted")
	probeAddr := fs.String("probe", "", "where the probe name leads (the subscription endpoint on loopback, R4-16)")
	connLimit := fs.String("conn-limit", "", "file that turns the per-user connection limits off with \"off\" (spec/conn-limit-v1.md §3.1), "+
		"read again when it changes; empty or absent: on")
	icmp := fs.Bool("icmp", false, "carry ping and traceroute through "+naive.ICMPName+" (spec/icmp-v1.md): echoes from ICMP datagram sockets, "+
		"which need the process's group in net.ipv4.ping_group_range")
	resetKey := fs.String("reset-key", "", "file with the key of naive-quic's stateless resets (32 bytes, hex), the same at every start: "+
		"a client whose connection the process no longer knows is told at once; empty or absent: no stateless resets")
	udp := fs.Bool("udp", false, "carry UDP as HTTP/3 datagrams of connect-udp requests to naive-quic (spec/naive-udp-v1.md): "+
		"naive-quic announces HTTP/3 datagrams; without it a connect-udp request gets the site's answer")
	cidFile := fs.String("cid", "", "file with the label of naive-quic's connection IDs and its key, \"<label> <16 bytes in hex>\" "+
		"(spec/quic-cid-route-v1.md): the IDs carry the label, by which the front finds a client whose address changed; "+
		"empty or absent: random IDs")
	fs.Parse(args)
	if *users == "" || *chain == "" || *key == "" || *socket == "" {
		return errors.New("naive needs -users, -chain, -key and -socket")
	}
	if *answer == site.AnswerPages {
		return errors.New("naive answers 404, 403 or silent: the pages are the site's")
	}
	handler, err := site.Responder(*answer, "")
	if err != nil {
		return err
	}
	log := logx.New(os.Stderr, slog.LevelInfo)
	certs, err := loadCertificate(*chain, *key, nil, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go certs.Watch(ctx)
	ln, err := nikoipc.ListenFD(*socket, *frontUID, log)
	if err != nil {
		return err
	}
	naive.SetResolverLog(log)
	nu := &naive.Users{Path: *users}
	// The users file is watched: a user taken off it (disabled, expired,
	// over the traffic limit) loses the live streams (traffic-limit-v1 §3.2).
	go nu.Watch(ctx)
	ns := &naive.Server{Users: nu, Answer: handler, ICMP: *icmp, Log: log}
	// The refusals of the connection limits go out with the bytes, and
	// with -udp the datagram requests' counts: set before the stats socket
	// answers.
	nu.SetRefused(ns.Refused)
	quicOpts := naiveUDP(ns, *udp)
	if *statsSocket != "" {
		if err := nu.ServeStats(ctx, *statsSocket, log); err != nil {
			return err
		}
	}
	if *connLimit != "" {
		ns.SetConnLimit(true)
		go ns.WatchConnLimit(ctx, *connLimit)
	}
	// Channel probes through the tunnel (R4-16): the probe name, and only
	// it, leads to the endpoint; the rest to public addresses.
	ns.Probe = *probeAddr
	if *quicSocket != "" {
		// naive-quic (R3-5): the same server over HTTP/3.
		pc, err := nikoipc.ListenPacket(*quicSocket, *frontUID, log)
		if err != nil {
			return err
		}
		o := quicOpts
		if *resetKey != "" {
			// Without the key the service is as it was before it had
			// one: clients wait out their idle time after a restart. Why
			// it is missing is said, the file's content never.
			if o.resetKey, err = readResetKey(*resetKey); err != nil {
				log.Warn("naive-quic: no key of stateless resets; serving without them", "err", err)
			}
		}
		if *cidFile != "" {
			// Without the label and its key the IDs are random, as before:
			// a client whose address changes loses its connection. Why is
			// said, the key never.
			label, key, err := quiccid.ReadLabelled(*cidFile)
			if err == nil {
				o.connIDs, err = connIDs(key, label)
			}
			if err != nil {
				log.Warn("naive-quic: connection IDs without a label", "file", *cidFile, "err", err)
			}
		}
		go func() {
			if err := serveHTTP3(ctx, pc, certs.GetCertificate, ns, o); err != nil {
				log.Error("naive-quic", "err", err)
			}
		}()
	}
	srv := naiveHTTPServer(ns, certs.GetCertificate, log)
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	log.Info("serving naive", "socket", *socket, "answer", *answer, "icmp", *icmp, "udp", *udp && *quicSocket != "", "conn_limit", ns.ConnLimitOn())
	if err := srv.ServeTLS(ln, "", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// cmdRelay serves the probe-v1 endpoint of a relay host (relay-v1 §9.1):
// TCP (TLS) and the UDP echo on the bundle's port, the devices and their
// K_relay from the exit, reports passed on to the exit. It takes the
// exit's word on the relay's updates as well
// (spec/relay-update-remote-v1.md §3.5): a request for root on the relay,
// when root's policy allows it.
func cmdRelay(args []string) error {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	bundle := fs.String("bundle", "", "the relay's bundle (rayctl relay bundle on the exit); a file only its owner reads")
	daily := fs.Int("probe-daily", 0, "probe volume per device and UTC day, MiB (default: probe-v1's)")
	state := fs.String("state", "", "keep the devices of the exit's last snapshot here, for a start while the exit is away")
	updateRequest := fs.String("update-request", nodeupdate.RelayRequestFile,
		"ask root for an update to the release the exit names here (in this daemon's own directory; root's unit watches it)")
	updateDir := fs.String("update-dir", nodeupdate.StatusDir, "root's update directory: its policy (rayctl update remote on) and the last update's status")
	fs.Parse(args)
	if *bundle == "" || fs.NArg() != 0 || *daily < 0 {
		return errors.New("relay needs -bundle")
	}
	b, err := node.ReadRelayBundle(*bundle)
	if err != nil {
		return err
	}
	log := logx.New(os.Stderr, slog.LevelInfo)
	s, tlsCfg, err := relayprobe.New(b, int64(*daily)<<20, log)
	if err != nil {
		return err
	}
	s.State = *state
	s.Updates = relayprobe.NewUpdates(version, *updateRequest, *updateDir, log)
	if err := s.Load(); err != nil {
		log.Warn("relay probe: kept devices not read; waiting for the exit", "err", err)
	}
	addr := ":" + strconv.Itoa(int(b.Probe.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		_ = ln.Close()
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("relay probe endpoint", "relay", b.Name, "port", b.Probe.Port, "exit", b.Exit, "version", version)
	return s.Serve(ctx, ln, pc, tlsCfg)
}

// dohHTTPServer is the HTTP/2 side of a DoH service: the site's TLS
// (site.TLSConfigFor: TLS 1.2 and 1.3, Go's groups, X25519MLKEM768 first)
// and the HTTP server every name of the node's address has
// (site.HTTPServer). Before v0.36.1 it took TLS 1.3 with X25519MLKEM768
// only, and a probe without ML-KEM told the name from the site's by the
// refusal; now the handler answers a query only over X25519MLKEM768
// (doh.Handler, site.PostQuantum), anything else as the site does.
func dohHTTPServer(h http.Handler, cert func(*tls.ClientHelloInfo) (*tls.Certificate, error), log *slog.Logger) *http.Server {
	srv := site.HTTPServer(h, site.IdleTimeout)
	srv.ErrorLog = slog.NewLogLogger(log.Handler(), slog.LevelDebug)
	srv.TLSConfig = site.TLSConfigFor(cert)
	return srv
}

// naiveHTTPServer is the HTTP/2 side of a naive service: the site's TLS, as
// DoH's (dohHTTPServer), and the same HTTP server (naive.Server.HTTPServer);
// a tunnel only over X25519MLKEM768 (naive.Server, site.PostQuantum).
func naiveHTTPServer(ns *naive.Server, cert func(*tls.ClientHelloInfo) (*tls.Certificate, error), log *slog.Logger) *http.Server {
	srv := ns.HTTPServer()
	srv.ErrorLog = slog.NewLogLogger(log.Handler(), slog.LevelDebug)
	srv.TLSConfig = site.TLSConfigFor(cert)
	return srv
}

// connLimitSources are the processes that count refusals of the connection
// limits (spec/conn-limit-v1.md §2, §7), each enabled service's: naive and
// the Hysteria2 backends (niko-server v0.17.0) at their stats socket with
// the traffic line, the Xray processes (inner, REALITY) through their
// API's StatsService, with the bytes. A process too old to count, or an
// Xray whose config has no stats (the limits off, no traffic limit), fails
// its read: nothing new from it.
func connLimitSources(st *store.Store, paths render.Paths) func(ctx context.Context) ([]connlimit.Source, error) {
	of := func(r traffic.Reading, err error) (connlimit.Reading, error) {
		return connlimit.Reading{Boot: r.Boot, Age: r.Age, AgeKnown: r.AgeKnown, Limits: r.Limits}, err
	}
	return func(ctx context.Context) ([]connlimit.Source, error) {
		services, err := st.ListServices(ctx)
		if err != nil {
			return nil, err
		}
		var out []connlimit.Source
		for _, svc := range services {
			switch {
			case !svc.Enabled:
			case svc.Kind == "naive" || render.IsHysteria(svc.Kind):
				socket := paths.StatsSocket(svc.Name)
				out = append(out, connlimit.Source{Service: svc.Name, Read: func(ctx context.Context) (connlimit.Reading, error) {
					return of(traffic.ReadLine(ctx, socket))
				}})
			case render.IsXray(svc.Kind):
				socket := paths.APISocket(svc.Name)
				out = append(out, connlimit.Source{Service: svc.Name, SameRun: traffic.SameBoot,
					Read: func(ctx context.Context) (connlimit.Reading, error) {
						return of(traffic.ReadXray(ctx, socket))
					}})
			}
		}
		return out, nil
	}
}
