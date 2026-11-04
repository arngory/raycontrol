// Command rayd is the raycontrol node daemon: it owns the node state and
// serves the node API.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/arngory/raycontrol/internal/api"
	"github.com/arngory/raycontrol/internal/asn"
	"github.com/arngory/raycontrol/internal/certs"
	"github.com/arngory/raycontrol/internal/cloudflare"
	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/doh"
	"github.com/arngory/raycontrol/internal/live"
	"github.com/arngory/raycontrol/internal/naive"
	"github.com/arngory/raycontrol/internal/nikoipc"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/probe"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/site"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
	"github.com/arngory/raycontrol/internal/summary"
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
  version  print the version
`)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
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
	fs.Parse(args)

	ctx := context.Background()
	st, err := store.Open(ctx, *db)
	if err != nil {
		return err
	}
	defer st.Close()
	p, err := provision.Init(ctx, st, provision.Options{Host: *host, Domain: *domain})
	if err != nil {
		return err
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
	acmeDir := fs.String("acme-directory", certs.LetsEncrypt, "ACME directory for the sites' certificates (empty: none)")
	credPeriod := fs.Duration("cred-period", 30*24*time.Hour, "how long a user credential stays current (0: no rotation)")
	credLead := fs.Duration("cred-lead", 3*24*time.Hour, "the next credential is in the subscription this long before the switch")
	probeDaily := fs.Int("probe-daily-mib", probe.DefaultDaily>>20, "channel probes: MiB per device and UTC day, both directions")
	credGrace := fs.Duration("cred-grace", 2*24*time.Hour, "the previous credential (and REALITY key set) is accepted this long after the switch (12h at least)")
	realityPeriod := fs.Duration("reality-period", 90*24*time.Hour, "how long REALITY keys stay current; their next set is published -cred-lead ahead (0: no rotation)")
	realityPrepare := fs.Duration("reality-prepare", 24*time.Hour, "how long a new REALITY server name may wait for its certificate")
	fs.Parse(args)
	epoch := provision.RealityEpoch{Period: *realityPeriod, Lead: *credLead, Prepare: *realityPrepare, Grace: *credGrace}
	if err := epoch.Check(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

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

	go pruneAudit(ctx, st, log)
	paths := render.Paths{Rendered: *rendered, Run: *run, Supervised: *supervise}
	rotateNow := make(chan struct{}, 1)
	srv := &api.Server{Store: st, Params: params, Version: version, Paths: paths, Binaries: deploy.DefaultBinaries,
		CheckRealityTarget: provision.CheckRealityTarget, RealityLead: *credLead,
		Rotate: func() {
			select {
			case rotateNow <- struct{}{}:
			default:
			}
		}}
	per := &api.PerimeterServer{Server: srv, RayspaUID: -1, DefaultTTL: *spaTTL, MaxTTL: *spaMaxTTL, TCPCarrier: *spaTCP, Refresh: time.Minute}
	policy := api.PeerPolicy{Group: *group}
	if u, err := user.Lookup(*rayspaUser); err == nil {
		per.RayspaUID, _ = strconv.Atoi(u.Uid)
		policy.Deny = []int{per.RayspaUID}
	} else {
		log.Warn("rayspa user not found; only root receives the perimeter feed", "user", *rayspaUser)
	}

	if *supervise && !*liveApply {
		return errors.New("-supervise needs -live: the processes read the rendered files")
	}
	if *liveApply {
		applier := &live.Applier{Store: st, Paths: paths, Log: log}
		var sup *live.Supervisor
		if *supervise {
			sup, err = supervisor(paths, *xrayBin, *nikoBin, st, log)
			if err != nil {
				return err
			}
			applier.Restart = sup.Restart
		}
		// The socket opens after the first render: rayctl apply waits for it
		// before it starts the data-plane units that read these files.
		if err := applier.Apply(ctx); err != nil {
			log.Error("apply", "err", err)
		}
		if sup != nil {
			done := make(chan struct{})
			go func() { sup.Run(ctx); close(done) }()
			// Stopped before rayd returns.
			defer func() { stop(); <-done }()
		}
		go applier.Run(ctx, srv.Changes)
	}
	if *credPeriod > 0 {
		if *credLead >= *credPeriod {
			return errors.New("-cred-lead must be shorter than -cred-period")
		}
		// Niko moves to a new credential up to 12 h after the switch
		// (RAYCONTROL.md §11): the previous one must outlive that.
		if *credGrace < minCredGrace {
			return fmt.Errorf("-cred-grace must be at least %v: clients move to the new credential up to 12 h after the switch", minCredGrace)
		}
		r := store.Rotation{Period: *credPeriod, Lead: *credLead, Grace: *credGrace}
		go rotateCredentials(ctx, st, r, func() { srv.Notify() }, log)
	}
	var cm *certs.Manager
	var is *certs.Issuer
	if *acmeDir != "" {
		if cm, is, err = startCertificates(ctx, st, srv, *acmeDir, log); err != nil {
			log.Error("certificates not managed", "err", err)
		}
	}
	go rotateReality(ctx, st, epoch, is, cm, rotateNow, func() { srv.Notify() }, log)
	go syncDNS(ctx, st, srv.Changes, log)
	go serveDoH(ctx, st, paths, srv.Changes, log)
	go serveRemote(ctx, &api.Remote{Server: srv, Log: log}, srv.Changes)
	if err := startSubscription(ctx, st, paths, log, *probeDaily); err != nil {
		log.Error("subscription endpoint not started", "err", err)
	}
	log.Info("serving", "socket", *socket, "node", fmt.Sprintf("%x", params.NodeID))
	return srv.ServeUnix(ctx, *socket, policy, per.Handler)
}

// supervisor runs the data plane without systemd (-supervise): the plan
// rayctl apply would install, as child processes.
func supervisor(paths render.Paths, xray, niko string, st *store.Store, log *slog.Logger) (*live.Supervisor, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	bins := deploy.Binaries{Rayd: self, Xray: xray, NikoServer: niko}
	for _, b := range []string{xray, niko} {
		if _, err := os.Stat(b); err != nil {
			log.Warn("supervise: binary missing; its services will not start", "err", err)
		}
	}
	return &live.Supervisor{Log: log, Plan: func(ctx context.Context) (deploy.Plan, error) {
		m, err := render.Collect(ctx, st)
		if err != nil {
			return deploy.Plan{}, err
		}
		files, _, err := render.Render(m, paths)
		if err != nil {
			return deploy.Plan{}, err
		}
		return deploy.Build(m, files, paths, bins), nil
	}}, nil
}

// startCertificates issues and renews the sites' certificates through ACME
// HTTP-01, opening the perimeter window for each order (R2-11).
func startCertificates(ctx context.Context, st *store.Store, srv *api.Server, directory string, log *slog.Logger) (*certs.Manager, *certs.Issuer, error) {
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
		Listen: ":" + strconv.Itoa(int(port))}
	// With Cloudflare: DNS-01 and one wildcard certificate, no window on
	// TCP 80 (R4-10).
	is.DNS = func(ctx context.Context) (certs.DNSSolver, error) {
		c, zone, err := provision.Cloudflare(ctx, st)
		if err != nil || c == nil {
			return nil, err
		}
		return &cloudflare.Solver{Client: c, Zone: zone}, nil
	}
	m := &certs.Manager{Store: st, Issue: is.Issue, Notify: srv.Notify, Log: log,
		Wildcard: func(ctx context.Context) string {
			if c, _, err := provision.Cloudflare(ctx, st); err != nil || c == nil {
				return ""
			}
			d, _ := provision.Domain(ctx, st)
			return d
		}}
	srv.DNSChanged = m.Wake
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

// dohListener is a running DoH endpoint and the certificate it serves.
type dohListener struct {
	srv  *http.Server
	h3   context.CancelFunc // DoH3
	cert [32]byte
}

// serveDoH keeps rayd's TLS listener on the socket of every enabled DoH
// service whose site has a certificate (R3-2); the front passes the
// connections for the DoH name to it (R2-15). A new certificate restarts the
// listener.
func serveDoH(ctx context.Context, st *store.Store, p render.Paths, changes func() <-chan struct{}, log *slog.Logger) {
	running := map[string]*dohListener{}
	stop := func(name string) {
		if l := running[name]; l != nil {
			_ = l.srv.Close()
			l.h3()
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
			if l := running[svc.Name]; l != nil && l.cert == sum {
				continue
			}
			stop(svc.Name)
			keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: secrets[provision.SecretTLSKey]})
			cert, err := tls.X509KeyPair(secrets[provision.SecretTLSChain], keyPEM)
			if err != nil {
				log.Error("doh certificate", "service", svc.Name, "err", err)
				continue
			}
			// The front passes the sockets of the DoH name here (R2-15).
			ln, err := nikoipc.ListenFD(p.DoHSocket(svc.Name), p.PeerUID(render.FrontUID), log)
			if err != nil {
				log.Error("doh socket", "service", svc.Name, "err", err)
				continue
			}
			id := svc.ID
			h := &doh.Handler{Tokens: func(ctx context.Context) (map[string]bool, error) { return dohTokens(ctx, st, id) }}
			srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute,
				ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelDebug),
				TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
					Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}}
			go func() { _ = srv.ServeTLS(ln, "", "") }()
			// DoH3: the same handler over QUIC, datagrams from the front (R3-5).
			h3ctx, h3stop := context.WithCancel(ctx)
			if pc, err := nikoipc.ListenPacket(p.DoH3Socket(svc.Name), p.PeerUID(render.FrontUID), log); err != nil {
				log.Error("doh3 socket", "service", svc.Name, "err", err)
			} else {
				go func() {
					if err := serveHTTP3(h3ctx, pc, cert, h); err != nil {
						log.Error("doh3", "service", svc.Name, "err", err)
					}
				}()
			}
			running[svc.Name] = &dohListener{srv: srv, h3: h3stop, cert: sum}
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

// dohTokens are the credentials DoH accepts now: those of enabled users
// with access to the service, with their rotation (R4-1).
func dohTokens(ctx context.Context, st *store.Store, service int64) (map[string]bool, error) {
	users, err := st.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	sets, err := st.CredentialSets(ctx, service, nil, nil)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := map[string]bool{}
	for _, u := range users {
		if !u.Enabled || (u.ExpiresAt != nil && !u.ExpiresAt.After(now)) || !slices.Contains(u.Services, service) {
			continue
		}
		for _, t := range sets[u.ID].Accepted(now) {
			if t != "" {
				out[t] = true
			}
		}
	}
	return out, nil
}

// syncDNS keeps the node's records in its DNS provider's zone: when the
// records it needs change (a DNS tunnel added or removed) and every hour
// against drift (R4-10).
func syncDNS(ctx context.Context, st *store.Store, changes func() <-chan struct{}, log *slog.Logger) {
	last := ""
	next := time.Time{}
	for {
		wake := changes()
		records, _, err := provision.DNSRecords(ctx, st)
		key := fmt.Sprint(records)
		if c, _, perr := provision.Cloudflare(ctx, st); err == nil && perr == nil && c != nil && (key != last || time.Now().After(next)) {
			done, problems, err := provision.SyncDNS(ctx, st)
			switch {
			case err != nil:
				log.Warn("DNS records not synced", "err", err)
			default:
				last, next = key, time.Now().Add(time.Hour)
				if len(done) > 0 {
					log.Info("DNS records synced", "changes", len(done))
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

// rotateReality advances the REALITY key rotation every minute (R4-7), so
// the switch lands within a minute of the time clients have, and at once
// on an operator request. A new server name needs a certificate first: the
// manager is woken for it. Without certificate management the names stay.
func rotateReality(ctx context.Context, st *store.Store, e provision.RealityEpoch, is *certs.Issuer, cm *certs.Manager,
	now <-chan struct{}, notify func(), log *slog.Logger) {
	var resolves func(context.Context, string) error
	if is != nil && cm != nil {
		resolves = func(ctx context.Context, name string) error { return is.CheckDNS(ctx, []string{name}) }
	}
	for {
		n, err := provision.RotateReality(ctx, st, time.Now(), e, resolves, log)
		if err != nil {
			log.Error("REALITY rotation", "err", err)
		} else if n > 0 {
			notify()
			if cm != nil {
				cm.Wake()
			}
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
// subscription service, if it is enabled.
func startSubscription(ctx context.Context, st *store.Store, paths render.Paths, log *slog.Logger, probeDailyMiB int) error {
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
	s := &sub.Server{Store: st, Keys: keys, Log: log}
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
		// The device's user as the Hysteria2 users file names it: link then
		// lists that user's own sessions one by one (niko-server v0.7).
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
	// Client summaries (R4-21): reports in, hints out; both only while the
	// administrator has them on (rayctl summary on).
	sum := &summary.Collector{Store: st, ASN: summary.Sources(st, &asn.DB{Path: summary.OperatorDB}, &asn.DB{Path: summary.ReleaseDB})}
	s.Probe.Report = sum.Take
	s.Hints = sum.Hints
	go pruneSummary(ctx, sum, log)
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
func rotateCredentials(ctx context.Context, st *store.Store, r store.Rotation, notify func(), log *slog.Logger) {
	for {
		n, err := st.RotateCredentials(ctx, time.Now(), r, render.NewUUID)
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

func pruneAudit(ctx context.Context, st *store.Store, log *slog.Logger) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		if err := st.PruneAudit(ctx, time.Now().Add(-auditKeep)); err != nil && ctx.Err() == nil {
			log.Warn("audit prune failed", "err", err)
		}
		// Invites used or expired a week ago: their key opens nothing anymore.
		if err := st.PruneInvites(ctx, time.Now().Add(-7*24*time.Hour)); err != nil && ctx.Err() == nil {
			log.Warn("invite prune failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// cmdSite serves the decoy site: TLS 1.3 with h2 on a unix socket, the
// self-steal target of REALITY (docs/08-decisions.md, R2-12).
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
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	chainPEM, err := os.ReadFile(*chain)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(*key)
	if err != nil {
		return err
	}
	cert, err := site.LoadCertificate(chainPEM, keyPEM, provision.RealityChainMin(), nil)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	_ = os.Remove(*socket)
	ln, err := net.Listen("unix", *socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(*socket, 0o660); err != nil { //nolint:gosec // G302: the REALITY process connects through the group
		return err
	}
	log.Info("serving the site", "socket", *socket, "chain", len(cert.Certificate), "answer", *answer)
	return site.Serve(ctx, ln, handler, cert, log)
}

// cmdNaive serves NaiveProxy (R2-14): TLS 1.3 with X25519MLKEM768 only and
// HTTP/2 on the connections the front passes for the service's name (R2-15).
func cmdNaive(args []string) error {
	fs := flag.NewFlagSet("naive", flag.ExitOnError)
	answer := fs.String("answer", site.Answer404, "what other requests get: 404, 403 or silent")
	users := fs.String("users", "", "JSON list of SHA-256 hashes of the passwords, read again when it changes")
	chain := fs.String("chain", "", "certificate chain (PEM, leaf first)")
	key := fs.String("key", "", "private key (PEM)")
	socket := fs.String("socket", "", "SOCK_SEQPACKET socket the front passes connections to (niko-server IPC, mode fd)")
	quicSocket := fs.String("quic-socket", "", "SOCK_SEQPACKET socket the front sends QUIC datagrams to (naive-quic; IPC mode packet)")
	frontUID := fs.Int("front-uid", render.FrontUID, "UID of the niko-server front, the only peer accepted")
	probeAddr := fs.String("probe", "", "where the probe name leads (the subscription endpoint on loopback, R4-16)")
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
	cert, err := tls.LoadX509KeyPair(*chain, *key)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ln, err := nikoipc.ListenFD(*socket, *frontUID, log)
	if err != nil {
		return err
	}
	ns := &naive.Server{Users: &naive.Users{Path: *users}, Answer: handler, Log: log}
	// Channel probes through the tunnel (R4-16): the probe name, and only
	// it, leads to the endpoint; the rest to public addresses.
	ns.Probe = *probeAddr
	if *quicSocket != "" {
		// naive-quic (R3-5): the same server over HTTP/3.
		pc, err := nikoipc.ListenPacket(*quicSocket, *frontUID, log)
		if err != nil {
			return err
		}
		go func() {
			if err := serveHTTP3(ctx, pc, cert, ns); err != nil {
				log.Error("naive-quic", "err", err)
			}
		}()
	}
	srv := &http.Server{
		Handler:           ns,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       5 * time.Minute,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
			Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}},
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	log.Info("serving naive", "socket", *socket, "answer", *answer)
	if err := srv.ServeTLS(ln, "", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// serveHTTP3 serves h on QUIC over the front's datagrams until ctx ends:
// TLS 1.3 with X25519MLKEM768 only, ALPN h3.
func serveHTTP3(ctx context.Context, pc net.PacketConn, cert tls.Certificate, h http.Handler) error {
	tlsConf := http3.ConfigureTLSConfig(&tls.Config{MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, Certificates: []tls.Certificate{cert}})
	ln, err := quic.ListenEarly(pc, tlsConf, &quic.Config{MaxIdleTimeout: 2 * time.Minute, KeepAlivePeriod: 0})
	if err != nil {
		return err
	}
	srv := &http3.Server{Handler: h, IdleTimeout: 2 * time.Minute}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
		_ = ln.Close()
		_ = pc.Close()
	}()
	if err := srv.ServeListener(ln); err != nil && ctx.Err() == nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, quic.ErrServerClosed) {
		return err
	}
	return nil
}
