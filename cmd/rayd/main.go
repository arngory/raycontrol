// Command rayd is the raycontrol node daemon: it owns the node state and
// serves the node API.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/arngory/raycontrol/internal/api"
	"github.com/arngory/raycontrol/internal/certs"
	"github.com/arngory/raycontrol/internal/cloudflare"
	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/live"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/site"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
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
	liveApply := fs.Bool("live", true, "render and apply data-plane files while serving")
	acmeDir := fs.String("acme-directory", certs.LetsEncrypt, "ACME directory for the sites' certificates (empty: none)")
	credPeriod := fs.Duration("cred-period", 30*24*time.Hour, "how long a user credential stays current (0: no rotation)")
	credLead := fs.Duration("cred-lead", 3*24*time.Hour, "the next credential is in the subscription this long before the switch")
	credGrace := fs.Duration("cred-grace", 2*24*time.Hour, "the previous credential is accepted this long after the switch")
	realityPeriod := fs.Duration("reality-period", 90*24*time.Hour, "how long REALITY keys stay current; their next set is published -cred-lead ahead (0: no rotation)")
	realityPrepare := fs.Duration("reality-prepare", 24*time.Hour, "how long a new REALITY server name may wait for its certificate")
	fs.Parse(args)
	epoch := provision.RealityEpoch{Period: *realityPeriod, Lead: *credLead, Prepare: *realityPrepare}
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
	paths := render.DefaultPaths
	paths.Rendered = *rendered
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

	if *liveApply {
		applier := &live.Applier{Store: st, Paths: paths, Log: log}
		// The socket opens after the first render: rayctl apply waits for it
		// before it starts the data-plane units that read these files.
		if err := applier.Apply(ctx); err != nil {
			log.Error("apply", "err", err)
		}
		go applier.Run(ctx, srv.Changes)
	}
	if *credPeriod > 0 {
		if *credLead >= *credPeriod {
			return errors.New("-cred-lead must be shorter than -cred-period")
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
	if err := startSubscription(ctx, st, log); err != nil {
		log.Error("subscription endpoint not started", "err", err)
	}
	log.Info("serving", "socket", *socket, "node", fmt.Sprintf("%x", params.NodeID))
	return srv.ServeUnix(ctx, *socket, policy, per.Handler)
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
func startSubscription(ctx context.Context, st *store.Store, log *slog.Logger) error {
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
	addr := ":" + strconv.Itoa(int(ports[0].Num))
	go func() {
		if err := s.Serve(ctx, addr, tlsCfg); err != nil {
			log.Error("subscription endpoint", "err", err)
		}
	}()
	log.Info("subscription endpoint", "addr", addr)
	return nil
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
