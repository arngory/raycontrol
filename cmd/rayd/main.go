// Command rayd is the raycontrol node daemon: it owns the node state and
// serves the node API.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/arngory/raycontrol/internal/api"
	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/live"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
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
	fs.Parse(args)

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
	srv := &api.Server{Store: st, Params: params, Version: version, Paths: paths, Binaries: deploy.DefaultBinaries}
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
		go applier.Run(ctx, srv.Changes)
	}
	if err := startSubscription(ctx, st, log); err != nil {
		log.Error("subscription endpoint not started", "err", err)
	}
	log.Info("serving", "socket", *socket, "node", fmt.Sprintf("%x", params.NodeID))
	return srv.ServeUnix(ctx, *socket, policy, per.Handler)
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
