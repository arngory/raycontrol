// Command rayspa runs the node perimeter: it owns the raycontrol nftables
// table, accepts SPA v2 packets and opens service ports for their senders.
// It has no database access; device keys come from rayd over the local
// socket.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/arngory/raycontrol/internal/api"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1/perimeterv1connect"
	"github.com/arngory/raycontrol/internal/logx"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/perimeter"
)

var version = "dev"

func usage() {
	fmt.Fprintf(os.Stderr, `usage: rayspa <command> [flags]

commands:
  run       install the perimeter table and serve SPA until stopped
  teardown  remove the perimeter table (console recovery: opens the node)
  version   print the version
`)
	os.Exit(2)
}

// teardown removes the perimeter table. While rayspa.service runs it puts
// the table back within seconds (R1-7), so it must be stopped first.
func teardown() error {
	if exec.Command("systemctl", "is-active", "--quiet", "rayspa.service").Run() == nil {
		return errors.New("rayspa.service is running and restores the table within seconds: systemctl stop rayspa first " +
			"(it starts again at boot or with systemctl start rayspa); to let only your address reach SSH, rayctl admin ADDR is enough")
	}
	if err := (&perimeter.NFT{}).Teardown(); err != nil {
		return err
	}
	fmt.Println("perimeter removed: the node is open until rayspa starts again")
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = run(os.Args[2:])
	case "teardown":
		err = teardown()
	case "version":
		fmt.Println(version)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "rayspa:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	socket := fs.String("socket", "/run/raycontrol/rayd.sock", "rayd API socket")
	group := fs.Uint("nflog-group", 7, "NFLOG group for SPA packets")
	rate := fs.Int("rate", 20, "SPA packets (and TCP SYNs) per second per source")
	debug := fs.Bool("debug", false, "log rejected packets")
	state := fs.String("state", "", "keep the last snapshot in this file and start from it (Q-3); empty: none")
	relayBundle := fs.String("relay", "", "run as a relay (relay-v1 §3.1): take the perimeter from the exit named in this bundle "+
		"(rayctl relay bundle) instead of rayd, and forward the services to the exit")
	fs.Parse(args)

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := logx.New(os.Stderr, level)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The table stays after rayspa exits: the node fails closed. Use
	// "rayspa teardown" from the console to open it.
	fw := &perimeter.NFT{NflogGroup: uint16(*group), RateLimit: *rate}
	open := localFeed(*socket)
	if *relayBundle != "" {
		b, err := readRelayBundle(*relayBundle)
		if err != nil {
			return err
		}
		fw.RelayTo = b.Exit
		if open, err = relayFeed(b); err != nil {
			return err
		}
		log.Info("relay", "name", b.Name, "exit", b.Exit)
		// Forwarding is the relay's job (relay-v1 §3.1): rayctl install
		// -relay turns it on; without it the kernel drops what it redirects.
		if v, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil && strings.TrimSpace(string(v)) != "1" {
			log.Error("net.ipv4.ip_forward is off: nothing reaches the exit (sysctl -w net.ipv4.ip_forward=1)")
		}
	}
	if err := fw.Setup(); err != nil {
		return err
	}
	gate := perimeter.NewGate(fw, log)
	handle := func(src netip.Addr, pkt []byte) {
		g, err := gate.Handle(src, pkt)
		if err != nil {
			log.Debug("spa rejected", "src", src, "err", err)
			return
		}
		// Who connected from where is user activity: not in the journal at
		// the default level (docs/09-observability.md, R4-3).
		log.Debug("spa granted", "src", src, "device", g.DeviceID, "scope", g.Scope, "ttl", g.TTL)
	}
	carrier := &perimeter.TCPCarrier{Handler: handle, LenMax: gate.LenMax, Log: log}
	defer carrier.Close()

	// The last snapshot from rayd, until rayd answers: the admin addresses
	// and SPA (the emergency bundle's SSH) work without rayd, after a reboot
	// or an update that left rayd down (Q-3).
	if *state != "" {
		restore(*state, gate, carrier, log)
	}
	go watch(ctx, open, *state, gate, carrier, log)
	go func() {
		if err := perimeter.ReadNFLOG(ctx, uint16(*group), handle, log); err != nil {
			log.Error("nflog", "err", err)
			stop()
		}
	}()

	// Every second: the slots move, and if a "flush ruleset" (nftables or
	// firewalld reload) removed the table, it is back within a second.
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	log.Info("perimeter up", "table", perimeter.Table, "version", version)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			ports, err := gate.Tick()
			if err != nil && !errors.Is(err, perimeter.ErrNotReady) {
				log.Warn("tick", "err", err)
			}
			if err == nil {
				carrier.Reconcile(ports)
			}
		}
	}
}

// restore applies the snapshot saved in file, if there is one.
func restore(file string, gate *perimeter.Gate, carrier *perimeter.TCPCarrier, log *slog.Logger) {
	b, err := os.ReadFile(file) //nolint:gosec // G304: the operator's -state path
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	snap := &perimeterv1.Snapshot{}
	if err == nil {
		err = proto.Unmarshal(b, snap)
	}
	if err == nil {
		err = gate.Update(snap)
	}
	if err != nil {
		log.Warn("saved snapshot not applied; waiting for rayd", "file", file, "err", err)
		return
	}
	if ports, err := gate.Tick(); err == nil {
		carrier.Reconcile(ports)
	}
	age := time.Duration(0)
	if fi, err := os.Stat(file); err == nil {
		age = time.Since(fi.ModTime()).Round(time.Second)
	}
	log.Info("saved snapshot applied until rayd answers", "revision", snap.GetRevision(), "devices", len(snap.Devices), "age", age)
}

// save keeps snap for the next start: written aside, then renamed, so a
// crash leaves the old one or the new one.
func save(file string, snap *perimeterv1.Snapshot) error {
	b, err := proto.Marshal(snap)
	if err != nil {
		return err
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

// watch follows the perimeter feed from rayd, reconnecting with backoff.
// While rayd is away the last snapshot stays in force.
// snapshots is a perimeter feed: rayd's on the node, the exit's on a relay.
type snapshots interface {
	Receive() bool
	Snapshot() *perimeterv1.Snapshot
	Err() error
	Close() error
}

type openFeed func(ctx context.Context) (snapshots, error)

type localStream struct {
	*connect.ServerStreamForClient[perimeterv1.WatchPerimeterResponse]
}

func (s localStream) Snapshot() *perimeterv1.Snapshot { return s.Msg().Snapshot }

type relayStream struct {
	*connect.ServerStreamForClient[perimeterv1.WatchRelayResponse]
}

func (s relayStream) Snapshot() *perimeterv1.Snapshot { return s.Msg().Snapshot }

// localFeed is rayd's feed on its socket.
func localFeed(socket string) openFeed {
	client := perimeterv1connect.NewPerimeterServiceClient(api.UnixHTTPClient(socket), api.BaseURL)
	return func(ctx context.Context) (snapshots, error) {
		s, err := client.WatchPerimeter(ctx, connect.NewRequest(&perimeterv1.WatchPerimeterRequest{}))
		if err != nil {
			return nil, err
		}
		return localStream{s}, nil
	}
}

// relayFeed is the exit's feed for this relay: its remote API, the exit's
// certificate checked by its pin, the relay's own client certificate.
func relayFeed(b node.RelayBundle) (openFeed, error) {
	cert, err := api.DecodeClientCertificate([]byte(b.Cert))
	if err != nil {
		return nil, fmt.Errorf("relay bundle certificate: %w", err)
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: api.PinnedTLS(b.API.Pin, &cert), ForceAttemptHTTP2: true}}
	base := "https://" + netip.AddrPortFrom(b.Exit, b.API.Port).String()
	client := perimeterv1connect.NewRelayServiceClient(hc, base)
	return func(ctx context.Context) (snapshots, error) {
		s, err := client.WatchRelay(ctx, connect.NewRequest(&perimeterv1.WatchRelayRequest{}))
		if err != nil {
			return nil, err
		}
		return relayStream{s}, nil
	}, nil
}

// readRelayBundle reads the relay's bundle: root's file, it holds the key.
func readRelayBundle(path string) (node.RelayBundle, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return node.RelayBundle{}, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return node.RelayBundle{}, fmt.Errorf("relay bundle %s is mode %v: it holds a private key, make it 0600", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: the configured bundle
	if err != nil {
		return node.RelayBundle{}, err
	}
	return node.DecodeRelayBundle(string(b))
}

func watch(ctx context.Context, open openFeed, state string, gate *perimeter.Gate, carrier *perimeter.TCPCarrier, log *slog.Logger) {
	backoff := time.Second
	for ctx.Err() == nil {
		stream, err := open(ctx)
		if err == nil {
			for stream.Receive() {
				backoff = time.Second
				snap := stream.Snapshot()
				if err := gate.Update(snap); err != nil {
					log.Error("applying snapshot", "revision", snap.GetRevision(), "err", err)
					continue
				}
				if ports, err := gate.Tick(); err == nil {
					carrier.Reconcile(ports)
				}
				log.Info("snapshot applied", "revision", snap.GetRevision(), "devices", len(snap.Devices))
				if state != "" {
					if err := save(state, snap); err != nil {
						log.Warn("saving the snapshot", "file", state, "err", err)
					}
				}
			}
			err = stream.Err()
			_ = stream.Close()
		}
		if ctx.Err() != nil {
			return
		}
		log.Warn("perimeter feed lost, retrying", "err", err, "in", backoff)
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, 30*time.Second)
	}
}
