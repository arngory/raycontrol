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
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/api"
	perimeterv1 "github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1/perimeterv1connect"
	"github.com/arngory/raycontrol/internal/logx"
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

	go watch(ctx, *socket, gate, carrier, log)
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

// watch follows the perimeter feed from rayd, reconnecting with backoff.
// While rayd is away the last snapshot stays in force.
func watch(ctx context.Context, socket string, gate *perimeter.Gate, carrier *perimeter.TCPCarrier, log *slog.Logger) {
	client := perimeterv1connect.NewPerimeterServiceClient(api.UnixHTTPClient(socket), api.BaseURL)
	backoff := time.Second
	for ctx.Err() == nil {
		stream, err := client.WatchPerimeter(ctx, connect.NewRequest(&perimeterv1.WatchPerimeterRequest{}))
		if err == nil {
			for stream.Receive() {
				backoff = time.Second
				snap := stream.Msg().Snapshot
				if err := gate.Update(snap); err != nil {
					log.Error("applying snapshot", "revision", snap.GetRevision(), "err", err)
					continue
				}
				if ports, err := gate.Tick(); err == nil {
					carrier.Reconcile(ports)
				}
				log.Info("snapshot applied", "revision", snap.GetRevision(), "devices", len(snap.Devices))
			}
			err = stream.Err()
			stream.Close()
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
