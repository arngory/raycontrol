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
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

	// -debug always; otherwise while rayd's debug window is open.
	dl := &debugLevel{always: *debug}
	dl.level.Set(map[bool]slog.Level{false: slog.LevelInfo, true: slog.LevelDebug}[*debug])
	log := logx.New(os.Stderr, &dl.level)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The table stays after rayspa exits: the node fails closed. Use
	// "rayspa teardown" from the console to open it.
	fw := &perimeter.NFT{NflogGroup: uint16(*group), RateLimit: *rate}
	open := localFeed(*socket)
	if *relayBundle != "" {
		b, err := node.ReadRelayBundle(*relayBundle)
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
			// rayctl install -relay turns it on only once this rayspa's
			// first snapshot is checked: a warning until then, no error.
			log.Warn("net.ipv4.ip_forward is off: nothing reaches the exit until it is on " +
				"(rayctl install -relay turns it on once the relay is checked; sysctl -w net.ipv4.ip_forward=1)")
		}
	}
	// The table goes in with the first snapshot (R4-40): the saved one
	// below, or rayd's. Before it the kernel stays as it is: an earlier
	// rayspa's table (a restart) or none (a boot), never an empty table
	// that would shut the administrator out until rayd answers.
	gate := perimeter.NewGate(fw, log)
	gate.SetupAtFirstSnapshot()
	if _, err := fw.Present(); err != nil {
		return err // no nft: nothing here can work
	}
	if *relayBundle != "" {
		// A boot: forwarding is on from sysctl.d, nothing forwards until
		// the table is in. A table there (an earlier rayspa's, or its
		// hold) stays.
		if err := fw.HoldForward(); err != nil {
			log.Error("forwarding not held: the relay forwards whatever the kernel routes until its table is in", "err", err)
		}
	}
	if *relayBundle == "" {
		// The conntrack table's guard (spec/conn-limit-v1.md §6.3): on the
		// node only, a relay runs no data plane. Its state goes to rayd.
		gate.EnableGuard(&perimeter.Guard{Sweep: (&perimeter.Sweeper{}).Sweep, Refused: fw.GuardRefused,
			Report: guardReporter(ctx, *socket, log), Log: log})
	}
	handle := func(src, dst netip.Addr, pkt []byte) {
		g, err := gate.Handle(src, dst, pkt)
		if err != nil {
			log.Debug("spa rejected", "src", src, "err", err)
			return
		}
		// Who connected from where is user activity: not in the journal at
		// the default level (docs/design/observability.md, R4-3).
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
	st := startState{gate: gate, inForce: fw.InForce, pid: os.Getpid()}
	cur := st.now()
	switch {
	case cur.state == perimeter.GateUp:
	case cur.leftOver:
		log.Warn("no saved snapshot applied: the table an earlier rayspa left stays in force until rayd answers", "table", perimeter.Table)
	default:
		// Loud: the journal at error, and systemctl status.
		log.Error("perimeter down: the host is open until rayd answers (no saved snapshot applied; rayctl status)", "table", perimeter.Table)
	}
	// Ready once the start's table is in, or known not to be: the unit is
	// ordered before network-pre.target, so interfaces come up after this.
	if err := notify("READY=1\nSTATUS=" + cur.status()); err != nil {
		log.Error("sd_notify: READY not sent; under Type=notify systemd stops rayspa 30 s after its start (TimeoutStartSec) "+
			"and starts it again (journalctl -u rayspa)", "err", err)
	}
	// rayd learns where the table stands (R4-40): at each change, after
	// each feed's first snapshot, and every 30 s. Not a relay's: its feed
	// is the exit's.
	report := func(stateNow) {}
	if *relayBundle == "" {
		report = gateReporter(ctx, *socket, log)
	}
	report(cur)
	fed := make(chan struct{}, 1)
	go watch(ctx, open, *state, gate, carrier, dl, &st.fromRayd, &st.refused, fed, log)
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
	log.Info("rayspa running", "table", perimeter.Table, "version", version, "state", cur.state)
	for {
		select {
		case <-ctx.Done():
			// The table stays, but the guard's refusal goes: no one would
			// turn it off, and the data plane would stay refused new flows
			// until rayspa runs again.
			if err := gate.ReleaseGuard(); err != nil {
				log.Warn("conntrack guard not switched off at exit", "err", err)
			}
			return nil
		case <-fed:
			report(st.now())
		case <-tick.C:
			ports, err := gate.Tick()
			if err != nil && !errors.Is(err, perimeter.ErrNotReady) {
				log.Warn("tick", "err", err)
			}
			if ports != nil {
				carrier.Reconcile(ports)
			}
			// Each tick, as what a table left over is changes too: a
			// flush ruleset before the first snapshot takes it away.
			next := st.now()
			if next == cur {
				continue
			}
			switch {
			case next.state == cur.state && next.leftOver == cur.leftOver:
				// Only where the snapshot came from (rayd's now).
			case next.state == perimeter.GateUp:
				log.Info("perimeter up", "table", perimeter.Table)
			case next.state == perimeter.GateBehind:
				log.Warn("perimeter behind its snapshot: the table is in, a part of the snapshot is not yet", "table", perimeter.Table)
			case next.leftOver:
				log.Warn("the table an earlier rayspa left is in force, not this one's", "table", perimeter.Table, "state", next.state)
			case next.state == perimeter.GateNotIn:
				log.Error("perimeter down: its table is not in; the host is open meanwhile (journalctl -u rayspa -p warning says why)", "table", perimeter.Table)
			default:
				log.Error("perimeter down: the table an earlier rayspa left went; the host is open until rayd answers", "table", perimeter.Table)
			}
			cur = next
			if err := notify("STATUS=" + cur.status()); err != nil {
				log.Debug("sd_notify", "err", err)
			}
			report(cur)
		}
	}
}

// startState is what rayspa says of its table: the gate's state, whether
// a table an earlier rayspa left is in force while this one has none, and
// whether its snapshot came from rayd (not the saved one), and whether the
// feed's newest was refused (an earlier one is in force).
type startState struct {
	gate     *perimeter.Gate
	inForce  func() (bool, error) // the table's input chain is in the kernel
	pid      int
	fromRayd atomic.Bool
	refused  atomic.Bool
}

type stateNow struct {
	state    perimeter.GateState
	leftOver bool // not this gate's table, but one with an input chain
	fromRayd bool
	refused  bool // the feed's newest snapshot did not apply
	pid      int
}

func (s *startState) now() stateNow {
	n := stateNow{state: s.gate.State(), fromRayd: s.fromRayd.Load(), refused: s.refused.Load(), pid: s.pid}
	if n.state == perimeter.GateNoSnapshot || n.state == perimeter.GateNotIn {
		// The input chain, not the table: a relay's hold has a table and
		// no input chain, and leaves the host open (R4-40).
		n.leftOver, _ = s.inForce()
	}
	return n
}

// status is rayspa's line in systemctl status. The table it means is this
// process's (its pid, which systemctl show -p MainPID gives) only when it
// begins "perimeter up: rayd's snapshot": rayctl update waits for that
// (a table an earlier rayspa left would also be in the kernel). "perimeter
// up: the saved snapshot" is one with no snapshot of rayd's yet (rayd
// away); one whose snapshots of rayd's are refused is behind rayd.
func (n stateNow) status() string {
	who := fmt.Sprintf("; rayspa %s, pid %d", version, n.pid)
	switch {
	case n.state == perimeter.GateUp && n.refused:
		return "perimeter behind rayd: the table is in with an earlier snapshot, rayd's newest was refused (journalctl -u rayspa)" + who
	case n.state == perimeter.GateUp && n.fromRayd:
		return "perimeter up: rayd's snapshot" + who
	case n.state == perimeter.GateUp:
		return "perimeter up: the saved snapshot, until rayd answers" + who
	case n.state == perimeter.GateBehind:
		return "perimeter behind: the table is in, its snapshot only in part (journalctl -u rayspa)" + who
	case n.leftOver:
		return "waiting for rayd: the table an earlier rayspa left is in force" + who
	case n.state == perimeter.GateNotIn:
		return "PERIMETER DOWN: the host is open, the table is not in (journalctl -u rayspa)" + who
	}
	return "PERIMETER DOWN: the host is open until rayd answers" + who
}

// notify sends state to systemd (sd_notify), when the unit asked for it
// (Type=notify): nothing otherwise.
func notify(state string) error {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return nil
	}
	// A leading "@" is an abstract socket, as the net package reads it.
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_, err = c.Write([]byte(state))
	return err
}

// guardReporter sends the guard's state to rayd (PerimeterService.
// ReportGuard), apart from the tick: the newest state replaces one not sent
// yet, and a rayd away loses nothing but a report (the next comes within a
// minute).
func guardReporter(ctx context.Context, socket string, log *slog.Logger) func(perimeter.GuardState) {
	client := perimeterv1connect.NewPerimeterServiceClient(api.UnixHTTPClient(socket), api.BaseURL)
	next := make(chan perimeter.GuardState, 1)
	go func() {
		for {
			var st perimeter.GuardState
			select {
			case <-ctx.Done():
				return
			case st = <-next:
			}
			rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, err := client.ReportGuard(rctx, connect.NewRequest(&perimeterv1.ReportGuardRequest{Guard: guardPB(st)}))
			cancel()
			if err != nil {
				log.Debug("guard report to rayd", "err", err)
			}
		}
	}()
	return func(st perimeter.GuardState) {
		select {
		case <-next: // an older one not sent yet
		default:
		}
		select {
		case next <- st:
		default:
		}
	}
}

// gateReporter sends where the table stands to rayd (PerimeterService.
// ReportGate): each state given, the newest replacing one not sent yet,
// and the last again every 30 s, so that rayd knows a report it holds is
// still this rayspa's. A rayd away, or one older than ReportGate, loses
// nothing but the report.
func gateReporter(ctx context.Context, socket string, log *slog.Logger) func(stateNow) {
	client := perimeterv1connect.NewPerimeterServiceClient(api.UnixHTTPClient(socket), api.BaseURL)
	next := make(chan stateNow, 1)
	go func() {
		var last *perimeterv1.Gate
		every := time.NewTicker(30 * time.Second)
		defer every.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case n := <-next:
				last = gatePB(n)
			case <-every.C:
				if last == nil {
					continue
				}
			}
			rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, err := client.ReportGate(rctx, connect.NewRequest(&perimeterv1.ReportGateRequest{Gate: last}))
			cancel()
			if err != nil {
				log.Debug("gate report to rayd", "err", err)
			}
		}
	}()
	return func(n stateNow) {
		select {
		case <-next: // an older one not sent yet
		default:
		}
		select {
		case next <- n:
		default:
		}
	}
}

// gatePB is the report of a state: no address, no error text.
func gatePB(n stateNow) *perimeterv1.Gate {
	state := map[perimeter.GateState]string{perimeter.GateUp: "up", perimeter.GateBehind: "behind",
		perimeter.GateNotIn: "not_in", perimeter.GateNoSnapshot: "no_snapshot"}[n.state]
	return &perimeterv1.Gate{State: state, LeftOver: n.leftOver, FromRayd: n.fromRayd, Refused: n.refused, Version: version,
		Pid: uint32(n.pid)} //nolint:gosec // G115: a pid
}

func guardPB(st perimeter.GuardState) *perimeterv1.Guard {
	unix := func(t time.Time) int64 {
		if t.IsZero() {
			return 0
		}
		return t.Unix()
	}
	return &perimeterv1.Guard{On: st.On, Since: unix(st.Since), LastOn: unix(st.LastOn), Switches: st.Switches, Refused: st.Refused,
		SweptUdp: st.SweptUDP, SweptTcpOut: st.SweptTCPOut, SweptTcpIn: st.SweptTCPIn}
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
	if errors.Is(err, perimeter.ErrPending) {
		log.Warn("saved snapshot applied in part; the rest follows", "file", file, "err", err)
	} else if err != nil {
		log.Warn("saved snapshot not applied; waiting for rayd", "file", file, "err", err)
		return
	}
	if ports, _ := gate.Tick(); ports != nil {
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
	// Synced before the rename, and the rename after it: a power cut
	// leaves the snapshot of before or this one, never an empty file
	// (XFS, Rocky's default, keeps the rename and not the data).
	tmp := file + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // G304: the operator's -state path
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, file); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(file)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
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
	hc := api.RemoteHTTPClient(b.API.Pin, cert)
	base := "https://" + netip.AddrPortFrom(b.Exit, b.API.Port).String()
	client := perimeterv1connect.NewRelayServiceClient(hc, base)
	return func(ctx context.Context) (snapshots, error) {
		s, err := client.WatchRelay(ctx, connect.NewRequest(&perimeterv1.WatchRelayRequest{SpaVersions: perimeter.SPAVersions}))
		if err != nil {
			return nil, err
		}
		return relayStream{s}, nil
	}, nil
}

// debugLevel is rayspa's log level: debug with -debug, or until the end of
// the debug window a snapshot names (rayctl debug), then back by itself.
type debugLevel struct {
	always bool
	level  slog.LevelVar
	mu     sync.Mutex
	timer  *time.Timer
	gen    uint64 // a timer set before the latest snapshot does nothing
}

func (d *debugLevel) until(t int64) {
	if d == nil || d.always {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
	}
	d.gen++
	left := time.Until(time.Unix(t, 0))
	if t == 0 || left <= 0 {
		d.level.Set(slog.LevelInfo)
		return
	}
	d.level.Set(slog.LevelDebug)
	gen := d.gen
	d.timer = time.AfterFunc(left, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.gen == gen {
			d.level.Set(slog.LevelInfo)
		}
	})
}

// fromRayd is set once a snapshot of the feed is the gate's (STATUS);
// refused while the feed's newest is not (rayd learns it: an earlier one,
// or the saved one, is in force); fed gets word of each feed's first
// snapshot.
func watch(ctx context.Context, open openFeed, state string, gate *perimeter.Gate, carrier *perimeter.TCPCarrier, dl *debugLevel,
	fromRayd, refused *atomic.Bool, fed chan<- struct{}, log *slog.Logger) {
	backoff := time.Second
	for ctx.Err() == nil {
		stream, err := open(ctx)
		if err == nil {
			first := true
			for stream.Receive() {
				backoff = time.Second
				snap := stream.Snapshot()
				dl.until(snap.GetDebugUntil())
				// A snapshot applied in part is the gate's all the same:
				// Tick applies the rest, and it is saved for the next start.
				if err := gate.Update(snap); errors.Is(err, perimeter.ErrPending) {
					log.Warn("snapshot applied in part; the rest follows", "revision", snap.GetRevision(), "err", err)
				} else if err != nil {
					log.Error("applying snapshot", "revision", snap.GetRevision(), "err", err)
					refused.Store(true)
					continue
				} else {
					log.Info("snapshot applied", "revision", snap.GetRevision(), "devices", len(snap.Devices))
				}
				refused.Store(false)
				fromRayd.Store(true)
				if first {
					first = false
					select {
					case fed <- struct{}{}:
					default:
					}
				}
				if ports, _ := gate.Tick(); ports != nil {
					carrier.Reconcile(ports)
				}
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
