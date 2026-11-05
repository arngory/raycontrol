package api

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
)

// relayE2E is what the exit leaves for the client in the shared directory.
type relayE2E struct {
	Relay     node.SPAParams `json:"relay"`
	ExitNode  string         `json:"exit_node"`
	DeviceKey string         `json:"device_key"`
}

// TestRelayE2ERole plays one part of the relay test with the real pieces
// (test/relay/e2e.sh, relay-v1 §3.1), chosen by RAYCONTROL_RELAY_E2E_ROLE,
// each in its own network namespace; between them runs the real rayspa
// with -relay:
//   - exit: a node with a REALITY on TCP and UDP 443, a device, the relay
//     r1 and its bundle; it serves the relay its perimeter on the remote API
//     and answers on 443 with the address it sees;
//   - client: 443 at the relay is closed, also after a knock with the
//     device's own key; after a knock with its K_relay, TCP and UDP 443
//     reach the exit, which sees the relay.
func TestRelayE2ERole(t *testing.T) {
	role := os.Getenv("RAYCONTROL_RELAY_E2E_ROLE")
	if role == "" {
		t.Skip("run by test/relay/e2e.sh")
	}
	dir := os.Getenv("RAYCONTROL_RELAY_DIR")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	switch role {
	case "exit":
		relayExit(ctx, t, dir, os.Getenv("RAYCONTROL_RELAY_EXIT"), os.Getenv("RAYCONTROL_RELAY_SEEN"))
	case "client":
		relayClient(ctx, t, dir, os.Getenv("RAYCONTROL_RELAY_ADDR"), os.Getenv("RAYCONTROL_RELAY_SEEN"))
	}
}

func relayExit(ctx context.Context, t *testing.T, dir, exit, relayAddr string) {
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	params, err := provision.Init(ctx, st, provision.Options{Host: exit})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{Store: st, Params: params, Version: "test"}
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "api", Name: "api", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	reality, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "reality", Enabled: true,
		Settings: `{"target":"www.example.org:443","ports":["tcp/443","udp/443"]}`})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserServices(ctx, "alice", []int64{reality.ID}); err != nil {
		t.Fatal(err)
	}
	_, key, err := st.CreateDevice(ctx, "alice", "phone", "user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateRelay(ctx, "r1", netip.MustParseAddr(relayAddr)); err != nil {
		t.Fatal(err)
	}
	bundle, err := srv.issueRelayBundle(ctx, &nodev1.IssueRelayBundleRequest{Name: "r1", ExitAddress: exit, Admin: []string{"192.0.2.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "relay.bundle"), []byte(bundle.Bundle+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rp, err := provision.RelayParams(ctx, st, "r1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(relayE2E{Relay: node.FromParams(rp), ExitNode: hex.EncodeToString(params.NodeID[:]), DeviceKey: hex.EncodeToString(key[:])})
	if err := os.WriteFile(filepath.Join(dir, "client.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}

	// The remote API, with the relays' feed.
	apiSvc, err := srv.apiEndpoint(ctx)
	if err != nil || apiSvc == nil {
		t.Fatalf("api service: %v", err)
	}
	secrets, _ := st.ServiceSecrets(ctx, apiSvc.svc.ID)
	cfg, err := RemoteTLSConfig(secrets[provision.SecretTLSCert], secrets[provision.SecretTLSKey])
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(exit, fmt.Sprint(apiSvc.endpoint.Port)))
	if err != nil {
		t.Fatal(err)
	}
	r := &Remote{Server: srv, Log: slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Perimeter: &PerimeterServer{Server: srv, DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour, Refresh: time.Minute}}
	go r.Serve(ctx, ln, cfg)

	// 443 answers with the address it sees.
	tl, err := net.Listen("tcp", ":443")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", ":443")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			fmt.Fprintln(c, c.RemoteAddr().(*net.TCPAddr).IP)
			c.Close()
		}
	}()
	go func() {
		buf := make([]byte, 64)
		for {
			_, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo([]byte(from.(*net.UDPAddr).IP.String()), from)
		}
	}()
	// A port the relay does not forward: the client must not reach it by
	// routing through the relay.
	other, err := net.Listen("tcp", ":8081")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := other.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	fmt.Println("exit ready")
	<-ctx.Done()
}

func relayClient(ctx context.Context, t *testing.T, dir, relay, seen string) {
	b, err := os.ReadFile(filepath.Join(dir, "client.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c relayE2E
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	params, err := c.Relay.Params()
	if err != nil {
		t.Fatal(err)
	}
	var devKey [spa.KeySize]byte
	var exitNode [spa.NodeIDSize]byte
	k, _ := hex.DecodeString(c.DeviceKey)
	n, _ := hex.DecodeString(c.ExitNode)
	copy(devKey[:], k)
	copy(exitNode[:], n)

	tcp := func() (string, error) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(relay, "443"), time.Second)
		if err != nil {
			return "", err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		line, err := bufio.NewReader(conn).ReadString('\n')
		return strings.TrimSpace(line), err
	}
	knock := func(key [spa.KeySize]byte) {
		t.Helper()
		pkt, err := spa.SealRandom(params, key, spa.Request{Time: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		u, err := net.Dial("udp", net.JoinHostPort(relay, fmt.Sprint(params.Port(params.Slot(time.Now())))))
		if err != nil {
			t.Fatal(err)
		}
		u.Write(pkt)
		u.Close()
		time.Sleep(500 * time.Millisecond)
	}
	if got, err := tcp(); err == nil {
		t.Fatalf("443 at the relay open before SPA (the exit saw %s)", got)
	}
	// The device's own key opens nothing at a relay: only K_relay does.
	knock(devKey)
	if got, err := tcp(); err == nil {
		t.Fatalf("443 at the relay open after a knock with the device's own key (the exit saw %s)", got)
	}
	knock(spa.RelayKey(devKey, exitNode, params.NodeID, "r1"))
	got, err := tcp()
	if err != nil {
		t.Fatalf("443 at the relay after SPA with K_relay: %v", err)
	}
	if got != seen {
		t.Fatalf("the exit saw %s, want the relay's %s", got, seen)
	}
	uc, err := net.Dial("udp", net.JoinHostPort(relay, "443"))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uc.SetDeadline(time.Now().Add(2 * time.Second))
	uc.Write([]byte("hi"))
	buf := make([]byte, 64)
	m, err := uc.Read(buf)
	if err != nil || string(buf[:m]) != seen {
		t.Fatalf("UDP 443 through the relay: %q %v", buf[:m], err)
	}
	// The relay forwards what it forwards, and is no router for the rest.
	if exit := os.Getenv("RAYCONTROL_RELAY_EXIT"); exit != "" {
		if c, err := net.DialTimeout("tcp", net.JoinHostPort(exit, "8081"), time.Second); err == nil {
			c.Close()
			t.Fatal("the exit's tcp/8081 reached through the relay as a router")
		}
	}
	fmt.Println("client: through the relay with K_relay, not with the device's own key, and not before; no routing")
}
