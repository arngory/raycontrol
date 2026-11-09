package xrayapi_test

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	proxyman "github.com/arngory/raycontrol/internal/gen/xray/app/proxyman/command"
	"github.com/arngory/raycontrol/internal/gen/xray/app/proxyman/command/commandconnect"
	statscmd "github.com/arngory/raycontrol/internal/gen/xray/app/stats/command"
	statsconnect "github.com/arngory/raycontrol/internal/gen/xray/app/stats/command/commandconnect"
	"github.com/arngory/raycontrol/internal/xrayapi"
)

// fakeXray answers the two API services rayd calls, gRPC over h2c on a
// unix socket, and counts the connections it accepts and holds.
type fakeXray struct {
	statsconnect.UnimplementedStatsServiceHandler
	commandconnect.UnimplementedHandlerServiceHandler
	accepted, open atomic.Int64
	srv            *http.Server
}

func (f *fakeXray) GetSysStats(context.Context, *connect.Request[statscmd.SysStatsRequest]) (*connect.Response[statscmd.SysStatsResponse], error) {
	return connect.NewResponse(&statscmd.SysStatsResponse{Uptime: 60}), nil
}

func (f *fakeXray) QueryStats(context.Context, *connect.Request[statscmd.QueryStatsRequest]) (*connect.Response[statscmd.QueryStatsResponse], error) {
	return connect.NewResponse(&statscmd.QueryStatsResponse{Stat: []*statscmd.Stat{
		{Name: "user>>>u1>>>traffic>>>uplink", Value: 5}, {Name: "user>>>u1>>>traffic>>>downlink", Value: 6},
		// The fork's refusals (TestStatsLimits), and names that are none.
		{Name: "user>>>u1>>>limit>>>tcp", Value: 3}, {Name: "user>>>u1>>>limit>>>rate", Value: 2},
		{Name: "user>>>u7>>>limit>>>udp", Value: 1}, {Name: "user>>>>>>limit>>>tcp", Value: 4},
		{Name: "user>>>u2>>>limit>>>", Value: 4}, {Name: "user>>>u2>>>limit>>>a>>>b", Value: 4},
		{Name: "user>>>u3>>>limit>>>tcp", Value: -1}, {Name: "inbound>>>x>>>limit>>>tcp", Value: 4}}}), nil
}

func (f *fakeXray) GetInboundUsers(context.Context, *connect.Request[proxyman.GetInboundUserRequest]) (*connect.Response[proxyman.GetInboundUserResponse], error) {
	return connect.NewResponse(&proxyman.GetInboundUserResponse{}), nil
}

type countingListener struct {
	net.Listener
	f *fakeXray
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.f.accepted.Add(1)
		l.f.open.Add(1)
		c = &countedConn{Conn: c, f: l.f}
	}
	return c, err
}

type countedConn struct {
	net.Conn
	f      *fakeXray
	closed atomic.Bool
}

func (c *countedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.f.open.Add(-1)
	}
	return c.Conn.Close()
}

func startFake(t *testing.T, sock string) *fakeXray {
	t.Helper()
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeXray{}
	mux := http.NewServeMux()
	mux.Handle(statsconnect.NewStatsServiceHandler(f))
	mux.Handle(commandconnect.NewHandlerServiceHandler(f))
	f.srv = &http.Server{Handler: mux, Protocols: new(http.Protocols)}
	f.srv.Protocols.SetUnencryptedHTTP2(true)
	go func() { _ = f.srv.Serve(countingListener{ln, f}) }()
	t.Cleanup(func() { _ = f.srv.Close() })
	return f
}

// Every poll of the stats, and every apply's user sync, goes over the one
// connection of its socket: none is left open per call on either side. An
// Xray restarted on a new socket is reached anew, the old connection
// closed.
func TestOneConnectionPerSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "api.sock")
	f := startFake(t, sock)
	ctx := context.Background()
	call := func() {
		t.Helper()
		users, uptime, err := xrayapi.DialStats(sock).Users(ctx)
		if err != nil || uptime != time.Minute || users["u1"] != (xrayapi.Counter{Up: 5, Down: 6}) {
			t.Fatalf("%v %v %v", users, uptime, err)
		}
		if _, err := xrayapi.Dial(sock).VLESSUsers(ctx, "inner"); err != nil {
			t.Fatal(err)
		}
	}
	call()
	runtime.GC()
	g0 := runtime.NumGoroutine()
	for range 300 {
		call()
	}
	time.Sleep(100 * time.Millisecond)
	if a, o, g := f.accepted.Load(), f.open.Load(), runtime.NumGoroutine(); a != 1 || o != 1 || g > g0+5 {
		t.Fatalf("after 600 calls: %d connections accepted, %d open, goroutines %d -> %d", a, o, g0, g)
	}

	// A new socket at the same path while the old process still holds
	// its connection: the calls go to the new one, the old connection is
	// closed.
	g := startFake(t, sock)
	call()
	for range 50 {
		call()
	}
	if a, o := g.accepted.Load(), g.open.Load(); a != 1 || o != 1 {
		t.Fatalf("after a new socket: %d connections accepted, %d open", a, o)
	}
	deadline := time.Now().Add(2 * time.Second)
	for f.open.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if o := f.open.Load(); o != 0 || f.accepted.Load() != 1 {
		t.Fatalf("the old socket's connection: %d open, %d accepted", o, f.accepted.Load())
	}

	// Xray restarts: its socket goes, a new one comes.
	_ = g.srv.Close()
	g = startFake(t, sock)
	call()
	for range 50 {
		call()
	}
	if a, o := g.accepted.Load(), g.open.Load(); a != 1 || o != 1 {
		t.Fatalf("after the restart: %d connections accepted, %d open", a, o)
	}
	xrayapi.Close()
	deadline = time.Now().Add(2 * time.Second)
	for g.open.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if o := g.open.Load(); o != 0 {
		t.Fatalf("%d connections open after Close", o)
	}
}
