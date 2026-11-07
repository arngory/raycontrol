package xrayapi_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/dnsstats"
	nodepkg "github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
)

// TestSlipstreamLoad measures a slipstream service under load
// (docs/14-capacity.md): SLIPSTREAM_LOAD clients (a list, like 1,8,32,64),
// each its own device with its own key, download through the niko-server
// front and the server for SLIPSTREAM_LOAD_SECONDS (20) from a sink in
// place of the inner stage, all on loopback. It logs the throughput, the
// CPU and memory of the front and the server and their cost per query. No
// resolvers in between: what the node itself carries, not what a client
// gets through public resolvers. Set XRAY_BIN (unused), NIKO_SERVER_BIN
// (v0.14.0 or later), SLIPSTREAM_SERVER_BIN (server-v0.2.0 or later) and
// SLIPSTREAM_CLIENT_BIN.
func TestSlipstreamLoad(t *testing.T) {
	counts := os.Getenv("SLIPSTREAM_LOAD")
	niko, server, client := os.Getenv("NIKO_SERVER_BIN"), os.Getenv("SLIPSTREAM_SERVER_BIN"), os.Getenv("SLIPSTREAM_CLIENT_BIN")
	if counts == "" || niko == "" || server == "" || client == "" {
		t.Skip("set SLIPSTREAM_LOAD (clients, e.g. 1,8,32,64), NIKO_SERVER_BIN, SLIPSTREAM_SERVER_BIN and SLIPSTREAM_CLIENT_BIN")
	}
	seconds := 20
	if s := os.Getenv("SLIPSTREAM_LOAD_SECONDS"); s != "" {
		seconds, _ = strconv.Atoi(s)
	}
	for _, c := range strings.Split(counts, ",") {
		n, err := strconv.Atoi(c)
		if err != nil || n < 1 {
			t.Fatalf("SLIPSTREAM_LOAD %q", counts)
		}
		t.Run(c, func(t *testing.T) { slipLoad(t, niko, server, client, n, time.Duration(seconds)*time.Second) })
	}
}

func slipLoad(t *testing.T, niko, server, client string, n int, span time.Duration) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "rayd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := provision.Init(ctx, st, provision.Options{Host: "127.0.0.1", Domain: "example.com"}); err != nil {
		t.Fatal(err)
	}
	total := max(n+8, provision.DefaultSlipstreamConnections)
	slip, err := provision.CreateService(ctx, st, store.Service{Kind: "slipstream", Name: "slip", Enabled: true,
		Settings: `{"max_connections":` + strconv.Itoa(min(total, provision.MaxSlipstreamConnections)) + `}`})
	if err != nil {
		t.Fatal(err)
	}
	st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	st.SetUserServices(ctx, "alice", []int64{slip.ID})
	keys := make([][spa.KeySize]byte, n)
	for i := range n {
		if _, keys[i], err = st.CreateDevice(ctx, "alice", "d"+strconv.Itoa(i), "user"); err != nil {
			t.Fatal(err)
		}
	}
	params, _ := nodepkg.LoadParams(ctx, st)
	m, err := render.CollectForRender(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	run, err := os.MkdirTemp("", "rc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(run)
	paths := render.Paths{Rendered: filepath.Join(dir, "rendered"), Run: run}
	files, _, err := render.Render(m, paths)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		os.MkdirAll(filepath.Dir(f.Path), 0o755)
		os.WriteFile(f.Path, f.Content, 0o600)
	}
	for _, d := range []string{"slip", "front"} {
		os.MkdirAll(filepath.Join(run, d), 0o700)
	}
	os.MkdirAll(paths.FrontDir("slip"), 0o700)
	b, _ := os.ReadFile(filepath.Join(paths.Rendered, "slip", render.SlipstreamKey))
	os.WriteFile(paths.Credential("slip", render.SlipstreamKey), b, 0o600)
	b, _ = os.ReadFile(filepath.Join(paths.Rendered, "front", render.DNSProbeKeyFile))
	os.WriteFile(paths.FrontDNSProbe(), b, 0o600)

	// The sink in place of inner: each stream gets data as fast as it
	// takes it.
	sinkPath := filepath.Join(run, "sink.sock")
	sink, err := net.Listen("unix", sinkPath)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	go func() {
		chunk := bytes.Repeat([]byte("slipstream load "), 4096)
		for {
			c, err := sink.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					if _, err := c.Write(chunk); err != nil {
						return
					}
				}
			}()
		}
	}()

	args, err := render.SlipstreamArgs(render.Service{Service: slip}, "inner", paths)
	if err != nil {
		t.Fatal(err)
	}
	for i := range args {
		switch args[i] {
		case "--front-uid":
			args[i+1] = strconv.Itoa(os.Getuid())
		case "--target-unix":
			args[i+1] = sinkPath
		}
	}
	srv := exec.Command(server, args...)
	var srvLog bytes.Buffer
	srv.Stdout, srv.Stderr = &srvLog, &srvLog
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { srv.Process.Kill(); srv.Wait() }()
	waitFile(t, paths.FrontSocket("slip", "packet"))

	port := freeUDP(t)
	frontPath := writeJSON(t, func() map[string]any {
		var cfg map[string]any
		b, _ := os.ReadFile(filepath.Join(paths.Rendered, "front", "front.json"))
		_ = json.Unmarshal(b, &cfg)
		cfg["dns"].(map[string]any)["listen"] = []string{"127.0.0.1:" + strconv.Itoa(port)}
		cfg["log"] = map[string]string{"level": "warn"}
		for _, ref := range cfg["backends"].(map[string]any) {
			ref.(map[string]any)["uid"] = os.Getuid()
		}
		return cfg
	}())
	front := exec.Command(niko, "front", "-c", frontPath)
	var frontLog bytes.Buffer
	front.Stderr = &frontLog
	if err := front.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { front.Process.Kill(); front.Wait() }()
	time.Sleep(300 * time.Millisecond)

	profiles, err := sub.Profiles(m, m.Users[0])
	if err != nil || len(profiles) != 1 {
		t.Fatalf("profiles %v %v", profiles, err)
	}
	link, _ := url.Parse(profiles[0].Link)
	q := link.Query()
	dnsf, slipf := strings.Split(q.Get("niko-dns"), ";"), strings.Split(q.Get("niko-slip"), ";")
	svcID, _ := strconv.Atoi(q.Get("niko-svc"))
	ports := make([]int, n)
	var clients []*exec.Cmd
	defer func() {
		for _, c := range clients {
			c.Process.Kill()
			c.Wait()
		}
	}()
	for i := range n {
		ports[i] = freePort(t)
		k := spa.DNSAuthKey(keys[i], params.NodeID, uint16(svcID))
		c := exec.Command(client, "-l", strconv.Itoa(ports[i]), "-r", "127.0.0.1:"+strconv.Itoa(port), "-d", dnsf[2],
			"--pin="+slipf[1], "--alpn="+slipf[2], "--sni="+slipf[3], "--dnsauth", "--quiet") // --pin=: a pin may start with "-"
		c.Env = append(os.Environ(), "SLIPSTREAM_DNSAUTH_KEY="+hex.EncodeToString(k[:]))
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
	}
	time.Sleep(3 * time.Second) // handshakes

	statsBefore, _ := dnsstats.ReadFront(ctx, paths.FrontStats())
	cpuFront0, cpuSrv0 := procCPU(front.Process.Pid), procCPU(srv.Process.Pid)
	var cpuClients0 time.Duration
	for _, c := range clients {
		cpuClients0 += procCPU(c.Process.Pid)
	}
	start := time.Now()
	got := make([]atomic.Int64, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(ports[i]))
			if err != nil {
				return
			}
			defer c.Close()
			// A stream reaches the server with its first byte.
			if _, err := c.Write([]byte{'g'}); err != nil {
				return
			}
			c.SetReadDeadline(start.Add(span))
			buf := make([]byte, 64<<10)
			for {
				k, err := c.Read(buf)
				got[i].Add(int64(k))
				if err != nil {
					return
				}
			}
		})
	}
	wg.Wait()
	elapsed := time.Since(start)
	statsAfter, _ := dnsstats.ReadFront(ctx, paths.FrontStats())
	cpuFront, cpuSrv := procCPU(front.Process.Pid)-cpuFront0, procCPU(srv.Process.Pid)-cpuSrv0
	var cpuClients time.Duration
	for _, c := range clients {
		cpuClients += procCPU(c.Process.Pid)
	}
	cpuClients -= cpuClients0

	var sum int64
	lo, hi, through := int64(-1), int64(0), 0
	for i := range n {
		v := got[i].Load()
		sum += v
		if v > 0 {
			through++
		}
		if lo < 0 || v < lo {
			lo = v
		}
		hi = max(hi, v)
	}
	mbit := func(b int64) float64 { return float64(b) * 8 / elapsed.Seconds() / 1e6 }
	queries := statsAfter.Forwarded - statsBefore.Forwarded
	qps := float64(queries) / elapsed.Seconds()
	perQuery := func(d time.Duration) float64 {
		if queries == 0 {
			return 0
		}
		return float64(d.Microseconds()) / float64(queries)
	}
	pct := func(d time.Duration) float64 { return 100 * d.Seconds() / elapsed.Seconds() }
	t.Logf("%d clients (%d through), %.1f s: %.2f Mbit/s down in all, a client %.2f to %.2f Mbit/s",
		n, through, elapsed.Seconds(), mbit(sum), mbit(lo), mbit(hi))
	t.Logf("front: %.0f queries/s passed, CPU %.0f %% of a core (%.1f µs a query), RSS %s; untagged %d, replayed %d, replay turns %d",
		qps, pct(cpuFront), perQuery(cpuFront), procRSS(front.Process.Pid),
		statsAfter.Untagged-statsBefore.Untagged, statsAfter.Replayed-statsBefore.Replayed, statsAfter.ReplayTurns-statsBefore.ReplayTurns)
	t.Logf("server: CPU %.0f %% of a core (%.1f µs a query), RSS %s; clients: CPU %.0f %% in all",
		pct(cpuSrv), perQuery(cpuSrv), procRSS(srv.Process.Pid), pct(cpuClients))
	if through < n {
		t.Errorf("%d of %d clients got nothing", n-through, n)
		t.Logf("server:\n%s", lastLines(srvLog.String(), 20))
	}
}

// procCPU is a process's CPU time, user and system (/proc/PID/stat).
func procCPU(pid int) time.Duration {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0
	}
	// After the command's ")": state is field 3; utime, stime are 14, 15.
	f := strings.Fields(string(b[bytes.LastIndexByte(b, ')')+2:]))
	if len(f) < 13 {
		return 0
	}
	u, _ := strconv.ParseInt(f[11], 10, 64)
	s, _ := strconv.ParseInt(f[12], 10, 64)
	return time.Duration(u+s) * time.Second / 100 // USER_HZ
}

// procRSS is a process's resident memory now and at its peak.
func procRSS(pid int) string {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return "?"
	}
	defer f.Close()
	var rss, hwm string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), ":")
		switch k {
		case "VmRSS":
			rss = strings.TrimSpace(v)
		case "VmHWM":
			hwm = strings.TrimSpace(v)
		}
	}
	return rss + " (peak " + hwm + ")"
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}
