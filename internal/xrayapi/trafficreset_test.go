package xrayapi_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/api"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
	"github.com/arngory/raycontrol/internal/testca"
)

// portless drops the ports of an error's addresses, which differ by try.
var portless = regexp.MustCompile(`:[0-9]+`)

// TestTrafficResetSupervised: the client's interop sequence on a node run
// as rayd serve -supervise runs it (traffic-limit-v1 §3.4): alice exhausts
// her limit through Hysteria2, rayctl user reset-usage, the subscription
// says she is back, and a new client goes through Hysteria2 at once. Each
// cycle says how long the new client waited for its first answer, and
// whether alice stays back. Minutes a cycle, so it runs only when asked:
// TRAFFIC_RESET_CYCLES cycles, with XRAY_BIN and NIKO_SERVER_BIN; it
// needs UDP 443 (root, or a network namespace of its own). Before
// v0.27.0 each cycle found her off again 71 s after the reset in the
// subscription and 125 s after it through Hysteria2 (internal/traffic
// TestResetUsageNotOverAgainByBytesBefore is the quick test of it).
func TestTrafficResetSupervised(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	niko := os.Getenv("NIKO_SERVER_BIN")
	cycles, _ := strconv.Atoi(os.Getenv("TRAFFIC_RESET_CYCLES"))
	if bin == "" || niko == "" || cycles <= 0 {
		t.Skip("set TRAFFIC_RESET_CYCLES, XRAY_BIN and NIKO_SERVER_BIN")
	}
	if pc, err := net.ListenPacket("udp", ":443"); err != nil {
		t.Skipf("UDP 443: %v", err)
	} else {
		pc.Close()
	}
	// How long a cycle watches her after the reset (TRAFFIC_RESET_WATCH):
	// past the loop's minute's write and apply's minute after it.
	watch := 150 * time.Second
	if d, err := time.ParseDuration(os.Getenv("TRAFFIC_RESET_WATCH")); err == nil {
		watch = d
	}
	waits := []string{"cut"}
	if w := os.Getenv("TRAFFIC_RESET_WAIT"); w != "" {
		waits = strings.Split(w, ",")
	}
	ip := hostAddr(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cycles)*(3*time.Minute+watch)+time.Minute)
	defer cancel()
	dir := t.TempDir()
	rayd := os.Getenv("RAYD_BIN")
	if rayd == "" {
		rayd = filepath.Join(dir, "rayd")
		if out, err := exec.Command("go", "build", "-o", rayd, "github.com/arngory/raycontrol/cmd/rayd").CombinedOutput(); err != nil {
			t.Fatalf("go build rayd: %v\n%s", err, out)
		}
	}

	db := filepath.Join(dir, "rayd.db")
	st, err := store.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provision.Init(ctx, st, provision.Options{Host: ip.String(), Domain: "example.test", Ports: provision.PortChoice{Sub: subPort(t)}}); err != nil {
		t.Fatal(err)
	}
	masq, err := provision.CreateService(ctx, st, store.Service{Kind: "hy2-masq", Name: "hy2", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	obfs, err := provision.CreateService(ctx, st, store.Service{Kind: "hy2-obfs", Name: "hy2o", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	ca, err := testca.New([]string{"*.example.test"}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provision.SetCertificate(ctx, st, "site", ca.ChainPEM, ca.KeyPEM, time.Now(), false); err != nil {
		t.Fatal(err)
	}
	rootFile := filepath.Join(dir, "root.pem")
	if err := os.WriteFile(rootFile, ca.RootPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	limit := int64(8 << 20)
	if _, err := st.CreateUser(ctx, store.User{Name: "alice", Enabled: true, TrafficLimit: &limit}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserServices(ctx, "alice", []int64{masq.ID, obfs.ID}); err != nil {
		t.Fatal(err)
	}
	dev, key, err := st.CreateDevice(ctx, "alice", "laptop", "user")
	if err != nil {
		t.Fatal(err)
	}
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := sub.Profiles(m, m.Users[0])
	if err != nil {
		t.Fatal(err)
	}
	linkOf := func(name string) string {
		i := slices.IndexFunc(profiles, func(p sub.Profile) bool { return p.Name == name })
		if i < 0 {
			t.Fatalf("no profile %s in %v", name, profiles)
		}
		return profiles[i].Link
	}
	subSvc, _ := st.ServiceByName(ctx, provision.SubscriptionService)
	subSecrets, _ := st.ServiceSecrets(ctx, subSvc.ID)
	keys, err := provision.LoadNodeKeys(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	sc := sub.Client{Addr: net.JoinHostPort(ip.String(), strconv.Itoa(m.SubscriptionPort())), Pin: mustPin(t, subSecrets[provision.SecretTLSCert]),
		DeviceID: dev.ID, DeviceKey: key, NodeKeys: keys.PublicJSON()}
	st.Close()

	run, err := os.MkdirTemp("", "rc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(run)
	cmd := exec.Command(rayd, "serve", "-db", db, "-socket", filepath.Join(run, "rayd.sock"),
		"-rendered", filepath.Join(dir, "rendered"), "-run", filepath.Join(run, "run"),
		"-supervise", "-xray", bin, "-niko-server", niko, "-acme-directory", "", "-dns-check", "0")
	cmd.Env = append(os.Environ(), "NIKO_SERVER_UNSAFE_ANY_DESTINATION=1")
	logs := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	defer func() {
		cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			cmd.Process.Kill()
			<-done
		}
		if f := os.Getenv("TRAFFIC_RESET_LOG"); f != "" {
			os.WriteFile(f, []byte(logs.String()), 0o600)
		}
		if t.Failed() {
			t.Logf("rayd:\n%s", logs.String())
		}
	}()
	paths := render.Paths{Run: filepath.Join(run, "run")}
	for _, sock := range []string{paths.StatsSocket("hy2"), paths.StatsSocket("hy2o")} {
		for i := 0; ; i++ {
			if _, err := os.Stat(sock); err == nil {
				break
			}
			if i == 100 {
				t.Fatalf("no %s", sock)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	ac := api.NewUnixClient(filepath.Join(run, "rayd.sock"))

	// The pages: 1 MiB for the traffic, a word for the check.
	big := bytes.Repeat([]byte("x"), 1<<20)
	page := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			w.Write(big)
			return
		}
		io.WriteString(w, "through reality")
	})}
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go page.Serve(pl)
	defer page.Close()
	base := "http://" + pl.Addr().String()

	fetch := func() (sub.Payload, error) {
		fctx, fcancel := context.WithTimeout(ctx, 5*time.Second)
		defer fcancel()
		return sc.Fetch(fctx, time.Now())
	}
	exhausted := func(p sub.Payload) bool { return p.Traffic != nil && p.Traffic.Exhausted }
	since := func() string { return fmt.Sprintf("%6.2fs", time.Since(start).Seconds()) }
	viaSocks := func(port int, timeout time.Duration) *http.Client {
		proxy, _ := url.Parse("socks5://127.0.0.1:" + strconv.Itoa(port))
		return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}, Timeout: timeout}
	}

	var slow []string
	for cycle := range cycles {
		name := []string{"hy2", "hy2o"}[cycle%2]
		link := linkOf(name)
		// The client that uses the traffic up: it downloads until the
		// subscription says she is over (the interop's loop).
		oldPort, stopOld := hysteriaSocks(t, bin, link, "", rootFile)
		var downloaded, failing atomic.Int64
		stopDownload := make(chan struct{})
		dlDone := make(chan struct{})
		go func() {
			defer close(dlDone)
			hc := viaSocks(oldPort, 10*time.Second)
			for {
				select {
				case <-stopDownload:
					return
				default:
				}
				resp, err := hc.Get(base + "/big")
				if err != nil {
					failing.Add(1)
					time.Sleep(100 * time.Millisecond)
					continue
				}
				n, _ := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				downloaded.Add(n)
				if n == int64(len(big)) {
					failing.Store(0)
				} else {
					failing.Add(1)
				}
			}
		}()
		exhaustedAt := time.Time{}
		for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
			if p, err := fetch(); err == nil && exhausted(p) {
				exhaustedAt = time.Now()
				break
			}
		}
		if exhaustedAt.IsZero() {
			t.Fatalf("cycle %d: alice never exhausted (downloaded %d)", cycle, downloaded.Load())
		}
		atExhaust := downloaded.Load()
		// What comes before the reset: nothing ("none"), the tunnel's
		// refusal of a new client ("refused", the old one stopped first),
		// or a pause (a duration).
		wait := waits[cycle%len(waits)]
		switch wait {
		case "none":
		case "cut":
			// The old client downloads on until the node cuts it.
			for deadline := time.Now().Add(60 * time.Second); failing.Load() < 3; time.Sleep(50 * time.Millisecond) {
				if time.Now().After(deadline) {
					t.Fatalf("cycle %d: the old client was never cut", cycle)
				}
			}
			close(stopDownload)
			stopOld()
			<-dlDone
			t.Logf("%s cycle %d (%s): the old client cut %v after the subscription said exhausted, %d MiB after it", since(), cycle, name,
				time.Since(exhaustedAt).Round(time.Millisecond), (downloaded.Load()-atExhaust)>>20)
		case "refused":
			close(stopDownload)
			stopOld()
			<-dlDone
			p, s := hysteriaSocks(t, bin, link, "", rootFile)
			hc := viaSocks(p, 5*time.Second)
			refusedFor := 0
			for deadline := time.Now().Add(60 * time.Second); refusedFor < 3; time.Sleep(200 * time.Millisecond) {
				if time.Now().After(deadline) {
					t.Fatalf("cycle %d: Hysteria2 never refused alice", cycle)
				}
				if resp, err := hc.Get(base + "/"); err == nil {
					resp.Body.Close()
					refusedFor = 0
				} else if !strings.Contains(err.Error(), "connection refused") {
					refusedFor++
				}
			}
			s()
			t.Logf("%s cycle %d (%s): refused %v after the subscription said exhausted", since(), cycle, name, time.Since(exhaustedAt).Round(time.Millisecond))
		default:
			d, err := time.ParseDuration(wait)
			if err != nil {
				t.Fatalf("TRAFFIC_RESET_WAIT %q", wait)
			}
			time.Sleep(d)
		}
		// As the interop: reset, wait for the subscription.
		if _, err := ac.SetUserTraffic(ctx, connect.NewRequest(&nodev1.SetUserTrafficRequest{Name: "alice", ResetUsage: true})); err != nil {
			t.Fatal(err)
		}
		resetAt := time.Now()
		var back sub.Payload
		for {
			if back, err = fetch(); err == nil && !exhausted(back) && len(back.Profiles) == 2 {
				break
			}
			if time.Since(resetAt) > 30*time.Second {
				t.Fatalf("cycle %d: the subscription still says exhausted: %+v %v", cycle, back.Traffic, err)
			}
			time.Sleep(100 * time.Millisecond)
		}
		backAt := time.Now()
		if wait != "refused" && wait != "cut" {
			close(stopDownload)
			stopOld()
			<-dlDone
		}
		t.Logf("%s cycle %d (%s, wait %s): exhausted after %d MiB, reset; subscription back %v after the reset (traffic %+v); %d MiB more by the old client",
			since(), cycle, name, wait, atExhaust>>20, backAt.Sub(resetAt).Round(time.Millisecond), *back.Traffic, (downloaded.Load()-atExhaust)>>20)

		// The new client, at once.
		newPort, stopNew := hysteriaSocks(t, bin, link, "", rootFile)
		hc := viaSocks(newPort, 5*time.Second)
		var errs []string
		var answered time.Duration
		tries := 0
		for time.Since(backAt) < 120*time.Second {
			tries++
			resp, err := hc.Get(base + "/")
			if err == nil {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if string(body) == "through reality" {
					answered = time.Since(backAt)
					break
				}
				err = fmt.Errorf("body %q", body)
			}
			msg := portless.ReplaceAllString(err.Error(), ":P")
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				msg = "timeout"
			}
			if len(errs) == 0 || !strings.HasSuffix(errs[len(errs)-1], msg) {
				errs = append(errs, fmt.Sprintf("%.1fs %s", time.Since(backAt).Seconds(), msg))
			}
			time.Sleep(200 * time.Millisecond)
		}
		// Does she stay back? The next rounds of the traffic loop, its
		// minute's write and apply's minute after it: she sends nothing
		// but a word every 3 s.
		var later []string
		var offAt, refusedAt time.Duration
		for time.Since(backAt) < watch {
			time.Sleep(3 * time.Second)
			p, err := fetch()
			if err == nil && exhausted(p) && offAt == 0 {
				offAt = time.Since(backAt)
				later = append(later, fmt.Sprintf("%.0fs subscription exhausted, used %d", offAt.Seconds(), p.Traffic.Used))
			}
			if resp, gerr := hc.Get(base + "/"); gerr != nil && refusedAt == 0 {
				refusedAt = time.Since(backAt)
				later = append(later, fmt.Sprintf("%.0fs refused through Hysteria2", refusedAt.Seconds()))
			} else if gerr == nil {
				resp.Body.Close()
			}
		}
		if offAt != 0 || refusedAt != 0 {
			slow = append(slow, fmt.Sprintf("cycle %d (%s): off again after the reset: %q", cycle, name, later))
		}
		stopNew()
		if answered == 0 {
			slow = append(slow, fmt.Sprintf("cycle %d (%s): no answer in 120 s", cycle, name))
		} else if answered > 15*time.Second {
			slow = append(slow, fmt.Sprintf("cycle %d (%s): answer after %v", cycle, name, answered.Round(time.Millisecond)))
		}
		t.Logf("%s cycle %d (%s): first answer %v after the subscription, %d tries; errors %q; then %q",
			since(), cycle, name, answered.Round(time.Millisecond), tries, errs, later)
		// Let the traffic loop see her under the limit again before the
		// next cycle uses it up.
		for p, err := fetch(); err != nil || exhausted(p); p, err = fetch() {
			if _, err := ac.SetUserTraffic(ctx, connect.NewRequest(&nodev1.SetUserTrafficRequest{Name: "alice", ResetUsage: true})); err != nil {
				t.Fatal(err)
			}
			time.Sleep(time.Second)
		}
		time.Sleep(16 * time.Second)
	}
	if len(slow) > 0 {
		t.Errorf("slow after reset-usage: %q", slow)
	}
}
