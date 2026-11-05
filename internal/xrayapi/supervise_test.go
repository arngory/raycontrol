package xrayapi_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/probe"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/render"
	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/sub"
	"github.com/arngory/raycontrol/internal/testca"
)

// TestSupervisedNode runs a node as rayd serve -supervise does it without
// systemd (CI, containers): REALITY with its site, Hysteria2 (hy2-obfs)
// and Yggdrasil with inner behind the front, all from the rendered files. A client then
// probes through both tunnels, and asks link directly from the address of
// its Hysteria2 session: its own session is listed (R4-20).
func TestSupervisedNode(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	niko := os.Getenv("NIKO_SERVER_BIN")
	if bin == "" || niko == "" {
		t.Skip("set XRAY_BIN and NIKO_SERVER_BIN (v0.7 or later)")
	}
	// The front and REALITY take port 443 as on a node.
	for _, network := range []string{"tcp", "udp"} {
		var err error
		if network == "tcp" {
			var ln net.Listener
			if ln, err = net.Listen("tcp", ":443"); err == nil {
				ln.Close()
			}
		} else {
			var pc net.PacketConn
			if pc, err = net.ListenPacket("udp", ":443"); err == nil {
				pc.Close()
			}
		}
		if err != nil {
			t.Skipf("port 443 (%s): %v; run as root or with net.ipv4.ip_unprivileged_port_start=0", network, err)
		}
	}
	ip := hostAddr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dir := t.TempDir()
	rayd := os.Getenv("RAYD_BIN")
	if rayd == "" {
		rayd = filepath.Join(dir, "rayd")
		if out, err := exec.Command("go", "build", "-o", rayd, "github.com/arngory/raycontrol/cmd/rayd").CombinedOutput(); err != nil {
			t.Fatalf("go build rayd: %v\n%s", err, out)
		}
	}

	// The node's state, as rayctl would make it.
	db := filepath.Join(dir, "rayd.db")
	st, err := store.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provision.Init(ctx, st, provision.Options{Host: ip.String(), Domain: "example.test"}); err != nil {
		t.Fatal(err)
	}
	reality, err := provision.CreateService(ctx, st, store.Service{Kind: "reality", Name: "reality", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	hy, err := provision.CreateService(ctx, st, store.Service{Kind: "hy2-obfs", Name: "hy2o", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	// Yggdrasil brings inner with it: both run, behind the front's TCP 443.
	if _, err := provision.CreateService(ctx, st, store.Service{Kind: "yggdrasil", Name: "ygg", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// dnstt behind the front's UDP 53, which answers dnsprobe-v1 itself
	// (niko-server v0.8.3).
	dnsSvc, err := provision.CreateService(ctx, st, store.Service{Kind: "dnstt", Name: "dns", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	var dnsZone struct {
		Zone string `json:"zone"`
	}
	json.Unmarshal([]byte(dnsSvc.Settings), &dnsZone)
	// The site's certificate from a test CA (rayctl service cert).
	ca, err := testca.New([]string{"*.example.test"}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provision.SetCertificate(ctx, st, "site", ca.ChainPEM, ca.KeyPEM, time.Now()); err != nil {
		t.Fatal(err)
	}
	st.CreateUser(ctx, store.User{Name: "alice", Enabled: true})
	st.SetUserServices(ctx, "alice", []int64{reality.ID, hy.ID})
	dev, key, err := st.CreateDevice(ctx, "alice", "laptop", "user")
	if err != nil {
		t.Fatal(err)
	}
	m, err := render.Collect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	probeKey, err := st.DNSProbeKey(ctx)
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
	pin := mustPin(t, subSecrets[provision.SecretTLSCert])
	st.Close()

	// rayd and its data plane, short paths: unix sockets take 107 bytes.
	run, err := os.MkdirTemp("", "rc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(run)
	cmd := exec.Command(rayd, "serve", "-db", db, "-socket", filepath.Join(run, "rayd.sock"),
		"-rendered", filepath.Join(dir, "rendered"), "-run", filepath.Join(run, "run"),
		"-supervise", "-xray", bin, "-niko-server", niko, "-acme-directory", "")
	// Hysteria2's backend reaches test addresses only with this.
	cmd.Env = append(os.Environ(), "NIKO_SERVER_UNSAFE_ANY_DESTINATION=1")
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			cmd.Process.Kill()
			<-done
			t.Error("rayd did not stop on SIGTERM")
		}
		if t.Failed() || testing.Verbose() {
			t.Logf("rayd:\n%s", logs.String())
		}
	}()

	// Every unit of the plan runs: its socket is there.
	paths := render.Paths{Run: filepath.Join(run, "run")}
	for _, sock := range []string{paths.InnerSocket("inner"), paths.FrontSocket("ygg", "fd"),
		paths.StatsSocket("hy2o"), paths.SiteSocket("site")} {
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

	// The front answers a resolver check with the subscription's key.
	if dnsZone.Zone == "" {
		t.Fatalf("no zone in %s", dnsSvc.Settings)
	}
	var probeAnswer []string
	for range 50 {
		if probeAnswer, err = dnsProbe(net.JoinHostPort(ip.String(), "53"), probeKey, dnsZone.Zone); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil || len(probeAnswer) != 2 || !strings.HasPrefix(probeAnswer[1], "seen edns=1232 case=0 from=") {
		t.Fatalf("dnsprobe: %q %v", probeAnswer, err)
	}

	probeVia := func(name string, socksPort int) {
		t.Helper()
		sc := sub.Client{Addr: net.JoinHostPort(render.ProbeName, "443"), Pin: pin, DeviceID: dev.ID, DeviceKey: key}
		hc := sc.HTTP()
		proxy, _ := url.Parse("socks5h://127.0.0.1:" + strconv.Itoa(socksPort))
		hc.Transport.(*http.Transport).Proxy = http.ProxyURL(proxy)
		c := probe.Client{HTTP: hc, Base: "https://" + sc.Addr, Authorize: sc.Authorize}
		var down probe.Transfer
		var err error
		for range 60 {
			if down, err = c.Down(ctx, 1<<20); err == nil {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if err != nil || down.Server.Bytes != 1<<20 {
			t.Fatalf("probe through %s: %+v %v", name, down, err)
		}
	}

	// Through REALITY (self-steal on the site) into inner.
	port, stop := realitySocks(t, bin, linkOf("reality"), "")
	probeVia("REALITY", port)
	stop()

	// Through Hysteria2 behind the front, then link directly from the same
	// address: the session is the device's user's own.
	port, stop = hysteriaSocks(t, bin, linkOf("hy2o"), "", "")
	defer stop()
	probeVia("Hysteria2", port)
	sc := sub.Client{Addr: net.JoinHostPort(ip.String(), strconv.Itoa(m.SubscriptionPort())), Pin: pin, DeviceID: dev.ID, DeviceKey: key}
	c := probe.Client{HTTP: sc.HTTP(), Base: "https://" + sc.Addr, Authorize: sc.Authorize}
	ls, err := c.Link(ctx)
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	var stats struct {
		Connections int
		Own         []struct {
			RTTus uint64 `json:"rtt_us"`
		}
	}
	raw := ls.Hysteria2[strconv.FormatInt(hy.ID, 10)]
	if err := json.Unmarshal(raw, &stats); err != nil || stats.Connections < 1 || len(stats.Own) < 1 || stats.Own[0].RTTus == 0 {
		t.Fatalf("link from %s: %s (%+v, %v)", ls.Address, raw, stats, err)
	}
}

// hostAddr is an address of this host other than loopback: the node's, and
// the one the test's client comes from.
func hostAddr(t *testing.T) netip.Addr {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() && !p.Addr().IsLoopback() && !p.Addr().IsLinkLocalUnicast() {
			return p.Addr()
		}
	}
	t.Skip("no address other than loopback")
	return netip.Addr{}
}

// dnsProbe checks a resolver as a client does (docs/spec/dnsprobe-v1.md):
// a small probe sent straight to the node, its TXT strings back, the token
// checked against the key.
func dnsProbe(server string, key []byte, zone string) ([]string, error) {
	var b [24]byte
	b[0] = 1
	binary.BigEndian.PutUint32(b[2:6], uint32(time.Now().Unix()/60))
	if _, err := rand.Read(b[6:14]); err != nil {
		return nil, err
	}
	mac := func(parts ...[]byte) []byte {
		m := hmac.New(sha256.New, key)
		for _, p := range parts {
			m.Write(p)
		}
		return m.Sum(nil)
	}
	copy(b[14:], mac([]byte("dnsprobe-v1 q"), []byte(zone), b[:14])[:10])
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	label := strings.ToLower(enc.EncodeToString(b[:]))
	q := []byte{0x42, 0x42, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1}
	for _, l := range strings.Split(label+"."+zone, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 16, 0, 1)                      // TXT IN
	q = append(q, 0, 0, 41, 4, 0xd0, 0, 0, 0, 0, 0, 0) // OPT 1232
	c, err := net.Dial("udp", server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	r := make([]byte, 4096)
	n, err := c.Read(r)
	if err != nil {
		return nil, err
	}
	r = r[:n]
	questionEnd := 12 + len(label) + 1 + len(zone) + 2 + 4
	if n < questionEnd+12 || binary.BigEndian.Uint16(r[6:8]) != 1 {
		return nil, fmt.Errorf("answer of %d bytes, %d records", n, binary.BigEndian.Uint16(r[6:8]))
	}
	rd := r[questionEnd+12 : questionEnd+12+int(binary.BigEndian.Uint16(r[questionEnd+10:questionEnd+12]))]
	var strs []string
	for len(rd) > 0 {
		l := int(rd[0])
		strs, rd = append(strs, string(rd[1:1+l])), rd[1+l:]
	}
	if want := "v1 " + strings.ToLower(enc.EncodeToString(mac([]byte("dnsprobe-v1 a"), b[:])[:16])); len(strs) == 0 || strs[0] != want {
		return strs, fmt.Errorf("token %q, want %q", strs, want)
	}
	return strs, nil
}
