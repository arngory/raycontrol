package naive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// writeNamed writes the users file as rayd v0.22.0 does: hash to name.
func writeNamed(t *testing.T, path string, names map[string]string) {
	t.Helper()
	m := map[string]string{}
	for pw, name := range names {
		m[HashPassword(pw)] = name
	}
	b, _ := json.Marshal(m)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	// A new file in its place, as rayd writes it.
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func TestUsersFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	// The list rayd wrote before v0.22.0: accepted, counted for nobody.
	writeUsers(t, path, "one")
	u := &Users{Path: path}
	a, ok := u.admit(t.Context(), "one")
	if !ok || a.traffic != nil {
		t.Fatalf("list: %v %v", ok, a.traffic)
	}
	a.leave()
	writeNamed(t, path, map[string]string{"one": "u1", "two": "u1-n"})
	u = &Users{Path: path}
	for pw, name := range map[string]string{"one": "u1", "two": "u1-n"} {
		a, ok := u.admit(t.Context(), pw)
		if !ok || a.traffic == nil || a.traffic != u.traffic[name] {
			t.Fatalf("%s: %v", pw, ok)
		}
		a.leave()
	}
	if _, ok := u.admit(t.Context(), "three"); ok {
		t.Fatal("a stranger admitted")
	}
	if _, ok := u.admit(t.Context(), ""); ok {
		t.Fatal("no password admitted")
	}
	// Every name of the file is listed from the start, at zero.
	if s := u.Snapshot(); s.V != 1 || len(s.Boot) != 16 || len(s.Users) != 2 || s.Users["u1"] != (UserTraffic{}) {
		t.Fatalf("snapshot %+v", s)
	}
	// A file that cannot be read keeps the table.
	u.every = time.Nanosecond
	for _, bad := range []string{`{"zz": "u1"}`, `{"` + strings.Repeat("a", 64) + `": 5}`, `nonsense`} {
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
		if !u.Accepts("one") {
			t.Fatalf("%s: the table went", bad)
		}
	}
}

// The bytes count at the destinations' side, by the password's name:
// TCP as it goes through, UDP over TCP and ICMP by their payloads.
func TestTrafficCounted(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	h, connect := uotServer(t, time.Minute)
	writeNamed(t, h.Users.Path, map[string]string{"secret-one": "u7"})
	fake := newFakeNet()
	h.ICMP, h.icmpOpen = true, fake.open
	dst := netip.MustParseAddr("8.8.8.8")
	routers := netip.MustParsePrefix("198.51.100.0/24")
	h.Allow = func(a netip.Addr) bool {
		return a == dst || routers.Contains(a) || a == netip.MustParseAddr("127.0.0.1")
	}
	fake.hops[dst] = 3

	counts := func() UserTraffic { return h.Users.Snapshot().Users["u7"] }

	// TCP: 3000 bytes each way; the padding is not counted.
	_, s, done := connect(echo.Addr().String())
	msg := bytes.Repeat([]byte("t"), 3000)
	if _, err := s.Write(msg); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(s, make([]byte, len(msg))); err != nil {
		t.Fatal(err)
	}
	done()
	eventually(t, "TCP not counted", func() bool { return counts() == UserTraffic{Up: 3000, Down: 3000} })

	// UDP over TCP: the payloads that went and came back; the stranger's
	// packet, never passed on, does not count.
	udp := udpEcho(t)
	_, s, done = connect(UoTName + ":0")
	if _, err := s.Write(append([]byte{0}, socksAddr(netip.MustParseAddrPort("0.0.0.0:0"))...)); err != nil {
		t.Fatal(err)
	}
	v4 := append([]byte{0x00}, udp.Addr().AsSlice()...)
	v4 = binary.BigEndian.AppendUint16(v4, udp.Port())
	if _, err := s.Write(packet(v4, []byte("hello"))); err != nil {
		t.Fatal(err)
	}
	readPacket(t, s, false)
	done()
	eventually(t, "UDP not counted", func() bool { return counts() == UserTraffic{Up: 3005, Down: 3005} })

	// ICMP: the echo's data out, the reply's back; time exceeded has none.
	_, s, done = connect(ICMPName + ":0")
	defer done()
	if _, err := s.Write(append([]byte{icmpVersion}, echoFrame(dst, 64, 1, 1, []byte("ping!!"))...)); err != nil {
		t.Fatal(err)
	}
	if f := readFrame(t, s); f.kind != icmpReply {
		t.Fatalf("frame %s", f)
	}
	if _, err := s.Write(echoFrame(dst, 1, 1, 2, []byte("trace"))); err != nil {
		t.Fatal(err)
	}
	if f := readFrame(t, s); f.kind != icmpTimeExceeded {
		t.Fatalf("frame %s", f)
	}
	eventually(t, "ICMP not counted", func() bool { return counts() == UserTraffic{Up: 3016, Down: 3011} })
	// Packet too big from a router: the echo went out, the MTU that comes
	// back is the router's, not the destination's data.
	fake.mu.Lock()
	fake.narrow[dst] = 1300
	fake.mu.Unlock()
	if _, err := s.Write(echoFrame(dst, 64, 1, 3, bytes.Repeat([]byte("b"), 1400))); err != nil {
		t.Fatal(err)
	}
	if f := readFrame(t, s); f.kind != icmpTooBig {
		t.Fatalf("frame %s", f)
	}
	eventually(t, "too big not counted", func() bool { return counts() == UserTraffic{Up: 4416, Down: 3011} })
}

// A revoked CONNECT whose client stops reading: the download is stuck in a
// write the client never takes (flow control); within a couple of seconds
// the stream is reset all the same and its handler gone.
func TestRevokedCutClientNotReading(t *testing.T) {
	// A destination that sends as fast as it can.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64<<10)
		for {
			if _, err := c.Write(buf); err != nil {
				return
			}
		}
	}()
	h, connect := uotServer(t, time.Minute)
	h.Users.every = 20 * time.Millisecond
	path := h.Users.Path
	writeNamed(t, path, map[string]string{"secret-one": "u1"})
	go h.Users.Watch(t.Context())
	_, _, done := connect(ln.Addr().String())
	defer done()
	tunnels := func() int {
		buf := make([]byte, 4<<20)
		return strings.Count(string(buf[:runtime.Stack(buf, true)]), "naive.(*Server).tunnel(")
	}
	eventually(t, "no tunnel", func() bool { return tunnels() == 1 })
	time.Sleep(300 * time.Millisecond) // the windows fill: the client reads nothing
	writeNamed(t, path, map[string]string{"secret-two": "u2"})
	start := time.Now()
	eventually(t, "the revoked CONNECT is held by a client that does not read", func() bool { return tunnels() == 0 })
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("held %v", d)
	}
}

// A password gone from the users file loses its live streams: a TCP
// tunnel, UDP over TCP and ICMP are reset, not ended; another user's stay.
func TestRevokedCut(t *testing.T) {
	// A destination that keeps the connection and sends a byte a tick.
	ticker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ticker.Close()
	go func() {
		for {
			c, err := ticker.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					if _, err := c.Write([]byte{'.'}); err != nil {
						return
					}
					time.Sleep(20 * time.Millisecond)
				}
			}()
		}
	}()
	h, connect := uotServer(t, time.Minute)
	h.ICMP, h.icmpOpen = true, newFakeNet().open
	h.Users.every = 20 * time.Millisecond
	path := h.Users.Path
	writeNamed(t, path, map[string]string{"secret-one": "u1"})
	go h.Users.Watch(t.Context())

	_, tcp, d1 := connect(ticker.Addr().String())
	defer d1()
	if _, err := io.ReadFull(tcp, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	_, uot, d2 := connect(UoTName + ":0")
	defer d2()
	if _, err := uot.Write(append([]byte{0}, socksAddr(netip.MustParseAddrPort("0.0.0.0:0"))...)); err != nil {
		t.Fatal(err)
	}
	_, icmp, d3 := connect(ICMPName + ":0")
	defer d3()
	if _, err := icmp.Write([]byte{icmpVersion}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "streams not in", func() bool {
		h.Users.mu.Lock()
		defer h.Users.mu.Unlock()
		return len(h.Users.live) == 1 && len(h.Users.live[hashOf("secret-one")]) == 3
	})

	// The same password under the same name: a reload changes nothing.
	time.Sleep(30 * time.Millisecond)
	writeNamed(t, path, map[string]string{"secret-one": "u1", "secret-two": "u2"})
	time.Sleep(100 * time.Millisecond)
	if _, err := io.ReadFull(tcp, make([]byte, 2)); err != nil {
		t.Fatalf("cut by a reload that kept the user: %v", err)
	}

	start := time.Now()
	writeNamed(t, path, map[string]string{"secret-two": "u2"})
	for name, s := range map[string]io.Reader{"TCP": tcp, "UDP over TCP": uot, "ICMP": icmp} {
		if !reset(t, s) {
			t.Errorf("%s: ended, not reset", name)
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("cut after %v", d)
	}
	eventually(t, "streams kept", func() bool {
		h.Users.mu.Lock()
		defer h.Users.mu.Unlock()
		return len(h.Users.live) == 0
	})
	if h.Users.Accepts("secret-one") {
		t.Fatal("still accepted")
	}
}

func hashOf(pw string) [32]byte { return sha256.Sum256([]byte(pw)) }

// A credential switch (R4-1): the next secret becomes the current one
// (u1-n to u1) and the current one the previous (u1 to u1-p), both still
// good. The same user: no stream is cut, and each counts on under the name
// it came in with, the user's.
func TestRotationSwitchKeepsStreams(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	writeNamed(t, path, map[string]string{"old": "u1", "new": "u1-n"})
	u := &Users{Path: path, every: time.Nanosecond}
	onOld, ok1 := u.admit(t.Context(), "old")
	onNew, ok2 := u.admit(t.Context(), "new")
	if !ok1 || !ok2 {
		t.Fatal("not admitted")
	}
	defer onOld.leave()
	defer onNew.leave()
	time.Sleep(2 * time.Millisecond)
	writeNamed(t, path, map[string]string{"new": "u1", "old": "u1-p"})
	time.Sleep(2 * time.Millisecond)
	if !u.Accepts("old") || !u.Accepts("new") {
		t.Fatal("a credential refused after the switch")
	}
	if onOld.ctx.Err() != nil || onNew.ctx.Err() != nil {
		t.Fatalf("a switch cut streams of good credentials: %v, %v", context.Cause(onOld.ctx), context.Cause(onNew.ctx))
	}
	if onOld.traffic != u.traffic["u1"] || onNew.traffic != u.traffic["u1-n"] {
		t.Fatal("the streams count under other names than they came in with")
	}
	// The grace ends: the previous one goes, and its stream with it.
	writeNamed(t, path, map[string]string{"new": "u1"})
	time.Sleep(2 * time.Millisecond)
	u.Accepts("new")
	if onOld.ctx.Err() == nil || onNew.ctx.Err() != nil {
		t.Fatalf("the grace's end: %v, %v", context.Cause(onOld.ctx), context.Cause(onNew.ctx))
	}
}

// A password that stays but counts under another user's name now is
// another user's: its streams go too, as niko-server's do (a name given
// another password).
func TestRenamedCut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	writeNamed(t, path, map[string]string{"pw": "u1", "other": "u2"})
	u := &Users{Path: path, every: time.Nanosecond}
	a, ok := u.admit(t.Context(), "pw")
	if !ok {
		t.Fatal("not admitted")
	}
	defer a.leave()
	b, ok := u.admit(t.Context(), "other")
	if !ok {
		t.Fatal("not admitted")
	}
	defer b.leave()
	time.Sleep(2 * time.Millisecond)
	writeNamed(t, path, map[string]string{"pw": "u3", "other": "u2"})
	time.Sleep(2 * time.Millisecond)
	u.Accepts("other") // a request reads the file
	if a.ctx.Err() == nil || b.ctx.Err() != nil {
		t.Fatalf("renamed: %v, kept: %v", a.ctx.Err(), b.ctx.Err())
	}
	if c, ok := u.admit(t.Context(), "pw"); !ok || c.traffic != u.traffic["u3"] {
		t.Fatal("the new name does not count")
	} else {
		c.leave()
	}
}
