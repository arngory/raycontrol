package traffic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"golang.org/x/sys/unix"

	"github.com/arngory/raycontrol/internal/store"
	"github.com/arngory/raycontrol/internal/xrayapi"
)

// Reading is what a process gave at one poll: its start and each name's
// bytes since then (or since the name's first sight).
type Reading struct {
	// Boot names the process's run: random at each start (niko-server,
	// rayd naive), or Xray's start ("xray:" and Unix seconds, for the
	// store and a rayd that has no reading of its own yet).
	Boot string
	// Start is the process's start when it says (Xray: the wall clock at
	// the read less the uptime), else zero.
	Start time.Time
	// Xray's uptime, and the monotonic time of the read (Mono, taken right
	// before it): one run of Xray is told by its uptime growing with the
	// time between two reads, which a step of the wall clock does not
	// touch.
	Uptime time.Duration
	Mono   time.Duration
	Users  map[string]store.TrafficCounter
}

// monoStart anchors Mono where the kernel's clock cannot be read:
// time.Since keeps to the monotonic clock.
var monoStart = time.Now()

// monoNow is the kernel's monotonic clock (CLOCK_MONOTONIC), the one
// Xray's uptime runs on, and whether it is that: one clock for every
// process of this boot, so a rayd started anew still tells an Xray's run
// by its start on it. Else this process's own monotonic time.
func monoNow() (time.Duration, bool) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return time.Since(monoStart), false
	}
	return time.Duration(ts.Nano()), true
}

// bootID is the kernel's boot (/proc/sys/kernel/random/boot_id), "" when
// it cannot be read: the monotonic clock counts from that boot.
var bootID = sync.OnceValue(func() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	id := strings.TrimSpace(string(b))
	if err != nil || len(id) != 36 || strings.Trim(id, "0123456789abcdef-") != "" {
		return ""
	}
	return id
})

// Answers from the processes are bounded: a data-plane process is not
// trusted to send a sane one (traffic-limit-v1 §6).
const (
	maxAnswer = 4 << 20
	maxNames  = 1 << 16
	readWait  = 2 * time.Second
)

// ErrNoCounters: the process closed the stats socket without an answer, as
// niko-server before v0.15.0 does to the traffic line (Hysteria2), or gave
// its counters without the users' bytes (Yggdrasil before v0.16.0).
var ErrNoCounters = errors.New("no byte counters (niko-server before v0.15.0?)")

// ReadLine asks a stats socket for its users' bytes: the line "traffic",
// answered by one JSON line {"v": 1, "boot": "...", "users": {"u5": {"up":
// N, "down": N}}} (niko-server v0.15.0's Hysteria2 backends, rayd naive).
func ReadLine(ctx context.Context, path string) (Reading, error) {
	body, err := ask(ctx, path)
	if err != nil {
		return Reading{}, err
	}
	return parseLine(body)
}

// ReadYggdrasil asks a Yggdrasil backend's stats socket for its users' LAN
// bytes through the node, by group (lan-v1 §4.4): the traffic line, as
// ReadLine, from niko-server v0.16.0 on. niko-server v0.15.0 answers any
// connection at once with its own counters ({"started": ...,
// "dropped_frames": ...}, no "v"), without reading the line, and closes:
// no counters (ErrNoCounters), for the seconds of an update that has not
// restarted it yet. The pin is v0.16.0 or later, which always answers: an
// empty answer is a failure, not "no counters", lest a backend that
// resets before it answers leave the LAN bytes uncounted unseen.
func ReadYggdrasil(ctx context.Context, path string) (Reading, error) {
	body, err := ask(ctx, path)
	if err != nil {
		return Reading{}, err
	}
	if len(body) == 0 {
		return Reading{}, errors.New("an empty answer to the traffic line")
	}
	var head struct {
		V, Started json.RawMessage // there or not
	}
	if json.Unmarshal(body, &head) == nil && head.V == nil && head.Started != nil {
		return Reading{}, ErrNoCounters
	}
	return parseLine(body)
}

// ask sends a stats socket the traffic line and reads the answer to its
// end. A process that answers without reading the line (an older one) and
// closes may reset the connection under the line or after its answer:
// what it sent is the answer.
func ask(ctx context.Context, path string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, readWait)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if d, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(d)
	}
	if _, err := io.WriteString(c, "traffic\n"); err != nil && !closedEarly(err) {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(c, maxAnswer+1))
	if err != nil && !closedEarly(err) {
		return nil, err
	}
	return body, nil
}

// closedEarly reports whether the other end closed the connection with the
// line unread.
func closedEarly(err error) bool {
	return errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET)
}

// parseLine checks and reads a stats socket's answer.
func parseLine(body []byte) (Reading, error) {
	if len(body) == 0 {
		return Reading{}, ErrNoCounters
	}
	if len(body) > maxAnswer {
		return Reading{}, fmt.Errorf("an answer over %d bytes", maxAnswer)
	}
	var a struct {
		V     int    `json:"v"`
		Boot  string `json:"boot"`
		Users map[string]struct {
			Up   int64 `json:"up"`
			Down int64 `json:"down"`
		} `json:"users"`
	}
	// The decoder's error is not passed on: it may quote the answer (a
	// key's path), and it goes to rayctl status.
	if json.Unmarshal(body, &a) != nil {
		return Reading{}, errors.New("not an answer to the traffic line (JSON)")
	}
	if a.V != 1 {
		return Reading{}, fmt.Errorf("answer version %d, want 1", a.V)
	}
	// Not echoed: the error goes to rayctl status.
	if err := checkBoot(a.Boot); err != nil || strings.HasPrefix(a.Boot, xrayBoot) {
		return Reading{}, errors.New("a bad boot: want 1-64 printable characters")
	}
	if len(a.Users) > maxNames {
		return Reading{}, fmt.Errorf("%d names, at most %d", len(a.Users), maxNames)
	}
	r := Reading{Boot: a.Boot, Users: make(map[string]store.TrafficCounter, len(a.Users))}
	for name, c := range a.Users {
		r.Users[name] = store.TrafficCounter{Up: max(c.Up, 0), Down: max(c.Down, 0)}
	}
	return r, nil
}

func checkBoot(b string) error {
	if b == "" || len(b) > 64 || strings.ContainsFunc(b, func(r rune) bool { return r > unicode.MaxASCII || !unicode.IsPrint(r) }) {
		return errors.New("bad boot")
	}
	return nil
}

// xrayBoot prefixes an Xray process's start.
const xrayBoot = "xray:"

// bootSlack is how far an Xray's uptime may fall behind the time between
// two reads and still be one run (its uptime comes in whole seconds, and
// a read waits up to readWait), and how far two readings of its start
// may differ.
const bootSlack = 5 * time.Second

// ReadXray reads an Xray's users' bytes through its API socket (inner,
// REALITY): QueryStats "user>>>" without a reset, and the uptime, which
// tells its run (traffic-limit-v1 §2.1). A reset would lose the bytes of
// a rayd that falls between the read and the write. The clocks are read
// right before the call.
func ReadXray(ctx context.Context, socket string) (Reading, error) {
	ctx, cancel := context.WithTimeout(ctx, readWait)
	defer cancel()
	at := time.Now()
	mono, kernel := monoNow()
	users, uptime, err := xrayapi.DialStats(socket).Users(ctx)
	if err != nil {
		return Reading{}, err
	}
	if len(users) > maxNames {
		return Reading{}, fmt.Errorf("%d names, at most %d", len(users), maxNames)
	}
	start := at.Add(-uptime).Truncate(time.Second)
	boot := xrayBoot + strconv.FormatInt(start.Unix(), 10)
	if id := bootID(); kernel && id != "" {
		boot = xrayRun(start, id, mono-uptime)
	}
	r := Reading{Boot: boot, Start: start, Uptime: uptime, Mono: mono,
		Users: make(map[string]store.TrafficCounter, len(users))}
	for name, c := range users {
		r.Users[name] = store.TrafficCounter{Up: c.Up, Down: c.Down}
	}
	return r, nil
}

// xrayRun names an Xray's run: "xray:", its start by the wall clock (Unix
// seconds), the kernel's boot and its start on the monotonic clock of
// that boot (seconds). A step of the wall clock moves the first, never the
// last two.
func xrayRun(start time.Time, boot string, mono time.Duration) string {
	return xrayBoot + strconv.FormatInt(start.Unix(), 10) + ":" + boot + ":" + strconv.FormatInt(int64(mono/time.Second), 10)
}

// xrayStart reads a run's name: the wall start, and the kernel's boot and
// the monotonic start when it has them (kernel).
func xrayStart(b string) (wall int64, boot string, mono int64, kernel, ok bool) {
	rest, ok := strings.CutPrefix(b, xrayBoot)
	if !ok {
		return 0, "", 0, false, false
	}
	parts := strings.Split(rest, ":")
	sane := func(v int64, err error) bool { return err == nil && v >= 0 && v < 1<<40 }
	wall, err := strconv.ParseInt(parts[0], 10, 64)
	switch {
	case !sane(wall, err):
		return 0, "", 0, false, false
	case len(parts) == 1:
		return wall, "", 0, false, true
	case len(parts) != 3 || parts[1] == "":
		return 0, "", 0, false, false
	}
	mono, err = strconv.ParseInt(parts[2], 10, 64)
	if !sane(mono, err) {
		return 0, "", 0, false, false
	}
	return wall, parts[1], mono, true, true
}

// SameBoot reports whether two boots are one run of a process: equal, or
// two readings of an Xray's start within bootSlack. Both with the kernel's
// boot: the same boot and the same start on its monotonic clock, whatever
// the wall clock did between them (a run never outlives its kernel's
// boot). Else by the wall clock.
func SameBoot(a, b string) bool {
	if a == b {
		return true
	}
	s, idA, ms, kA, okA := xrayStart(a)
	t, idB, mt, kB, okB := xrayStart(b)
	slack := int64(bootSlack / time.Second)
	switch {
	case !okA || !okB:
		return false
	case kA && kB:
		return idA == idB && max(ms-mt, mt-ms) <= slack
	}
	return max(s-t, t-s) <= slack
}

// knownRun reports whether two Xray boots both carry the kernel's boot:
// then SameBoot tells their runs apart without the wall clock.
func knownRun(a, b string) bool {
	_, _, _, kA, okA := xrayStart(a)
	_, _, _, kB, okB := xrayStart(b)
	return okA && okB && kA && kB
}
