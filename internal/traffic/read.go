package traffic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"

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

// monoStart anchors Mono: time.Since keeps to the monotonic clock.
var monoStart = time.Now()

func monoNow() time.Duration { return time.Since(monoStart) }

// Answers from the processes are bounded: a data-plane process is not
// trusted to send a sane one (traffic-limit-v1 §6).
const (
	maxAnswer = 4 << 20
	maxNames  = 1 << 16
	readWait  = 2 * time.Second
)

// ErrNoCounters: the process closed the stats socket without an answer, as
// niko-server before v0.15.0 does to the traffic line.
var ErrNoCounters = errors.New("no byte counters (niko-server before v0.15.0?)")

// ReadLine asks a stats socket for its users' bytes: the line "traffic",
// answered by one JSON line {"v": 1, "boot": "...", "users": {"u5": {"up":
// N, "down": N}}} (niko-server v0.15.0's Hysteria2 backends, rayd naive).
func ReadLine(ctx context.Context, path string) (Reading, error) {
	ctx, cancel := context.WithTimeout(ctx, readWait)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return Reading{}, err
	}
	defer c.Close()
	if d, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(d)
	}
	if _, err := io.WriteString(c, "traffic\n"); err != nil {
		return Reading{}, err
	}
	body, err := io.ReadAll(io.LimitReader(c, maxAnswer+1))
	if err != nil {
		return Reading{}, err
	}
	return parseLine(body)
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
	at, mono := time.Now(), monoNow()
	users, uptime, err := xrayapi.DialStats(socket).Users(ctx)
	if err != nil {
		return Reading{}, err
	}
	if len(users) > maxNames {
		return Reading{}, fmt.Errorf("%d names, at most %d", len(users), maxNames)
	}
	start := at.Add(-uptime).Truncate(time.Second)
	r := Reading{Boot: xrayBoot + strconv.FormatInt(start.Unix(), 10), Start: start, Uptime: uptime, Mono: mono,
		Users: make(map[string]store.TrafficCounter, len(users))}
	for name, c := range users {
		r.Users[name] = store.TrafficCounter{Up: c.Up, Down: c.Down}
	}
	return r, nil
}

// SameBoot reports whether two boots are one run of a process: equal, or
// two readings of an Xray's start within bootSlack.
func SameBoot(a, b string) bool {
	if a == b {
		return true
	}
	x, okA := strings.CutPrefix(a, xrayBoot)
	y, okB := strings.CutPrefix(b, xrayBoot)
	if !okA || !okB {
		return false
	}
	s, err1 := strconv.ParseInt(x, 10, 64)
	t, err2 := strconv.ParseInt(y, 10, 64)
	sane := func(v int64) bool { return v >= 0 && v < 1<<40 }
	return err1 == nil && err2 == nil && sane(s) && sane(t) && max(s-t, t-s) <= int64(bootSlack/time.Second)
}
