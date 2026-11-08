package nodeupdate

import (
	"cmp"
	"os"
	"sync"
	"time"
)

// LocalNow is the time in the node's zone as it is now: /etc/localtime
// read again whenever it changes. Go reads the zone once, when a process
// starts, so a long-running rayd would choose the window by the zone it
// started in after timedatectl set-timezone (roadmap: after v0.19.0). TZ,
// when set, wins, as it does for Go.
func LocalNow() time.Time { return time.Now().In(zone.get()) }

// localtime is the zone file. Tests replace it.
var localtime = "/etc/localtime"

var zone zoneCache

type zoneCache struct {
	mu    sync.Mutex
	mod   time.Time
	size  int64
	loc   *time.Location
	since time.Time
}

func (z *zoneCache) get() *time.Location {
	if os.Getenv("TZ") != "" {
		return time.Local
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	// A look at the file at most once a second; its content only when it
	// changed (a new link is a new file to Stat).
	if z.loc != nil && time.Since(z.since) < time.Second {
		return z.loc
	}
	z.since = time.Now()
	fi, err := os.Stat(localtime)
	if err != nil {
		// No zone file: UTC, as Go takes it.
		z.loc, z.mod, z.size = time.UTC, time.Time{}, -1
		return z.loc
	}
	if z.loc != nil && fi.ModTime().Equal(z.mod) && fi.Size() == z.size {
		return z.loc
	}
	data, err := os.ReadFile(localtime) //nolint:gosec // G304: a fixed path
	if err != nil {
		return cmp.Or(z.loc, time.Local)
	}
	loc, err := time.LoadLocationFromTZData("Local", data)
	if err != nil {
		return cmp.Or(z.loc, time.Local)
	}
	z.loc, z.mod, z.size = loc, fi.ModTime(), fi.Size()
	return loc
}
