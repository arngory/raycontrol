package nodeupdate

import (
	"bytes"
	"cmp"
	"errors"
	"io/fs"
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
	data  []byte // the zone file as last read
	loc   *time.Location
	since time.Time
}

func (z *zoneCache) get() *time.Location {
	if os.Getenv("TZ") != "" {
		return time.Local
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	// The file at most once a second. Its bytes, not its mtime and size,
	// tell a change: timedatectl swaps a link between files of one tzdata
	// package, which share the mtime and often the size (Asia/Yekaterinburg
	// and Asia/Irkutsk are both 1243 bytes). A zone file is 1-3 KB.
	if z.loc != nil && time.Since(z.since) < time.Second {
		return z.loc
	}
	z.since = time.Now()
	data, err := os.ReadFile(localtime) //nolint:gosec // G304: a fixed path
	if errors.Is(err, fs.ErrNotExist) {
		// No zone file: UTC, as Go takes it.
		z.loc, z.data = time.UTC, nil
		return z.loc
	}
	if err != nil {
		return cmp.Or(z.loc, time.Local)
	}
	if z.loc != nil && z.data != nil && bytes.Equal(data, z.data) {
		return z.loc
	}
	loc, err := time.LoadLocationFromTZData("Local", data)
	if err != nil {
		return cmp.Or(z.loc, time.Local)
	}
	z.loc, z.data = loc, data
	return loc
}
