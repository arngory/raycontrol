package nodeupdate

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The node's zone is followed as it changes, not taken once at start.
func TestLocalNowFollowsTheZone(t *testing.T) {
	t.Setenv("TZ", "")
	read := func(name string) []byte {
		for _, dir := range []string{"/usr/share/zoneinfo", "/usr/lib/go/lib/time"} {
			if b, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
				return b
			}
		}
		t.Skipf("no zoneinfo for %s here", name)
		return nil
	}
	tokyo, berlin := read("Asia/Tokyo"), read("Europe/Berlin")
	saved := localtime
	localtime = filepath.Join(t.TempDir(), "localtime")
	t.Cleanup(func() { localtime = saved; zone = zoneCache{} })
	zone = zoneCache{}

	os.WriteFile(localtime, tokyo, 0o644)
	if _, off := LocalNow().Zone(); off != 9*3600 {
		t.Fatalf("Tokyo: offset %d", off)
	}
	// timedatectl set-timezone: a new file (here new content and time).
	os.WriteFile(localtime, berlin, 0o644)
	os.Chtimes(localtime, time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	zone.since = time.Time{} // past the once-a-second look
	if name, off := LocalNow().Zone(); off != 3600 && off != 7200 {
		t.Fatalf("Berlin: %s %d", name, off)
	}
	// No file: UTC.
	os.Remove(localtime)
	zone.since = time.Time{}
	if _, off := LocalNow().Zone(); off != 0 {
		t.Fatalf("no zone file: offset %d", off)
	}
}

// A swap between two zone files of one size and one mtime (timedatectl
// moves a link between files of one tzdata package) is a change too.
func TestLocalNowSameSizeZones(t *testing.T) {
	t.Setenv("TZ", "")
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("/usr/share/zoneinfo", name))
		if err != nil {
			t.Skipf("no zoneinfo for %s here", name)
		}
		return b
	}
	ekb, irk := read("Asia/Yekaterinburg"), read("Asia/Irkutsk")
	if len(ekb) != len(irk) {
		t.Skipf("these tzdata files differ in size (%d, %d): the case does not arise", len(ekb), len(irk))
	}
	saved := localtime
	localtime = filepath.Join(t.TempDir(), "localtime")
	t.Cleanup(func() { localtime = saved; zone = zoneCache{} })
	zone = zoneCache{}
	when := time.Now().Add(-time.Hour)

	os.WriteFile(localtime, ekb, 0o644)
	os.Chtimes(localtime, when, when)
	if _, off := LocalNow().Zone(); off != 5*3600 {
		t.Fatalf("Yekaterinburg: offset %d", off)
	}
	os.WriteFile(localtime, irk, 0o644)
	os.Chtimes(localtime, when, when) // same size, same mtime
	zone.since = time.Time{}
	if _, off := LocalNow().Zone(); off != 8*3600 {
		t.Fatalf("Irkutsk after Yekaterinburg: offset %d, want %d", off, 8*3600)
	}
}
