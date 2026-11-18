package stats

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadHost(t *testing.T) {
	proc := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		p := filepath.Join(proc, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("stat", "cpu  100 5 50 800 20 3 2 10 7 0\ncpu0 50 2 25 400 10 1 1 5 3 0\ncpu1 50 3 25 400 10 2 1 5 4 0\nintr 1 2 3\n")
	write("meminfo", "MemTotal:        4000000 kB\nMemFree:  100 kB\nMemAvailable:    1000000 kB\n")
	write("loadavg", "0.52 0.41 0.30 1/234 5678\n")
	write("net/dev", `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 9999 99 0 0 0 0 0 0 9999 99 0 0 0 0 0 0
  eth0: 1000 10 1 2 0 0 0 0 2000 20 3 4 0 0 0 0
  ens4: 500 5 0 0 0 0 0 0 600 6 0 1 0 0 0 0
`)
	write("uptime", "12345.67 20000.00\n")
	h := readHost(proc, t.TempDir())
	if !h.OK {
		t.Fatal("not read")
	}
	// busy: everything but idle (800) and iowait (20) of the first eight.
	if h.CPUTotal != 990 || h.CPUBusy != 170 || h.CPUs != 2 {
		t.Fatalf("cpu: %+v", h)
	}
	if h.MemTotal != 4000000<<10 || h.MemAvailable != 1000000<<10 || h.Load != [3]float64{0.52, 0.41, 0.30} || h.Uptime != 12345.67 {
		t.Fatalf("mem, load, uptime: %+v", h)
	}
	want := NetCounters{RxBytes: 1500, RxPackets: 15, RxErrors: 1, RxDrops: 2, TxBytes: 2600, TxPackets: 26, TxErrors: 3, TxDrops: 5}
	if h.Net != want {
		t.Fatalf("net: %+v, want %+v (lo left out)", h.Net, want)
	}
	if h.DiskTotal == 0 {
		t.Fatal("no disk")
	}
	if readHost(t.TempDir(), "").OK {
		t.Fatal("an empty /proc read")
	}
	// The real one, where there is one.
	if _, err := os.Stat("/proc/stat"); err == nil {
		if h := HostReader(os.TempDir())(); !h.OK || h.CPUTotal == 0 {
			t.Fatalf("this host: %+v", h)
		}
	}
}
