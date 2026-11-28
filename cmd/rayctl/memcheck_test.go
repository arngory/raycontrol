package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/hostcheck"
)

// The budget of the host; a unit the kernel does not hold to its limit; the
// data plane at its high mark. Nothing without the host's memory.
func TestMemoryResults(t *testing.T) {
	root := t.TempDir()
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, p), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	props := map[string]string{
		"rayd.service ActiveState": "active", "rayd.service MemoryMax": "241590272", "rayd.service ControlGroup": "/system.slice/rayd.service",
		"niko-dns.service ActiveState": "active", "niko-dns.service MemoryMax": "328830976",
		"niko-dns.service ControlGroup":    "/raycontrol.slice/raycontrol-data.slice/niko-dns.service",
		"niko-off.service ActiveState":     "inactive",
		deploy.DataSlice + " ControlGroup": "/raycontrol.slice/raycontrol-data.slice",
	}
	h := memoryHost{
		total:      func() int64 { return 1 << 30 },
		units:      func() []string { return []string{"rayd.service", "niko-dns.service", "niko-off.service"} },
		show:       func(u, p string) string { return props[u+" "+p] },
		cgroupRoot: root,
	}
	write("system.slice/rayd.service/memory.max", "241590272\n")
	write("raycontrol.slice/raycontrol-data.slice/niko-dns.service/memory.max", "328830976\n")
	write("raycontrol.slice/raycontrol-data.slice/memory.current", "104857600\n")
	write("raycontrol.slice/raycontrol-data.slice/memory.high", "576716800\n")

	byName := func(rs []hostcheck.Result) map[string]hostcheck.Result {
		m := map[string]hostcheck.Result{}
		for _, r := range rs {
			m[r.Name] = r
		}
		return m
	}
	rs := byName(memoryResults(h))
	if b := rs["memory budget"]; !b.OK || !strings.Contains(b.Detail, "921 MiB of 1024 for raycontrol: rayd 230, rayspa 64, the data plane 627 (each of its units up to 313)") {
		t.Errorf("budget %+v", b)
	}
	if l := rs["memory limits"]; !l.OK || !strings.Contains(l.Detail, "the 2 running units") {
		t.Errorf("limits %+v", l)
	}
	if _, ok := rs["data plane memory"]; ok {
		t.Error("data plane at its high mark at 100 MiB of 550")
	}

	// A container without a memory controller: memory.max is "max".
	write("raycontrol.slice/raycontrol-data.slice/niko-dns.service/memory.max", "max\n")
	// The data plane at its high mark.
	write("raycontrol.slice/raycontrol-data.slice/memory.current", "576716800\n")
	rs = byName(memoryResults(h))
	if l := rs["memory limits"]; l.OK || !strings.Contains(l.Detail, "niko-dns.service") || strings.Contains(l.Detail, "rayd.service") {
		t.Errorf("limits %+v", l)
	}
	if d := rs["data plane memory"]; d.OK || !strings.Contains(d.Detail, "uses 550 MiB, at its high mark 550 MiB") {
		t.Errorf("data plane %+v", d)
	}

	// The host's memory not known: nothing.
	h.total = func() int64 { return 0 }
	if rs := memoryResults(h); len(rs) != 0 {
		t.Errorf("without the host's memory: %+v", rs)
	}
}

func TestSameLimit(t *testing.T) {
	for _, c := range []struct {
		kernel, systemd string
		want            bool
	}{
		{"328830976", "328830976", true},
		{"328826880", "328830976", true}, // a page less
		{"max", "328830976", false},
		{"104857600", "328830976", false},
		{"328830976", "infinity", false},
	} {
		if got := sameLimit(c.kernel, c.systemd); got != c.want {
			t.Errorf("sameLimit(%s, %s) = %v", c.kernel, c.systemd, got)
		}
	}
}
