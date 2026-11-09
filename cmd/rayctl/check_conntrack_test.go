package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rayctl check on the conntrack table: big enough, raised by apply, not
// changeable here (a container), a hashsize option in modprobe.d.
func TestConntrackCheck(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	mem := write("meminfo", "MemTotal:        2097152 kB\n")
	big := write("max-big", "262144\n")
	small := write("max-small", "65536\n")
	if r := conntrackResults(conntrackPaths{max: big, meminfo: mem}); len(r) != 1 || !r[0].OK || !strings.Contains(r[0].Detail, "131072") {
		t.Errorf("big enough: %+v", r)
	}
	if r := conntrackResults(conntrackPaths{max: small, meminfo: mem}); !r[0].OK || !strings.Contains(r[0].Detail, "rayctl apply raises it to 131072") {
		t.Errorf("to raise: %+v", r)
	}
	if r := conntrackResults(conntrackPaths{max: filepath.Join(dir, "none"), meminfo: mem}); !r[0].OK || !strings.Contains(r[0].Detail, "not loaded") {
		t.Errorf("no module: %+v", r)
	}
	// A key root may read and not write, as in a container.
	if os.Geteuid() == 0 {
		if b, err := os.ReadFile("/proc/sys/kernel/ngroups_max"); err == nil && strings.TrimSpace(string(b)) == "65536" {
			r := conntrackResults(conntrackPaths{max: "/proc/sys/kernel/ngroups_max", meminfo: mem})
			if r[0].OK || !strings.Contains(r[0].Detail, "cannot be changed here") || !strings.Contains(r[0].Detail, "131072 for 2048 MiB") {
				t.Errorf("a container: %+v", r)
			}
		}
	}
	write("nf.conf", "# tuned\noptions nf_conntrack hashsize=4096 expect_hashsize=64\n")
	r := conntrackResults(conntrackPaths{max: big, meminfo: mem, modprobe: []string{filepath.Join(dir, "*.conf")}})
	if len(r) != 2 || r[1].OK || !strings.Contains(r[1].Detail, "8 × hashsize") {
		t.Errorf("hashsize: %+v", r)
	}
}
