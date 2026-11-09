package deploy_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/deploy"
)

// The table's size by memory (spec/conn-limit-v1.md §6.1): MemTotal / 16
// KiB, up to a power of two, within 65 536 and 262 144.
func TestConntrackSize(t *testing.T) {
	for kib, want := range map[uint64]uint64{
		0: 65536, 512 << 10: 65536, 1 << 20: 65536, 1<<20 - 30<<10: 65536, 1536 << 10: 131072, 2 << 20: 131072,
		4 << 20: 262144, 4<<20 - 100<<10: 262144, 16 << 20: 262144,
	} {
		if got := deploy.ConntrackSize(kib); got != want {
			t.Errorf("%d KiB: %d, want %d", kib, got, want)
		}
	}
}

// Which keys apply writes: the size only up, the times only down, either
// also while the live value is the file's (raycontrol's); a size not
// writable here, never.
func TestConntrackKeys(t *testing.T) {
	all := map[string]bool{deploy.ConntrackMaxKey: true, deploy.ConntrackBucketsKey: true}
	kernel := map[string]uint64{deploy.ConntrackMaxKey: 65536, deploy.ConntrackBucketsKey: 65536,
		deploy.SynSentKey: 120, deploy.FinWaitKey: 120, deploy.TimeWaitKey: 120}
	str := func(keys []deploy.ConntrackKey) string {
		var b []string
		for _, k := range keys {
			b = append(b, fmt.Sprintf("%s=%d", strings.TrimPrefix(k.Key, "net.netfilter.nf_conntrack_"), k.Value))
		}
		return strings.Join(b, " ")
	}
	with := func(m map[string]uint64, kv ...any) map[string]uint64 {
		out := map[string]uint64{}
		for k, v := range m {
			out[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			out[kv[i].(string)] = uint64(kv[i+1].(int))
		}
		return out
	}
	for name, c := range map[string]struct {
		size       uint64
		live, file map[string]uint64
		writable   map[string]bool
		want       string
	}{
		"the kernel's":       {131072, kernel, nil, all, "max=131072 buckets=131072 tcp_timeout_syn_sent=30 tcp_timeout_fin_wait=30 tcp_timeout_time_wait=60"},
		"1 GiB, already big": {65536, kernel, nil, all, "tcp_timeout_syn_sent=30 tcp_timeout_fin_wait=30 tcp_timeout_time_wait=60"},
		"the admin's": {131072, with(kernel, deploy.ConntrackMaxKey, 524288, deploy.SynSentKey, 10, deploy.TimeWaitKey, 60), nil, all,
			"buckets=131072 tcp_timeout_fin_wait=30"},
		"ours, the memory grew": {262144, with(kernel, deploy.ConntrackMaxKey, 131072, deploy.ConntrackBucketsKey, 131072, deploy.SynSentKey, 30),
			map[string]uint64{deploy.ConntrackMaxKey: 131072, deploy.ConntrackBucketsKey: 131072, deploy.SynSentKey: 30}, all,
			"max=262144 buckets=262144 tcp_timeout_syn_sent=30 tcp_timeout_fin_wait=30 tcp_timeout_time_wait=60"},
		"ours, the memory shrank": {65536, with(kernel, deploy.ConntrackMaxKey, 131072), map[string]uint64{deploy.ConntrackMaxKey: 131072}, all,
			"max=65536 tcp_timeout_syn_sent=30 tcp_timeout_fin_wait=30 tcp_timeout_time_wait=60"},
		"ours once, the admin's now": {131072, with(kernel, deploy.TimeWaitKey, 20), map[string]uint64{deploy.TimeWaitKey: 60}, all,
			"max=131072 buckets=131072 tcp_timeout_syn_sent=30 tcp_timeout_fin_wait=30"},
		"a container":  {131072, kernel, nil, nil, "tcp_timeout_syn_sent=30 tcp_timeout_fin_wait=30 tcp_timeout_time_wait=60"},
		"not readable": {131072, map[string]uint64{deploy.SynSentKey: 120}, nil, all, "tcp_timeout_syn_sent=30"},
	} {
		if got := str(deploy.ConntrackKeys(c.size, c.live, c.file, c.writable)); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

// fakeKernel is a host's sysctl keys: read, set (unless locked), loaded
// from a file.
type fakeKernel struct {
	root   string
	vals   map[string]string
	locked map[string]bool
	cmds   []string
}

func (k *fakeKernel) run(name string, args ...string) ([]byte, error) {
	cmd := name + " " + strings.Join(args, " ")
	k.cmds = append(k.cmds, cmd)
	set := func(kv string) error {
		key, v, _ := strings.Cut(kv, "=")
		key = strings.TrimSpace(key)
		if k.locked[key] {
			return errors.New("permission denied")
		}
		k.vals[key] = strings.TrimSpace(v)
		return nil
	}
	switch {
	case name == "sysctl" && len(args) == 2 && args[0] == "-n":
		v, ok := k.vals[args[1]]
		if !ok {
			return []byte("sysctl: cannot stat\n"), errors.New("exit status 255")
		}
		return []byte(v + "\n"), nil
	case name == "sysctl" && len(args) == 3 && args[1] == "-w":
		if err := set(args[2]); err != nil {
			return []byte("sysctl: permission denied\n"), err
		}
	case name == "sysctl" && len(args) == 4 && args[2] == "-p":
		b, err := os.ReadFile(filepath.Join(k.root, args[3]))
		if err != nil {
			return nil, err
		}
		var failed error
		for _, line := range strings.Split(string(b), "\n") {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if err := set(line); err != nil {
				failed = err
			}
		}
		return nil, failed
	}
	return nil, nil
}

func memHost(t *testing.T, mib int, k *fakeKernel) *deploy.Host {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(k.root, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(k.root, "proc/meminfo"), []byte(fmt.Sprintf("MemTotal:       %d kB\nMemFree: 1 kB\n", mib<<10)), 0o644); err != nil {
		t.Fatal(err)
	}
	j, err := deploy.OpenJournal(k.root)
	if err != nil {
		t.Fatal(err)
	}
	return &deploy.Host{Root: k.root, Run: k.run, Out: &bytes.Buffer{}, Journal: j, LookPath: func(string) (string, error) { return "", errors.New("none") }}
}

func kernelDefaults(root string) *fakeKernel {
	return &fakeKernel{root: root, vals: map[string]string{deploy.ConntrackMaxKey: "65536", deploy.ConntrackBucketsKey: "65536",
		deploy.SynSentKey: "120", deploy.FinWaitKey: "120", deploy.TimeWaitKey: "120"}}
}

// apply on a 2 GiB node: the table and the times at once, the module at
// boot, the values before journaled; the next apply changes nothing; a
// time the administrator lowers since is left alone, by apply and by
// uninstall, which puts the rest back and removes the files.
func TestHostConntrack(t *testing.T) {
	k := kernelDefaults(t.TempDir())
	h := memHost(t, 2048, k)
	if err := h.Apply(deploy.Plan{Conntrack: true}); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{deploy.ConntrackMaxKey: "131072", deploy.ConntrackBucketsKey: "131072",
		deploy.SynSentKey: "30", deploy.FinWaitKey: "30", deploy.TimeWaitKey: "60"} {
		if k.vals[key] != want {
			t.Errorf("%s = %s, want %s", key, k.vals[key], want)
		}
	}
	if b, err := os.ReadFile(filepath.Join(k.root, deploy.ModulesLoad)); err != nil || !strings.Contains(string(b), "\nnf_conntrack\n") {
		t.Fatalf("modules-load.d: %q %v", b, err)
	}
	for _, key := range []string{deploy.ConntrackMaxKey, deploy.SynSentKey, deploy.TimeWaitKey} {
		if c, ok := h.Journal.Original(deploy.ChangeSysctl, "", key); !ok || c.Value != map[string]string{deploy.ConntrackMaxKey: "65536"}[key] && c.Value != "120" {
			t.Errorf("%s not journaled: %+v", key, c)
		}
	}
	file := func() string {
		b, _ := os.ReadFile(filepath.Join(k.root, deploy.ConntrackSysctl))
		return string(b)
	}
	first := file()
	k.cmds = nil
	if err := h.Apply(deploy.Plan{Conntrack: true}); err != nil {
		t.Fatal(err)
	}
	if file() != first || strings.Contains(strings.Join(k.cmds, "\n"), "-p "+deploy.ConntrackSysctl) {
		t.Fatalf("the second apply changed it: %q\n%v", file(), k.cmds)
	}
	// The administrator lowers TIME_WAIT further: not raised again.
	k.vals[deploy.TimeWaitKey] = "20"
	if err := h.Apply(deploy.Plan{Conntrack: true}); err != nil {
		t.Fatal(err)
	}
	if k.vals[deploy.TimeWaitKey] != "20" || strings.Contains(file(), deploy.TimeWaitKey) {
		t.Fatalf("a shorter time raised: %s\n%s", k.vals[deploy.TimeWaitKey], file())
	}
	// Set back by hand: written again.
	k.vals[deploy.SynSentKey] = "120"
	if err := h.Apply(deploy.Plan{Conntrack: true}); err != nil {
		t.Fatal(err)
	}
	if k.vals[deploy.SynSentKey] != "30" {
		t.Fatalf("a time set back by hand: %s", k.vals[deploy.SynSentKey])
	}
	if err := h.Uninstall(h.Journal, deploy.UninstallOptions{}); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{deploy.ConntrackMaxKey: "65536", deploy.ConntrackBucketsKey: "65536",
		deploy.SynSentKey: "120", deploy.FinWaitKey: "120", deploy.TimeWaitKey: "20"} {
		if k.vals[key] != want {
			t.Errorf("after uninstall %s = %s, want %s", key, k.vals[key], want)
		}
	}
	for _, f := range []string{deploy.ConntrackSysctl, deploy.ModulesLoad} {
		if _, err := os.Stat(filepath.Join(k.root, f)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left: %v", f, err)
		}
	}
}

// Values the administrator set before: a bigger table and shorter times
// stay, at apply and at uninstall.
func TestHostConntrackAdmin(t *testing.T) {
	k := kernelDefaults(t.TempDir())
	k.vals[deploy.ConntrackMaxKey], k.vals[deploy.SynSentKey] = "1048576", "10"
	h := memHost(t, 4096, k)
	if err := h.Apply(deploy.Plan{Conntrack: true}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(k.root, deploy.ConntrackSysctl))
	if strings.Contains(string(b), deploy.ConntrackMaxKey) || strings.Contains(string(b), deploy.SynSentKey) ||
		!strings.Contains(string(b), deploy.ConntrackBucketsKey+" = 262144") {
		t.Fatalf("file:\n%s", b)
	}
	if err := h.Uninstall(h.Journal, deploy.UninstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if k.vals[deploy.ConntrackMaxKey] != "1048576" || k.vals[deploy.SynSentKey] != "10" || k.vals[deploy.ConntrackBucketsKey] != "65536" {
		t.Fatalf("after uninstall: %v", k.vals)
	}
}

// A container: the size cannot change there (only the initial network
// namespace has it); apply says so with the numbers and sets the times.
func TestHostConntrackContainer(t *testing.T) {
	k := kernelDefaults(t.TempDir())
	k.locked = map[string]bool{deploy.ConntrackMaxKey: true, deploy.ConntrackBucketsKey: true}
	h := memHost(t, 2048, k)
	if err := h.Apply(deploy.Plan{Conntrack: true}); err != nil {
		t.Fatal(err)
	}
	out := h.Out.(*bytes.Buffer).String()
	if !strings.Contains(out, "cannot be changed here") || !strings.Contains(out, "would set 131072 for 2048 MiB") {
		t.Fatalf("no warning: %q", out)
	}
	b, _ := os.ReadFile(filepath.Join(k.root, deploy.ConntrackSysctl))
	if strings.Contains(string(b), "nf_conntrack_max") || k.vals[deploy.TimeWaitKey] != "60" {
		t.Fatalf("file:\n%s\ntime_wait %s", b, k.vals[deploy.TimeWaitKey])
	}
	if strings.Contains(out, "another sysctl file overrides") {
		t.Fatalf("a misleading warning: %q", out)
	}
}
