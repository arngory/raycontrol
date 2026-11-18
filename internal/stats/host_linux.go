package stats

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// HostReader reads the host's counters from /proc, and the free room of
// the file system holding Dir (the node's state).
func HostReader(dir string) func() Host {
	return func() Host { return readHost("/proc", dir) }
}

func readHost(proc, dir string) Host {
	var h Host
	stat, err1 := readProc(proc, "stat")
	mem, err2 := readProc(proc, "meminfo")
	load, err3 := readProc(proc, "loadavg")
	dev, err4 := readProc(proc, "net/dev")
	up, err5 := readProc(proc, "uptime")
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil {
		return h
	}
	var ok bool
	if h.CPUBusy, h.CPUTotal, h.CPUs, ok = parseCPU(stat); !ok {
		return h
	}
	if h.MemTotal, h.MemAvailable, ok = parseMem(mem); !ok {
		return h
	}
	if h.Load, ok = parseLoad(load); !ok {
		return h
	}
	if h.Net, ok = parseNetDev(dev); !ok {
		return h
	}
	if f := strings.Fields(string(up)); len(f) > 0 {
		h.Uptime, _ = strconv.ParseFloat(f[0], 64)
	}
	if dir != "" {
		var st syscall.Statfs_t
		if err := syscall.Statfs(dir, &st); err == nil {
			h.DiskFree = st.Bavail * uint64(st.Bsize)  //nolint:gosec // G115: a block size is positive
			h.DiskTotal = st.Blocks * uint64(st.Bsize) //nolint:gosec // G115: a block size is positive
		}
	}
	h.OK = true
	return h
}

// readProc reads one of /proc's files (proc is another directory in tests).
func readProc(proc, name string) ([]byte, error) {
	return os.ReadFile(proc + "/" + name) //nolint:gosec // G304: fixed names under /proc
}

// parseCPU reads the first line of /proc/stat: user nice system idle iowait
// irq softirq steal (guest and guest_nice are within user and nice).
func parseCPU(b []byte) (busy, total uint64, cpus int, ok bool) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || !strings.HasPrefix(f[0], "cpu") {
			continue
		}
		if f[0] != "cpu" {
			cpus++
			continue
		}
		if len(f) < 5 {
			return 0, 0, 0, false
		}
		var v [8]uint64
		for i := 0; i < 8 && i+1 < len(f); i++ {
			n, err := strconv.ParseUint(f[i+1], 10, 64)
			if err != nil {
				return 0, 0, 0, false
			}
			v[i] = n
		}
		for _, n := range v {
			total += n
		}
		busy = total - v[3] - v[4]
		ok = true
	}
	return busy, total, cpus, ok
}

// parseMem reads MemTotal and MemAvailable (kB) from /proc/meminfo.
func parseMem(b []byte) (total, avail uint64, ok bool) {
	var seenT, seenA bool
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		n, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			total, seenT = n<<10, true
		case "MemAvailable:":
			avail, seenA = n<<10, true
		}
	}
	return total, avail, seenT && seenA
}

func parseLoad(b []byte) (l [3]float64, ok bool) {
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return l, false
	}
	for i := range 3 {
		v, err := strconv.ParseFloat(f[i], 64)
		if err != nil {
			return l, false
		}
		l[i] = v
	}
	return l, true
}

// parseNetDev sums /proc/net/dev over every interface but lo.
func parseNetDev(b []byte) (sum NetCounters, ok bool) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		name, rest, found := strings.Cut(sc.Text(), ":")
		if !found {
			continue // the two header lines
		}
		if strings.TrimSpace(name) == "lo" {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 12 {
			return NetCounters{}, false
		}
		var v [12]uint64
		for i := range v {
			n, err := strconv.ParseUint(f[i], 10, 64)
			if err != nil {
				return NetCounters{}, false
			}
			v[i] = n
		}
		// rx: bytes packets errs drop fifo frame compressed multicast;
		// tx: bytes packets errs drop ...
		sum = sum.add(NetCounters{RxBytes: v[0], RxPackets: v[1], RxErrors: v[2], RxDrops: v[3],
			TxBytes: v[8], TxPackets: v[9], TxErrors: v[10], TxDrops: v[11]})
	}
	return sum, true
}
