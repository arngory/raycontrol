package memlimit

import (
	"log/slog"
	"os"
	"runtime/debug"
	"strconv"
)

// The Go memory limit's share of the cgroup's limit (GoLimit) for
// raycontrol's processes: 7/8, as niko-server's backends and Xray; the
// rest is for the sockets' buffers the kernel charges to the cgroup and
// the runtime does not see.
const goLimitNum, goLimitDen = 7, 8

// Start gives the Go runtime a memory limit from the process's cgroup at
// its start, when GOMEMLIMIT is not set and the cgroup has a limit below
// the host's memory; one line in log says so, with the figures. Without
// such a limit it does nothing: a soft limit at the host's memory would do
// nothing either. Go (1.27) reads cpu.max of its cgroup, not memory.max.
// It returns the limits it read, for budgets sized by them.
func Start(log *slog.Logger) Limits {
	l := Read(System)
	start(log, l, os.Getenv, debug.SetMemoryLimit)
	return l
}

func start(log *slog.Logger, l Limits, getenv func(string) string, set func(int64) int64) int64 {
	n := SetGoLimit(l, goLimitNum, goLimitDen, getenv, set)
	if n > 0 && log != nil {
		log.Info("memory: Go memory limit from the cgroup",
			"memory_max", mibOrNone(l.Max, l), "memory_high", mibOrNone(l.High, l),
			"host_mib", l.MemTotal>>20, "go_limit_mib", n>>20,
			"share", strconv.Itoa(goLimitNum)+"/"+strconv.Itoa(goLimitDen)+" of the less of high and 15/16 of max, 64 MiB at least")
	}
	return n
}

// mibOrNone is n in MiB, or "none" when it limits nothing below the host.
func mibOrNone(n int64, l Limits) string {
	if (Limits{Max: n, MemTotal: l.MemTotal}).Limit() == 0 {
		return "none"
	}
	return strconv.FormatInt(n>>20, 10) + " MiB"
}
