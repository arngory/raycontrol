package stats

// Host is the host's counters at one moment, from /proc and the file
// system of the node's state. OK is false when they could not be read.
type Host struct {
	OK bool
	// CPU time in clock ticks, all CPUs together: busy is everything but
	// idle and iowait; CPUs is how many the kernel lists.
	CPUBusy, CPUTotal uint64
	CPUs              int
	// Memory in bytes: total, and what is available without swapping.
	MemTotal, MemAvailable uint64
	Load                   [3]float64
	// Every interface but lo, summed: bytes, packets, errors and drops.
	Net NetCounters
	// The file system of the node's state: bytes free to rayd, and its size.
	DiskFree, DiskTotal uint64
	Uptime              float64 // seconds since boot
}

// NetCounters are an interface's (or a sum's) counters from /proc/net/dev.
type NetCounters struct {
	RxBytes   uint64 `json:"rx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	RxDrops   uint64 `json:"rx_drops"`
	TxBytes   uint64 `json:"tx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
	TxErrors  uint64 `json:"tx_errors"`
	TxDrops   uint64 `json:"tx_drops"`
}

func (a NetCounters) add(b NetCounters) NetCounters {
	return NetCounters{
		RxBytes: a.RxBytes + b.RxBytes, RxPackets: a.RxPackets + b.RxPackets, RxErrors: a.RxErrors + b.RxErrors, RxDrops: a.RxDrops + b.RxDrops,
		TxBytes: a.TxBytes + b.TxBytes, TxPackets: a.TxPackets + b.TxPackets, TxErrors: a.TxErrors + b.TxErrors, TxDrops: a.TxDrops + b.TxDrops,
	}
}
