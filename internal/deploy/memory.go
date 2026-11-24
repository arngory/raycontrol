package deploy

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// DataSlice is the slice of the data plane's units (docs/spec/memory-v1.md
// §4): the front, the backends, Xray and the site, under one limit within
// the node's budget. rayd and rayspa are outside it, with limits of their
// own: the control plane and SSH outlive any data plane.
const DataSlice = "raycontrol-data.slice"

// dataSliceDescription is the slice unit's description.
const dataSliceDescription = "raycontrol data plane (docs/spec/memory-v1.md)"

// The node's memory as rayctl apply sizes it (docs/spec/memory-v1.md §1,
// §4): what the units are given, in bytes of a host of MemTotal.
const (
	// systemReserveCap: the system's share of the host is a tenth, but no
	// more than this, and no less than a twentieth.
	systemReserveCap = 256 << 20
	// rayspaMemory is rayspa's limit: nftables, the SPA keys, a few MiB
	// of heap.
	rayspaMemory = 64 << 20
	// raydMemoryMin, raydMemoryMax bound rayd's limit, a quarter of the
	// budget: the database, the API, subscriptions and DoH.
	raydMemoryMin = 128 << 20
	raydMemoryMax = 512 << 20
	// unitMemoryMin is a data unit's least limit.
	unitMemoryMin = 128 << 20
)

// Memory is the budget of a node with Total bytes (docs/spec/memory-v1.md
// §1, §4), each limit in bytes. Zero without a known Total: the units then
// get no memory lines.
type Memory struct {
	Total  int64 // the host's memory (MemTotal)
	Budget int64 // Total less the system's share: all of raycontrol fits in it
	Rayd   int64 // rayd's MemoryMax
	Rayspa int64 // rayspa's MemoryMax
	Slice  int64 // the data slice's MemoryMax: the budget less rayd and rayspa
	Unit   int64 // each data unit's MemoryMax: half the slice, unitMemoryMin at least
}

// MemoryOf is the budget of a host of total bytes; the zero Memory when
// total is not known (0 or less).
func MemoryOf(total int64) Memory {
	if total <= 0 {
		return Memory{}
	}
	reserve := max(total/20, min(total/10, systemReserveCap))
	m := Memory{Total: total, Budget: total - reserve, Rayspa: rayspaMemory}
	m.Rayd = min(max(m.Budget/4, raydMemoryMin), raydMemoryMax)
	// A host too small for the slice's least (under some 400 MiB): the
	// slice gets a unit's least; rayctl check says the host is too small.
	m.Slice = max(m.Budget-m.Rayd-m.Rayspa, unitMemoryMin)
	m.Unit = max(m.Slice/2, unitMemoryMin)
	return m
}

// high is the MemoryHigh of a MemoryMax: 7/8 of it, where the kernel
// throttles and reclaims before it kills.
func high(n int64) int64 { return n / 8 * 7 }

// Share is n as systemd's share of the host's memory: a percentage with
// two decimals (systemd takes no more), rounded down, 0.01% at least.
// systemd recomputes it when the host's size changes; rayctl apply
// recomputes the bytes.
func (m Memory) Share(n int64) string {
	pm := max(n*10000/m.Total, 1) // per ten thousand
	return fmt.Sprintf("%d.%02d%%", pm/100, pm%100)
}

// shareLine matches a share as Share writes it, at most 100.00%.
var shareLine = regexp.MustCompile(`^(100\.00|[1-9]?[0-9]\.[0-9]{2})%$`)

// memoryShareLine reports whether a unit's line is a memory limit as a
// share: the one place a % may be, which systemd takes as is there.
func memoryShareLine(l string) bool {
	k, v, _ := strings.Cut(l, "=")
	return (k == "MemoryMax" || k == "MemoryHigh") && validShare(v)
}

// validShare reports whether v is a share as Share writes it, above 0.
func validShare(v string) bool { return shareLine.MatchString(v) && v != "0.00%" }

// OOM scores of the units (docs/spec/memory-v1.md §4): under the kernel's
// OOM killer a backend dies first and rayspa last.
const (
	oomRayspa  = -900
	oomRayd    = -800
	oomFront   = -500
	oomXray    = -200
	oomSite    = 0
	oomBackend = 200
)

// oomScore is the OOMScoreAdjust of a unit by its name and command line.
func oomScore(unit, execStart string) int {
	switch unit {
	case "rayspa.service":
		return oomRayspa
	case "rayd.service":
		return oomRayd
	case "niko-front.service":
		return oomFront
	}
	f := strings.Fields(execStart)
	switch {
	case len(f) > 0 && path.Base(f[0]) == "xray":
		return oomXray
	case len(f) > 1 && path.Base(f[0]) == "rayd" && f[1] == "site":
		return oomSite
	}
	return oomBackend
}

// controlUnit reports whether a unit is of the control plane: outside the
// data slice.
func controlUnit(unit string) bool { return unit == "rayd.service" || unit == "rayspa.service" }

// lines are a node unit's memory lines: its slice (data units), its limits
// and its OOM score; none without a known Total.
func (m Memory) lines(u unit) []string {
	if m.Total <= 0 {
		return nil
	}
	limit := m.Unit
	switch u.name {
	case "rayd.service":
		limit = m.Rayd
	case "rayspa.service":
		limit = m.Rayspa
	}
	var exec string
	for _, l := range u.service {
		if v, ok := strings.CutPrefix(l, "ExecStart="); ok {
			exec = v
		}
	}
	var out []string
	if !controlUnit(u.name) {
		out = append(out, "Slice="+DataSlice)
	}
	return append(out,
		"MemoryMax="+m.Share(limit),
		"MemoryHigh="+m.Share(high(limit)),
		"OOMPolicy=stop",
		"OOMScoreAdjust="+strconv.Itoa(oomScore(u.name, exec)),
	)
}

// sliceFile is the data slice's unit.
func (m Memory) sliceFile() File {
	return File{Path: UnitPath(DataSlice), Mode: 0o644, Content: []byte(sliceContent(m.Share(m.Slice), m.Share(high(m.Slice))))}
}

func sliceContent(memoryMax, memoryHigh string) string {
	return "# Generated by raycontrol; changes are overwritten by rayctl apply.\n[Unit]\nDescription=" + dataSliceDescription +
		"\n\n[Slice]\nMemoryMax=" + memoryMax + "\nMemoryHigh=" + memoryHigh + "\n"
}

// checkSlice checks the data slice's unit: as sliceFile writes it, with
// two shares.
func checkSlice(content string) error {
	var memoryMax, memoryHigh string
	for _, l := range strings.Split(content, "\n") {
		if v, ok := strings.CutPrefix(l, "MemoryMax="); ok {
			memoryMax = v
		}
		if v, ok := strings.CutPrefix(l, "MemoryHigh="); ok {
			memoryHigh = v
		}
	}
	if !validShare(memoryMax) || !validShare(memoryHigh) || content != sliceContent(memoryMax, memoryHigh) {
		return fmt.Errorf("not the data slice as rayctl writes it")
	}
	return nil
}
