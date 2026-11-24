package deploy_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/deploy"
	"github.com/arngory/raycontrol/internal/render"
)

const mib = 1 << 20

// The budget (docs/spec/memory-v1.md §1, §4): the system's tenth on a small
// host, 256 MiB at most, a twentieth at least; rayd a quarter of the rest
// within 128–512 MiB, rayspa 64 MiB, the data slice what is left, each data
// unit half of it, 128 MiB at least.
func TestMemoryOf(t *testing.T) {
	for _, c := range []struct {
		total                                         int64
		budget, rayd, rayspa, slice, unitLimit        int64
		raydShare, sliceShare, unitShare, rayspaShare string
	}{
		// 512 MiB: a tenth (51.2 MiB) for the system.
		{512 * mib, 512*mib - 53687091, 128 * mib, 64 * mib, 512*mib - 53687091 - 192*mib, (512*mib - 53687091 - 192*mib) / 2,
			"25.00%", "52.50%", "26.24%", "12.50%"},
		// 4 GiB: 256 MiB for the system (a tenth would be 409.6).
		{4096 * mib, 3840 * mib, 512 * mib, 64 * mib, 3264 * mib, 1632 * mib, "12.50%", "79.68%", "39.84%", "1.56%"},
		// 16 GiB: a twentieth (819.2 MiB) for the system.
		{16384 * mib, 16384*mib - 858993459, 512 * mib, 64 * mib, 16384*mib - 858993459 - 576*mib, (16384*mib - 858993459 - 576*mib) / 2,
			"3.12%", "91.48%", "45.74%", "0.39%"},
		// 256 MiB: too small; the slice and units get their least.
		{256 * mib, 256*mib - 26843545, 128 * mib, 64 * mib, 128 * mib, 128 * mib, "50.00%", "50.00%", "50.00%", "25.00%"},
	} {
		m := deploy.MemoryOf(c.total)
		got := []int64{m.Budget, m.Rayd, m.Rayspa, m.Slice, m.Unit}
		want := []int64{c.budget, c.rayd, c.rayspa, c.slice, c.unitLimit}
		if !slices.Equal(got, want) {
			t.Errorf("%d MiB: budget, rayd, rayspa, slice, unit %v, want %v", c.total/mib, got, want)
		}
		shares := []string{m.Share(m.Rayd), m.Share(m.Slice), m.Share(m.Unit), m.Share(m.Rayspa)}
		if wantShares := []string{c.raydShare, c.sliceShare, c.unitShare, c.rayspaShare}; !slices.Equal(shares, wantShares) {
			t.Errorf("%d MiB: shares %v, want %v", c.total/mib, shares, wantShares)
		}
	}
	if m := deploy.MemoryOf(0); m != (deploy.Memory{}) {
		t.Errorf("unknown memory: %+v", m)
	}
}

// memPlan is the test node's plan on a host of 1 GiB.
func memPlan(t *testing.T) deploy.Plan {
	t.Helper()
	in := goodInputs()
	in.MemTotal = 1 << 30
	p := deploy.Build(in, render.DefaultPaths, deploy.DefaultBinaries)
	if len(p.Warnings) != 0 {
		t.Fatalf("warnings: %v", p.Warnings)
	}
	return p
}

func unitFile(t *testing.T, p deploy.Plan, unit string) string {
	t.Helper()
	for _, f := range p.Files {
		if f.Path == deploy.UnitPath(unit) {
			return string(f.Content)
		}
	}
	t.Fatalf("no %s in the plan", unit)
	return ""
}

// With the host's memory each unit has its limits and OOM score, the data
// units are in the data slice, and the plan passes its check; without it
// there are none.
func TestBuildMemory(t *testing.T) {
	p := memPlan(t)
	if err := p.Check(); err != nil {
		t.Fatal(err)
	}
	slice := unitFile(t, p, deploy.DataSlice)
	if !strings.Contains(slice, "\n[Slice]\nMemoryMax=61.25%\nMemoryHigh=53.59%\n") {
		t.Errorf("slice:\n%s", slice)
	}
	if slices.Contains(p.Units, deploy.DataSlice) {
		t.Error("the slice among the units to start")
	}
	for unit, want := range map[string][]string{
		"rayd.service":         {"MemoryMax=22.49%", "MemoryHigh=19.68%", "OOMPolicy=stop", "OOMScoreAdjust=-800"},
		"rayspa.service":       {"MemoryMax=6.25%", "MemoryHigh=5.46%", "OOMScoreAdjust=-900"},
		"niko-front.service":   {"Slice=raycontrol-data.slice", "MemoryMax=30.62%", "MemoryHigh=26.79%", "OOMScoreAdjust=-500"},
		"niko-inner.service":   {"Slice=raycontrol-data.slice", "OOMScoreAdjust=-200"},
		"niko-reality.service": {"Slice=raycontrol-data.slice", "OOMScoreAdjust=-200"},
		"niko-site.service":    {"Slice=raycontrol-data.slice", "OOMScoreAdjust=0"},
		"niko-dns.service":     {"Slice=raycontrol-data.slice", "OOMScoreAdjust=200"},
		"niko-naive.service":   {"Slice=raycontrol-data.slice", "MemoryMax=30.62%", "OOMScoreAdjust=200"},
	} {
		lines := strings.Split(unitFile(t, p, unit), "\n")
		for _, l := range want {
			if !slices.Contains(lines, l) {
				t.Errorf("%s: no %q", unit, l)
			}
		}
		if (unit == "rayd.service" || unit == "rayspa.service") && slices.ContainsFunc(lines, func(l string) bool { return strings.HasPrefix(l, "Slice=") }) {
			t.Errorf("%s in a slice", unit)
		}
	}
	// No memory known: no lines, no slice.
	plain := deploy.Build(goodInputs(), render.DefaultPaths, deploy.DefaultBinaries)
	for _, f := range plain.Files {
		if f.Path == deploy.UnitPath(deploy.DataSlice) || strings.Contains(string(f.Content), "OOMScoreAdjust") || strings.Contains(string(f.Content), "MemoryMax") {
			t.Fatalf("%s: memory lines without the host's memory", f.Path)
		}
	}
}

// What rayctl never writes of memory is refused: a score not of the unit's
// kind, rayd in the data slice, another slice, a share systemd would read
// otherwise, a line twice, a slice unit changed.
func TestPlanCheckMemory(t *testing.T) {
	const (
		dns   = "/etc/systemd/system/niko-dns.service"
		rayd  = "/etc/systemd/system/rayd.service"
		slice = "/etc/systemd/system/" + deploy.DataSlice
	)
	for name, c := range map[string]struct{ path, old, new string }{
		"a score to outlive the front": {dns, "OOMScoreAdjust=200", "OOMScoreAdjust=-1000"},
		"Xray's score on a backend":    {dns, "OOMScoreAdjust=200", "OOMScoreAdjust=-200"},
		"rayd's score unset":           {rayd, "OOMScoreAdjust=-800", "OOMScoreAdjust=0"},
		"rayd in the data slice":       {rayd, "OOMPolicy=stop", "OOMPolicy=stop\nSlice=raycontrol-data.slice"},
		"another slice":                {dns, "Slice=raycontrol-data.slice", "Slice=system.slice"},
		"OOMPolicy continue":           {dns, "OOMPolicy=stop", "OOMPolicy=continue"},
		"three decimals":               {dns, "MemoryMax=30.62%", "MemoryMax=30.625%"},
		"above the host":               {dns, "MemoryMax=30.62%", "MemoryMax=130.00%"},
		"nothing":                      {dns, "MemoryMax=30.62%", "MemoryMax=0.00%"},
		"a specifier":                  {dns, "MemoryMax=30.62%", "MemoryMax=%h"},
		"a share elsewhere":            {dns, "OOMPolicy=stop", "OOMPolicy=stop\nDescription=30.62%"},
		"MemoryMax twice":              {dns, "MemoryMax=30.62%", "MemoryMax=30.62%\nMemoryMax=99.00%"},
		"infinity":                     {dns, "MemoryMax=30.62%", "MemoryMax=infinity"},
		"a slice's line more":          {slice, "MemoryHigh=53.59%\n", "MemoryHigh=53.59%\nDelegate=yes\n"},
		"a slice's share bad":          {slice, "MemoryMax=61.25%", "MemoryMax=61%"},
		"a slice's description":        {slice, "Description=raycontrol data plane", "Description=x"},
	} {
		p := clonePlan(memPlan(t))
		edit(t, &p, c.path, c.old, c.new)
		if err := p.Check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
