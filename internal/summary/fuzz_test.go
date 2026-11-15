package summary

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/provision"
)

// countingReader counts what Parse reads of a body.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// FuzzParse: a client's summary (probe-v1 §6, any device's, over the
// node's public probe endpoint) is taken only as the buckets and bounds
// say, by an oracle of its own, and no more of its body is read than
// MaxBody and a byte; what is taken reads back the same once written
// again, so the counters it goes into hold buckets only.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		`{"v":1,"net":"cellular","obs":[{"svc":3,"result":"works","tcp_stall_kib":16,"udp":"0-1","mbps":"5-20"},{"svc":4,"result":"fails"}]}`,
		`{"v":1,"net":"wifi","udp_mtu":"1350-1472","path":"relay","obs":[{"svc":1,"result":"works","dns":"tcp"}]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":1,"result":"works","zone":0},{"svc":2,"result":"degraded","zone":4},{"svc":3,"result":"works"}]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":1,"result":"works"},{"svc":1,"result":"fails"}]}`,
		`{"v":1,"net":"wifi","mcc_mnc":"25001","obs":[{"svc":1,"result":"works"}]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":1,"result":"fails","dns":"doh"}]}`,
		`{"v":1,"net":"wifi","obs":[{"svc":65536,"result":"works","zone":-1}]}`,
		`{"V":1,"NET":"wifi","Obs":[{"SVC":1,"Result":"works"}],"v":1} trailing`,
		`{"v":1.0,"net":"wifi","obs":[{"svc":1e0,"result":"works"}]}`,
		`{"v":1,"net":"wifi","obs":[` + strings.Repeat(`{"svc":1,"result":"works"},`, 200) + `{"svc":2,"result":"works"}]}`,
		strings.Repeat(" ", MaxBody) + `{}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		c := &countingReader{r: bytes.NewReader(body)}
		r, err := Parse(c)
		if c.n > MaxBody+1 {
			t.Fatalf("%d bytes of the body read", c.n)
		}
		if err != nil {
			return
		}
		switch {
		case len(body) > MaxBody:
			t.Fatalf("a body of %d bytes taken", len(body))
		case r.V != 1 || !slices.Contains(Nets, r.Net):
			t.Fatalf("v %d, net %q taken", r.V, r.Net)
		case r.UDPMTU != "" && !slices.Contains(MTUs, r.UDPMTU), r.Path != "" && !slices.Contains(Paths, r.Path):
			t.Fatalf("udp_mtu %q, path %q taken", r.UDPMTU, r.Path)
		case len(r.Obs) < 1 || len(r.Obs) > MaxObs:
			t.Fatalf("%d observations taken", len(r.Obs))
		}
		for i, o := range r.Obs {
			bad := o.Svc < 1 || o.Svc > 65535 || slices.ContainsFunc(r.Obs[:i], func(p Obs) bool { return p.Svc == o.Svc }) ||
				!slices.Contains(Results, o.Result) || o.TCPStallKiB != 0 && !slices.Contains(Stalls, o.TCPStallKiB) ||
				o.UDP != "" && !slices.Contains(UDP, o.UDP) || o.Mbps != "" && !slices.Contains(Mbps, o.Mbps) ||
				o.DNS != "" && (!slices.Contains(Resolvers, o.DNS) || o.Result == "fails") ||
				o.Zone != nil && (*o.Zone < 0 || *o.Zone > provision.MaxSpareZones || o.Result == "fails")
			if bad {
				t.Fatalf("observation %+v taken", o)
			}
		}
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		again, err := Parse(bytes.NewReader(b))
		if err != nil || !reflect.DeepEqual(again, r) {
			t.Fatalf("%s read back as %+v: %v", b, again, err)
		}
	})
}
