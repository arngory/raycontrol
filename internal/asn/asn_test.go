package asn

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// writeMMDB writes a database with one network and its record.
func writeMMDB(t *testing.T, path, kind, cidr string, rec mmdbtype.Map) {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: kind, RecordSize: 24, IncludeReservedNetworks: true})
	if err != nil {
		t.Fatal(err)
	}
	_, network, _ := net.ParseCIDR(cidr)
	if err := tree.Insert(network, rec); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := tree.WriteTo(f); err != nil {
		t.Fatal(err)
	}
}

func ipinfoRecord(asn, name, cc string) mmdbtype.Map {
	return mmdbtype.Map{"asn": mmdbtype.String(asn), "as_name": mmdbtype.String(name), "country_code": mmdbtype.String(cc),
		"country": mmdbtype.String("Somewhere"), "network": mmdbtype.String("x")}
}

func TestDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lite.mmdb")
	db := &DB{Path: path}
	if _, ok := db.Lookup(context.Background(), netip.MustParseAddr("203.0.113.9")); ok {
		t.Fatal("found in a missing file")
	}
	writeMMDB(t, path, "ipinfo_lite.mmdb", "203.0.113.0/24", ipinfoRecord("AS64500", "Example Net", "KZ"))
	info, ok := db.Lookup(context.Background(), netip.MustParseAddr("::ffff:203.0.113.9"))
	if !ok || info != (Info{ASN: 64500, Name: "Example Net", Country: "KZ"}) {
		t.Fatalf("lookup %+v %v", info, ok)
	}
	if _, ok := db.Lookup(context.Background(), netip.MustParseAddr("198.51.100.1")); ok {
		t.Fatal("found outside the networks")
	}
	if _, kind, ok := db.Built(); !ok || kind != "ipinfo_lite.mmdb" {
		t.Fatalf("built %q %v", kind, ok)
	}

	// Replaced by a GeoLite2 ASN layout: opened again at the next lookup.
	writeMMDB(t, path+".new", "GeoLite2-ASN", "203.0.113.0/24", mmdbtype.Map{
		"autonomous_system_number": mmdbtype.Uint32(64501), "autonomous_system_organization": mmdbtype.String("Geo Net")})
	os.Rename(path+".new", path)
	if info, ok := db.Lookup(context.Background(), netip.MustParseAddr("203.0.113.9")); !ok || info.ASN != 64501 || info.Name != "Geo Net" {
		t.Fatalf("after replacing: %+v %v", info, ok)
	}
	if _, _, err := Check(path); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "junk"), []byte("not a database"), 0o600)
	if _, _, err := Check(filepath.Join(dir, "junk")); err == nil {
		t.Fatal("junk passed the check")
	}
}

type fixed map[string]Info

func (f fixed) Lookup(_ context.Context, a netip.Addr) (Info, bool) {
	i, ok := f[a.String()]
	return i, ok
}

func TestChain(t *testing.T) {
	c := Chain{nil, fixed{"203.0.113.1": {ASN: 1}}, fixed{"203.0.113.1": {ASN: 2}, "203.0.113.2": {ASN: 3}}}
	if i, _ := c.Lookup(context.Background(), netip.MustParseAddr("203.0.113.1")); i.ASN != 1 {
		t.Fatal("first source does not win")
	}
	if i, _ := c.Lookup(context.Background(), netip.MustParseAddr("203.0.113.2")); i.ASN != 3 {
		t.Fatal("no fallback")
	}
	if _, ok := c.Lookup(context.Background(), netip.MustParseAddr("203.0.113.3")); ok {
		t.Fatal("found nowhere")
	}
	for in, want := range map[string]uint32{"AS13335": 13335, "13335": 13335, "AS0": 0, "": 0, "ASx": 0} {
		if n, _ := ParseASN(in); n != want {
			t.Errorf("ParseASN(%q) = %d", in, n)
		}
	}
	if Network(netip.MustParseAddr("203.0.113.77")).String() != "203.0.113.0/24" ||
		Network(netip.MustParseAddr("2001:db8:1:2::7")).String() != "2001:db8:1::/48" {
		t.Fatal("networks")
	}
}

// The API is asked about the network, never the address; with the token
// in a header; once per network.
func TestIPinfoAPI(t *testing.T) {
	var asked []string
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		asked = append(asked, r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer tok" || strings.Contains(r.URL.RawQuery, "tok") {
			http.Error(w, "token", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/lite/198.51.100.0" {
			http.Error(w, "nothing", http.StatusNotFound)
			return
		}
		w.Write([]byte(`{"ip":"203.0.113.0","asn":"AS64502","as_name":"Api Net","country_code":"UZ","country":"Uzbekistan"}`))
	}))
	defer srv.Close()
	api := &API{Provider: &IPinfo{Token: "tok", BaseURL: srv.URL, HTTP: srv.Client()}}
	ctx := context.Background()
	for range 3 {
		info, ok := api.Lookup(ctx, netip.MustParseAddr("203.0.113.200"))
		if !ok || info != (Info{ASN: 64502, Name: "Api Net", Country: "UZ"}) {
			t.Fatalf("lookup %+v %v", info, ok)
		}
	}
	if _, ok := api.Lookup(ctx, netip.MustParseAddr("198.51.100.9")); ok {
		t.Fatal("a failed lookup found something")
	}
	api.Lookup(ctx, netip.MustParseAddr("198.51.100.10")) // the failure is cached too
	for _, private := range []string{"10.1.2.3", "127.0.0.1", "192.168.0.1", "fe80::1"} {
		if _, ok := api.Lookup(ctx, netip.MustParseAddr(private)); ok {
			t.Fatalf("%s looked up", private)
		}
	}
	if calls.Load() != 2 || asked[0] != "/lite/203.0.113.0" || asked[1] != "/lite/198.51.100.0" {
		t.Fatalf("asked %v (%d calls)", asked, calls.Load())
	}
	if p := Providers["ipinfo"]("x", nil); p.Name() != "ipinfo" {
		t.Fatal("provider registry")
	}
}
