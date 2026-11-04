package asn

import (
	"context"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// DB is an MMDB file: IPinfo Lite (asn "AS13335", as_name, country_code) or
// MaxMind's GeoLite2/GeoIP2 ASN layout (autonomous_system_number,
// autonomous_system_organization). The file may come, go or be replaced
// while the node runs: each lookup looks at it (a stat) and opens it again
// when it changed. It answers for any address it holds, private ones too:
// a test database may map a test network to an AS.
type DB struct {
	Path string

	mu   sync.Mutex
	r    *maxminddb.Reader
	mod  time.Time
	size int64
}

// record holds the fields of both layouts.
type record struct {
	ASN         string `maxminddb:"asn"`
	ASName      string `maxminddb:"as_name"`
	CountryCode string `maxminddb:"country_code"`
	GeoASN      uint32 `maxminddb:"autonomous_system_number"`
	GeoOrg      string `maxminddb:"autonomous_system_organization"`
}

// reader returns the open file, opening it again if it changed.
func (d *DB) reader() *maxminddb.Reader {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, err := os.Stat(d.Path)
	if err != nil {
		if d.r != nil {
			_ = d.r.Close()
			d.r = nil
		}
		return nil
	}
	if d.r != nil && st.ModTime().Equal(d.mod) && st.Size() == d.size {
		return d.r
	}
	r, err := maxminddb.Open(d.Path)
	if err != nil {
		return d.r // keep the previous one while a new file is half written
	}
	if d.r != nil {
		_ = d.r.Close()
	}
	d.r, d.mod, d.size = r, st.ModTime(), st.Size()
	return r
}

// Lookup finds the AS of addr.
func (d *DB) Lookup(_ context.Context, addr netip.Addr) (Info, bool) {
	r := d.reader()
	if r == nil {
		return Info{}, false
	}
	var rec record
	res := r.Lookup(addr.Unmap())
	if !res.Found() || res.Decode(&rec) != nil {
		return Info{}, false
	}
	if n, ok := ParseASN(rec.ASN); ok {
		return Info{ASN: n, Name: rec.ASName, Country: rec.CountryCode}, true
	}
	if rec.GeoASN != 0 {
		return Info{ASN: rec.GeoASN, Name: rec.GeoOrg}, true
	}
	return Info{}, false
}

// Built returns when the file was built (its metadata) and its database
// type; ok is false without a readable file.
func (d *DB) Built() (built time.Time, kind string, ok bool) {
	r := d.reader()
	if r == nil {
		return time.Time{}, "", false
	}
	return r.Metadata.BuildTime(), r.Metadata.DatabaseType, true
}

// Check opens an MMDB file and looks up a well-known address, to vet a
// file before it replaces the node's database.
func Check(path string) (built time.Time, kind string, err error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return time.Time{}, "", err
	}
	defer func() { _ = r.Close() }()
	return r.Metadata.BuildTime(), r.Metadata.DatabaseType, nil
}
