// Command asndb writes a test AS database (MMDB, IPinfo Lite layout) that
// puts the given networks in AS64512 "Test Net": the install test imports it
// (rayctl summary db) so that reports from its private network count under
// an AS and give hints (R4-21).
//
//	go run ./test/install/asndb -o asn-test.mmdb 0.0.0.0/0
package main

import (
	"flag"
	"log"
	"net"
	"os"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func main() {
	out := flag.String("o", "asn-test.mmdb", "output file")
	flag.Parse()
	tree, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "raycontrol-test-asn", RecordSize: 24, IncludeReservedNetworks: true})
	if err != nil {
		log.Fatal(err)
	}
	rec := mmdbtype.Map{"asn": mmdbtype.String("AS64512"), "as_name": mmdbtype.String("Test Net"), "country_code": mmdbtype.String("ZZ")}
	for _, cidr := range flag.Args() {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatal(err)
		}
		if err := tree.Insert(network, rec); err != nil {
			log.Fatal(err)
		}
	}
	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := tree.WriteTo(f); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
}
