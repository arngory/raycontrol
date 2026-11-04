// Command testcert writes a test certificate for a node's site: chain.pem,
// key.pem and root.pem (for the clients) in a directory. Load it with
// rayctl service cert site -chain chain.pem -key key.pem. Tests only.
//
//	go run ./test/supervise/testcert -o DIR '*.example.test'
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/arngory/raycontrol/internal/testca"
)

func main() {
	dir := flag.String("o", ".", "output directory")
	days := flag.Int("days", 30, "validity")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: testcert [-o DIR] [-days N] NAME...")
		os.Exit(2)
	}
	now := time.Now()
	c, err := testca.New(flag.Args(), now.Add(-time.Hour), now.Add(time.Duration(*days)*24*time.Hour))
	if err != nil {
		fmt.Fprintln(os.Stderr, "testcert:", err)
		os.Exit(1)
	}
	for name, b := range map[string][]byte{"chain.pem": c.ChainPEM, "key.pem": c.KeyPEM, "root.pem": c.RootPEM} {
		mode := os.FileMode(0o644)
		if name == "key.pem" {
			mode = 0o600
		}
		if err := os.WriteFile(filepath.Join(*dir, name), b, mode); err != nil {
			fmt.Fprintln(os.Stderr, "testcert:", err)
			os.Exit(1)
		}
	}
}
