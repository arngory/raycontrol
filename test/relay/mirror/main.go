// Command mirror serves a directory as a mirror of GitHub's releases, for
// test/relay/host.sh: rayctl asks a mirror for the prefix followed by the
// whole GitHub URL (RAYCONTROL_MIRRORS="http://HOST:PORT/"), which is
// DIR/https:/github.com/OWNER/REPO/releases/download/VERSION/FILE here.
// Each request goes to standard output.
//
//	mirror -dir DIR [-addr :8080]
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	dir := flag.String("dir", "", "the directory served")
	addr := flag.String("addr", ":8080", "where to listen")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "usage: mirror -dir DIR [-addr :8080]")
		os.Exit(2)
	}
	// The file server itself, not a ServeMux: the mux would redirect the
	// path's "//" away.
	files := http.FileServer(http.Dir(*dir))
	srv := &http.Server{Addr: *addr, ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Printf("%s %s %s\n", time.Now().UTC().Format(time.RFC3339), r.Method, r.URL.Path)
			files.ServeHTTP(w, r)
		})}
	log.Fatal(srv.ListenAndServe())
}
