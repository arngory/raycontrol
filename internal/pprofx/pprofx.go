// Package pprofx serves Go's profiles (net/http/pprof) for a profile under
// real load on a node (O-3), on a unix socket only: profiles show what the
// process does, and they cost CPU while taken. Not on loopback: the data
// plane's processes reach loopback (S-2 leaves it to them), not a 0600
// socket of root or rayd.
//
//	RAYD_PPROF=unix:/run/raycontrol/rayd-pprof.sock   (any rayd command)
//	curl --unix-socket /run/raycontrol/rayd-pprof.sock -o cpu.pb.gz 'http://x/debug/pprof/profile?seconds=30'
package pprofx

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"syscall"
	"time"
)

// Env names the variable Start reads.
const Env = "RAYD_PPROF"

// Start serves the profiles at the address in Env, if it is set: unix:PATH,
// the socket its owner's only (made under umask 077, so never wider even
// for a moment). Anything else is refused.
func Start(log *slog.Logger) error {
	addr := os.Getenv(Env)
	if addr == "" {
		return nil
	}
	ln, err := listen(addr)
	if err != nil {
		return fmt.Errorf("%s: %w", Env, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	log.Warn("profiles served (RAYD_PPROF): for measurements only", "addr", ln.Addr().String())
	return nil
}

func listen(addr string) (net.Listener, error) {
	path, ok := strings.CutPrefix(addr, "unix:")
	if !ok || path == "" {
		return nil, errors.New("only unix:PATH (a socket for its owner only)")
	}
	_ = os.Remove(path)
	// Start runs first thing in main, before other goroutines make files.
	old := syscall.Umask(0o077)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	return ln, err
}
