// Package pprofx serves Go's profiles (net/http/pprof) for a profile under
// real load on a node (O-3), on loopback or a unix socket only: profiles
// show what the process does, and they cost CPU while taken.
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
	"time"
)

// Env names the variable Start reads.
const Env = "RAYD_PPROF"

// Start serves the profiles at the address in Env, if it is set:
// unix:PATH (the socket 0600), or a loopback host:port. Anything else is
// refused.
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
	if path, ok := strings.CutPrefix(addr, "unix:"); ok {
		_ = os.Remove(path)
		ln, err := net.Listen("unix", path)
		if err != nil {
			return nil, err
		}
		if err := os.Chmod(path, 0o600); err != nil {
			ln.Close()
			return nil, err
		}
		return ln, nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return nil, errors.New("only unix:PATH or a loopback address (127.0.0.1:PORT, [::1]:PORT)")
	}
	return net.Listen("tcp", addr)
}
