package main

import (
	"crypto/tls"
	"log/slog"
	"os"
	"time"

	"github.com/arngory/raycontrol/internal/certfile"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/site"
)

// loadCertificate reads the certificate of rayd naive or rayd site from its
// files and returns the loader that keeps it current (spec/cert-pin-v1.md
// §6): its Watch, started once the process has its context, takes a renewed
// chain as rayd writes it, so the unit is not restarted for it and no
// connection is cut. The key is the copy systemd made at the start
// (Paths.Credential): a chain for another key does not pair with it and is
// left alone until the unit restarts with the new key, which a change of
// the key file brings (internal/live).
//
// That restart can be lost (rayd stopped between the write and systemctl).
// rayd makes it again at its next apply (internal/live), and the process
// does not wait for that for good either: after certUnpairedAfter with a
// chain for another key it exits, and its unit, or rayd serve -supervise,
// starts it again with the key copied anew. If the key file is not there
// yet, the start fails and is tried again every two seconds until it is.
func loadCertificate(chain, key string, parse func(chainPEM, keyPEM []byte) (tls.Certificate, error), log *slog.Logger) (*certfile.Loader, error) {
	l := &certfile.Loader{Chain: chain, Key: key, Parse: parse, Log: log, UnpairedAfter: certUnpairedAfter}
	l.Unpaired = func() {
		log.Error("the certificate chain is for another key than the one this process was started with, and no restart came: "+
			"exiting, to be started again with that key", "chain", chain, "after", certUnpairedAfter)
		os.Exit(1)
	}
	return l, l.Load()
}

// settleAfterStart is how long after its start rayd holds back what an
// update rolled back in its first minutes could not take back from clients:
// the subscription's seq by the clock (sub.Server.ClockSeqAfter) and the
// first pins of a node updated to cert-pin-v1 (certs.Manager.NextKeyFrom).
const settleAfterStart = 10 * time.Minute

// certUnpairedAfter is how long rayd naive and rayd site wait for the
// restart of a key switch before they exit to get it (tests shorten it).
var certUnpairedAfter = certfile.DefaultUnpairedAfter

// siteCertificate is the site's certificate from its files: with the root
// appended when the chain is too short for REALITY (site.LoadCertificate).
func siteCertificate(chainPEM, keyPEM []byte) (tls.Certificate, error) {
	return site.LoadCertificate(chainPEM, keyPEM, provision.RealityChainMin(), nil)
}
