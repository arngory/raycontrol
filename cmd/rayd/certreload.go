package main

import (
	"crypto/tls"
	"log/slog"

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
func loadCertificate(chain, key string, parse func(chainPEM, keyPEM []byte) (tls.Certificate, error), log *slog.Logger) (*certfile.Loader, error) {
	l := &certfile.Loader{Chain: chain, Key: key, Parse: parse, Log: log}
	return l, l.Load()
}

// siteCertificate is the site's certificate from its files: with the root
// appended when the chain is too short for REALITY (site.LoadCertificate).
func siteCertificate(chainPEM, keyPEM []byte) (tls.Certificate, error) {
	return site.LoadCertificate(chainPEM, keyPEM, provision.RealityChainMin(), nil)
}
