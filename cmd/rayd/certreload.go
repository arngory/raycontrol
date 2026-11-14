package main

import (
	"crypto/tls"
	"errors"
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
// first pins of a node updated to cert-pin-v1 (certs.Manager.NextKeyFrom),
// and in the subscription every pin made meanwhile, by a switch too
// (sub.Server.PinsSince).
const settleAfterStart = 10 * time.Minute

// pinSettle is the part of settleAfterStart that holds the pins: the first
// next key (certs.Manager.NextKeyFrom) and the pins in the subscription
// (sub.Server.PinsAfter). A test stand shortens it (unsafeStand); the
// seq's clock keeps settleAfterStart whatever this is.
var pinSettle = settleAfterStart

// unsafeSettle is pinSettle on a test stand with
// RAYCONTROL_UNSAFE_SITE_KEY_SETTLE_NOW.
const unsafeSettle = 5 * time.Second

// unsafeStand takes the switches of a test stand (the client's CI) that
// walks through the site's keys in minutes. Only with -supervise, where
// no node in use runs: otherwise rayd refuses to start with them.
//   - RAYCONTROL_UNSAFE_SITE_KEY_FORCE_ANY_AGE: a forced switch at any age
//     of the key in use (provision.UnsafeForceSwitchAtAnyAge);
//   - RAYCONTROL_UNSAFE_SITE_KEY_SETTLE_NOW: the first next key and the
//     pins in the subscription after unsafeSettle, not ten minutes
//     (pinSettle). A rollback in those minutes on such a stand may leave
//     clients pins the old version does not serve: a stand has no users.
func unsafeStand(supervise bool, getenv func(string) string, log *slog.Logger) error {
	for _, name := range []string{"RAYCONTROL_UNSAFE_SITE_KEY_FORCE_ANY_AGE", "RAYCONTROL_UNSAFE_SITE_KEY_SETTLE_NOW"} {
		if getenv(name) != "" && !supervise {
			return errors.New(name + " is for a test stand (-supervise) only")
		}
	}
	if getenv("RAYCONTROL_UNSAFE_SITE_KEY_FORCE_ANY_AGE") != "" {
		provision.UnsafeForceSwitchAtAnyAge()
		log.Warn("UNSAFE: a forced switch of a site's key is taken at any age of the key in use")
	}
	if getenv("RAYCONTROL_UNSAFE_SITE_KEY_SETTLE_NOW") != "" {
		pinSettle = unsafeSettle
		log.Warn("UNSAFE: the first next key of a site and the pins in subscriptions come seconds after the start, not minutes")
	}
	return nil
}

// processStart is this process's start: the pins made since are held back
// from the subscription for settleAfterStart (sub.Server.PinsSince), those
// of before are not.
var processStart = time.Now()

// certUnpairedAfter is how long rayd naive and rayd site wait for the
// restart of a key switch before they exit to get it (tests shorten it).
var certUnpairedAfter = certfile.DefaultUnpairedAfter

// siteCertificate is the site's certificate from its files: with the root
// appended when the chain is too short for REALITY (site.LoadCertificate).
func siteCertificate(chainPEM, keyPEM []byte) (tls.Certificate, error) {
	return site.LoadCertificate(chainPEM, keyPEM, provision.RealityChainMin(), nil)
}
