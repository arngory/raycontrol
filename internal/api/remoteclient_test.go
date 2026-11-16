package api_test

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/api"
)

// TestPinnedTLSResumed: the pin is checked on a resumed session too.
// VerifyPeerCertificate is not called on resumption, so a client given a
// session cache would have taken any server that resumed its ticket.
func TestPinnedTLSResumed(t *testing.T) {
	cert, err := api.NewClientCertificate()
	if err != nil {
		t.Fatal(err)
	}
	pin := api.CertPin(cert.Leaf)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				// A byte after the handshake, the session tickets before it.
				if _, err := c.Write([]byte{1}); err == nil {
					_, _ = c.Read(make([]byte, 1))
				}
			}()
		}
	}()

	cache := tls.NewLRUClientSessionCache(4)
	dial := func(pin string) (resumed bool, err error) {
		cfg := api.PinnedTLS(pin, nil)
		cfg.ClientSessionCache = cache
		check := cfg.VerifyConnection
		if check == nil {
			t.Fatal("no VerifyConnection")
		}
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			resumed = cs.DidResume
			return check(cs)
		}
		c, err := tls.Dial("tcp", ln.Addr().String(), cfg)
		if err != nil {
			return resumed, err
		}
		defer c.Close()
		_, err = c.Read(make([]byte, 1))
		return resumed, err
	}
	if resumed, err := dial(pin); err != nil || resumed {
		t.Fatalf("first connection: resumed %v, %v", resumed, err)
	}
	if resumed, err := dial(pin); err != nil || !resumed {
		t.Fatalf("second connection: resumed %v, %v", resumed, err)
	}
	wrong := strings.Repeat("A", len(pin))
	resumed, err := dial(wrong)
	if !resumed {
		t.Fatal("the session was not resumed: the test checks nothing")
	}
	if err == nil || !strings.Contains(err.Error(), "certificate pin") {
		t.Fatalf("a resumed session under another pin: %v", err)
	}
}
