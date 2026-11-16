package sub_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/sub"
)

// TestClientPinResumed: the client's pin is checked on a resumed session
// too. VerifyPeerCertificate is not called on resumption, so a client
// given a session cache would have taken any server that resumed its
// ticket.
func TestClientPinResumed(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := provision.SPKIPin(der)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
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
		cfg := sub.Client{Pin: pin}.HTTP().Transport.(*http.Transport).TLSClientConfig.Clone()
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
	resumed, err := dial(strings.Repeat("A", len(pin)))
	if !resumed {
		t.Fatal("the session was not resumed: the test checks nothing")
	}
	if err == nil || !strings.Contains(err.Error(), "certificate pin") {
		t.Fatalf("a resumed session under another pin: %v", err)
	}
}
