package main

import "crypto/tls"

// fixedCert gives cert at every handshake, as a server whose certificate
// never changes.
func fixedCert(cert tls.Certificate) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }
}
