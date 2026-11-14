//go:build !linux

package api

import "errors"

// ucred: rayd's socket is a node's, and a node is Linux (SO_PEERCRED).
// Elsewhere the package builds for rayctl, the API's client; a server
// there would let nobody in.
type ucred struct{ Uid uint32 }

func peerCred(uintptr) (*ucred, error) {
	return nil, errors.New("api: a socket's peer is told on a Linux node only")
}
