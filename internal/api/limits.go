package api

import "connectrpc.com/connect"

// MaxRequest is the most a handler reads of one request message, after
// gzip: connect reads and unpacks a message before the interceptors that
// check the caller, on a socket every local user may open and on the
// remote API to anyone past SPA. The largest real one, SetCertificate's
// chain and key, is a few dozen KiB; a relay's Report is 4 KiB at most.
const MaxRequest = 1 << 20

// readLimit is the handler option that sets MaxRequest; larger is
// resource_exhausted.
func readLimit() connect.HandlerOption {
	return connect.WithReadMaxBytes(MaxRequest)
}
