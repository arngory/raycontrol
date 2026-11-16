package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/arngory/raycontrol/internal/h3serve"
	"github.com/arngory/raycontrol/internal/naive"
	"github.com/arngory/raycontrol/internal/quiccid"
	"github.com/arngory/raycontrol/internal/render"
)

// rayd's QUIC servers behind the front, naive-quic and DoH3, are one
// server to whoever has no password and no token (h3serve): the same
// numbers below for both.
const quicConnIDLen = h3serve.ConnIDLen

// quicOptions are what one of rayd's QUIC servers has of its own.
type quicOptions struct {
	// resetKey makes the tokens of stateless resets (h3serve.Options);
	// nil: none are sent.
	resetKey *quic.StatelessResetKey
	// headerWait is h3serve.HeaderTimeout when 0 (tests make it short).
	headerWait time.Duration
	// datagrams announces HTTP/3 datagrams (h3serve.Options.Datagrams):
	// naive-quic with udp=on (spec/naive-udp-v1.md).
	datagrams bool
	// connIDs makes the server's connection IDs with the service's label
	// (h3serve.Options.ConnIDs, spec/quic-cid-route-v1.md); nil: random.
	connIDs quic.ConnectionIDGenerator
}

// h3Options are o with what both servers share: an idle time the front
// outlasts (render.QUICIdle, render.FrontUDPIdle), room for all the
// requests a naive user may have at once (naive.MaxStreams), and naive's
// bounds of the streams without a header and of a header.
func h3Options(o quicOptions) h3serve.Options {
	return h3serve.Options{ResetKey: o.resetKey, HeaderWait: o.headerWait, Idle: render.QUICIdle,
		MaxStreams: naive.MaxStreams, PendingStreams: naive.PendingStreams, MaxHeaderBytes: naive.MaxHeaderBytes,
		Datagrams: o.datagrams, ConnIDs: o.connIDs}
}

// connIDs is the generator of a QUIC server's connection IDs with its
// service's label under the node's secret (spec/quic-cid-route-v1.md): the
// front finds the service of a client whose address changed by it. The
// error says what is wrong, nothing of the secret; the server then serves
// with random IDs, as before the label, and only clients whose address
// changes lose their connections.
func connIDs(secret []byte, label int) (quic.ConnectionIDGenerator, error) {
	g, err := quiccid.NewGenerator(secret, label)
	if err != nil {
		return nil, err
	}
	return g, nil
}

// naiveUDP is what -udp makes of a naive server (spec/naive-udp-v1.md),
// and the options of its QUIC side: with it, connect-udp served
// (naive.Server.UDP, the streams h3serve gives), HTTP/3 datagrams announced
// and the datagram requests' counts on the stats socket; without it,
// none of these. Its users (Server.Users) must be set.
func naiveUDP(ns *naive.Server, udp bool) quicOptions {
	ns.UDP, ns.H3 = udp, naiveH3
	if udp {
		ns.Users.SetUDP(ns.UDPStats)
	} else {
		ns.Users.SetUDP(nil)
	}
	return quicOptions{datagrams: udp}
}

// naiveH3 gives naive a request's HTTP/3 stream with its datagrams
// (naive.H3): h3serve's, for internal/naive does not import quic-go.
func naiveH3(ctx context.Context, w http.ResponseWriter) (func() naive.H3Stream, bool) {
	take, ok := h3serve.Datagrams(ctx, w)
	if !ok {
		return nil, false
	}
	return func() naive.H3Stream { return take() }, true
}

// parseResetKey reads a key of stateless resets from its text: 32 bytes,
// hex. Its error says what is wrong, and nothing of the text.
func parseResetKey(text []byte) (*quic.StatelessResetKey, error) {
	var key quic.StatelessResetKey
	text = bytes.TrimSpace(text)
	if hex.DecodedLen(len(text)) != len(key) {
		return nil, fmt.Errorf("not %d bytes in hex", len(key))
	}
	if _, err := hex.Decode(key[:], text); err != nil {
		return nil, errors.New("not hex")
	}
	return &key, nil
}

// readResetKey reads the key of stateless resets from its file
// (render.NaiveQUICReset). Its errors say what is wrong with the file, and
// nothing of what is in it.
func readResetKey(file string) (*quic.StatelessResetKey, error) {
	b, err := os.ReadFile(file) //nolint:gosec // G304: the unit's own file
	if err != nil {
		return nil, err
	}
	key, err := parseResetKey(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return key, nil
}

// quicConfig is the QUIC side of both servers.
func quicConfig() *quic.Config { return h3serve.Config(h3Options(quicOptions{})) }

// serveHTTP3 serves h on QUIC over the front's datagrams until ctx ends
// (h3serve.Serve): TLS 1.3 with X25519MLKEM768 only, ALPN h3, the
// certificate cert gives at each handshake (certfile.Holder).
func serveHTTP3(ctx context.Context, pc net.PacketConn, cert func(*tls.ClientHelloInfo) (*tls.Certificate, error), h http.Handler, o quicOptions) error {
	return h3serve.Serve(ctx, pc, cert, h, h3Options(o))
}
