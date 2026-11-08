package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"connectrpc.com/connect"

	devicev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/device/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/device/v1/devicev1connect"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/perimeter/v1/perimeterv1connect"
	"github.com/arngory/raycontrol/internal/httpx"
	"github.com/arngory/raycontrol/internal/spa"
	"github.com/arngory/raycontrol/internal/store"
)

// Remote serves the API to client devices (docs/08-decisions.md, R3-3):
// on its own TCP port behind SPA, which only admin devices and invites
// pass; TLS 1.3 with X25519MLKEM768 only; a client certificate on every
// connection. The device is its certificate's key: no CA, the node keeps
// the pin of each device, like clients keep the node's. DeviceService is
// for any registered device and for invites; NodeService for admins.
type Remote struct {
	Server *Server
	Log    *slog.Logger
	// Perimeter, if set, serves the relays in front of the node their
	// perimeter (RelayService, relay-v1 §3.1); its TTLs and carrier apply.
	Perimeter *PerimeterServer
	// RelayReport takes the client summary reports relays pass on
	// (summary.Collector.TakeVia); nil, relays' reports are refused.
	RelayReport func(ctx context.Context, device string, network netip.Prefix, body io.Reader) error
	now         func() time.Time

	relayMu      sync.Mutex
	relayStreams map[string]int       // WatchRelay streams open per relay
	relayReports map[string]int       // Report calls under way per relay
	relayProbes  map[string]int       // rayd relay's feeds open per relay
	relayProbeAt map[string]time.Time // when the last of them closed
	started      time.Time            // when Serve began
}

// relayProbeGrace keeps a relay's probe endpoint listed while its rayd relay
// reconnects (an exit's restart, a network blip).
const relayProbeGrace = 2 * time.Minute

// RelayProbeUp reports whether a relay's rayd relay is there, so that the
// subscription lists its probe endpoint (relay-v1 §9.2): its feed is open,
// or closed less than relayProbeGrace ago. A relay not seen since this
// node's start counts as gone at the start: rayd relay reconnects after a
// restart of the exit within its backoff.
func (r *Remote) RelayProbeUp(name string) bool {
	r.relayMu.Lock()
	defer r.relayMu.Unlock()
	if r.relayProbes[name] > 0 {
		return true
	}
	if r.started.IsZero() {
		r.started = r.clock() // asked before Serve began
	}
	at, ok := r.relayProbeAt[name]
	if !ok {
		at = r.started
	}
	return r.clock().Sub(at) < relayProbeGrace
}

var (
	_ devicev1connect.DeviceServiceHandler = (*Remote)(nil)

	errInvite = connect.NewError(connect.CodeNotFound, errors.New("no such invite"))
)

// Labels of the device's proofs (docs/spec/api-v1.md).
const (
	RegisterLabel = "raycontrol-register-v1"
	RotateLabel   = "raycontrol-rotate-v1"
	PinLabel      = "raycontrol-invite-pin-v1"
)

// InvitePinProof is what Register brings for an invite's PIN (api-v1 §4).
func InvitePinProof(inviteKey [spa.KeySize]byte, pin string) []byte {
	m := hmac.New(sha256.New, inviteKey[:])
	m.Write([]byte(PinLabel))
	m.Write([]byte(pin))
	return m.Sum(nil)
}

// pinRefused is Register's answer for a PIN missing or wrong: what the
// client tells its user, with the tries the invite has still.
func pinRefused(why string, left int) error {
	err := connect.NewError(connect.CodePermissionDenied, fmt.Errorf("%s: %d tries left", why, left))
	if detail, derr := connect.NewErrorDetail(&devicev1.PinTries{Left: int32(left)}); derr == nil {
		err.AddDetail(detail)
	}
	return err
}

type certPinKey struct{}

// CertPin is how the node and clients name a certificate's key: base64url
// SHA-256 of its SubjectPublicKeyInfo.
func CertPin(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (r *Remote) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// RemoteTLSConfig is the server side of the remote API: the node's
// self-signed certificate (clients pin it), any client certificate (the
// handlers decide who it is).
func RemoteTLSConfig(certDER, keyDER []byte) (*tls.Config, error) {
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		Certificates:     []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}},
		ClientAuth:       tls.RequireAnyClientCert,
		NextProtos:       []string{"h2"},
	}, nil
}

// Handler routes both services; a request without a client certificate
// gets a plain 404.
func (r *Remote) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(nodev1connect.NewNodeServiceHandler(r.Server, connect.WithInterceptors(r.adminOnly())))
	mux.Handle(devicev1connect.NewDeviceServiceHandler(r))
	if r.Perimeter != nil {
		mux.Handle(perimeterv1connect.NewRelayServiceHandler(&relayFeed{r}))
	}
	// No redirects: Niko takes a 3xx for an error (RAYCONTROL.md §22).
	return httpx.NoRedirect(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
			http.NotFound(w, req)
			return
		}
		pin := CertPin(req.TLS.PeerCertificates[0])
		mux.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), certPinKey{}, pin)))
	}))
}

// Serve serves on ln until ctx ends.
func (r *Remote) Serve(ctx context.Context, ln net.Listener, cfg *tls.Config) error {
	r.relayMu.Lock()
	if r.started.IsZero() {
		r.started = r.clock()
	}
	r.relayMu.Unlock()
	srv := &http.Server{
		Handler:           r.Handler(),
		TLSConfig:         cfg,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(r.Log.Handler(), slog.LevelDebug),
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ServeTLS(ln, "", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func pinFrom(ctx context.Context) string {
	p, _ := ctx.Value(certPinKey{}).(string)
	return p
}

// device returns the registered, active device of the connection.
func (r *Remote) device(ctx context.Context) (store.Device, error) {
	d, err := r.Server.Store.DeviceByCertPin(ctx, pinFrom(ctx))
	if errors.Is(err, store.ErrNotFound) {
		return d, connect.NewError(connect.CodeUnauthenticated, errors.New("unknown or revoked device"))
	}
	if err != nil {
		return d, connect.NewError(connect.CodeInternal, err)
	}
	return d, nil
}

// nodeOnly are the calls for root on the node itself: what they return
// holds every private key (the rendered files, the database).
var nodeOnly = map[string]bool{
	nodev1connect.NodeServiceGetDeploymentProcedure: true,
	nodev1connect.NodeServiceBackupProcedure:        true,
	// A relay's bundle holds its private key.
	nodev1connect.NodeServiceIssueRelayBundleProcedure: true,
	// The site's private key stays off the network.
	nodev1connect.NodeServiceSetCertificateProcedure: true,
	// A relay opens the service ports to an address (relay-v1).
	nodev1connect.NodeServiceAddRelayProcedure:    true,
	nodev1connect.NodeServiceRemoveRelayProcedure: true,
	// Client addresses go to the journal, which only root reads.
	nodev1connect.NodeServiceSetDebugProcedure: true,
	// Whether admins may update the node at all is root's (node-update-v1).
	nodev1connect.NodeServiceSetUpdatePolicyProcedure: true,
}

// adminOnly lets admin devices call NodeService; the audit log names them.
func (r *Remote) adminOnly() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			d, err := r.device(ctx)
			if err != nil {
				return nil, err
			}
			if d.Role != "admin" {
				return nil, connect.NewError(connect.CodePermissionDenied, errors.New("admin devices only"))
			}
			if nodeOnly[req.Spec().Procedure] {
				return nil, connect.NewError(connect.CodePermissionDenied, errors.New("on the node only (rayctl as root)"))
			}
			return next(context.WithValue(ctx, actorKey{}, d.UserName+"/"+d.Name+" (remote)"), req)
		}
	}
}

// RegisterMAC is the proof of an invite for a client certificate.
func RegisterMAC(inviteKey [spa.KeySize]byte, minute int64, certPin string) []byte {
	m := hmac.New(sha256.New, inviteKey[:])
	m.Write([]byte(RegisterLabel))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(minute))
	m.Write(b[:])
	m.Write([]byte(certPin))
	return m.Sum(nil)
}

func (r *Remote) Register(ctx context.Context, req *connect.Request[devicev1.RegisterRequest]) (*connect.Response[devicev1.RegisterResponse], error) {
	s := r.Server
	pin := pinFrom(ctx)
	inv, key, err := s.Store.ActiveInvite(ctx, req.Msg.InviteId)
	if err != nil {
		return nil, errInvite
	}
	if d := r.clock().Unix()/60 - req.Msg.Minute; d < -2 || d > 2 {
		return nil, errInvite
	}
	if !hmac.Equal(req.Msg.Mac, RegisterMAC(key, req.Msg.Minute, pin)) {
		return nil, errInvite
	}
	ctx = context.WithValue(ctx, actorKey{}, "invite "+inv.ID)
	// The PIN (api-v1 §4), only now the request has proved the invite:
	// whoever gets this far holds it. A missing PIN costs no try (an
	// older client); a wrong one does, and the last withdraws the invite.
	if inv.PinProof != nil {
		if len(req.Msg.PinProof) == 0 {
			return nil, pinRefused("the invite needs its PIN", inv.PinTries)
		}
		if !hmac.Equal(req.Msg.PinProof, inv.PinProof) {
			left, err := s.Store.FailInvitePIN(ctx, inv.ID)
			if err != nil {
				return nil, errInvite
			}
			s.pinWrong.Add(1)
			why := "wrong PIN"
			if left == 0 {
				why = "wrong PIN, the invite is withdrawn"
				s.pinWithdrawn.Add(1)
			}
			_ = s.done(ctx, "invite.pin-wrong", inv.UserName+"/"+inv.Name, nil)
			return nil, pinRefused(why, left)
		}
	}
	d, devKey, err := s.Store.UseInvite(ctx, inv.ID, pin)
	var bundle string
	if err == nil {
		bundle, err = s.bundle(ctx, d, devKey)
	}
	if err := s.done(ctx, "device.register:"+inv.Role, inv.UserName+"/"+inv.Name, err); err != nil {
		r.Log.Debug("register", "err", err)
		return nil, errInvite
	}
	return connect.NewResponse(&devicev1.RegisterResponse{Bundle: bundle, DeviceId: d.ID, Role: d.Role}), nil
}

func (r *Remote) GetSelf(ctx context.Context, _ *connect.Request[devicev1.GetSelfRequest]) (*connect.Response[devicev1.GetSelfResponse], error) {
	d, err := r.device(ctx)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&devicev1.GetSelfResponse{DeviceId: d.ID, User: d.UserName, Name: d.Name, Role: d.Role}), nil
}

// RotateMessage is what the new key signs to take over from the old one.
func RotateMessage(oldPin, newPin string) []byte {
	return []byte(RotateLabel + oldPin + newPin)
}

func (r *Remote) RotateCertificate(ctx context.Context, req *connect.Request[devicev1.RotateCertificateRequest]) (*connect.Response[devicev1.RotateCertificateResponse], error) {
	d, err := r.device(ctx)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(req.Msg.Certificate)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	oldPin, newPin := pinFrom(ctx), CertPin(cert)
	msg := RotateMessage(oldPin, newPin)
	ok := false
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		sum := sha256.Sum256(msg)
		ok = ecdsa.VerifyASN1(pub, sum[:], req.Msg.Signature)
	case ed25519.PublicKey:
		ok = ed25519.Verify(pub, msg, req.Msg.Signature)
	}
	if !ok || newPin == oldPin {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the new key did not sign the rotation"))
	}
	ctx = context.WithValue(ctx, actorKey{}, d.UserName+"/"+d.Name+" (remote)")
	err = r.Server.Store.SetCertPin(ctx, d.ID, oldPin, newPin)
	if err := r.Server.done(ctx, "device.rotate-certificate", d.ID, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&devicev1.RotateCertificateResponse{}), nil
}
