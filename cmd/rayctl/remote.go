package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/arngory/raycontrol/internal/api"
	devicev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/device/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/device/v1/devicev1connect"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
	"github.com/arngory/raycontrol/internal/node"
	"github.com/arngory/raycontrol/internal/spa"
)

// The remote mode (R3-3): rayctl on the administrator's own machine talks to
// the node's remote API with a device registered from an invite. The
// device file holds its bundle and its client key; it is a secret like a
// bundle.

// remoteIdentity is a device file: the bundle and the client certificate.
type remoteIdentity struct {
	path   string
	bundle node.Bundle
	raw    string // the encoded bundle
	cert   tls.Certificate
}

func loadIdentity(path string) (remoteIdentity, error) {
	id := remoteIdentity{path: path}
	b, err := os.ReadFile(path) //nolint:gosec // G304: the operator's file
	if err != nil {
		return id, err
	}
	if id.raw, err = readArg("@" + path); err != nil {
		return id, err
	}
	if id.bundle, err = node.DecodeBundle(id.raw); err != nil {
		return id, fmt.Errorf("%s: %w", path, err)
	}
	if id.bundle.API == nil {
		return id, fmt.Errorf("%s: the device has no API access (an admin device registered from an invite has)", path)
	}
	if id.cert, err = api.DecodeClientCertificate(b); err != nil {
		return id, fmt.Errorf("%s: client key: %w", path, err)
	}
	return id, nil
}

// save writes the device file atomically, mode 0600; with exclusive, it
// never replaces an existing file.
func (id remoteIdentity) save(exclusive bool) error {
	pemBytes, err := api.EncodeClientCertificate(id.cert)
	if err != nil {
		return err
	}
	content := append([]byte(id.raw+"\n"), pemBytes...)
	if exclusive {
		f, err := os.OpenFile(id.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the operator's file
		if err != nil {
			return err
		}
		if _, err := f.Write(content); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	}
	tmp, err := os.CreateTemp(filepath.Dir(id.path), ".rayctl-device-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), id.path)
}

// openPort sends SPA for the bundle's device and waits until the port
// answers, over UDP and then TCP with carrier auto.
func openPort(ctx context.Context, b node.Bundle, ip netip.Addr, port uint16, carrier string) error {
	params, err := b.SPA.Params()
	if err != nil {
		return err
	}
	k, err := hex.DecodeString(b.DeviceKey)
	if err != nil || len(k) != spa.KeySize {
		return errors.New("bad device key")
	}
	carriers := carrierList(carrier)
	if carriers == nil {
		return errUsage
	}
	target := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
	var lastErr error
	for _, c := range carriers {
		now := time.Now()
		pkt, err := spa.SealRandom(params, [spa.KeySize]byte(k), spa.Request{Time: now})
		if err != nil {
			return err
		}
		if err := sendSPA(c, netip.AddrPortFrom(ip, params.Port(params.Slot(now))), pkt); err != nil {
			lastErr = err
			continue
		}
		time.Sleep(300 * time.Millisecond) // spa-v2.md §7
		d := net.Dialer{Timeout: 3 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", target)
		if err != nil {
			lastErr = fmt.Errorf("SPA over %s, then %s: %w", c, target, err)
			continue
		}
		conn.Close()
		return nil
	}
	return fmt.Errorf("the node's API is not reachable: %w", lastErr)
}

// connect passes SPA and returns the API clients of the device.
func (id remoteIdentity) connect(ctx context.Context, addr, carrier string) (nodev1connect.NodeServiceClient, devicev1connect.DeviceServiceClient, error) {
	host := id.bundle.Host
	if addr != "" {
		host = addr
	}
	ip, err := resolve(ctx, host)
	if err != nil {
		return nil, nil, err
	}
	if err := openPort(ctx, id.bundle, ip, id.bundle.API.Port, carrier); err != nil {
		return nil, nil, err
	}
	n, d := api.NewRemoteClients(net.JoinHostPort(ip.String(), strconv.Itoa(int(id.bundle.API.Port))), id.bundle.API.Pin, id.cert)
	return n, d, nil
}

// remoteCmd runs "rayctl remote enroll|whoami|rotate".
func (c *cli) remoteCmd(ctx context.Context, sub string, args []string) error {
	switch sub {
	case "enroll":
		return remoteEnroll(ctx, args)
	case "whoami", "rotate":
		if c.identity == nil {
			return errors.New("rayctl -remote FILE remote " + sub)
		}
		if sub == "whoami" {
			r, err := c.dev.GetSelf(ctx, connect.NewRequest(&devicev1.GetSelfRequest{}))
			if err != nil {
				return err
			}
			fmt.Printf("device %s (%s/%s, %s) on node %s\n", r.Msg.DeviceId, r.Msg.User, r.Msg.Name, r.Msg.Role, c.identity.bundle.SPA.NodeID)
			return nil
		}
		return c.remoteRotate(ctx)
	}
	return errUsage
}

// remoteEnroll registers a device from an invite and writes its file.
func remoteEnroll(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("remote enroll", flag.ContinueOnError)
	out := fs.String("o", "", "the device file to write (mode 0600; default: <node>-<device>.rcdev)")
	carrier := fs.String("carrier", "auto", "SPA carrier: udp, tls (TCP as a TLS ClientHello), tcp (bare TCP) or auto (UDP, then tls, then bare TCP for a node before v0.10)")
	addr := fs.String("addr", "", "node address to use instead of the invite's host")
	pin := fs.String("pin", "", "the invite's PIN, when it needs one (6 digits, told apart from the invite); asked for on a terminal when not given, which keeps it out of ps and the shell's history")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		return errUsage
	}
	raw, err := readArg(fs.Arg(0))
	if err != nil {
		return err
	}
	inv, err := node.DecodeInvite(raw)
	if err != nil {
		return err
	}
	if time.Now().Unix() >= inv.Expires {
		return fmt.Errorf("the invite expired at %s", time.Unix(inv.Expires, 0).UTC().Format(time.RFC3339))
	}
	k, err := hex.DecodeString(inv.DeviceKey)
	if err != nil || len(k) != spa.KeySize {
		return errors.New("bad key in the invite")
	}
	// Asked before anything goes to the node: a missing PIN costs no try,
	// but the user should know before the walk to the API.
	code := strings.ReplaceAll(*pin, " ", "")
	if inv.PIN && code == "" && terminal(os.Stdin) {
		if code, err = readSecret("the invite's PIN, as the administrator told it: ", "", false); err != nil {
			return err
		}
		code = strings.ReplaceAll(code, " ", "")
	}
	if inv.PIN && code == "" {
		return errors.New("the invite needs its PIN: -pin, as the administrator told it")
	}
	cert, err := api.NewClientCertificate()
	if err != nil {
		return err
	}
	id := remoteIdentity{bundle: inv, cert: cert}
	_, dev, err := id.connect(ctx, *addr, *carrier)
	if err != nil {
		return err
	}
	minute := time.Now().Unix() / 60
	req := &devicev1.RegisterRequest{
		InviteId: inv.DeviceID, Minute: minute, Mac: api.RegisterMAC([spa.KeySize]byte(k), minute, api.CertPin(cert.Leaf)),
	}
	if code != "" {
		req.PinProof = api.InvitePinProof([spa.KeySize]byte(k), code)
	}
	r, err := dev.Register(ctx, connect.NewRequest(req))
	if left, ok := pinTriesLeft(err); ok {
		if left == 0 {
			return errors.New("register: wrong PIN, and the invite is withdrawn: ask for a new one")
		}
		return fmt.Errorf("register: the PIN is missing or wrong; %d tries left", left)
	}
	if err != nil {
		return fmt.Errorf("register: %w (used, expired or withdrawn invite, or the clock is off)", err)
	}
	id.raw = r.Msg.Bundle
	if id.bundle, err = node.DecodeBundle(r.Msg.Bundle); err != nil {
		return err
	}
	id.path = *out
	if id.path == "" {
		id.path = fmt.Sprintf("%s-%s.rcdev", inv.SPA.NodeID[:8], r.Msg.DeviceId)
	}
	if err := id.save(true); err != nil {
		return fmt.Errorf("device %s registered, but its file was not written: %w", r.Msg.DeviceId, err)
	}
	fmt.Printf("device %s registered (%s); its bundle and client key are in %s, keep it like a key\n", r.Msg.DeviceId, r.Msg.Role, id.path)
	if id.bundle.API == nil {
		fmt.Println("a user device: give the bundle in it to the client app; the API is for admin devices")
		return nil
	}
	// The perimeter learns the new device in a moment.
	for range 3 {
		if _, dev, err = id.connect(ctx, *addr, *carrier); err == nil {
			if _, err = dev.GetSelf(ctx, connect.NewRequest(&devicev1.GetSelfRequest{})); err == nil {
				break
			}
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		return fmt.Errorf("registered, but the API does not answer the new device yet: %w", err)
	}
	fmt.Printf("checked: rayctl -remote %s status\n", id.path)
	return nil
}

// remoteRotate moves the device to a new client key and rewrites its file.
func (c *cli) remoteRotate(ctx context.Context) error {
	next, err := api.NewClientCertificate()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(api.RotateMessage(api.CertPin(c.identity.cert.Leaf), api.CertPin(next.Leaf)))
	sig, err := ecdsa.SignASN1(rand.Reader, next.PrivateKey.(*ecdsa.PrivateKey), sum[:])
	if err != nil {
		return err
	}
	if _, err := c.dev.RotateCertificate(ctx, connect.NewRequest(&devicev1.RotateCertificateRequest{Certificate: next.Certificate[0], Signature: sig})); err != nil {
		return err
	}
	id := *c.identity
	id.cert = next
	if err := id.save(false); err != nil {
		// The key goes out as it is: an error's text is cleaned and cut
		// when printed (printableError).
		pemBytes, _ := api.EncodeClientCertificate(next)
		fmt.Fprintf(os.Stderr, "the new key:\n%s", pemBytes)
		return fmt.Errorf("the node took the new key, but %s was not rewritten: %w; the new key is above", id.path, err)
	}
	fmt.Println("new client key in", id.path)
	return nil
}

// localOnly lists the commands that act on this host, not through an API.
var localOnly = []string{"install", "apply", "update", "uninstall", "backup", "restore", "report", "probe", "egress"}

func isLocalOnly(cmd string) bool {
	return slices.Contains(localOnly, cmd) || strings.HasPrefix(cmd, "-")
}

// useRemote points the CLI at the node's remote API.
func (c *cli) useRemote(ctx context.Context, path, cmd string) error {
	if isLocalOnly(cmd) {
		return fmt.Errorf("%s works on the node itself, not through -remote", cmd)
	}
	id, err := loadIdentity(path)
	if err != nil {
		return err
	}
	n, d, err := id.connect(ctx, "", "auto")
	if err != nil {
		return err
	}
	c.c, c.dev, c.identity = n, d, &id
	return nil
}

// pinTriesLeft reads Register's answer for a PIN missing or wrong (api-v1
// §7): the tries the invite has still.
func pinTriesLeft(err error) (int, bool) {
	var cerr *connect.Error
	if !errors.As(err, &cerr) || cerr.Code() != connect.CodePermissionDenied {
		return 0, false
	}
	for _, d := range cerr.Details() {
		if v, derr := d.Value(); derr == nil {
			if t, ok := v.(*devicev1.PinTries); ok {
				return int(t.Left), true
			}
		}
	}
	return 0, false
}
