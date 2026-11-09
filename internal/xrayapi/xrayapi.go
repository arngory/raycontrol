// Package xrayapi manages users of an Xray inbound through Xray's gRPC
// HandlerService on a unix socket, without restarting Xray, and reads the
// users' byte counters through its StatsService.
package xrayapi

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/arngory/raycontrol/internal/gen/xray/app/proxyman/command"
	"github.com/arngory/raycontrol/internal/gen/xray/app/proxyman/command/commandconnect"
	statscmd "github.com/arngory/raycontrol/internal/gen/xray/app/stats/command"
	statsconnect "github.com/arngory/raycontrol/internal/gen/xray/app/stats/command/commandconnect"
	"github.com/arngory/raycontrol/internal/gen/xray/common/protocol"
	"github.com/arngory/raycontrol/internal/gen/xray/common/serial"
	"github.com/arngory/raycontrol/internal/gen/xray/proxy/vless"
)

// Client talks to one Xray instance.
type Client struct {
	c commandconnect.HandlerServiceClient
}

// Dial returns a client for the API socket. gRPC needs HTTP/2; over a unix
// socket it runs without TLS. Clients of one socket share its connection.
func Dial(socket string) *Client {
	return &Client{c: commandconnect.NewHandlerServiceClient(unixHTTP(socket), "http://xray", connect.WithGRPC())}
}

// pool keeps one HTTP/2 client per API socket, and with it one
// connection: a transport made per call left its connection open on both
// sides, a goroutine in rayd and a file and buffers in Xray for every
// poll. A socket made anew (Xray restarted) gets a new client, and the
// old one's connections are closed.
var pool struct {
	mu      sync.Mutex
	clients map[string]*pooled
}

type pooled struct {
	client *http.Client
	tr     *http.Transport
	id     [2]uint64 // the socket's device and inode when made; zero: not there
}

// socketID names the file at path: device and inode, zero when it is not
// there.
func socketID(path string) [2]uint64 {
	st, err := os.Stat(path)
	if err != nil {
		return [2]uint64{}
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return [2]uint64{uint64(sys.Dev), sys.Ino} //nolint:unconvert // Dev's type differs by platform
	}
	return [2]uint64{}
}

func unixHTTP(socket string) *http.Client {
	id := socketID(socket)
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if p := pool.clients[socket]; p != nil {
		if p.id == id && id != ([2]uint64{}) {
			return p.client
		}
		p.tr.CloseIdleConnections()
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		Protocols: new(http.Protocols),
		// A connection left behind (its transport replaced while a call
		// was on it) closes itself; the 15 s poll keeps the live one.
		IdleConnTimeout: 2 * time.Minute,
	}
	tr.Protocols.SetUnencryptedHTTP2(true)
	if pool.clients == nil {
		pool.clients = map[string]*pooled{}
	}
	p := &pooled{client: &http.Client{Transport: tr}, tr: tr, id: id}
	pool.clients[socket] = p
	return p.client
}

// Close closes the connections of every API client: rayd stops.
func Close() {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	for socket, p := range pool.clients {
		p.tr.CloseIdleConnections()
		delete(pool.clients, socket)
	}
}

// Stats reads the users' byte counters of one Xray instance, on the same
// API socket (StatsService, rendered while a user has a traffic limit:
// docs/spec/traffic-limit-v1.md §2.1).
type Stats struct {
	c statsconnect.StatsServiceClient
}

// statsMaxBytes bounds an answer: ~100 bytes a counter, two a name, three
// names a user while credentials rotate. The process is not trusted to
// send a sane one.
const statsMaxBytes = 8 << 20

// DialStats returns a stats client for the API socket.
func DialStats(socket string) *Stats {
	return &Stats{c: statsconnect.NewStatsServiceClient(unixHTTP(socket), "http://xray", connect.WithGRPC(),
		connect.WithReadMaxBytes(statsMaxBytes))}
}

// Counter is a user's bytes: Up from the client to destinations
// (uplink), Down back (downlink).
type Counter struct{ Up, Down int64 }

// Users returns each user's counters by email, as they are (reading
// resets nothing), and the process's uptime: a counter is from the
// process's start or the user's first connection since. Counters with
// other names, and negative values, are left out.
func (s *Stats) Users(ctx context.Context) (map[string]Counter, time.Duration, error) {
	users, uptime, err := s.users(ctx)
	if again(ctx, err) {
		users, uptime, err = s.users(ctx)
	}
	return users, uptime, err
}

// again reports whether a read that failed in transport is worth one more
// try: Xray restarted, and its new socket came back at the same path with
// the same inode (ext4 reuses them), so the call went out on the dead
// process's connection before the transport saw it close. The transport
// drops a connection that failed and dials the socket again.
func again(ctx context.Context, err error) bool {
	return err != nil && ctx.Err() == nil && connect.CodeOf(err) == connect.CodeUnavailable
}

func (s *Stats) users(ctx context.Context) (map[string]Counter, time.Duration, error) {
	sys, err := s.c.GetSysStats(ctx, connect.NewRequest(&statscmd.SysStatsRequest{}))
	if err != nil {
		return nil, 0, err
	}
	resp, err := s.c.QueryStats(ctx, connect.NewRequest(&statscmd.QueryStatsRequest{Pattern: "user>>>", Reset_: false}))
	if err != nil {
		return nil, 0, err
	}
	out := map[string]Counter{}
	for _, st := range resp.Msg.Stat {
		rest, ok := strings.CutPrefix(st.Name, "user>>>")
		if !ok || st.Value < 0 {
			continue
		}
		if email, ok := strings.CutSuffix(rest, ">>>traffic>>>uplink"); ok {
			c := out[email]
			c.Up = st.Value
			out[email] = c
		} else if email, ok := strings.CutSuffix(rest, ">>>traffic>>>downlink"); ok {
			c := out[email]
			c.Down = st.Value
			out[email] = c
		}
	}
	return out, time.Duration(sys.Msg.Uptime) * time.Second, nil
}

func typed(m proto.Message) (*serial.TypedMessage, error) {
	b, err := proto.Marshal(m)
	if err != nil {
		return nil, err
	}
	return &serial.TypedMessage{Type: string(m.ProtoReflect().Descriptor().FullName()), Value: b}, nil
}

func (c *Client) alter(ctx context.Context, tag string, op proto.Message) error {
	t, err := typed(op)
	if err != nil {
		return err
	}
	_, err = c.c.AlterInbound(ctx, connect.NewRequest(&command.AlterInboundRequest{Tag: tag, Operation: t}))
	return err
}

// AddVLESS adds a VLESS user to the inbound; flow is "" or the inbound's
// flow (xtls-rprx-vision for REALITY).
func (c *Client) AddVLESS(ctx context.Context, tag, flow, email, id string) error {
	acc, err := typed(&vless.Account{Id: id, Flow: flow})
	if err != nil {
		return err
	}
	return c.alter(ctx, tag, &command.AddUserOperation{User: &protocol.User{Email: email, Account: acc}})
}

// Remove removes a user by email.
func (c *Client) Remove(ctx context.Context, tag, email string) error {
	return c.alter(ctx, tag, &command.RemoveUserOperation{Email: email})
}

// codec turns a user's secret into an account of the inbound's protocol
// and back.
type codec struct {
	account func(secret string) proto.Message
	secret  func(b []byte) (string, error)
}

func vlessCodec(flow string) codec {
	return codec{
		account: func(id string) proto.Message { return &vless.Account{Id: id, Flow: flow} },
		secret: func(b []byte) (string, error) {
			var acc vless.Account
			err := proto.Unmarshal(b, &acc)
			return acc.Id, err
		},
	}
}

func (c *Client) users(ctx context.Context, tag string, cd codec) (map[string]string, error) {
	resp, err := c.c.GetInboundUsers(ctx, connect.NewRequest(&command.GetInboundUserRequest{Tag: tag}))
	if again(ctx, err) {
		resp, err = c.c.GetInboundUsers(ctx, connect.NewRequest(&command.GetInboundUserRequest{Tag: tag}))
	}
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, u := range resp.Msg.Users {
		secret := ""
		if u.Account != nil {
			if secret, err = cd.secret(u.Account.Value); err != nil {
				return nil, fmt.Errorf("user %s: %w", u.Email, err)
			}
		}
		out[u.Email] = secret
	}
	return out, nil
}

// VLESSUsers returns email -> UUID of the inbound's users.
func (c *Client) VLESSUsers(ctx context.Context, tag string) (map[string]string, error) {
	return c.users(ctx, tag, vlessCodec(""))
}

// SyncVLESS makes the inbound's users exactly want (email -> UUID), added
// with the given flow, and reports how many were added and removed.
func (c *Client) SyncVLESS(ctx context.Context, tag, flow string, want map[string]string) (added, removed int, err error) {
	return c.sync(ctx, tag, vlessCodec(flow), want)
}

func (c *Client) sync(ctx context.Context, tag string, cd codec, want map[string]string) (added, removed int, err error) {
	have, err := c.users(ctx, tag, cd)
	if err != nil {
		return 0, 0, err
	}
	for email, secret := range have {
		if want[email] != secret {
			if err := c.Remove(ctx, tag, email); err != nil {
				return added, removed, fmt.Errorf("remove %s: %w", email, err)
			}
			removed++
		}
	}
	for email, secret := range want {
		if have[email] != secret {
			acc, err := typed(cd.account(secret))
			if err != nil {
				return added, removed, err
			}
			if err := c.alter(ctx, tag, &command.AddUserOperation{User: &protocol.User{Email: email, Account: acc}}); err != nil {
				return added, removed, fmt.Errorf("add %s: %w", email, err)
			}
			added++
		}
	}
	return added, removed, nil
}
