// Package xrayapi manages users of an Xray inbound through Xray's gRPC
// HandlerService on a unix socket, without restarting Xray.
package xrayapi

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/arngory/raycontrol/internal/gen/xray/app/proxyman/command"
	"github.com/arngory/raycontrol/internal/gen/xray/app/proxyman/command/commandconnect"
	"github.com/arngory/raycontrol/internal/gen/xray/common/protocol"
	"github.com/arngory/raycontrol/internal/gen/xray/common/serial"
	"github.com/arngory/raycontrol/internal/gen/xray/proxy/vless"
)

// Client talks to one Xray instance.
type Client struct {
	c commandconnect.HandlerServiceClient
}

// Dial returns a client for the API socket. gRPC needs HTTP/2; over a unix
// socket it runs without TLS.
func Dial(socket string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		Protocols: new(http.Protocols),
	}
	tr.Protocols.SetUnencryptedHTTP2(true)
	return &Client{c: commandconnect.NewHandlerServiceClient(&http.Client{Transport: tr}, "http://xray", connect.WithGRPC())}
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
