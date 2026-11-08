package api

import (
	"context"
	"fmt"
	"unicode/utf8"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/node"
)

// SetNodeName names the node or takes its name away (subscription-v1 §3):
// it goes out with the next subscription a client fetches.
func (s *Server) SetNodeName(ctx context.Context, req *connect.Request[nodev1.SetNodeNameRequest]) (*connect.Response[nodev1.SetNodeNameResponse], error) {
	name, err := node.SetName(ctx, s.Store, req.Msg.Name)
	if err := s.done(ctx, "node name", name, err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetNodeNameResponse{Name: name}), nil
}

// SetNodeNote sets the node's note for its users or takes it away
// (subscription-v1 §3): it goes out with the next subscription a client
// fetches.
func (s *Server) SetNodeNote(ctx context.Context, req *connect.Request[nodev1.SetNodeNoteRequest]) (*connect.Response[nodev1.SetNodeNoteResponse], error) {
	note, err := node.SetNote(ctx, s.Store, req.Msg.Note)
	// The audit says it changed, not what it says.
	if err := s.done(ctx, "node note", fmt.Sprintf("%d characters", utf8.RuneCountInString(note)), err); err != nil {
		return nil, err
	}
	return connect.NewResponse(&nodev1.SetNodeNoteResponse{Note: note}), nil
}
