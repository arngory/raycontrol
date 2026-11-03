package api

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// Backup returns a consistent snapshot of the database (R4-13). It holds
// every key of the node, so only root gets it, and rayctl seals it with a
// passphrase before it touches a disk.
func (s *Server) Backup(ctx context.Context, _ *connect.Request[nodev1.BackupRequest]) (*connect.Response[nodev1.BackupResponse], error) {
	if !isRoot(ctx) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("a backup holds every key of the node: root only"))
	}
	db, err := s.Store.Snapshot(ctx)
	result := "ok"
	if err != nil {
		result = "error: " + err.Error()
	}
	if aerr := s.Store.Audit(ctx, actorFrom(ctx), "node.backup", "", result); aerr != nil && err == nil {
		err = aerr
	}
	if err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&nodev1.BackupResponse{
		Database:  db,
		NodeId:    hex.EncodeToString(s.Params.NodeID[:]),
		Version:   s.Version,
		CreatedAt: time.Now().Unix(),
	}), nil
}
