package api

import (
	"context"
	"fmt"

	"github.com/arngory/raycontrol/internal/store"
)

// lastSSH refuses taking the service name out (disabled or deleted, as
// verb says) when it is the last enabled service of kind ssh: the ports
// of those are the ones the perimeter admits SSH on, from the admin
// addresses and after a knock (PerimeterServer's AdminPorts), so without
// one SSH is closed to everyone at the next snapshot. Sessions already
// open go on; a new one does not get in. force takes it out anyway.
func lastSSH(ctx context.Context, st *store.Store, name, verb string, force bool) error {
	if force {
		return nil
	}
	services, err := st.ListServices(ctx)
	if err != nil {
		return err
	}
	last := false
	for _, svc := range services {
		if !svc.Enabled || svc.Kind != "ssh" {
			continue
		}
		if svc.Name != name {
			return nil
		}
		last = true
	}
	if !last {
		return nil
	}
	// rayctl prints 512 bytes of an error (printableError): the command
	// comes first, and the whole text stays well under that with a name of
	// 64 bytes (TestLastSSHMessageLength).
	return fmt.Errorf("%w: rayctl service %s %s -force does it anyway (rayctl before v0.27.0 has no -force): the last "+
		"enabled ssh service; without it SSH is closed to everyone at the next snapshot, open sessions go on",
		store.ErrPrecondition, verbCmd[verb], name)
}

var verbCmd = map[string]string{"disable": "disable", "delete": "del"}
