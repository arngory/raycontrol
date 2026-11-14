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
	// rayctl prints 512 bytes of it (deploy.PrintableWarning): the command
	// at its end must fit.
	return fmt.Errorf("%w: service %s is the only enabled ssh service, and the perimeter lets SSH in (from the admin "+
		"addresses, after a knock) on its ports only. With it %s, SSH to this node is closed to everyone from the next "+
		"snapshot: open sessions go on, new ones do not get in. Add another ssh service first (rayctl service add ssh "+
		"ssh-2222 -settings '{\"ports\":[\"tcp/2222\"]}'), or %s it anyway: rayctl service %s %s -force (a rayctl "+
		"before v0.27.0 has no -force: update it)", store.ErrPrecondition, name, verbed[verb], verb, verbCmd[verb], name)
}

var (
	verbed  = map[string]string{"disable": "disabled", "delete": "deleted"}
	verbCmd = map[string]string{"disable": "disable", "delete": "del"}
)
