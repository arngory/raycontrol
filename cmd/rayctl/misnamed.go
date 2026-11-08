package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/hostcheck"
	"github.com/arngory/raycontrol/internal/store"
)

// misnamedAdvice is what to do about a service misnamed lists.
const misnamedAdvice = "since v0.10.1 a service with a process may not be named front or end in -in or -api: " +
	"from v0.21.0 it is not deployed, and rayctl apply removes its unit. Create it again under another name " +
	"(rayctl service add), move its users to it, then delete this one"

// misnamed lists rayd's services with a process whose names the store no
// longer takes (before v0.10.1 it took names ending in -in or -api): the
// plan leaves them out (deploy.CheckService), so apply removes their
// units. Nothing when rayd does not answer.
func (c *cli) misnamed(ctx context.Context) []string {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	r, err := c.c.ListServices(ctx, connect.NewRequest(&nodev1.ListServicesRequest{}))
	if err != nil {
		return nil
	}
	var out []string
	for _, s := range r.Msg.Services {
		if store.HasProcess(s.Kind) && store.CheckProcessName(s.Name) != nil {
			out = append(out, fmt.Sprintf("service %q (%s)", s.Name, s.Kind))
		}
	}
	return out
}

// misnamedResults are misnamed services as rayctl check reports them.
func misnamedResults(names []string) []hostcheck.Result {
	var rs []hostcheck.Result
	for _, n := range names {
		rs = append(rs, hostcheck.Result{Level: hostcheck.Advised, Name: n, Detail: "not deployed from v0.21.0", Fix: misnamedAdvice})
	}
	return rs
}

// misnamedUpdate is the update's word on misnamed services, before
// anything changes: it refuses, unless force, which goes on without them
// and says so.
func misnamedUpdate(w io.Writer, names []string, force bool) error {
	if len(names) == 0 {
		return nil
	}
	msg := strings.Join(names, ", ") + ": " + misnamedAdvice
	if !force {
		return fmt.Errorf("%s. Nothing was changed; rayctl update -force goes on without them "+
			"(handed over from a rayctl before v0.21.0, which does not pass -force: rayctl update -no-handoff)", msg)
	}
	fmt.Fprintln(w, "warning:", msg+"; the update goes on without them (-force)")
	return nil
}
