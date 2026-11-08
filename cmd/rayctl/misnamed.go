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
	"github.com/arngory/raycontrol/internal/release"
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

// misnamedSince is the first version that leaves misnamed services out.
const misnamedSince = "v0.21.0"

// leavesOut reports whether an update to version leaves misnamed services
// out: a release from misnamedSince on, or a build that is not a release.
func leavesOut(version string) bool {
	return !release.IsRelease(version) || !release.Newer(misnamedSince, version)
}

// misnamedUpdate is the update's word on misnamed services, before
// anything changes and before the handoff: it refuses, unless force, which
// goes on without them and says so. request is an update by request, run
// with no one to give -force; handedFrom the version of the rayctl that
// handed the update over, if one did: before misnamedSince, it neither
// checks nor passes -force on.
func misnamedUpdate(w io.Writer, names []string, force, request bool, handedFrom string) error {
	if len(names) == 0 {
		return nil
	}
	list := strings.Join(names, ", ")
	if force {
		fmt.Fprintln(w, "warning:", list+": "+misnamedAdvice+"; the update goes on without them (-force)")
		return nil
	}
	goOn := "rayctl update -force"
	if release.IsRelease(handedFrom) && release.Newer(misnamedSince, handedFrom) {
		goOn = "rayctl update -no-handoff (the rayctl of " + handedFrom + " hands the update over without -force)"
	}
	// What to do first: the status and the terminal keep the start of it
	// (512 bytes).
	if request {
		return fmt.Errorf("an update by request does not go on without services the new version leaves out: "+
			"on the node, %s does. Nothing was changed. %s: %s", goOn, list, misnamedAdvice)
	}
	return fmt.Errorf("services the new version leaves out; nothing was changed: %s goes on without them. %s: %s", goOn, list, misnamedAdvice)
}
