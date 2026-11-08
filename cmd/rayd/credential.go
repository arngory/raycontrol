package main

import (
	"errors"
	"fmt"
	"os/user"
	"strconv"

	"github.com/arngory/raycontrol/internal/deploy"
)

// cmdCredential copies a credential in for a service before its start:
// rayd credential ANCHOR REL OWNER USER DST. systemd runs it as root from
// the service's unit (ExecStartPre=+); the file is rayd's, so no link below
// ANCHOR is followed, and it must belong to OWNER (rayd, or root for the
// relay's bundle) (deploy.CopyCredential, spec/apply-plan-v1.md §6, 3).
// DST becomes USER's, group USER, mode 0400.
func cmdCredential(args []string) error {
	if len(args) != 5 {
		return errors.New("usage: rayd " + deploy.CredentialCommand + " ANCHOR REL OWNER USER DST")
	}
	anchor, rel, ownerName, name, dst := args[0], args[1], args[2], args[3], args[4]
	o, err := user.Lookup(ownerName)
	if err != nil {
		return err
	}
	owner, err := strconv.Atoi(o.Uid)
	if err != nil {
		return fmt.Errorf("user %s: uid %q", ownerName, o.Uid)
	}
	u, err := user.Lookup(name)
	if err != nil {
		return err
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("user %s: uid %q", name, u.Uid)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("group %s: gid %q", name, g.Gid)
	}
	return deploy.CopyCredential(anchor, rel, owner, dst, uid, gid)
}
