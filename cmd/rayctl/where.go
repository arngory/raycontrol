package main

import (
	"flag"
	"fmt"
	"runtime"
)

// Where a command works. A node is Linux; rayctl is also built for the
// administrator's own machine (macOS, FreeBSD), where it reaches a node
// through its remote API and from outside like a client. There the
// commands that act on the node's host refuse before anything is done:
// one table, one check (refusal), called once from main.

// place is where a command can do its work.
type place int

const (
	// anywhere: no node on this host and no API is needed, the bundle or
	// the invite on the command line is enough.
	anywhere place = iota
	// viaAPI: rayd's API, over the node's socket or, from any system, with
	// -remote FILE. What a remote device may ask is the node's to say.
	viaAPI
	// onNode: this host is the node (its files, units, perimeter, root).
	onNode
)

// places is where each command works, by "command" or "command sub"; the
// longer key wins. Every command of (*cli).run is here (TestPlaces).
var places = map[string]place{
	"status":       viaAPI,
	"node":         viaAPI,
	"user":         viaAPI,
	"service":      viaAPI,
	"service cert": onNode, // the key's file is the node's, the call root's
	"device":       viaAPI,
	"audit":        viaAPI,
	"relay":        viaAPI,
	"relay bundle": onNode, // root on the node; this SSH session's address
	"admin":        viaAPI,
	"dns":          viaAPI,
	"summary":      viaAPI,
	"summary db":   onNode, // a file put in rayd's directory
	"app-mirror":   viaAPI,
	"metrics":      viaAPI,

	"remote":        viaAPI,
	"remote whoami": viaAPI, // the device of -remote FILE
	"remote rotate": viaAPI,
	"remote enroll": anywhere,
	"knock":         anywhere,
	"probe":         anywhere,

	"check":      onNode,
	"legacy":     onNode,
	"install":    onNode,
	"apply":      onNode,
	"update":     onNode,
	"uninstall":  onNode,
	"backup":     onNode,
	"restore":    onNode,
	"report":     onNode,
	"debug":      onNode,
	"egress":     onNode,
	"conn-limit": onNode,
}

// nodeOS is the system a node runs on.
const nodeOS = "linux"

// placeOf is where the command line args works, and the command as the
// table names it; false for a command the table does not have (run then
// answers with the usage).
func placeOf(args []string) (place, string, bool) {
	if len(args) == 0 {
		return 0, "", false
	}
	if len(args) > 1 {
		if p, ok := places[args[0]+" "+args[1]]; ok {
			return p, args[0] + " " + args[1], true
		}
	}
	p, ok := places[args[0]]
	return p, args[0], ok
}

// refusal is why the command args does not run on the system goos, or nil.
// Nothing is refused on Linux. Elsewhere: a command that acts on the
// node's host, always; one that asks rayd, unless -remote FILE says which
// node (or -socket where its socket is: one forwarded here over SSH).
func refusal(goos string, remote, socket bool, args []string) error {
	if goos == nodeOS {
		return nil
	}
	p, name, ok := placeOf(args)
	if !ok {
		return nil
	}
	switch {
	case p == onNode:
		return fmt.Errorf("%s works on a Linux node only, and this is %s: run it on the node (here: -remote FILE, remote enroll, knock, probe)", name, goos)
	case p == viaAPI && !remote && !socket:
		return fmt.Errorf("%s asks a node, and there is none on %s: rayctl -remote FILE %s (rayctl remote enroll writes the device file)", name, goos, name)
	}
	return nil
}

// misplaced is refusal for this system and the command line as parsed.
func misplaced(fs *flag.FlagSet) error {
	remote, socket := false, false
	fs.Visit(func(f *flag.Flag) {
		remote = remote || f.Name == "remote" && f.Value.String() != ""
		socket = socket || f.Name == "socket"
	})
	return refusal(runtime.GOOS, remote, socket, fs.Args())
}
