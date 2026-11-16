package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// relay manages the relays in front of the node (spec/relay-v1.md, R6-a):
// their addresses reach the service ports without SPA.
func (c *cli) relay(ctx context.Context, sub string, args []string) error {
	switch sub {
	case "add":
		if len(args) != 2 {
			return errUsage
		}
		r, err := c.c.AddRelay(ctx, connect.NewRequest(&nodev1.AddRelayRequest{Name: args[0], Address: args[1]}))
		if err != nil {
			return err
		}
		fmt.Printf("relay %s (%s) added: it reaches the service ports without SPA, never SSH\n", r.Msg.Relay.Name, r.Msg.Relay.Address)
		return nil
	case "list", "":
		r, err := c.c.ListRelays(ctx, connect.NewRequest(&nodev1.ListRelaysRequest{}))
		if err != nil {
			return err
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) {
			if len(r.Msg.Relays) == 0 {
				fmt.Fprintln(w, "no relays")
				return
			}
			fmt.Fprintln(w, "NAME\tADDRESS\tPROBE\tADDED")
			for _, r := range r.Msg.Relays {
				probe := "-"
				if r.ProbePort != 0 {
					probe = strconv.FormatUint(uint64(r.ProbePort), 10)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Name, r.Address, probe, time.Unix(r.CreatedAt, 0).UTC().Format(time.DateOnly))
			}
		})
	case "bundle":
		fs := flag.NewFlagSet("relay bundle", flag.ContinueOnError)
		exit := fs.String("exit", "", "the exit's IP the relay forwards to (default: the node's host)")
		ssh := fs.Uint("ssh-port", 0, "the relay host's SSH port, reached from the admin addresses (default: as before, 22 at first)")
		out := fs.String("o", "", "write the bundle to this new file (0600) instead of printing it")
		admin := fs.String("admin", "", "addresses that reach the relay host's SSH without SPA (comma-separated; default: the relay's, "+
			"or this SSH session's for a relay with none yet; needed: nothing else opens it yet)")
		if err := fs.Parse(args); err != nil || fs.NArg() != 1 || *ssh > 65535 {
			return errUsage
		}
		if err := needRoot(); err != nil {
			return err
		}
		// The file first: issuing the bundle changes the relay's keys, so
		// a bundle that then found no file to go to (one there already, a
		// directory that takes none) was lost, the one before dead too.
		var file *os.File
		if *out != "" {
			f, err := createNew(*out)
			if err != nil {
				return fmt.Errorf("%w: nothing issued, the relay's bundle before still works", err)
			}
			file = f
			defer func() {
				if file != nil { // no bundle in it
					_ = file.Close()
					_ = os.Remove(*out)
				}
			}()
		}
		session := sshClient()
		r, err := c.c.IssueRelayBundle(ctx, connect.NewRequest(&nodev1.IssueRelayBundleRequest{
			Name: fs.Arg(0), ExitAddress: *exit, SshPort: uint32(*ssh), Admin: splitList(*admin), AdminIfNone: splitList(session)}))
		if err != nil {
			return err
		}
		from := "as given"
		switch {
		case r.Msg.AdminKept:
			from = "the relay's own, kept (rayctl relay set changes them)"
		case *admin == "":
			from = "this SSH session's address (" + session + "), the default for a relay with none"
		}
		fmt.Fprintf(os.Stderr, "relay %s: its host's SSH (tcp/%d) from %s: %s\n", fs.Arg(0), r.Msg.SshPort, strings.Join(r.Msg.Admin, ", "), from)
		switch {
		case len(r.Msg.Ports) > 0:
			fmt.Fprintf(os.Stderr, "relay %s: a provider's firewall in front of the relay host lets in all of these (rayctl relay ports %s\n"+
				"lists them again; the exit's ports follow its services):\n", fs.Arg(0), fs.Arg(0))
			w := tabwriter.NewWriter(os.Stderr, 0, 0, 2, ' ', 0)
			printRelayPorts(w, r.Msg.Ports)
			if err := w.Flush(); err != nil {
				return err
			}
		case r.Msg.ProbePort != 0:
			// A node before v0.31.0 names the probe endpoint only.
			fmt.Fprintf(os.Stderr, "relay %s: its probe endpoint on tcp/%d and udp/%d (rayd relay): a provider's firewall in front of\n"+
				"the relay host lets both through, as it does the forwarded ports\n", fs.Arg(0), r.Msg.ProbePort, r.Msg.ProbePort)
		}
		if file == nil {
			fmt.Println(r.Msg.Bundle)
		} else {
			_, err := file.WriteString(r.Msg.Bundle + "\n")
			if cerr := file.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
			file = nil
		}
		fmt.Fprintf(os.Stderr, "relay %s: a new certificate and new SPA keys for it; the bundle before no longer works, and the\n"+
			"running relay stops taking its perimeter until the new bundle is installed there. Clients take the new keys\n"+
			"with their next subscription. A lost relay host still reaches the services from its address: rayctl relay\n"+
			"remove it. The bundle holds the relay's private key: copy it to the relay host only, then there:\n"+
			"  bootstrap.sh -relay BUNDLE_FILE\n", fs.Arg(0))
		return nil
	case "ports":
		if len(args) != 1 {
			return errUsage
		}
		r, err := c.c.ListRelays(ctx, connect.NewRequest(&nodev1.ListRelaysRequest{}))
		if err != nil {
			return err
		}
		i := slices.IndexFunc(r.Msg.Relays, func(r *nodev1.Relay) bool { return r.Name == args[0] })
		if i < 0 {
			return fmt.Errorf("no relay %s (rayctl relay list)", args[0])
		}
		relay := r.Msg.Relays[i]
		if len(relay.Ports) == 0 {
			// Every relay has its SSH port: none is a node before v0.31.0.
			return errors.New("the node runs a version before v0.31.0, which does not list a relay's ports: there, rayctl relay bundle " +
				"names the relay's SSH and probe ports, and the relay forwards the ports of rayctl ports that are reached after the knock")
		}
		return c.print(relay, func(w *tabwriter.Writer) {
			printRelayPorts(w, relay.Ports)
			if !slices.ContainsFunc(relay.Ports, func(p *nodev1.RelayPort) bool { return p.Name == "spa" }) {
				fmt.Fprintf(w, "\nno SPA range yet: rayctl relay bundle %s makes it, with the probe endpoint\n", relay.Name)
			}
		})
	case "set":
		fs := flag.NewFlagSet("relay set", flag.ContinueOnError)
		ssh := fs.Uint("ssh-port", 0, "the relay host's SSH port (0 keeps it)")
		admin := fs.String("admin", "", "addresses that reach the relay host's SSH without SPA (comma-separated; empty keeps them)")
		if err := fs.Parse(args); err != nil || fs.NArg() != 1 || *ssh > 65535 || (*ssh == 0 && *admin == "") {
			return errUsage
		}
		if _, err := c.c.SetRelayAccess(ctx, connect.NewRequest(&nodev1.SetRelayAccessRequest{
			Name: fs.Arg(0), SshPort: uint32(*ssh), Admin: splitList(*admin)})); err != nil {
			return err
		}
		fmt.Printf("relay %s: the relay takes the new SSH access with its next snapshot (within a minute)\n", fs.Arg(0))
		return nil
	case "remove":
		if len(args) != 1 {
			return errUsage
		}
		if _, err := c.c.RemoveRelay(ctx, connect.NewRequest(&nodev1.RemoveRelayRequest{Name: args[0]})); err != nil {
			return err
		}
		fmt.Printf("relay %s removed\n", args[0])
		return nil
	}
	return errUsage
}

// relayPortAccess is what RelayPort's access means, for a person.
var relayPortAccess = map[string]string{
	"everyone": "everyone",
	"spa":      "after the knock",
	"admin":    "the relay's admin addresses; after the knock for SSH devices",
}

// printRelayPorts is a relay's ports as rayctl ports has the node's: what
// a provider's firewall in front of the relay host lets in, where it goes
// (the relay host itself or the exit, on the same port) and who reaches it.
func printRelayPorts(w *tabwriter.Writer, ports []*nodev1.RelayPort) {
	fmt.Fprintln(w, "PROTO\tPORTS\tNAME\tTO\tREACHED BY")
	for _, p := range ports {
		span := strconv.Itoa(int(p.From))
		if p.To != p.From {
			span += "-" + strconv.Itoa(int(p.To))
		}
		to := "relay host"
		if p.Forwarded {
			to = "the exit"
		}
		access := relayPortAccess[p.Access]
		if access == "" {
			access = p.Access
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", strings.Join(p.Protos, "+"), span, p.Name, to, access)
	}
}

// createNew makes a new file for root only; an existing one is left alone.
func createNew(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the operator's file
}
