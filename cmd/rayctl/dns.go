package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"connectrpc.com/connect"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
)

// dns manages the node's DNS provider (docs/08-decisions.md, R4-10).
func (c *cli) dns(ctx context.Context, sub string, args []string) error {
	switch sub {
	case "", "status":
		r, err := c.c.GetDNS(ctx, connect.NewRequest(&nodev1.GetDNSRequest{}))
		if err != nil {
			return err
		}
		return c.printDNS(r.Msg, r.Msg.Status)
	case "cloudflare":
		fs := flag.NewFlagSet("dns cloudflare", flag.ContinueOnError)
		file := fs.String("token-file", "", "file with the API token (default: asked for, not echoed)")
		if err := fs.Parse(args); err != nil {
			return errUsage
		}
		token, err := readToken(*file)
		if err != nil {
			return err
		}
		r, err := c.c.SetDNSProvider(ctx, connect.NewRequest(&nodev1.SetDNSProviderRequest{Provider: "cloudflare", Token: token}))
		if err != nil {
			return err
		}
		return c.printDNS(r.Msg, r.Msg.Status)
	case "sync":
		r, err := c.c.SyncDNS(ctx, connect.NewRequest(&nodev1.SyncDNSRequest{}))
		if err != nil {
			return err
		}
		return c.printDNS(r.Msg, r.Msg.Status)
	case "remove":
		fs := flag.NewFlagSet("dns remove", flag.ContinueOnError)
		keep := fs.Bool("keep-records", false, "forget the provider, leave the records in the zone")
		if err := fs.Parse(args); err != nil {
			return errUsage
		}
		r, err := c.c.RemoveDNS(ctx, connect.NewRequest(&nodev1.RemoveDNSRequest{KeepRecords: *keep}))
		if err != nil {
			return err
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) {
			for _, rec := range r.Msg.Removed {
				fmt.Fprintln(w, "removed", rec)
			}
			fmt.Fprintln(w, "the node has no DNS provider now")
		})
	}
	return errUsage
}

func (c *cli) printDNS(msg proto.Message, st *nodev1.DNSStatus) error {
	return c.print(msg, func(w *tabwriter.Writer) {
		if st.Provider == "" {
			fmt.Fprintln(w, "provider\tnone: records by hand, certificates through HTTP-01 (rayctl dns cloudflare sets one up)")
		} else {
			fmt.Fprintf(w, "provider\t%s, zone %s\n", st.Provider, st.Zone)
		}
		fmt.Fprintln(w, "\nTYPE\tNAME\tCONTENT")
		for _, r := range st.Records {
			fmt.Fprintf(w, "%s\t%s\t%s\n", r.Type, r.Name, r.Content)
		}
		for _, ch := range st.Changes {
			fmt.Fprintln(w, "\n"+ch)
		}
		for _, p := range st.Problems {
			fmt.Fprintln(w, "\nproblem:", p)
		}
	})
}

// readToken reads the Cloudflare token (readSecret).
func readToken(file string) (string, error) {
	t, err := readSecret("Cloudflare API token (Zone.DNS:Edit and Zone.Zone:Read on the node's zone): ", file, false)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(t), nil
}

// readSecret reads a secret from a file, or from the terminal without echo
// (twice with confirm), never from the command line (shell history, ps).
// Only the line end is cut off.
func readSecret(prompt, file string, confirm bool) (string, error) {
	if file != "" {
		b, err := os.ReadFile(file) //nolint:gosec // G304: the operator's file
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	in := bufio.NewReader(os.Stdin)
	fd := int(os.Stdin.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	terminal := err == nil
	ask := func(prompt string) (string, error) {
		if terminal {
			fmt.Fprint(os.Stderr, prompt)
			quiet := *old
			quiet.Lflag &^= unix.ECHO
			if err := unix.IoctlSetTermios(fd, unix.TCSETS, &quiet); err == nil {
				defer func() {
					_ = unix.IoctlSetTermios(fd, unix.TCSETS, old)
					fmt.Fprintln(os.Stderr)
				}()
			}
		}
		line, err := in.ReadString('\n')
		if err != nil && line == "" {
			return "", err
		}
		if line = strings.TrimRight(line, "\r\n"); line == "" {
			return "", errors.New("nothing entered")
		}
		return line, nil
	}
	secret, err := ask(prompt)
	if err != nil || !confirm || !terminal {
		return secret, err
	}
	again, err := ask("Again: ")
	if err != nil {
		return "", err
	}
	if again != secret {
		return "", errors.New("the two entries differ")
	}
	return secret, nil
}
