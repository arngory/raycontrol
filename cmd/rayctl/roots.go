package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/arngory/raycontrol/internal/roots"
)

// rootsCmd: rayctl roots [show] | system on|off | file PEM|none. The
// roots the node's own outbound TLS trusts (R4-41) are root's file in
// /etc: rayd reads it at its next connection, rayctl update when it runs,
// before rayd is up if need be.
func rootsCmd(out io.Writer, settingsFile, extraFile string, args []string) error {
	s, err := roots.ReadSettings(settingsFile)
	switch {
	case len(args) == 0 || len(args) == 1 && args[0] == "show":
		return rootsShow(out, settingsFile, s, err)
	case len(args) != 2:
		return errUsage
	}
	if err := needRoot(); err != nil {
		return err
	}
	if err != nil {
		// A file that does not parse is replaced by what root says now.
		fmt.Fprintf(out, "warning: %v: starting from the default\n", err)
		s = roots.Settings{}
	}
	switch args[0] {
	case "system":
		if args[1] != "on" && args[1] != "off" {
			return errUsage
		}
		s.System = args[1] == "on"
	case "file":
		if args[1] == "none" {
			s.File = ""
			if err := os.Remove(extraFile); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			break
		}
		cs, err := roots.ReadExtra(args[1])
		if err != nil {
			return err
		}
		// A copy of root's in /etc: rayd reads it whatever its sandbox,
		// and the operator's file may go.
		if err := roots.WriteExtra(extraFile, cs); err != nil {
			return err
		}
		s.File = extraFile
	default:
		return errUsage
	}
	if err := roots.WriteSettings(settingsFile, s); err != nil {
		return err
	}
	p := roots.Build(s, nil)
	if p.Err != nil {
		return fmt.Errorf("written, but it is not followed: %w", p.Err)
	}
	fmt.Fprintf(out, "the node's outbound TLS trusts: %s\n", p)
	fmt.Fprintln(out, "rayd follows from its next connection, rayctl update when it runs; no restart")
	if s.System {
		fmt.Fprintln(out, "with the system store a root installed in this image (by its maker, a provider or an intruder)\n"+
			"may read the node's connections: ACME, Cloudflare's token, IPinfo's, the DoH upstreams")
	}
	return nil
}

func rootsShow(out io.Writer, settingsFile string, s roots.Settings, readErr error) error {
	p := roots.Build(s, nil)
	if readErr != nil {
		p.Err = readErr
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "embedded\t%d roots of %s: Chrome's and Mozilla's lists without the CAs based in China, as the client's\n",
		len(roots.Embedded()), roots.Date())
	fmt.Fprintf(w, "source\t%s\n", roots.Source())
	switch {
	case p.Err != nil:
		fmt.Fprintf(w, "WARNING\t%v: the embedded list only\n", p.Err)
	default:
		fmt.Fprintf(w, "system store\t%s\n", map[bool]string{true: "added (rayctl roots system off)", false: "not trusted (rayctl roots system on)"}[s.System])
		if s.File == "" {
			fmt.Fprintln(w, "extra file\tnone (rayctl roots file PEM: a TLS-intercepting proxy's root, a private ACME CA's)")
		} else {
			fmt.Fprintf(w, "extra file\t%s (rayctl roots file none), its roots:\n", s.File)
			cs, _ := roots.ReadExtra(s.File)
			for _, c := range cs {
				fmt.Fprintf(w, "\t%s\n", c.Subject)
			}
		}
	}
	fmt.Fprintf(w, "settings\t%s\n", settingsFile)
	fmt.Fprintln(w, "used by\trayd (ACME, Cloudflare, IPinfo, app mirror, DoH upstreams, update check), rayctl update;")
	fmt.Fprintln(w, "\tconnections they refused: rayctl status, tls-roots")
	return w.Flush()
}
