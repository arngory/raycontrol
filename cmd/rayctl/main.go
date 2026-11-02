// Command rayctl is the administrator CLI. It talks to rayd over the local
// socket and never reads the database itself.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/arngory/raycontrol/internal/api"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
)

const usageText = `usage: rayctl [-socket PATH] [-json] <command>

  status
  user list
  user add [NAME] [-services a,b] [-expires 2026-12-31|30d] [-limit 50G] [-note TEXT]
                                            without NAME: an opaque handle such as u-k3f9-x2qa
  user enable|disable|del NAME
  user services NAME a,b
  service list
  service add KIND NAME [-settings JSON]
  service enable|disable|del NAME
  service set NAME KEY=VALUE                site: answer=404|403|silent|pages; reality: rotate_sni=true|false
  service rotate NAME [-now]                new REALITY keys (and server name, self-steal) ahead of
                                            schedule: after the lead time, or at once with -now
  device list [USER]
  device add USER NAME [-role user|admin] [-o FILE]
                                            the enrollment bundle, once: on the screen or alone in FILE
  device revoke ID
  audit [-n 50]
  admin [ADDR|CIDR ...]                     show or replace addresses that reach SSH without SPA
  dns [status]                              the DNS provider and the records the node needs
  dns cloudflare [-token-file F]            records and wildcard certificates through Cloudflare
                                            (token asked for without echo when no file is given)
  dns sync                                  bring the zone in line now
  dns remove [-keep-records]                delete raycontrol's records and forget the provider

  install -host ADDR [-domain D] [-admin A] [-cloudflare-token-file F] [-services reality,hy2-masq,hy2-obfs,dnstt,masterdns|none]
          [-dataplane DIR]                    set the node up on this host (root); with -domain REALITY by default
  apply                                       install what the current services need (root)
  update [-check] [-version vX.Y.Z] [-from DIR] [-yes] [-rollback]
                                              the newest verified release in place, back to the
                                              previous binaries if the node does not come back (root)
  uninstall [-yes] [-keep-state] [-keep-dns] [-purge-packages]
                                              take back everything install and apply changed (root)

  report [-o FILE] [-logs warning|info|none] [-since 24h] [-id ID]
      a redacted report for an issue: versions, system, checks, units,
      counts and warnings; nothing is sent anywhere
  probe [-carrier udp|tcp|auto] [-addr A] [-links] [-redact] BUNDLE|@FILE|-
      check a node from outside like a client: SPA, then the subscription
      (pin, both signatures). Needs only the device bundle.
`

// version is set at release build time (-X main.version).
var version = "dev"

type cli struct {
	c    nodev1connect.NodeServiceClient
	json bool
}

func main() {
	fs := flag.NewFlagSet("rayctl", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usageText) }
	socket := fs.String("socket", "/run/raycontrol/rayd.sock", "rayd API socket")
	asJSON := fs.Bool("json", false, "print responses as JSON")
	fs.Parse(os.Args[1:])
	if fs.NArg() == 0 {
		fs.Usage()
		os.Exit(2)
	}

	c := &cli{c: api.NewUnixClient(*socket), json: *asJSON}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := c.run(ctx, fs.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "rayctl:", err)
		if errors.Is(err, errUsage) {
			fmt.Fprint(os.Stderr, usageText)
			os.Exit(2)
		}
		os.Exit(1)
	}
}

var errUsage = errors.New("bad usage")

func need(args []string, n int) error {
	if len(args) < n {
		return errUsage
	}
	return nil
}

func (c *cli) run(ctx context.Context, args []string) error {
	cmd, sub := args[0], ""
	if len(args) > 1 {
		sub = args[1]
	}
	rest := args[min(2, len(args)):]
	switch cmd {
	case "status":
		return c.status(ctx)
	case "user":
		return c.user(ctx, sub, rest)
	case "service":
		return c.service(ctx, sub, rest)
	case "device":
		return c.device(ctx, sub, rest)
	case "audit":
		return c.audit(ctx, args[1:])
	case "admin":
		return c.adminAccess(ctx, args[1:])
	case "install":
		return c.install(ctx, args[1:])
	case "apply":
		return c.apply(ctx, args[1:])
	case "probe":
		return probe(ctx, args[1:])
	case "report":
		return c.report(ctx, args[1:])
	case "dns":
		return c.dns(ctx, sub, rest)
	case "update":
		return c.update(ctx, args[1:])
	case "uninstall":
		return c.uninstall(ctx, args[1:])
	}
	return errUsage
}

// print shows msg as JSON when -json is set; otherwise it calls text.
func (c *cli) print(msg proto.Message, text func(w *tabwriter.Writer)) error {
	if c.json {
		b, err := protojson.MarshalOptions{Multiline: true, EmitUnpopulated: true}.Marshal(msg)
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	text(w)
	return w.Flush()
}

func when(unix int64) string {
	if unix == 0 {
		return "-"
	}
	return time.Unix(unix, 0).Format("2006-01-02 15:04")
}

func (c *cli) status(ctx context.Context) error {
	r, err := c.c.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{}))
	if err != nil {
		return err
	}
	m := r.Msg
	return c.print(m, func(w *tabwriter.Writer) {
		fmt.Fprintf(w, "version\t%s\nnode\t%s\nhost\t%s\nusers\t%d\nservices\t%d\nactive devices\t%d\nspa ports\t%v\n",
			m.Version, m.NodeId, m.Host, m.Users, m.Services, m.ActiveDevices, m.SpaPorts)
	})
}

func (c *cli) user(ctx context.Context, sub string, args []string) error {
	switch sub {
	case "list":
		r, err := c.c.ListUsers(ctx, connect.NewRequest(&nodev1.ListUsersRequest{}))
		if err != nil {
			return err
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) {
			fmt.Fprintln(w, "NAME\tENABLED\tEXPIRES\tLIMIT\tSERVICES\tNOTE")
			for _, u := range r.Msg.Users {
				limit := "-"
				if u.TrafficLimitBytes > 0 {
					limit = formatBytes(u.TrafficLimitBytes)
				}
				fmt.Fprintf(w, "%s\t%v\t%s\t%s\t%s\t%s\n", u.Name, u.Enabled, when(u.ExpiresAt), limit, strings.Join(u.Services, ","), u.Note)
			}
		})
	case "add":
		fs := flag.NewFlagSet("user add", flag.ContinueOnError)
		services := fs.String("services", "", "comma-separated service names")
		expires := fs.String("expires", "", "expiry date (2006-01-02) or duration (30d, 12h)")
		limit := fs.String("limit", "", "traffic limit (e.g. 50G)")
		note := fs.String("note", "", "free text")
		// Without a name the user gets an opaque handle: nothing personal
		// on the node, in its logs or reports (docs/09-observability.md).
		name := ""
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			name, args = args[0], args[1:]
		} else {
			name = userHandle()
		}
		if err := fs.Parse(args); err != nil {
			return errUsage
		}
		req := &nodev1.CreateUserRequest{Name: name, Note: *note, Services: splitList(*services)}
		var err error
		if req.ExpiresAt, err = parseExpiry(*expires, time.Now()); err != nil {
			return err
		}
		if req.TrafficLimitBytes, err = parseBytes(*limit); err != nil {
			return err
		}
		r, err := c.c.CreateUser(ctx, connect.NewRequest(req))
		if err != nil {
			return err
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) { fmt.Fprintf(w, "user %s created\n", r.Msg.User.Name) })
	case "enable", "disable":
		if err := need(args, 1); err != nil {
			return err
		}
		_, err := c.c.SetUserEnabled(ctx, connect.NewRequest(&nodev1.SetUserEnabledRequest{Name: args[0], Enabled: sub == "enable"}))
		return err
	case "services":
		if err := need(args, 2); err != nil {
			return err
		}
		_, err := c.c.SetUserServices(ctx, connect.NewRequest(&nodev1.SetUserServicesRequest{Name: args[0], Services: splitList(args[1])}))
		return err
	case "del":
		if err := need(args, 1); err != nil {
			return err
		}
		_, err := c.c.DeleteUser(ctx, connect.NewRequest(&nodev1.DeleteUserRequest{Name: args[0]}))
		return err
	}
	return errUsage
}

func (c *cli) service(ctx context.Context, sub string, args []string) error {
	switch sub {
	case "list":
		r, err := c.c.ListServices(ctx, connect.NewRequest(&nodev1.ListServicesRequest{}))
		if err != nil {
			return err
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) {
			fmt.Fprintln(w, "ID\tNAME\tKIND\tENABLED\tKEYS")
			for _, s := range r.Msg.Services {
				fmt.Fprintf(w, "%d\t%s\t%s\t%v\t%s\n", s.Id, s.Name, s.Kind, s.Enabled, keyState(s))
			}
			fmt.Fprintf(w, "\nkinds: %s\n", strings.Join(r.Msg.Kinds, " "))
		})
	case "add":
		fs := flag.NewFlagSet("service add", flag.ContinueOnError)
		settings := fs.String("settings", "", "settings JSON")
		if err := need(args, 2); err != nil {
			return err
		}
		if err := fs.Parse(args[2:]); err != nil {
			return errUsage
		}
		r, err := c.c.CreateService(ctx, connect.NewRequest(&nodev1.CreateServiceRequest{Kind: args[0], Name: args[1], SettingsJson: *settings}))
		if err != nil {
			return err
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) {
			fmt.Fprintf(w, "service %s created with id %d\n", r.Msg.Service.Name, r.Msg.Service.Id)
			var rs struct{ Site, SNI string }
			if r.Msg.Service.Kind == "reality" && json.Unmarshal([]byte(r.Msg.Service.SettingsJson), &rs) == nil && rs.Site != "" {
				fmt.Fprintf(w, "\nSelf-steal on the decoy site %s: it must resolve to this node (a wildcard record *.<domain>).\n"+
					"rayd gets its certificate (ACME HTTP-01, a short window on TCP 80) and starts the site and REALITY;\n"+
					"run rayctl apply now to install their units.\n", rs.SNI)
			}
		})
	case "enable", "disable":
		if err := need(args, 1); err != nil {
			return err
		}
		_, err := c.c.SetServiceEnabled(ctx, connect.NewRequest(&nodev1.SetServiceEnabledRequest{Name: args[0], Enabled: sub == "enable"}))
		return err
	case "del":
		if err := need(args, 1); err != nil {
			return err
		}
		_, err := c.c.DeleteService(ctx, connect.NewRequest(&nodev1.DeleteServiceRequest{Name: args[0]}))
		return err
	case "set":
		if err := need(args, 2); err != nil {
			return err
		}
		key, value, ok := strings.Cut(args[1], "=")
		if !ok {
			return errUsage
		}
		r, err := c.c.SetServiceOption(ctx, connect.NewRequest(&nodev1.SetServiceOptionRequest{Name: args[0], Key: key, Value: value}))
		if err != nil {
			return err
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) {
			fmt.Fprintf(w, "%s: %s\n", r.Msg.Service.Name, r.Msg.Service.SettingsJson)
			if r.Msg.Service.Kind == "site" {
				fmt.Fprintln(w, "run rayctl apply to restart the site with it")
			}
		})
	case "rotate":
		fs := flag.NewFlagSet("service rotate", flag.ContinueOnError)
		now := fs.Bool("now", false, "switch at once; clients that have not fetched their subscription since lose this profile until they do")
		if err := need(args, 1); err != nil {
			return err
		}
		if err := fs.Parse(args[1:]); err != nil {
			return errUsage
		}
		r, err := c.c.RotateService(ctx, connect.NewRequest(&nodev1.RotateServiceRequest{Name: args[0], Now: *now}))
		if err != nil {
			return err
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) {
			fmt.Fprintf(w, "%s switches to new keys at %s (later if a new server name waits for its certificate)\n",
				args[0], time.Unix(r.Msg.SwitchAt, 0).UTC().Format(time.RFC3339))
		})
	}
	return errUsage
}

// keyState says when a REALITY service last switched keys and when the
// published next switch is (R4-7).
func keyState(s *nodev1.Service) string {
	if s.Kind != "reality" {
		return ""
	}
	var st struct {
		RotatedAt int64  `json:"rotated_at"`
		NextFrom  int64  `json:"next_from"`
		SNINext   string `json:"sni_next"`
	}
	_ = json.Unmarshal([]byte(s.SettingsJson), &st)
	day := func(t int64) string { return time.Unix(t, 0).UTC().Format("2006-01-02 15:04") }
	out := "since creation"
	if st.RotatedAt != 0 {
		out = "since " + day(st.RotatedAt)
	}
	switch {
	case st.NextFrom != 0:
		out += ", switch " + day(st.NextFrom)
	case st.SNINext != "":
		out += ", next name waits for its certificate"
	}
	if st.NextFrom != 0 && st.SNINext != "" {
		out += " with a new name"
	}
	return out
}

func (c *cli) device(ctx context.Context, sub string, args []string) error {
	switch sub {
	case "list":
		req := &nodev1.ListDevicesRequest{}
		if len(args) > 0 {
			req.User = args[0]
		}
		r, err := c.c.ListDevices(ctx, connect.NewRequest(req))
		if err != nil {
			return err
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) {
			fmt.Fprintln(w, "ID\tUSER\tNAME\tROLE\tCREATED\tREVOKED")
			for _, d := range r.Msg.Devices {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", d.Id, d.User, d.Name, d.Role, when(d.CreatedAt), when(d.RevokedAt))
			}
		})
	case "add":
		fs := flag.NewFlagSet("device add", flag.ContinueOnError)
		role := fs.String("role", "user", "user or admin")
		out := fs.String("o", "", "write the bundle alone to this file (mode 0600) instead of the screen")
		if err := need(args, 2); err != nil {
			return err
		}
		if err := fs.Parse(args[2:]); err != nil {
			return errUsage
		}
		r, err := c.c.CreateDevice(ctx, connect.NewRequest(&nodev1.CreateDeviceRequest{User: args[0], Name: args[1], Role: *role}))
		if err != nil {
			return err
		}
		if *out != "" {
			if err := os.WriteFile(*out, []byte(r.Msg.Bundle+"\n"), 0o600); err != nil {
				return fmt.Errorf("device %s enrolled, but the bundle was not written (revoke it): %w", r.Msg.Device.Id, err)
			}
			fmt.Printf("device %s (%s/%s) enrolled; bundle in %s: pass it over a trusted channel, then delete it\n",
				r.Msg.Device.Id, r.Msg.Device.User, r.Msg.Device.Name, *out)
			return nil
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) {
			fmt.Fprintf(w, "device %s (%s/%s) enrolled. Bundle, shown once — pass it to the client over a trusted channel:\n\n%s\n",
				r.Msg.Device.Id, r.Msg.Device.User, r.Msg.Device.Name, r.Msg.Bundle)
		})
	case "revoke":
		if err := need(args, 1); err != nil {
			return err
		}
		_, err := c.c.RevokeDevice(ctx, connect.NewRequest(&nodev1.RevokeDeviceRequest{Id: args[0]}))
		return err
	}
	return errUsage
}

func (c *cli) audit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	n := fs.Uint("n", 50, "number of entries")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	r, err := c.c.ListAudit(ctx, connect.NewRequest(&nodev1.ListAuditRequest{Limit: uint32(*n)}))
	if err != nil {
		return err
	}
	return c.print(r.Msg, func(w *tabwriter.Writer) {
		fmt.Fprintln(w, "TIME\tACTOR\tACTION\tTARGET\tRESULT")
		for _, e := range r.Msg.Entries {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", when(e.Time), e.Actor, e.Action, e.Target, e.Result)
		}
	})
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseExpiry accepts a date (2006-01-02, end of that day UTC) or a duration
// with an optional d suffix for days.
func parseExpiry(s string, now time.Time) (int64, error) {
	if s == "" {
		return 0, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.Add(24*time.Hour - time.Second).Unix(), nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("bad expiry %q", s)
		}
		return now.Add(time.Duration(n) * 24 * time.Hour).Unix(), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("bad expiry %q: use 2006-01-02, 30d or 12h", s)
	}
	return now.Add(d).Unix(), nil
}

var units = []struct {
	suffix string
	mult   int64
}{{"T", 1 << 40}, {"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10}}

// parseBytes accepts a byte count with an optional K, M, G or T suffix
// (powers of 1024).
func parseBytes(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	mult := int64(1)
	num := strings.ToUpper(s)
	for _, u := range units {
		if v, ok := strings.CutSuffix(num, u.suffix); ok {
			num, mult = v, u.mult
			break
		}
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n <= 0 || n > (1<<62)/mult {
		return 0, fmt.Errorf("bad size %q: use e.g. 500M or 50G", s)
	}
	return n * mult, nil
}

func formatBytes(n int64) string {
	for _, u := range units {
		if n >= u.mult && n%u.mult == 0 {
			return strconv.FormatInt(n/u.mult, 10) + u.suffix
		}
	}
	return strconv.FormatInt(n, 10)
}

// userHandle is an opaque user name: "u-" and two groups of four base32
// characters, like an account number.
func userHandle() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	h := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
	return "u-" + h[:4] + "-" + h[4:]
}
