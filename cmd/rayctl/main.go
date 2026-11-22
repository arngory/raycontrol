// Command rayctl is the administrator CLI. It talks to rayd over the local
// socket and never reads the database itself.
package main

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/arngory/raycontrol/internal/api"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/device/v1/devicev1connect"
	nodev1 "github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1"
	"github.com/arngory/raycontrol/internal/gen/raycontrol/node/v1/nodev1connect"
	"github.com/arngory/raycontrol/internal/hostcheck"
	"github.com/arngory/raycontrol/internal/nodeupdate"
	"github.com/arngory/raycontrol/internal/provision"
	"github.com/arngory/raycontrol/internal/release"
	"github.com/arngory/raycontrol/internal/roots"
	"github.com/arngory/raycontrol/internal/store"
)

const usageText = `usage: rayctl [-socket PATH | -remote FILE] [-json] <command>

  status
  version                                   this rayctl's version and, on a node or relay host, the one installed
                                            (rayd's); with -remote FILE, the node's
  node name [NAME | ""]                     show, set or remove the node's name, which clients show
                                            with its address (at most 48 characters)
  node note [TEXT | ""]                     show, set or remove the note clients show their users (200 characters, one line)
  user list
  user add [NAME] [-services a,b] [-expires 2026-12-31|30d] [-limit 50G [-period monthly|none] [-reset-day 1]] [-note TEXT]
                                            without NAME: an opaque handle such as u-k3f9-x2qa
  user enable|disable|del NAME
  user expires NAME 2026-12-31|30d|never|now  when the user expires: a later time, never, or at once
  user services NAME a,b
  user limit NAME 50G|off [-period monthly|none] [-reset-day N]
                                            the traffic limit, up + down a period (monthly from day N,
                                            00:00 UTC, or none: the user's whole time); over it the
                                            user is off every profile until the reset or a higher limit
  user lan NAME [on|off]                    the user's devices see each other over Yggdrasil (LAN), each that
                                            shows itself in the client (needs a Yggdrasil service); on again:
                                            a new password; without on|off: show it
  user usage [NAME]                         the users' counts against their limits
  user reset-usage NAME                     the current period's count from zero, now
  user export NAME [-o FILE]                the user's links, as in the subscription (they hold credentials)
  user renew NAME                           new credentials for the user at once, no overlap, as a device
                                            revocation gives them; the user's devices are cut until they
                                            fetch their subscription (Niko: at its next connection check,
                                            within about 10 minutes)
  service list
  service add KIND NAME [-settings JSON]    slipstream: -settings '{"zone":"s.example.net"}' for a zone
                                            of your own (20 characters at most), else one is made up
  service enable|disable|del NAME [-force]
                                            -force: disable or delete the last enabled ssh service anyway
                                            (refused without it: SSH to the node closes to everyone)
  service set NAME KEY=VALUE                site: answer=404|403|silent|pages;
                                            reality: rotate_sni=on|off|auto (whether a switch moves the
                                            server name; auto: a scheduled one only under a wildcard
                                            certificate, one you ask for always),
                                            target=HOST:PORT (who answers non-clients, checked as at
                                            creation; keys, shortIds and server name stay);
                                            hy2-*: up_mbps=N|0|auto (Brutal's ceiling; 0: none; auto,
                                            the default: the speed of the node's link, 1 Gbit/s or more,
                                            where the kernel knows it), down_mbps=N (told to clients,
                                            0: none);
                                            naive: icmp=on|off (ping and traceroute through it, then
                                            rayctl apply), udp=on|off (UDP as HTTP/3 datagrams,
                                            naive-udp-v1; off by default; then rayctl apply),
                                            rotate_sni=on|off|auto (its server name
                                            every -naive-sni-period; auto: under a wildcard certificate
                                            only; rotate always switches);
                                            yggdrasil: peers=URI,URI|none (public peers, then rayctl apply),
                                            lan_relay=N (LAN through the node, Mbit/s a user, 20 unless set;
                                            0: in one Wi-Fi only);
                                            dnstt, masterdns: auth=, auth_hint=, seal=off|optional|required
                                            (auth_hint: dnsauth-v2 tags; required needs auth=required),
                                            spare_zones=N|ZONE,ZONE|none (spare zones, made up or your own),
                                            zone=SPARE (a spare becomes the main zone, the main one leaves);
                                            slipstream: max_connections=16..1024, device_connections=1..16
                                            (0: the defaults, 256 and 4; the server restarts)
  service peer-keys [-names] NAME           yggdrasil: the public keys a peer of your own (peers=) lets in
                                            with AllowedPublicKeys, as HJSON for its config: the node's,
                                            then each user's and device's, labelled as in the node's users
                                            file (-names: with the users' and devices' names, which then
                                            sit on a host outside the node); they change with devices,
                                            users and credential switches
  service cert SITE -chain F -key F [-force]
                                            a certificate of your own for the site and the services under
                                            it, in place of ACME's (root on the node only); the links
                                            under it then carry no niko-pin; it says whether the chain leads
                                            to a root clients know. Refused, unless -force, when
                                            they carry the node's pins and its key is another: clients
                                            that hold them are cut off until they fetch their subscription
  service rotate NAME [-now] [-force] [-fresh]
                                            new REALITY keys (and server name, self-steal) ahead of
                                            schedule: after the lead time, or at once with -now;
                                            naive: a new server name after the lead time, or at once
                                            with -now, the previous ones accepted until a switch a
                                            period after theirs, 3 at most (it says which stay);
                                            dnstt: a new seal key at once, masterdns: a new service key
                                            at once; the previous one accepted for -cred-grace (with
                                            -now: not at all); refused while the key before is still
                                            in its grace, unless -force (that key then goes at once);
                                            a site (root): its certificate moves to the next key, the
                                            one clients already pin; refused until that key has been
                                            in subscriptions for -site-key-lead, unless -force (the
                                            key in use leaked; not twice within 72 h); -fresh: to a
                                            key made now, the next key replaced too (the store
                                            leaked): every pinned client is cut off until it fetches
  device list [USER]
  device add USER NAME [-role user|admin] [-o FILE]
                                            the enrollment bundle, once: on the screen or alone in FILE
  device revoke [-overlap] ID               a device, or an invite not yet used; a device's user gets new
                                            credentials at once, the user's other devices cut until they
                                            fetch their subscription. -overlap, for a device given away
                                            or broken, not stolen: they rotate instead, the next ones
                                            published now, the switch after -cred-lead (3 days), the old
                                            ones, which the device knew, accepted -cred-grace (2 days)
                                            more; the other devices move over without a cut
  device invite USER NAME [-role user|admin|billing|support] [-ttl 24h] [-o FILE | -qr] [-pin[=false]] [-format rcinv3|rcinv2|rcinv1]
                [-allow ADDR,...]
                                            a one-time invite: the client registers the device itself
                                            through the remote API (service add api api); by default
                                            rcinv3, with the node's name and SPA v3 when it has them
                                            (Niko 1.63 or later); rcinv2 the short form by the host
                                            (Niko 1.35 or later), rcinv1 for older Niko. -pin: a PIN
                                            too, told by another channel; on for admin and billing
                                            unless -pin=false. -allow, billing and support only:
                                            the integration's server calls from these without a knock
  device allow ID ADDR[,ADDR...] | -clear   an integration's device calls from these addresses (IPv4
                                            /28-/32, IPv6 /64-/128, at most 8) without a knock, and
                                            from nowhere else; -clear: back to SPA
  audit [-n 50]
  admin [ADDR|CIDR ...]                     show or replace addresses that reach SSH without SPA: IPv4
                                            and IPv6, networks to /16 and /48; the list is replaced
                                            whole (name the ones you keep too)
  ports                                     every port the node uses, for a provider's firewall: who
                                            reaches it, whether chosen at install (-ports) or random,
                                            the current port of each rotating range
  relay add NAME ADDRESS | list | remove NAME   relays in front of the node (relay-v1): one address
                                            each, reaching the service ports without SPA
  relay bundle [-exit IP] [-ssh-port N] [-admin CIDRS] [-o FILE] NAME   the relay host's bundle: new certificate, new SPA keys (root only)
  relay set [-ssh-port N] [-admin CIDRS] [-users U,..|all] [-renew-names] NAME
                                            the relay host's SSH access, without a new bundle; the users
                                            the relay is for; its names made again with long labels
  relay ports NAME                          every port the relay host takes, for a provider's firewall
                                            in front of it: its SSH, SPA range and probe endpoint, and
                                            the exit's ports it forwards (relay bundle prints them too)
  dns [status]                              the DNS provider and the records the node needs
  dns cloudflare [-token-file F]            records and wildcard certificates through Cloudflare
                                            (token asked for without echo when no file is given)
  dns sync                                  bring the zone in line now
  dns check [-now] [-resolver google,nsdi,udp:IP,…]
                                            the DNS tunnel zones from the node: delegation, front,
                                            backend, resolvers (rayd's last check; -now: at once)
  dns remove [-keep-records]                delete raycontrol's records and forget the provider
  summary [show] [-days 7]                  client summaries: networks with enough reports (R4-21)
  summary on|off                            take client reports (and give hints) or not
  summary api ipinfo [-token-file F] | none the online AS lookup for addresses the databases miss
  summary db FILE.mmdb | -remove            an AS database of your own before the release's (root)
  app-mirror [show] | on | off              the client's releases on the node for its devices
                                            (spec/app-update-v1.md; off by default)
  integration [status]                      outside systems' devices (billing, support): their calls,
                                            the limits, the settings (spec/integrations-v1.md)
  integration set support-notes on|off      support sees users' notes
  integration set mass-limit N              billing's deletions and disables an hour before each needs
                                            confirm_mass (root)
  integration limits [billing|support|DEVICE_ID [read=100,10/s] [write=50,5/s] [heavy=20,60/h]
                     [inflight=4] | -reset]   the rate limits of a role or one device (root)
  traffic counting [on|auto]                on: Xray counts users' traffic with no limit set too, so
                                            that no limit set or taken away restarts it (billing's)
  client [show]                             the minimum client version and the devices by client
  client min PRODUCT VERSION|none [-from YYYY-MM-DD|now] [-unknown allow|refuse [-yes]]
                                            refuse clients below it (spec/client-min-v1.md)
  debug [show] | on [-for 30m] | off        the debug window: rayd, rayspa and niko-server log at debug
                                            level (client addresses too) until it closes by itself; root
  egress [show]                             the node's egress policy on every profile, whether it is in
                                            force and (root) what it blocked
  egress block|allow bittorrent|smtp|local  block or allow BitTorrent, SMTP (TCP 25), or the node's own
                                            and local networks (blocked by default), on every
                                            profile (spec/egress-policy-v1.md; root, on the node)
  conn-limit [show]                         the connection limits: on or off, their numbers, the
                                            conntrack table, the guard, users at a limit in 15 min
  conn-limit on|off                         per-user limits (naive, Hysteria2, Xray) and the
                                            per-address limit on new inbound connections
                                            (spec/conn-limit-v1.md; root, on the node)
  roots [show] | system on|off | file PEM|none
                                            the roots the node's own outbound TLS trusts (ACME, updates,
                                            Cloudflare, the app mirror, DoH upstreams): its embedded list,
                                            plus the system store or a PEM file only when root adds them
                                            (a TLS-intercepting proxy, a private ACME CA)

  check [-host ADDR] [-domain D] [-services a,b] [-ports LIST]
                                              whether this host can run a node: what is required (install
                                              refuses without it), what is advised, whether the -ports are
                                              free; changes nothing (root)
  legacy [-remove [-yes] [-purge-packages]]  raycontrol v0 (ray.sh) on this host; -remove backs it up, then
                                              removes only what it installed (root)
  install -host ADDR [-domain D] [-name NAME] [-admin A] [-cloudflare-token-file F] [-services reality,hy2-masq,hy2-obfs,dnstt,masterdns,slipstream|none]
          [-dataplane DIR] [-ports spa=A-B,sub=N,api=N,rotation=A-B|off]
                                              set the node up on this host (root); with -domain REALITY by
                                              default; -ports: ports of your choice at the first install
                                              only (1024 and up; the rest random, 443 and 53 fixed)
  apply                                       install what the current services need (root)
  update [-check] [-version vX.Y.Z] [-from DIR] [-yes] [-no-handoff] [-no-relays] [-rollback [-no-carry]]
                                              the newest verified release in place, back to the
                                              previous binaries if the node does not come back (root);
                                              on a relay host the relay, with its stored bundle
                                              (not yet run on a real relay host); -check and
                                              -rollback do not go together; the node's relays
                                              follow an update unless -no-relays
  update status | remote on|off | auto off|patch [-window HH:MM-HH:MM]
                                              updates by request: admin devices over the API, rayd's
                                              own to patch releases in the window (root); on a relay
                                              remote only: the releases its exit names
  uninstall [-yes] [-keep-state] [-keep-dns] [-purge-packages]
                                              take back everything install and apply changed (root)
  backup [-o FILE] [-passphrase-file F]       the node's state sealed with a passphrase (root):
                                              users, keys, services, certificates
  restore -i FILE [-passphrase-file F] [-host ADDR] [-no-carry] [-yes]
                                              put a backup in place and bring the node up on it,
                                              here or on a new host after install (root); -no-carry
                                              brings back the backup's credentials and revocations
  metrics [-o FILE]                           counts and times in the Prometheus text format; with
                                              -o for a collector's textfile directory

  stats [-last 1h] [-id RUN] [-o FILE]        the last hour (5m to 2h) as JSON: counts, levels, the
                                              host, clients by version; no names, addresses or keys,
                                              made to be passed on with the client's (spec/stats-v1.md)
  report [-o FILE] [-logs warning|info|debug|none] [-since 24h] [-id ID]
      a redacted report for an issue: versions, system, checks, units,
      counts and warnings; nothing is sent anywhere
  knock [-carrier udp|tls|tcp|auto] [-addr A] [-ttl 10m] BUNDLE|@FILE
      SPA only: open the device's services to this address for a while; with
      the emergency bundle, SSH (then ssh as usual)
  probe [-carrier udp|tls|tcp|auto] [-addr A] [-links] [-payload] [-redact] [-channel] [-report JSON|@FILE]
        [-dns [-resolver system,google,udp:IP,…]] BUNDLE|@FILE|-
      check a node from outside like a client: SPA, then the subscription
      (pin, both signatures). Needs only the device bundle. -channel then
      measures the channel (TCP down and up, UDP echo; probe-v1); -dns checks
      the subscription's DNS tunnel zones from this machine.

  From another machine, with a device file and the node's remote API:
  remote enroll [-o FILE] [-carrier udp|tls|tcp|auto] [-addr A] [-pin PIN] INVITE|@FILE|-
      register a device from an invite (RCINV3:..., RCINV2:... or rcinv1:...): a new client
      key, SPA, then the API; writes the device file (bundle and key, mode 0600)
  -remote FILE <command>                    status, node, user, service, device, audit, admin, ports, relay
                                            list|ports|set, dns, metrics, summary, app-mirror, debug, version run
                                            against the node through its API
  -remote FILE remote whoami|rotate         the device; a new client key for it
  remote export FILE -pem OUT               the device's certificate and key as PEM (a new file, 0600), and
                                            the API's address and pin as curl takes them
                                            (spec/integrations-v1.md §5.2)
`

// version is set at release build time (-X main.version).
var version = "dev"

type cli struct {
	c nodev1connect.NodeServiceClient
	// backupClient is c for Backup, whose answer is the whole database
	// (nil: c).
	backupClient nodev1connect.NodeServiceClient
	json         bool
	// With -remote: the device and its DeviceService client.
	identity *remoteIdentity
	dev      devicev1connect.DeviceServiceClient
}

func main() {
	fs := flag.NewFlagSet("rayctl", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usageText) }
	socket := fs.String("socket", "/run/raycontrol/rayd.sock", "rayd API socket")
	asJSON := fs.Bool("json", false, "print responses as JSON")
	remote := fs.String("remote", "", "use a node's remote API with this device file (rayctl remote enroll)")
	fs.Parse(os.Args[1:])
	if fs.NArg() == 0 {
		fs.Usage()
		os.Exit(2)
	}
	if err := misplaced(fs); err != nil {
		fmt.Fprintln(os.Stderr, "rayctl:", err)
		os.Exit(1)
	}

	// Root's umask may be 027 or 077 (hardened images): what rayctl puts in
	// place for the services (directories, binaries) must not follow it.
	if os.Geteuid() == 0 {
		syscall.Umask(0o022)
	}
	c := &cli{c: api.NewUnixClient(*socket), backupClient: api.NewUnixBackupClient(*socket), json: *asJSON}
	// An update downloads ~50 MB, maybe through slow mirrors; its restart
	// and rollback have their own time (Q-2).
	timeout := 5 * time.Minute
	if fs.Arg(0) == "update" {
		timeout = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var err error
	if *remote != "" && (fs.Arg(0) != "remote" || fs.Arg(1) != "enroll") {
		err = c.useRemote(ctx, *remote, fs.Args())
	}
	if err == nil {
		err = c.run(ctx, fs.Args())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "rayctl:", printableError(err))
		if errors.Is(err, errUsage) {
			fmt.Fprint(os.Stderr, usageText)
			os.Exit(2)
		}
		os.Exit(1)
	}
}

var errUsage = errors.New("bad usage")

// maxErrorText bounds an error as rayctl prints it.
const maxErrorText = 512

// printableError is err's text as rayctl prints it: a node's answers, a
// remote node's, files and names reach it, so nothing a terminal acts on
// (nodeupdate.Printable, line by line: rayctl's own errors may have
// several), and maxErrorText bytes at most (second review, A).
func printableError(err error) string {
	lines := strings.Split(err.Error(), "\n")
	for i, l := range lines {
		lines[i] = nodeupdate.Printable(l)
	}
	s := strings.Join(lines, "\n")
	if len(s) <= maxErrorText {
		return s
	}
	n := maxErrorText
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

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
	case "node":
		return c.nodeCmd(ctx, sub, rest)
	case "user":
		return c.user(ctx, sub, rest)
	case "service":
		return c.service(ctx, sub, rest)
	case "device":
		return c.device(ctx, sub, rest)
	case "audit":
		return c.audit(ctx, args[1:])
	case "relay":
		return c.relay(ctx, sub, rest)
	case "admin":
		return c.adminAccess(ctx, args[1:])
	case "ports":
		return c.ports(ctx, args[1:])
	case "check":
		return c.check(ctx, args[1:])
	case "legacy":
		return c.legacyCmd(ctx, args[1:])
	case "knock":
		return knock(ctx, args[1:])
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
	case "summary":
		return c.summaryCmd(ctx, sub, rest)
	case "app-mirror":
		return c.appMirror(ctx, sub)
	case "client":
		return c.clientCmd(ctx, sub, rest)
	case "integration":
		return c.integrationCmd(ctx, sub, rest)
	case "traffic":
		return c.trafficCmd(ctx, sub, rest)
	case "debug":
		return c.debug(ctx, sub, rest)
	case "egress":
		return c.egress(ctx, args[1:])
	case "conn-limit":
		return c.connLimit(ctx, args[1:])
	case "roots":
		return rootsCmd(os.Stdout, roots.SettingsFile, roots.ExtraFile, args[1:])
	case "remote":
		return c.remoteCmd(ctx, sub, rest)
	case "backup":
		return c.backup(ctx, args[1:])
	case "restore":
		return c.restore(ctx, args[1:])
	case "metrics":
		return c.metrics(ctx, args[1:])
	case "stats":
		return c.stats(ctx, args[1:])
	case "update":
		return c.update(ctx, args[1:])
	case "version":
		return c.versionCmd(ctx, args[1:])
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
		// rayd away (a boot it did not come up in): the perimeter all the
		// same, which does not need it.
		if c.identity == nil && thisOS == nodeOS && os.Geteuid() == 0 {
			for _, r := range perimeterResult(defaultPerimeterHost) {
				fmt.Fprintf(os.Stderr, "perimeter table: %s\n", perimeterLine(r))
			}
		}
		return err
	}
	m := r.Msg
	// A node of rayd serve -supervise (GetEgress names rayd's UID): no
	// perimeter of its own, so the policy is not the kernel's there.
	supervised := false
	if m.Egress != nil {
		if e, err := c.c.GetEgress(ctx, connect.NewRequest(&nodev1.GetEgressRequest{})); err == nil {
			supervised = len(e.Msg.Uids) > 0
		}
	}
	// naive's server names (R4-42): the one in use and the published next;
	// a rayd that cannot answer leaves the lines out.
	var naives []*nodev1.Service
	if !c.json {
		if l, err := c.c.ListServices(ctx, connect.NewRequest(&nodev1.ListServicesRequest{})); err == nil {
			for _, s := range l.Msg.Services {
				if s.Kind == "naive" && s.Enabled {
					naives = append(naives, s)
				}
			}
		}
	}
	// Integrations' addresses no call came from for long (integrations-v1
	// §3.4): the address may be someone else's now.
	var stale []string
	if !c.json {
		if l, err := c.c.ListDevices(ctx, connect.NewRequest(&nodev1.ListDevicesRequest{})); err == nil {
			stale = staleAllow(l.Msg.Devices, time.Now())
		}
	}
	// sshd's ports against the perimeter's: root on the node only (sshd -T).
	var ssh, per []hostcheck.Result
	if !c.json && c.identity == nil && thisOS == nodeOS && os.Geteuid() == 0 {
		ssh = c.sshPortResults(ctx)
		// The table in the kernel, as rayd cannot see it (R4-40).
		per = perimeterResult(defaultPerimeterHost)
	}
	return c.print(m, func(w *tabwriter.Writer) {
		fmt.Fprintf(w, "version\t%s\nnode\t%s\n", m.Version, m.NodeId)
		if m.Name != "" {
			fmt.Fprintf(w, "name\t%s\n", m.Name)
		}
		fmt.Fprintf(w, "host\t%s\nusers\t%d\nservices\t%d\nactive devices\t%d\nspa ports\t%v\n",
			m.Host, m.Users, m.Services, m.ActiveDevices, m.SpaPorts)
		if m.DebugUntil != 0 {
			fmt.Fprintf(w, "debug\topen until %s (rayctl debug off)\n", clock(m.DebugUntil))
		}
		if m.Egress != nil {
			fmt.Fprintf(w, "egress\t%s\n", egressStatusLine(m.Egress, supervised))
		}
		for _, s := range naives {
			fmt.Fprintf(w, "naive %s\t%s\n", s.Name, naiveStatus(s))
		}
		// rayd's loops: the last round of each (O-2).
		for _, l := range m.Loops {
			fmt.Fprintf(w, "%s\t%s\n", l.Name, perimeterLoopState(l, time.Now()))
		}
		for _, r := range ssh {
			if !r.OK {
				fmt.Fprintf(w, "ssh port\tWARNING %s: %s\n", r.Detail, r.Fix)
			}
		}
		for _, r := range per {
			fmt.Fprintf(w, "perimeter table\t%s\n", perimeterLine(r))
		}
		for _, line := range stale {
			fmt.Fprintf(w, "integration\tWARNING %s\n", line)
		}
		for _, line := range m.Warnings {
			fmt.Fprintf(w, "node\tWARNING %s\n", line)
		}
	})
}

// staleAfter is how long an integration's addresses may go without a call
// before status points them out.
const staleAfter = 30 * 24 * time.Hour

// staleAllow are the integrations' devices with addresses and no call
// for staleAfter (none since they were made that long ago).
func staleAllow(devices []*nodev1.Device, now time.Time) []string {
	var out []string
	for _, d := range devices {
		if len(d.Allow) == 0 || d.RevokedAt != 0 {
			continue
		}
		last := cmp.Or(d.LastCall, d.CreatedAt)
		if now.Sub(time.Unix(last, 0)) < staleAfter {
			continue
		}
		what := "no call for 30 days"
		if d.LastCall == 0 {
			what = "never called"
		}
		out = append(out, fmt.Sprintf("%s %s/%s (%s, %s): %s; the address may be someone else's now: rayctl device allow %s -clear, or device revoke %s",
			d.Id, d.User, d.Name, d.Role, accessOf(d.Allow), what, d.Id, d.Id))
	}
	return out
}

// nodeCmd: rayctl node name [NAME]. Without NAME it shows the name; ""
// removes it.
func (c *cli) nodeCmd(ctx context.Context, sub string, args []string) error {
	if sub == "note" && len(args) <= 1 {
		return c.nodeNote(ctx, args)
	}
	if sub != "name" || len(args) > 1 {
		return errUsage
	}
	if len(args) == 0 {
		r, err := c.c.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{}))
		if err != nil {
			return err
		}
		return c.print(&nodev1.SetNodeNameResponse{Name: r.Msg.Name}, func(w *tabwriter.Writer) {
			if r.Msg.Name == "" {
				fmt.Fprintln(w, "no name (rayctl node name NAME)")
				return
			}
			fmt.Fprintln(w, r.Msg.Name)
		})
	}
	r, err := c.c.SetNodeName(ctx, connect.NewRequest(&nodev1.SetNodeNameRequest{Name: args[0]}))
	if err != nil {
		return err
	}
	return c.print(r.Msg, func(w *tabwriter.Writer) {
		if r.Msg.Name == "" {
			fmt.Fprintln(w, "the node has no name now; clients show its address from their next subscription")
			return
		}
		fmt.Fprintf(w, "the node is %q now; clients show it from their next subscription\n", r.Msg.Name)
	})
}

// nodeNote: rayctl node note [TEXT]. The note goes on a line of its own,
// never into a table: wide characters and emoji would push columns apart.
func (c *cli) nodeNote(ctx context.Context, args []string) error {
	if len(args) == 0 {
		r, err := c.c.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{}))
		if err != nil {
			return err
		}
		return c.print(&nodev1.SetNodeNoteResponse{Note: r.Msg.Note}, func(w *tabwriter.Writer) {
			if r.Msg.Note == "" {
				fmt.Fprintln(w, "no note (rayctl node note TEXT)")
				return
			}
			fmt.Fprintln(w, r.Msg.Note)
		})
	}
	r, err := c.c.SetNodeNote(ctx, connect.NewRequest(&nodev1.SetNodeNoteRequest{Note: args[0]}))
	if err != nil {
		return err
	}
	return c.print(r.Msg, func(w *tabwriter.Writer) {
		if r.Msg.Note == "" {
			fmt.Fprintln(w, "the node has no note now; clients drop it from their next subscription")
			return
		}
		fmt.Fprintln(w, "clients show this from their next subscription:")
		fmt.Fprintln(w, r.Msg.Note)
	})
}

// loopState says how a loop's last round went: "ok 12s ago", or "FAILED
// 3m ago: <error> (last ok 2h ago)".
func loopState(l *nodev1.LoopHealth, now time.Time) string {
	ago := func(unix int64) string {
		if unix == 0 {
			return "never"
		}
		return now.Sub(time.Unix(unix, 0)).Round(time.Second).String() + " ago"
	}
	// failing comes from rayd after v0.10.0; an older one gives the times.
	if l.Failing || l.LastError > l.LastOk {
		return fmt.Sprintf("FAILED %s: %s (last ok %s)", ago(l.LastError), l.Error, ago(l.LastOk))
	}
	if l.Detail != "" {
		// What the round found (dns-zone: the zone's summary).
		return "ok " + ago(l.LastOk) + ": " + l.Detail
	}
	return "ok " + ago(l.LastOk)
}

func (c *cli) user(ctx context.Context, sub string, args []string) error {
	switch sub {
	case "list":
		r, err := c.c.ListUsers(ctx, connect.NewRequest(&nodev1.ListUsersRequest{}))
		if err != nil {
			return err
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) {
			fmt.Fprintln(w, "NAME\tENABLED\tEXPIRES\tUSED\tSERVICES\tNOTE")
			for _, u := range r.Msg.Users {
				fmt.Fprintf(w, "%s\t%v\t%s\t%s\t%s\t%s\n", u.Name, u.Enabled, when(u.ExpiresAt), usedOf(u), strings.Join(u.Services, ","), u.Note)
			}
		})
	case "add":
		fs := flag.NewFlagSet("user add", flag.ContinueOnError)
		services := fs.String("services", "", "comma-separated service names")
		expires := fs.String("expires", "", "expiry date (2006-01-02) or duration (30d, 12h)")
		limit := fs.String("limit", "", "traffic limit, up + down a period (e.g. 50G): over it the user is off every profile")
		period := fs.String("period", "", "the limit's period: monthly (default) or none (the user's whole time)")
		resetDay := fs.Int("reset-day", 0, "monthly: the day of the month the count starts again, 00:00 UTC, 1 to 28 (default 1)")
		note := fs.String("note", "", "free text")
		// Without a name the user gets an opaque handle: nothing personal
		// on the node, in its logs or reports (docs/design/observability.md).
		name := ""
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			name, args = args[0], args[1:]
		} else {
			name = userHandle()
		}
		if err := fs.Parse(args); err != nil {
			return errUsage
		}
		req := &nodev1.CreateUserRequest{Name: name, Note: *note, Services: splitList(*services), TrafficPeriod: *period,
			TrafficResetDay: int32(*resetDay)} //nolint:gosec // G115: checked by rayd, 1..28
		var err error
		if req.ExpiresAt, err = parseExpiry(*expires, time.Now()); err != nil {
			return err
		}
		if req.TrafficLimitBytes, err = parseBytes(*limit); err != nil {
			return err
		}
		var counting string
		if req.TrafficLimitBytes > 0 {
			counting = c.countingWarning(ctx, name, true)
		}
		r, err := c.c.CreateUser(ctx, connect.NewRequest(req))
		if err != nil {
			return err
		}
		warn(counting)
		return c.print(r.Msg, func(w *tabwriter.Writer) { fmt.Fprintf(w, "user %s created\n", r.Msg.User.Name) })
	case "limit":
		return c.userLimit(ctx, args)
	case "lan":
		return c.userLAN(ctx, args)
	case "usage":
		return c.userUsage(ctx, args)
	case "reset-usage":
		if err := need(args, 1); err != nil {
			return err
		}
		r, err := c.c.SetUserTraffic(ctx, connect.NewRequest(&nodev1.SetUserTrafficRequest{Name: args[0], ResetUsage: true}))
		if err != nil {
			return err
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) {
			fmt.Fprintf(w, "%s: the count starts again from zero now; back on the profiles within seconds if it was over\n", args[0])
		})
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
	case "export":
		return c.exportUser(ctx, args)
	case "expires":
		return c.userExpires(ctx, args)
	case "renew":
		if err := need(args, 1); err != nil {
			return err
		}
		r, err := c.c.RenewUser(ctx, connect.NewRequest(&nodev1.RenewUserRequest{Name: args[0]}))
		if connect.CodeOf(err) == connect.CodeUnimplemented {
			return errors.New("the node is older than v0.27.0: it cannot renew a user's credentials")
		}
		if err != nil {
			return err
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) { fmt.Fprint(w, renewText(r.Msg)) })
	}
	return errUsage
}

// renewText says what rayctl user renew did (R4-36).
func renewText(r *nodev1.RenewUserResponse) string {
	if r.Credentials == 0 {
		return fmt.Sprintf("%s has no credentials yet: nothing to renew\n", r.Name)
	}
	return fmt.Sprintf("%s's credentials are new (%d credentials): the old ones stop working once rayd has applied\n"+
		"them, in seconds. %s's devices are cut until they fetch their subscription: Niko does it by\n"+
		"itself at its next connection check (every 10 minutes, 15 to 30 s after a network change; a\n"+
		"sleeping phone once it wakes), its keys still open the subscription.\n", r.Name, r.Credentials, r.Name)
}

// exportUser prints the links of a user's subscription (P-10), or writes
// them to a file 0600. They hold the user's credentials.
func (c *cli) exportUser(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("user export", flag.ContinueOnError)
	out := fs.String("o", "", "write the links to this file (mode 0600) instead of the screen")
	if err := need(args, 1); err != nil {
		return err
	}
	if err := fs.Parse(args[1:]); err != nil {
		return errUsage
	}
	r, err := c.c.ExportUser(ctx, connect.NewRequest(&nodev1.ExportUserRequest{Name: args[0]}))
	if err != nil {
		return err
	}
	text := exportText(r.Msg.Profiles)
	if c.json {
		b, err := protojson.MarshalOptions{Multiline: true, EmitUnpopulated: true}.Marshal(r.Msg)
		if err != nil {
			return err
		}
		text = string(b) + "\n"
	}
	if *out == "" {
		fmt.Print(text)
		return nil
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the operator's file
	if err != nil {
		return err
	}
	if _, err := f.WriteString(text); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Printf("%d profiles of %s in %s: pass it over a trusted channel, then delete it\n", len(r.Msg.Profiles), args[0], *out)
	return nil
}

// exportText is one comment line and one link per profile; a pending
// switch adds the next link with its time.
func exportText(profiles []*nodev1.Profile) string {
	var b strings.Builder
	for _, p := range profiles {
		fmt.Fprintf(&b, "# %s (service %d)\n%s\n", p.Service, p.ServiceId, p.Link)
		if p.NextLink != "" {
			fmt.Fprintf(&b, "# %s from %s\n%s\n", p.Service, time.Unix(p.NextFrom, 0).UTC().Format(time.RFC3339), p.NextLink)
		}
	}
	return b.String()
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
	case "enable", "disable", "del":
		// -force: the last enabled ssh service may go too (rayd refuses
		// otherwise: SSH would be closed to everyone).
		fs := flag.NewFlagSet("service "+sub, flag.ContinueOnError)
		force := fs.Bool("force", false, "disable or delete the last enabled ssh service anyway: SSH to the node is then closed to "+
			"everyone from the perimeter's next snapshot, and only the provider's console is left")
		if err := need(args, 1); err != nil {
			return err
		}
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() > 0 || (sub == "enable" && *force) {
			return errUsage
		}
		var err error
		if sub == "del" {
			_, err = c.c.DeleteService(ctx, connect.NewRequest(&nodev1.DeleteServiceRequest{Name: args[0], Force: *force}))
		} else {
			_, err = c.c.SetServiceEnabled(ctx, connect.NewRequest(&nodev1.SetServiceEnabledRequest{Name: args[0], Enabled: sub == "enable",
				Force: *force}))
		}
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
			switch r.Msg.Service.Kind {
			case "site":
				fmt.Fprintln(w, "run rayctl apply to restart the site with it")
			case "reality":
				if key == "target" {
					fmt.Fprintln(w, "rayd restarts its Xray with the new target within seconds; the keys, shortIds and server name stay,\n"+
						"so the clients' links do not change (rayctl egress lists the target when it is a local address)")
				}
			case "yggdrasil":
				if key == "lan_relay" {
					fmt.Fprintln(w, "rayd restarts the backend with it: LAN traffic through the node up to "+value+
						" Mbit/s a user (0: between devices in one Wi-Fi only), in the users' traffic limits")
					break
				}
				fmt.Fprintln(w, "run rayctl apply: the unit gets network access with public peers, and loses it without")
				if key == "peers" && value != "" && value != "none" {
					fmt.Fprintln(w, "warning: with public peers a modified client can carry data through the node's Yggdrasil\n"+
						"core past the LAN ceiling and the users' traffic limits (docs/spec/lan-v1.md §2.3);\n"+
						"keep them off on a node with LAN or traffic limits")
				}
			case "naive":
				if key == "icmp" {
					fmt.Fprintln(w, "run rayctl apply: naive restarts with ICMP "+value+" (with it on, apply lets its group open ICMP sockets);\n"+
						"until then clients that see icmp=1 in the link get their ICMP streams reset")
				}
				if key == "udp" {
					fmt.Fprintln(w, "run rayctl apply: naive restarts with UDP datagrams "+value+"; links say udp=1 while it is on;\n"+
						"clients without the second engine ignore it and keep UDP over the HTTP/2 stream (uot=2)")
					svc := store.Service{Kind: r.Msg.Service.Kind, Settings: r.Msg.Service.SettingsJson}
					if provision.NaiveUDP(svc) && !provision.NaiveUDPLink(svc) {
						fmt.Fprintln(w, "warning: the service has no UDP port: naive-quic cannot be reached, and no link says udp=1")
					}
				}
			}
		})
	case "peer-keys":
		return c.peerKeys(ctx, args)
	case "cert":
		fs := flag.NewFlagSet("service cert", flag.ContinueOnError)
		chain := fs.String("chain", "", "certificate chain, PEM, leaf first")
		key := fs.String("key", "", "private key, PEM")
		force := fs.Bool("force", false, "import it although the links under the site carry the pins of the node's keys and this "+
			"certificate has another key: clients that hold them refuse it until they fetch their subscription")
		if err := need(args, 1); err != nil {
			return err
		}
		if err := fs.Parse(args[1:]); err != nil || *chain == "" || *key == "" {
			return errUsage
		}
		chainPEM, err := os.ReadFile(*chain)
		if err != nil {
			return err
		}
		keyPEM, err := os.ReadFile(*key)
		if err != nil {
			return err
		}
		r, err := c.c.SetCertificate(ctx, connect.NewRequest(&nodev1.SetCertificateRequest{Service: args[0], ChainPem: chainPEM, KeyPem: keyPEM,
			Force: *force}))
		if err != nil {
			return err
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) {
			fmt.Fprintf(w, "certificate on %s until %s for %s\n", args[0],
				time.Unix(r.Msg.NotAfter, 0).UTC().Format(time.RFC3339), strings.Join(r.Msg.Names, ", "))
			if len(r.Msg.MissingNext) > 0 {
				fmt.Fprintf(w, "it does not cover %s, the name REALITY moves to next: that switch waits for a certificate that does\n",
					strings.Join(r.Msg.MissingNext, ", "))
			}
			// spec/cert-pin-v1.md §7: the node pins only keys of its own.
			fmt.Fprintln(w, "with a certificate of your own the links of naive, hy2-masq and DoH under it carry no niko-pin:\n"+
				"clients check its chain only, as before pins")
			// What clients will make of the chain (spec/cert-pin-v1.md §7).
			fmt.Fprint(w, certVerdict(chainPEM, time.Now()))
			if r.Msg.Unpinned {
				fmt.Fprintln(w, "warning: these links carried the pins of the node's keys, and this certificate has another key:\n"+
					"clients refuse it (Niko 1.45.0: on hy2-masq) until they fetch their subscription. A client whose\n"+
					"working profile is one of these notices by itself at its next connection check (every 10 minutes,\n"+
					"15 to 30 s after a network change); the others when they next fetch, within the subscription's 72 hours")
			}
		})
	case "rotate":
		fs := flag.NewFlagSet("service rotate", flag.ContinueOnError)
		now := fs.Bool("now", false, "switch at once; clients that have not fetched their subscription since lose this profile until they do")
		force := fs.Bool("force", false, "dnstt, masterdns: switch even while the previous key is in its grace, which drops it at once; "+
			"a site: switch to the next certificate key before clients have had its pin for the lead (the key in use leaked)")
		fresh := fs.Bool("fresh", false, "a site: move its certificate to a key made now and replace the next key too (the node's store "+
			"leaked, both keys with it); no client holds its pin, all refuse the site's services until they fetch their subscription")
		if err := need(args, 1); err != nil {
			return err
		}
		if err := fs.Parse(args[1:]); err != nil {
			return errUsage
		}
		r, err := c.c.RotateService(ctx, connect.NewRequest(&nodev1.RotateServiceRequest{Name: args[0], Now: *now, Force: *force, Fresh: *fresh}))
		if err != nil {
			return err
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) {
			what := cmp.Or(r.Msg.Key, "seal")
			switch {
			case r.Msg.Key == "tls":
				// spec/cert-pin-v1.md §5: the switch is an issuance, and
				// nothing changes until the certificate is stored.
				which := "the next key"
				if *fresh {
					which = "a key made for it"
				}
				fmt.Fprintf(w, "%s: asked. rayd orders a certificate with %s: one try now, whatever its back-off (asked again the same\n"+
					"way: 15 minutes after the last try at the earliest), and if that fails again after the back-off (an hour,\n"+
					"doubling to a day; rayctl status: acme %s). The key in use serves until\n"+
					"the certificate is stored. Then the processes that keep the key restart once (naive, the site, hy2-masq,\n"+
					"Yggdrasil), and the key after it is in subscriptions from then\n", args[0], which, args[0])
				if *fresh {
					fmt.Fprintln(w, "no client holds the pin of that key: from the switch on all of them refuse naive, hy2-masq and DoH\n"+
						"under this site until they fetch their subscription (by themselves at their next connection check,\n"+
						"within about 10 minutes, when one of these is their working profile; otherwise when they next fetch)")
				}
			case r.Msg.Seal && r.Msg.PrevUntil != 0:
				fmt.Fprintf(w, "%s has a new %s key, in subscriptions from now; the previous one is accepted until %s\n",
					args[0], what, time.Unix(r.Msg.PrevUntil, 0).UTC().Format(time.RFC3339))
			case r.Msg.Seal:
				fmt.Fprintf(w, "%s has a new %s key; the previous one is no longer accepted (its sessions closed): clients get nothing until they fetch their subscription\n", args[0], what)
			case r.Msg.Kind == "naive" && *now:
				// R4-42: the next name is routed already; nothing leaked.
				fmt.Fprintf(w, "%s moves to its next server name within a minute (under a certificate of listed names once the certificate\n"+
					"covers it, -reality-prepare at most). Clients move with their next subscription (Niko at its next scheduled\n"+
					"fetch, or sooner once the old name stops working for it: two failed connection checks)\n", args[0])
				naivePreviousText(w, r.Msg)
			case r.Msg.Kind == "naive":
				fmt.Fprintf(w, "%s moves to a new server name at %s, which clients get in their subscription before (under a certificate\n"+
					"of listed names it waits for its certificate first, and the switch comes a lead after that)\n",
					args[0], time.Unix(r.Msg.SwitchAt, 0).UTC().Format(time.RFC3339))
				naivePreviousText(w, r.Msg)
			default:
				fmt.Fprintf(w, "%s switches to new keys at %s (later if a new server name waits for its certificate)\n",
					args[0], time.Unix(r.Msg.SwitchAt, 0).UTC().Format(time.RFC3339))
			}
		})
	}
	return errUsage
}

// naivePreviousText says which previous names of a naive service its
// switch keeps on the front, and which it takes off (R4-42,
// provision.NaivePrevious); a rayd before says neither.
func naivePreviousText(w *tabwriter.Writer, r *nodev1.RotateServiceResponse) {
	if len(r.KeptNames) == 0 && len(r.DroppedNames) == 0 {
		fmt.Fprintln(w, "the previous name stays accepted until the switch after")
		return
	}
	if len(r.KeptNames) > 0 {
		kept := append([]string{r.KeptNames[0] + " (in use now)"}, r.KeptNames[1:]...)
		fmt.Fprintf(w, "still accepted after the switch: %s; each until a switch -naive-sni-period after the one that left it\n",
			strings.Join(kept, ", "))
	}
	if len(r.DroppedNames) > 0 {
		fmt.Fprintf(w, "no longer accepted after the switch: %s (left a period ago or more, or over %d previous names):\n"+
			"devices that know only it lose naive until they fetch their subscription\n", strings.Join(r.DroppedNames, ", "), provision.NaivePrevCap)
	}
}

// keyState says when a REALITY service last switched keys and when the
// published next switch is (R4-7); for a DNS tunnel, its dnsauth and seal
// modes; for a site, since when its certificate's keys are in use and
// pinned (spec/cert-pin-v1.md).
func keyState(s *nodev1.Service) string {
	day := func(t int64) string { return time.Unix(t, 0).UTC().Format("2006-01-02 15:04") }
	if s.Kind == "slipstream" {
		// The front checks every query's dnsauth-v2 tag; the server's key
		// is pinned, never rotated (spec/slipstream-v1.md); its limits.
		ss, _ := provision.ParseSlipstream(store.Service{Kind: s.Kind, Settings: s.SettingsJson})
		total, device := ss.Connections()
		return fmt.Sprintf("auth required, v2 required (at the front), pinned key, connections %d, %d a device", total, device)
	}
	if s.Kind == "dnstt" || s.Kind == "masterdns" {
		// The modes, and the switch of a dnstt seal key if there was one
		// (masterdns seals with its own key).
		var st struct {
			Auth      string `json:"auth"`
			AuthHint  string `json:"auth_hint"`
			Seal      string `json:"seal"`
			RotatedAt int64  `json:"seal_rotated_at"`
			PrevUntil int64  `json:"seal_prev_until"`
			// masterdns's service key (spec/masterdns-key-rotation.md)
			KeyRotatedAt int64 `json:"key_rotated_at"`
			KeyPrevUntil int64 `json:"key_prev_until"`
		}
		_ = json.Unmarshal([]byte(s.SettingsJson), &st)
		if s.Kind == "masterdns" {
			st.RotatedAt, st.PrevUntil = st.KeyRotatedAt, st.KeyPrevUntil
		}
		if st.Seal == "" {
			st.Seal = "off"
		}
		out := "auth " + st.Auth
		if st.Auth != "required" {
			// dnsauth-v1 off or optional: new sessions can be held back
			// by anyone (niko-server's load test).
			out = "auth " + cmp.Or(st.Auth, "off") + " (open: auth=required keeps floods out)"
		}
		if st.Auth != "" && st.Auth != "off" {
			// dnsauth-v2: optional when unset (provision.DNSAuthHint).
			out += ", v2 " + cmp.Or(st.AuthHint, "optional")
		}
		out += ", seal " + st.Seal
		if st.RotatedAt != 0 {
			out += ", key since " + day(st.RotatedAt)
		}
		if st.PrevUntil != 0 {
			out += ", previous key until " + day(st.PrevUntil)
		}
		return out + spareZones(s)
	}
	if s.Kind == "site" {
		// The certificate's keys (spec/cert-pin-v1.md): pinned in the links
		// of naive, hy2-masq and DoH once the next key is there.
		st := provision.ParseSiteKeyState(store.Service{Kind: s.Kind, Settings: s.SettingsJson})
		switch {
		case st.Imported:
			return "certificate of your own: no pins"
		case st.NextAt == 0:
			return ""
		}
		out := "key since " + day(st.KeyAt) + ", next key pinned since " + day(st.NextAt)
		switch {
		case st.RotateAt != 0 && st.RotateHow == provision.SiteSwitchFresh:
			out += ", switch to a fresh key asked"
		case st.RotateAt != 0:
			out += ", switch to it asked"
		}
		if st.PrevPin != "" && time.Now().Unix() < st.PrevUntil {
			out += ", previous key pinned until " + day(st.PrevUntil)
		}
		return out
	}
	if s.Kind == "naive" {
		return naiveNameState(s, day)
	}
	if s.Kind != "reality" {
		return ""
	}
	var st struct {
		RotatedAt  int64  `json:"rotated_at"`
		PreparedAt int64  `json:"prepared_at"`
		NextFrom   int64  `json:"next_from"`
		SNINext    string `json:"sni_next"`
		PrevUntil  int64  `json:"prev_until"`
	}
	_ = json.Unmarshal([]byte(s.SettingsJson), &st)
	out := "since creation"
	if st.RotatedAt != 0 {
		out = "since " + day(st.RotatedAt)
	}
	switch {
	case st.NextFrom != 0:
		out += ", switch " + day(st.NextFrom)
	case st.PreparedAt != 0 || st.SNINext != "":
		// Prepared and not published: a new name waits for its
		// certificate (rayd since v0.29.0 shows no unpublished name, a
		// rayd before shows it).
		out += ", next name waits for its certificate"
	}
	if st.NextFrom != 0 && st.SNINext != "" {
		out += " with a new name"
	}
	if st.PrevUntil != 0 {
		out += ", previous keys until " + day(st.PrevUntil) // R4-19
	}
	return out
}

// naiveStatus is a naive service's line in rayctl status: the server name
// in its links and, once published, the next one from its time (the
// API's fields; a rayd before v0.29.0 fills neither, and the name comes
// from the settings).
func naiveStatus(s *nodev1.Service) string {
	name := s.Sni
	if name == "" {
		name = provision.SiteName(store.Service{Settings: s.SettingsJson})
	}
	out := "name " + name
	if s.SniNext != "" && s.NextFrom != 0 {
		out += ", next " + s.SniNext + " from " + time.Unix(s.NextFrom, 0).UTC().Format("2006-01-02 15:04") + " UTC"
	}
	return out
}

// naiveNameState says where naive's server name stands (R4-42): the name
// in use and since when, the published switch and its name, a next name
// waiting for its certificate or a switch asked, the previous names still
// accepted, and rotate_sni when set. A next name not yet published is not
// shown: no client has it (nor does rayd since v0.29.0 give it).
func naiveNameState(s *nodev1.Service, day func(int64) string) string {
	st := provision.ParseNaiveState(store.Service{Kind: s.Kind, Settings: s.SettingsJson, CreatedAt: time.Unix(s.CreatedAt, 0)})
	out := "name " + st.SNI + " since creation"
	if st.RotatedAt != s.CreatedAt {
		out = "name " + st.SNI + " since " + day(st.RotatedAt)
	}
	switch {
	case st.NextFrom != 0:
		out += ", switch " + day(st.NextFrom) + " to " + st.SNINext
	case st.PreparedAt != 0:
		out += ", next name waits for its certificate"
	case st.RotateAt != 0:
		out += ", switch asked for " + day(st.RotateAt)
	}
	switch prev := st.Previous(); {
	case len(prev) == 1:
		out += ", " + prev[0] + " accepted until a switch a period after the last"
	case len(prev) > 1:
		out += ", " + strings.Join(prev, ", ") + " accepted until a switch a period after the one that left each"
	}
	if st.RotateSNI != nil {
		out += map[bool]string{true: ", rotate_sni on", false: ", rotate_sni off"}[*st.RotateSNI]
	}
	return out
}

// spareZones lists a DNS tunnel's spare zones (spec/dnszones-v1.md) after
// its keys, "" without any.
func spareZones(s *nodev1.Service) string {
	var st struct {
		Spare []string `json:"spare_zones"`
	}
	_ = json.Unmarshal([]byte(s.SettingsJson), &st)
	if len(st.Spare) == 0 {
		return ""
	}
	return ", spare zones " + strings.Join(st.Spare, " ")
}

// accessOf is how an integration's device reaches the API: "spa" (a
// knock) or "static (N)", N addresses (integrations-v1 §3.4).
func accessOf(allow []string) string {
	if len(allow) == 0 {
		return "spa"
	}
	return fmt.Sprintf("static (%d)", len(allow))
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
			fmt.Fprintln(w, "ID\tUSER\tNAME\tROLE\tCREATED\tREVOKED\tLAN\tAPI\tCLIENT\tACCESS\tLAST CALL")
			for _, d := range r.Msg.Devices {
				api := "-"
				if d.Registered {
					api = "registered"
				}
				// The client its requests last named (client-min-v1 §5).
				client := cmp.Or(d.Client, "-")
				// An integration's: how it reaches the API and when it
				// last called (integrations-v1 §3.4).
				access, last := "-", "-"
				if d.Role == "billing" || d.Role == "support" {
					access, last = accessOf(d.Allow), when(d.LastCall)
				}
				// The device's own LAN consent (lan-v1 §1.1); it is in the
				// LAN when its user's is on too (rayctl user lan).
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", d.Id, d.User, d.Name, d.Role, when(d.CreatedAt), when(d.RevokedAt), onOff(d.Lan), api, client,
					access, last)
			}
			for _, inv := range r.Msg.Invites {
				state := "invite until " + when(inv.ExpiresAt)
				if inv.ExpiresAt <= time.Now().Unix() {
					state = "invite expired"
				}
				if inv.PinTries > 0 {
					state += fmt.Sprintf(", PIN (%d tries)", inv.PinTries)
				}
				access := "-"
				if inv.Role == "billing" || inv.Role == "support" {
					access = accessOf(inv.Allow)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t-\t-\t%s\t-\t%s\t-\n", inv.Id, inv.User, inv.Name, inv.Role, when(inv.CreatedAt), state, access)
			}
		})
	case "invite":
		fs := flag.NewFlagSet("device invite", flag.ContinueOnError)
		role := fs.String("role", "user", "user, admin, or billing or support for an integration (its user without services)")
		ttl := fs.Duration("ttl", 24*time.Hour, "how long the invite works (up to a week)")
		out := fs.String("o", "", "write the invite alone to this file (mode 0600) instead of the screen")
		showQR := fs.Bool("qr", false, "draw the invite as a QR code on the screen for the phone to scan, instead of the text")
		withPIN := fs.Bool("pin", false, "the invite also needs a PIN of 6 digits, shown here once: tell it by another channel; on unless -pin=false for -role admin and billing")
		allow := fs.String("allow", "", "billing or support: the integration server's addresses, comma-separated (IPv4 /28-/32, IPv6 /64-/128): it registers and calls from them without a knock")
		format := fs.String("format", "rcinv3", "rcinv3, the default: with the node's name and SPA v3 when it has them (Niko 1.63 or later); rcinv2: the short form, a QR half the size (Niko 1.35 or later); rcinv1 for older Niko")
		if err := need(args, 2); err != nil {
			return err
		}
		if err := fs.Parse(args[2:]); err != nil {
			return errUsage
		}
		// -format given: that form or none; without it the first form the
		// node makes of rcinv3, rcinv2 and rcinv1. -pin not given: a PIN
		// for admin and billing (api-v1 §3).
		asked, pinGiven := false, false
		fs.Visit(func(f *flag.Flag) {
			asked = asked || f.Name == "format"
			pinGiven = pinGiven || f.Name == "pin"
		})
		if !pinGiven {
			*withPIN = api.InvitePINByDefault(*role)
		}
		if *showQR && (*out != "" || c.json) {
			return fmt.Errorf("%w: -qr draws on the screen: not with -o or -json", errUsage)
		}
		// The PIN comes after the QR is wiped, which needs a terminal to
		// read Enter from and draw on (review 9: on stderr it still landed
		// under the QR through ssh without -t, | tee or </dev/null).
		if *showQR && *withPIN && (!terminal(os.Stdin) || !terminal(os.Stdout)) {
			if !pinGiven {
				return fmt.Errorf("%w: -qr with a PIN (-role %s has one unless -pin=false) needs a terminal (ssh -t), or -o to write the invite to a file", errUsage, *role)
			}
			return fmt.Errorf("%w: -qr with -pin needs a terminal (ssh -t), or -o to write the invite to a file", errUsage)
		}
		if *format != "rcinv1" && *format != "rcinv2" && *format != "rcinv3" {
			return fmt.Errorf("%w: -format rcinv1, rcinv2 or rcinv3", errUsage)
		}
		allowList := splitList(*allow)
		if *allow != "" && len(allowList) == 0 {
			return fmt.Errorf("%w: -allow with no address", errUsage)
		}
		r, err := c.c.CreateInvite(ctx, connect.NewRequest(&nodev1.CreateInviteRequest{
			User: args[0], Name: args[1], Role: *role, TtlSeconds: int64(ttl.Seconds()), Pin: *withPIN, Allow: allowList}))
		if err != nil {
			return err
		}
		inv := r.Msg.Invite
		if len(allowList) > 0 && len(inv.Allow) == 0 {
			// A node before the addresses of integrations drops the field
			// and makes an invite that knocks: withdrawn, as above.
			if _, rerr := c.c.RevokeDevice(ctx, connect.NewRequest(&nodev1.RevokeDeviceRequest{Id: inv.Id})); rerr != nil {
				return fmt.Errorf("the node made invite %s without the addresses (an older node), and it is not withdrawn: rayctl device revoke %s: %w", inv.Id, inv.Id, rerr)
			}
			return errors.New("the node made the invite without the addresses (an older node): withdrawn; update the node or invite without -allow")
		}
		for _, w := range r.Msg.Warnings {
			fmt.Fprintln(os.Stderr, "rayctl: warning:", w)
		}
		if *withPIN && r.Msg.Pin == "" {
			// A node from before v0.13 drops the field it does not know
			// and makes an invite without a PIN: withdraw it rather than
			// let it pass for one that has one.
			_, rerr := c.c.RevokeDevice(ctx, connect.NewRequest(&nodev1.RevokeDeviceRequest{Id: inv.Id}))
			if rerr != nil {
				return fmt.Errorf("the node made invite %s without a PIN (raycontrol v0.13 has them), and it is not withdrawn: rayctl device revoke %s: %w", inv.Id, inv.Id, rerr)
			}
			return fmt.Errorf("the node made the invite without a PIN (raycontrol v0.13 has them): withdrawn; update the node or invite with -pin=false")
		}
		code, next, err := inviteForm(r.Msg, *format, asked)
		if err != nil {
			// Asked for a form the node does not make: withdraw rather than
			// hand out another, which an older phone could not read or a
			// newer one would take by the node's host.
			if _, rerr := c.c.RevokeDevice(ctx, connect.NewRequest(&nodev1.RevokeDeviceRequest{Id: inv.Id})); rerr != nil {
				return fmt.Errorf("the node made invite %s, but %w, and it is not withdrawn: rayctl device revoke %s: %w", inv.Id, err, inv.Id, rerr)
			}
			if next != "" {
				return fmt.Errorf("the node made the invite, but %w: withdrawn; invite with -format %s", err, next)
			}
			return fmt.Errorf("the node made the invite, but %w: withdrawn", err)
		}
		r.Msg.InviteCode = code
		// The PIN goes to the screen, never into the invite's file: it
		// travels apart from the invite.
		pinLine := func() {
			if r.Msg.Pin != "" {
				fmt.Printf("\nPIN %s %s: tell it by another channel than the invite; %d wrong tries withdraw it\n",
					r.Msg.Pin[:3], r.Msg.Pin[3:], inv.PinTries)
			}
		}
		if *out != "" {
			if err := os.WriteFile(*out, []byte(r.Msg.InviteCode+"\n"), 0o600); err != nil {
				return fmt.Errorf("invite %s made, but not written (rayctl device revoke %s): %w", inv.Id, inv.Id, err)
			}
			fmt.Printf("invite %s for %s/%s (%s) until %s in %s\n", inv.Id, inv.User, inv.Name, inv.Role, when(inv.ExpiresAt), *out)
			pinLine()
			return nil
		}
		if *showQR {
			fmt.Printf("invite %s for %s/%s (%s), once, until %s. Scan it in Niko:\n\n", inv.Id, inv.User, inv.Name, inv.Role, when(inv.ExpiresAt))
			var qrText bytes.Buffer
			if err := writeQR(&qrText, r.Msg.InviteCode); err != nil {
				return fmt.Errorf("invite %s made, but not drawn (rayctl device revoke %s): %w", inv.Id, inv.Id, err)
			}
			if _, err := os.Stdout.Write(qrText.Bytes()); err != nil {
				return fmt.Errorf("invite %s made, but not drawn (rayctl device revoke %s): %w", inv.Id, inv.Id, err)
			}
			if r.Msg.Pin == "" {
				return nil
			}
			// Never the PIN beside the QR, where one photo or screenshot
			// takes both (review 8): it comes once the QR is wiped. What
			// was typed ahead (a pasted blank line) does not wipe it
			// unseen; Ctrl-C says how to withdraw the invite.
			flushInput(os.Stdin)
			fmt.Print("\nOnce the QR is scanned or sent, Enter wipes it and shows the PIN.")
			stop := make(chan os.Signal, 1)
			signal.Notify(stop, os.Interrupt)
			defer signal.Stop(stop)
			line := make(chan error, 1)
			go func() {
				_, err := bufio.NewReader(os.Stdin).ReadString('\n')
				line <- err
			}()
			select {
			case err := <-line:
				if err != nil {
					return fmt.Errorf("invite %s made, its PIN not shown (rayctl device revoke %s): %w", inv.Id, inv.Id, err)
				}
			case <-stop:
				return fmt.Errorf("invite %s made, its PIN not shown: rayctl device revoke %s", inv.Id, inv.Id)
			}
			// Up over the QR, the prompt and the Enter, and clear below.
			fmt.Printf("\033[%dA\033[J", bytes.Count(qrText.Bytes(), []byte("\n"))+2)
			pinLine()
			return nil
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) {
			fmt.Fprintf(w, "invite %s for %s/%s (%s), once, until %s. The client registers with it through the API:\n\n%s\n",
				inv.Id, inv.User, inv.Name, inv.Role, when(inv.ExpiresAt), r.Msg.InviteCode)
			if r.Msg.Pin != "" {
				fmt.Fprintf(w, "\nPIN %s %s: tell it by another channel than the invite; %d wrong tries withdraw it\n",
					r.Msg.Pin[:3], r.Msg.Pin[3:], inv.PinTries)
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
	case "allow":
		// integrations-v1 §3.4: an integration's device calls from its
		// addresses without a knock, or knocks again (-clear).
		fs := flag.NewFlagSet("device allow", flag.ContinueOnError)
		off := fs.Bool("clear", false, "take the addresses away: the device knocks again (SPA)")
		if len(args) < 1 {
			return errUsage
		}
		if err := fs.Parse(args[1:]); err != nil {
			return errUsage
		}
		var list []string
		switch {
		case *off && fs.NArg() == 0:
		case !*off && fs.NArg() == 1 && len(splitList(fs.Arg(0))) > 0:
			list = splitList(fs.Arg(0))
		default:
			return fmt.Errorf("%w: device allow ID ADDR[,ADDR...] or device allow ID -clear", errUsage)
		}
		r, err := c.c.SetDeviceAllow(ctx, connect.NewRequest(&nodev1.SetDeviceAllowRequest{Id: args[0], Prefixes: list}))
		if err != nil {
			return err
		}
		for _, w := range r.Msg.Warnings {
			fmt.Fprintln(os.Stderr, "rayctl: warning:", w)
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) {
			d := r.Msg.Device
			if len(d.Allow) == 0 {
				fmt.Fprintf(w, "%s %s/%s: back to SPA (it knocks); the perimeter follows in a second or two\n", d.Id, d.User, d.Name)
				return
			}
			fmt.Fprintf(w, "%s %s/%s calls from %s without a knock; the perimeter follows in a second or two\n",
				d.Id, d.User, d.Name, strings.Join(d.Allow, ", "))
		})
	case "revoke":
		fs := flag.NewFlagSet("device revoke", flag.ContinueOnError)
		overlap := fs.Bool("overlap", false, "rotate the user's credentials with overlap instead of new ones at once (a device given away or broken, not stolen)")
		id, err := oneArg(fs, args)
		if err != nil {
			return err
		}
		if *overlap {
			// A node before v0.31.0 reads no overlap and would revoke
			// without it, cutting the user's other devices: refused here,
			// before anything is revoked. Not an invite: any node withdraws
			// it alike, and no credentials change.
			st, err := c.c.GetStatus(ctx, connect.NewRequest(&nodev1.GetStatusRequest{}))
			if err != nil {
				return err
			}
			if err := overlapKnown(st.Msg.Version); err != nil && !c.isInvite(ctx, id) {
				return err
			}
		}
		r, err := c.c.RevokeDevice(ctx, connect.NewRequest(&nodev1.RevokeDeviceRequest{Id: id, Overlap: *overlap}))
		if err != nil {
			return err
		}
		if c.json {
			// What the text says beside the answer, for -json on stderr.
			if note := revokeNote(*overlap, r.Msg); note != "" {
				fmt.Fprint(os.Stderr, note)
			}
		}
		if *overlap && r.Msg.SwitchAt != 0 {
			// The user's last device: nothing else needed the overlap.
			if devs, err := c.c.ListDevices(ctx, connect.NewRequest(&nodev1.ListDevicesRequest{User: r.Msg.User})); err == nil &&
				!slices.ContainsFunc(devs.Msg.Devices, func(d *nodev1.Device) bool { return d.RevokedAt == 0 }) {
				fmt.Fprint(os.Stderr, lastDeviceWarning(id, r.Msg))
			}
		}
		return c.print(r.Msg, func(w *tabwriter.Writer) { fmt.Fprint(w, revokeText(id, *overlap, r.Msg)) })
	}
	return errUsage
}

// oneArg parses the flags of fs before or after its one argument, and
// returns the argument.
func oneArg(fs *flag.FlagSet, args []string) (string, error) {
	if err := fs.Parse(args); err != nil || fs.NArg() == 0 {
		return "", errUsage
	}
	arg := fs.Arg(0)
	if err := fs.Parse(fs.Args()[1:]); err != nil || fs.NArg() != 0 {
		return "", errUsage
	}
	return arg, nil
}

// overlapSince is the first release whose node reads RevokeDeviceRequest.
// overlap.
const overlapSince = "v0.31.0"

// overlapKnown refuses -overlap for a node of a release before
// overlapSince: it would revoke without overlap. A build that is no release
// (dev) is taken at its word; revokeNote says what it did.
func overlapKnown(version string) error {
	if release.IsRelease(version) && release.Newer(overlapSince, version) {
		return fmt.Errorf("the node runs raycontrol %s, which knows no -overlap (%s has it): it would revoke without it,\n"+
			"cutting the user's other devices at once. Nothing revoked: update the node, or revoke without -overlap", version, overlapSince)
	}
	return nil
}

// isInvite reports whether id is an invite not used yet on the node (an
// error: no).
func (c *cli) isInvite(ctx context.Context, id string) bool {
	l, err := c.c.ListDevices(ctx, connect.NewRequest(&nodev1.ListDevicesRequest{}))
	return err == nil && slices.ContainsFunc(l.Msg.Invites, func(inv *nodev1.Invite) bool { return inv.Id == id })
}

// revokeNote is what revokeText says besides the answer's fields: a node
// that revoked without overlap though it was asked for.
func revokeNote(overlap bool, r *nodev1.RevokeDeviceResponse) string {
	if overlap && !r.Invite && !r.Already && r.User != "" && r.Credentials > 0 && r.SwitchAt == 0 {
		return "The node is older than v0.31.0: it knows no -overlap, and revoked without it.\n"
	}
	return ""
}

// lastDeviceWarning says that a revocation with overlap left the user no
// active device: the overlap kept nobody up and only lets the revoked
// device in until the end of the grace.
func lastDeviceWarning(id string, r *nodev1.RevokeDeviceResponse) string {
	return fmt.Sprintf("warning: %s was %s's last active device: the overlap keeps no other device up, and only lets this one\n"+
		"in until %s; to cut it off now: rayctl user renew %s\n", id, r.User, revokeAt(r.Until), r.User)
}

// revokeAt is a time of a revocation's answer, in UTC to the minute.
func revokeAt(t int64) string { return time.Unix(t, 0).UTC().Format("2006-01-02 15:04") + " UTC" }

// revokeText says what a revocation did (R4-36): the user's credentials
// are new, so the user's other devices are off until their next
// subscription fetch. With overlap (R4-43) they rotate instead: the other
// devices move over with their next fetch, and what the device knew stops
// working at the end of the grace, which it says.
func revokeText(id string, overlap bool, r *nodev1.RevokeDeviceResponse) string {
	switch {
	case r.Invite:
		return fmt.Sprintf("invite %s withdrawn\n", id)
	case r.User == "":
		// A node before v0.27.0: it said nothing, and changed no credentials.
		return fmt.Sprintf("device %s revoked (the node is older than v0.27.0: the user's credentials stay as they were)\n", id)
	case r.Already && r.Until != 0:
		// Revoked with overlap before, its rotation not switched yet.
		return fmt.Sprintf("device %s (%s/%s) was revoked already, with overlap: nothing changed, and what it knew is still\n"+
			"accepted until %s. To cut it off now: rayctl user renew %s (the other devices are then cut too,\n"+
			"until they fetch their subscription).\n", id, r.User, r.Device, revokeAt(r.Until), r.User)
	case r.Already:
		return fmt.Sprintf("device %s (%s/%s) was revoked already: nothing changed (rayctl user renew %s gives the user\n"+
			"other credentials at once)\n", id, r.User, r.Device, r.User)
	case r.Credentials == 0:
		return fmt.Sprintf("device %s (%s/%s) revoked; %s has no credentials yet\n", id, r.User, r.Device, r.User)
	case overlap && r.SwitchAt != 0:
		at := revokeAt
		return fmt.Sprintf("device %s (%s/%s) revoked with overlap. %s's credentials rotate (%d credentials): the next ones are\n"+
			"accepted now, and %s's other devices get them with their next subscription fetch and switch to them\n"+
			"at %s. The old ones, which the revoked device knew, stop working at %s\n"+
			"(rayd's rotation runs every 10 minutes: up to 10 minutes later). For a stolen device revoke without\n"+
			"-overlap; to cut this one off now: rayctl user renew %s (the other devices are then cut too, until\n"+
			"they fetch their subscription).\n",
			id, r.User, r.Device, r.User, r.Credentials, r.User, at(r.SwitchAt), at(r.Until), r.User)
	}
	return revokeNote(overlap, r) + fmt.Sprintf("device %s (%s/%s) revoked. %s's credentials are new (%d credentials): what the device kept stops\n"+
		"working once rayd has applied them, in seconds. %s's other devices are cut too, until they fetch\n"+
		"their subscription: Niko does it by itself at its next connection check (every 10 minutes, 15 to 30 s\n"+
		"after a network change; a sleeping phone once it wakes), its keys still open the subscription.\n",
		id, r.User, r.Device, r.User, r.Credentials, r.User)
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

// userExpires sets when a user expires (rayctl user expires NAME WHEN,
// integrations-v1 §11): a date, a time from now, never or now. "now" is
// the node's: a time long past, which it takes for its own now.
func (c *cli) userExpires(ctx context.Context, args []string) error {
	if err := need(args, 2); err != nil {
		return err
	}
	var at int64
	switch args[1] {
	case "never":
	case "now":
		at = 1
	case "":
		return errors.New("when: a date (2006-01-02), a time from now (30d, 12h), never or now")
	default:
		var err error
		if at, err = parseExpiry(args[1], time.Now()); err != nil {
			return err
		}
	}
	r, err := c.c.SetUserExpiry(ctx, connect.NewRequest(&nodev1.SetUserExpiryRequest{Name: args[0], ExpiresAt: at}))
	if connect.CodeOf(err) == connect.CodeUnimplemented {
		return errors.New("the node is older than this rayctl: it sets an expiry only with the user (user add -expires)")
	}
	if err != nil {
		return err
	}
	return c.print(r.Msg, func(w *tabwriter.Writer) {
		if r.Msg.User.ExpiresAt == 0 {
			fmt.Fprintf(w, "%s: expires never\n", r.Msg.User.Name)
			return
		}
		fmt.Fprintf(w, "%s: expires %s\n", r.Msg.User.Name, when(r.Msg.User.ExpiresAt))
	})
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

// inviteForms are the forms of an invite, newest first: which raycontrol
// makes it and which Niko reads it.
var inviteForms = []struct{ name, node, niko string }{
	{"rcinv3", "raycontrol v0.35", "Niko 1.63"},
	{"rcinv2", "raycontrol v0.13", "Niko 1.35"},
	{"rcinv1", "", "every Niko"},
}

// inviteForm picks the invite's text from what the node made (api-v1 §3a,
// §3b). Asked for a form, that one, or an error and the next form the node
// made; by default the first the node made from the one named on, with a
// note on stderr when it is not that one. A short form is "" when the node
// is older or its host or name cannot go in it; rcinv1 is always there.
func inviteForm(m *nodev1.CreateInviteResponse, format string, asked bool) (code, next string, err error) {
	codes := map[string]string{"rcinv3": m.InviteCodeV3, "rcinv2": m.InviteCodeShort, "rcinv1": m.InviteCode}
	start := slices.IndexFunc(inviteForms, func(f struct{ name, node, niko string }) bool { return f.name == format })
	if start < 0 {
		return "", "", fmt.Errorf("no invite form %q", format)
	}
	if codes[format] != "" {
		return codes[format], "", nil
	}
	made := start + 1
	for made < len(inviteForms) && codes[inviteForms[made].name] == "" {
		made++
	}
	if made == len(inviteForms) {
		return "", "", errors.New("no invite in the node's answer")
	}
	// rcinv2 and rcinv3 carry the host alike: with rcinv2 and no rcinv3 the
	// node is older or could not read its name; with neither, older still
	// or its host fits in no short form.
	var missing []string
	for _, f := range inviteForms[start:made] {
		missing = append(missing, f.name)
	}
	why := "raycontrol v0.35 has it, or the node could not read its name"
	if codes["rcinv2"] == "" {
		why = "raycontrol v0.13 has the short forms, and the node's host must be an address or an ASCII name"
	}
	if asked {
		return "", inviteForms[made].name, fmt.Errorf("not as %s (%s)", format, why)
	}
	fmt.Fprintf(os.Stderr, "rayctl: the invite is %s, which %s reads: the node makes no %s (%s)\n",
		inviteForms[made].name, inviteForms[made].niko, strings.Join(missing, " and no "), why)
	return codes[inviteForms[made].name], "", nil
}
