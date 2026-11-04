// Package legacy finds and removes raycontrol v0 (legacy/ray.sh, "Ray-AIO"):
// its Xray on TCP 443 and 8443, Hysteria2 on UDP 3478, PostgreSQL user
// store, certbot certificate and port-knocking nftables table. The node
// cannot run next to it: its Xray holds 443 and its table drops what the
// node serves. Only what v0 put there goes, each item recognised by v0's
// own markers; a backup comes first (docs/08-decisions.md, R4-26).
package legacy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Paths v0 used (legacy/ray.sh).
const (
	rayAIODir     = "/etc/ray-aio"
	installConf   = "/etc/ray-aio/install.conf"
	rayctlV0      = "/usr/local/bin/raycontrol"
	applyNFT      = "/usr/local/bin/apply_nftables_xray.sh"
	xrayBin       = "/usr/local/bin/xray"
	xrayUnit      = "/etc/systemd/system/xray.service"
	xrayDir       = "/etc/xray"
	xrayLogDir    = "/var/log/xray"
	hysteriaBin   = "/usr/local/bin/hysteria-server"
	hysteriaUnit  = "/etc/systemd/system/hysteria-server.service"
	hysteriaDir   = "/etc/hysteria"
	backupsDir    = "/var/backups/ray-aio"
	secretsDir    = "/root/.secrets"
	cloudflareINI = "/root/.secrets/cloudflare.ini"
	dbConf        = "/root/.secrets/db.conf"
	logFile       = "/var/log/raycontrol.log"
	leHook        = "/etc/letsencrypt/renewal-hooks/post/reload_services.sh"
	leLive        = "/etc/letsencrypt/live"
	nftConf       = "/etc/nftables.conf"
	xanmodList    = "/etc/apt/sources.list.d/xanmod-kernel.list"
	// knockMarker names a set only v0's table has.
	knockMarker = "knock_stage1"
)

// debianNFTConf is Debian's stock /etc/nftables.conf: v0 saved its whole
// ruleset over it.
const debianNFTConf = `#!/usr/sbin/nft -f

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter;
	}
	chain forward {
		type filter hook forward priority filter;
	}
	chain output {
		type filter hook output priority filter;
	}
}
`

// Host is the machine; tests replace the parts.
type Host struct {
	Root     string // prefix of every path: "" on the host
	Run      func(ctx context.Context, name string, args ...string) ([]byte, error)
	LookPath func(name string) error
	Out      io.Writer
	Now      func() time.Time
}

// System is this machine.
func System(out io.Writer) *Host {
	return &Host{
		Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		},
		LookPath: func(name string) error { _, err := exec.LookPath(name); return err },
		Out:      out,
		Now:      time.Now,
	}
}

func (h *Host) path(p string) string { return filepath.Join(h.Root, p) }

func (h *Host) exists(p string) bool { _, err := os.Lstat(h.path(p)); return err == nil }

func (h *Host) contains(p, s string) bool {
	b, err := os.ReadFile(h.path(p))
	return err == nil && strings.Contains(string(b), s)
}

func (h *Host) logf(format string, a ...any) {
	if h.Out != nil {
		fmt.Fprintf(h.Out, format+"\n", a...)
	}
}

// Found is what v0 left on the host.
type Found struct {
	Items  []string // what will go, for a person
	Kept   []string // what stays, and why
	Domain string   // the certificate's name, from install.conf
	DB     string   // the PostgreSQL database and role
	Role   string
	// What the removal acts on.
	xrayUnit, hysteriaUnit, rayctl, nftTable, nftConf bool
}

// Any reports whether v0 is there at all.
func (f Found) Any() bool { return len(f.Items) > 0 }

var ident = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)
var domainRE = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)

// confValue reads KEY="value" from a shell-style file without running it.
func (h *Host) confValue(p, key string) string {
	b, err := os.ReadFile(h.path(p))
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), key+"="); ok {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

// Detect looks for v0, marker by marker.
func (h *Host) Detect(ctx context.Context) Found {
	var f Found
	add := func(s string) { f.Items = append(f.Items, s) }
	if h.exists(rayAIODir) {
		add(rayAIODir + " (v0's settings)")
	}
	if h.contains(rayctlV0, "ray-aio") {
		f.rayctl = true
		add(rayctlV0 + " (v0's bash CLI)")
	}
	if h.exists(applyNFT) {
		add(applyNFT)
	}
	if h.contains(xrayUnit, xrayBin+" -config "+xrayDir+"/config.json") {
		f.xrayUnit = true
		add("xray.service, " + xrayBin + ", " + xrayDir + ", " + xrayLogDir + " (Xray on TCP 443 and 8443)")
	}
	if h.contains(hysteriaUnit, hysteriaBin+" server -c "+hysteriaDir+"/config.yaml") {
		f.hysteriaUnit = true
		add("hysteria-server.service, " + hysteriaBin + ", " + hysteriaDir + " (Hysteria2 on UDP 3478)")
	}
	if out, err := h.Run(ctx, "nft", "list", "table", "inet", "filter"); err == nil && strings.Contains(string(out), knockMarker) {
		f.nftTable = true
		add("nftables table inet filter (v0's port knocking, policy drop)")
	}
	if h.contains(nftConf, knockMarker) {
		f.nftConf = true
		add(nftConf + " (v0's saved rules; back to the stock file)")
	}
	if !f.Any() {
		return f
	}
	// The rest only next to a v0 marker: these names are generic.
	f.DB, f.Role = h.confValue(dbConf, "PG_DB_NAME"), h.confValue(dbConf, "PG_USER")
	if f.DB == "" {
		f.DB, f.Role = h.confValue(hysteriaDir+"/db.conf", "PG_DB_NAME"), h.confValue(hysteriaDir+"/db.conf", "PG_USER")
	}
	if !ident.MatchString(f.DB) || !ident.MatchString(f.Role) {
		f.DB, f.Role = "", ""
	} else {
		add(fmt.Sprintf("PostgreSQL database %s and role %s (v0's users)", f.DB, f.Role))
	}
	if d := h.confValue(installConf, "DOMAIN"); domainRE.MatchString(d) && !strings.Contains(d, "..") {
		f.Domain = d
		if h.exists(filepath.Join(leLive, d)) {
			add("Let's Encrypt certificate " + d + " (certbot)")
		}
	}
	if h.contains(leHook, rayctlV0) {
		add(leHook)
	}
	for _, p := range []string{cloudflareINI, dbConf} {
		if h.exists(p) {
			add(p)
		}
	}
	for _, p := range []string{backupsDir, logFile} {
		if h.exists(p) {
			add(p)
		}
	}
	if h.exists(xanmodList) {
		f.Kept = append(f.Kept, "XanMod kernel and its repository: removing a kernel is yours to do, after booting another one "+
			"(apt purge 'linux-xanmod*'; rm "+xanmodList+")")
	}
	return f
}

// Backup writes v0's settings, secrets, saved rules and database to a
// gzipped tar readable by root only, before anything is removed.
func (h *Host) Backup(ctx context.Context, f Found, dir string) (string, error) {
	name := filepath.Join(dir, "raycontrol-v0-"+h.Now().UTC().Format("20060102-150405")+".tar.gz")
	out, err := os.OpenFile(h.path(name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	put := func(name string, b []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), ModTime: h.Now()}); err != nil {
			return err
		}
		_, err := tw.Write(b)
		return err
	}
	var errs []error
	for _, p := range []string{rayAIODir, xrayDir, hysteriaDir, cloudflareINI, dbConf, nftConf, xrayUnit, hysteriaUnit} {
		_ = filepath.Walk(h.path(p), func(path string, info os.FileInfo, err error) error {
			if err != nil || !info.Mode().IsRegular() {
				return nil //nolint:nilerr // missing parts are fine
			}
			b, err := os.ReadFile(path) //nolint:gosec // G304: v0's own files
			if err == nil {
				rel, _ := filepath.Rel(h.path("/"), path)
				err = put(rel, b)
			}
			errs = append(errs, err)
			return nil
		})
	}
	if f.DB != "" && h.LookPath("pg_dump") == nil {
		dump, err := h.Run(ctx, "runuser", "-u", "postgres", "--", "pg_dump", "--no-owner", f.DB)
		if err != nil {
			h.logf("warning: no dump of database %s: %v", f.DB, firstLine(dump))
		} else {
			errs = append(errs, put("ray-aio-db.sql", dump))
		}
	}
	errs = append(errs, tw.Close(), gz.Close(), out.Close())
	if err := errors.Join(errs...); err != nil {
		_ = os.Remove(h.path(name))
		return "", err
	}
	return name, nil
}

// Remove takes v0 away: services, firewall table, database, certificate,
// files. Packages go only with purge, and only those v0 alone needed:
// certbot when no other certificate is left, PostgreSQL when no other
// database is.
func (h *Host) Remove(ctx context.Context, f Found, purge bool) error {
	var errs []error
	run := func(name string, args ...string) error {
		out, err := h.Run(ctx, name, args...)
		if err != nil {
			err = fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, firstLine(out))
		}
		return err
	}
	note := func(err error) {
		if err != nil {
			errs = append(errs, err)
			h.logf("warning: %v", err)
		}
	}
	rm := func(p string) {
		if !h.exists(p) {
			return
		}
		if err := os.RemoveAll(h.path(p)); err != nil {
			note(err)
			return
		}
		h.logf("removed %s", p)
	}

	// Services first: they hold the ports.
	for _, u := range []struct {
		on   bool
		unit string
	}{{f.xrayUnit, "xray.service"}, {f.hysteriaUnit, "hysteria-server.service"}} {
		if u.on {
			_ = run("systemctl", "disable", "--now", u.unit)
			h.logf("stopped and disabled %s", u.unit)
		}
	}
	if f.nftTable {
		note(run("nft", "delete", "table", "inet", "filter"))
		h.logf("removed nftables table inet filter")
	}
	if f.nftConf {
		if err := os.WriteFile(h.path(nftConf), []byte(debianNFTConf), 0o755); err != nil { //nolint:gosec // G306: the stock mode
			note(err)
		} else {
			h.logf("restored the stock %s", nftConf)
		}
	}

	if f.DB != "" && h.LookPath("psql") == nil {
		note(h.dropDB(ctx, f, purge))
	}

	if f.Domain != "" && h.exists(filepath.Join(leLive, f.Domain)) && h.LookPath("certbot") == nil {
		note(run("certbot", "delete", "--non-interactive", "--cert-name", f.Domain))
		h.logf("deleted the certificate %s", f.Domain)
	}
	if h.contains(leHook, rayctlV0) {
		rm(leHook)
	}
	if out, err := h.Run(ctx, "id", "-nG", "nobody"); err == nil && slices.Contains(strings.Fields(string(out)), "ssl-cert") {
		note(run("gpasswd", "-d", "nobody", "ssl-cert"))
	}

	if f.xrayUnit {
		rm(xrayUnit)
		rm(xrayBin)
		rm(xrayDir)
		rm(xrayLogDir)
	}
	if f.hysteriaUnit {
		rm(hysteriaUnit)
		rm(hysteriaBin)
		rm(hysteriaDir)
	}
	if f.rayctl {
		rm(rayctlV0)
	}
	for _, p := range []string{applyNFT, rayAIODir, backupsDir, cloudflareINI, dbConf, logFile} {
		rm(p)
	}
	if entries, err := os.ReadDir(h.path(secretsDir)); err == nil && len(entries) == 0 {
		rm(secretsDir)
	}
	_ = run("systemctl", "daemon-reload")

	if purge {
		pkgs := []string{"qrencode"}
		if entries, err := os.ReadDir(h.path(leLive)); err != nil || onlyReadme(entries) {
			pkgs = append(pkgs, "python3-certbot-dns-cloudflare", "certbot")
		} else {
			h.logf("certbot stays: other certificates are in %s", leLive)
		}
		note(h.purge(ctx, pkgs))
	}
	for _, k := range f.Kept {
		h.logf("kept: %s", k)
	}
	return errors.Join(errs...)
}

// dropDB drops v0's database and role, and with purge PostgreSQL itself
// when no other database is left.
func (h *Host) dropDB(ctx context.Context, f Found, purge bool) error {
	psql := func(sql string) ([]byte, error) {
		return h.Run(ctx, "runuser", "-u", "postgres", "--", "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-c", sql)
	}
	started := false
	if _, err := h.Run(ctx, "systemctl", "is-active", "--quiet", "postgresql"); err != nil {
		if out, err := h.Run(ctx, "systemctl", "start", "postgresql"); err != nil {
			return fmt.Errorf("postgresql does not start, database %s stays: %w: %s", f.DB, err, firstLine(out))
		}
		started = true
	}
	// The names are checked identifiers (ident): quoting them is enough.
	if out, err := psql(`DROP DATABASE IF EXISTS "` + f.DB + `"`); err != nil {
		return fmt.Errorf("drop database %s: %w: %s", f.DB, err, firstLine(out))
	}
	if out, err := psql(`DROP ROLE IF EXISTS "` + f.Role + `"`); err != nil {
		return fmt.Errorf("drop role %s: %w: %s", f.Role, err, firstLine(out))
	}
	h.logf("dropped the PostgreSQL database %s and role %s", f.DB, f.Role)
	others, err := psql(`SELECT datname FROM pg_database WHERE datname NOT IN ('postgres', 'template0', 'template1')`)
	if purge && err == nil && len(bytes.TrimSpace(others)) == 0 {
		_, _ = h.Run(ctx, "systemctl", "disable", "--now", "postgresql")
		return h.purge(ctx, []string{"postgresql", "postgresql-client", "postgresql-common", "postgresql-client-common"},
			"postgresql-[0-9]*", "postgresql-client-[0-9]*")
	}
	if purge {
		h.logf("PostgreSQL stays: other databases are on it")
	}
	if started {
		_, _ = h.Run(ctx, "systemctl", "stop", "postgresql")
	}
	return nil
}

// purge removes the installed ones of these packages (and patterns), with
// their configuration; nothing else.
func (h *Host) purge(ctx context.Context, names []string, patterns ...string) error {
	if h.LookPath("dpkg-query") != nil {
		return nil
	}
	args := append([]string{"-W", "-f", "${db:Status-Status} ${Package}\n"}, append(names, patterns...)...)
	out, _ := h.Run(ctx, "dpkg-query", args...)
	var installed []string
	for _, l := range strings.Split(string(out), "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "installed" {
			installed = append(installed, f[1])
		}
	}
	if len(installed) == 0 {
		return nil
	}
	if out, err := h.Run(ctx, "apt-get", append([]string{"-o", "DPkg::Lock::Timeout=300", "purge", "-y", "-q"}, installed...)...); err != nil {
		return fmt.Errorf("apt-get purge %s: %w: %s", strings.Join(installed, " "), err, firstLine(out))
	}
	h.logf("purged %s", strings.Join(installed, " "))
	return nil
}

func onlyReadme(entries []os.DirEntry) bool {
	for _, e := range entries {
		if e.Name() != "README" {
			return false
		}
	}
	return true
}

func firstLine(b []byte) string {
	s, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	return s
}
