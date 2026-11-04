package legacy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type fake struct {
	root  string
	calls []string
	nft   string // nft list table inet filter
	dbs   string // other databases
}

func (f *fake) host() *Host {
	return &Host{Root: f.root, Out: io.Discard, Now: func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) },
		LookPath: func(string) error { return nil },
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			c := strings.Join(append([]string{name}, args...), " ")
			f.calls = append(f.calls, c)
			switch {
			case c == "nft list table inet filter":
				if f.nft == "" {
					return []byte("Error: No such file or directory"), errors.New("exit status 1")
				}
				return []byte(f.nft), nil
			case strings.Contains(c, "pg_dump"):
				return []byte("-- dump of ray_aio_db\n"), nil
			case strings.Contains(c, "SELECT datname"):
				return []byte(f.dbs), nil
			case c == "id -nG nobody":
				return []byte("nogroup ssl-cert\n"), nil
			case c == "nft delete table inet filter":
				f.nft = ""
			case name == "dpkg-query":
				// Installed: certbot, qrencode, postgresql and postgresql-17.
				var out []string
				for _, a := range args[3:] {
					switch a {
					case "certbot", "qrencode", "postgresql":
						out = append(out, "installed "+a)
					case "postgresql-[0-9]*":
						out = append(out, "installed postgresql-17")
					}
				}
				return []byte(strings.Join(out, "\n")), nil
			}
			return nil, nil
		}}
}

func (f *fake) write(t *testing.T, p, s string) {
	t.Helper()
	full := filepath.Join(f.root, p)
	os.MkdirAll(filepath.Dir(full), 0o755)
	if err := os.WriteFile(full, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *fake) exists(p string) bool { _, err := os.Lstat(filepath.Join(f.root, p)); return err == nil }

// v0 installs what legacy/ray.sh does, next to things that are not v0's.
func v0(t *testing.T) *fake {
	f := &fake{root: t.TempDir(), nft: "table inet filter {\n\tset knock_stage1 { type ipv4_addr; }\n}\n"}
	f.write(t, "/etc/ray-aio/install.conf", "DOMAIN=\"vpn.example.com\"\nEMAIL=\"a@example.com\"\n")
	f.write(t, "/etc/ray-aio/settings.json", "{}")
	f.write(t, "/usr/local/bin/raycontrol", "#!/bin/bash\nsource /etc/ray-aio/install.conf\n")
	f.write(t, "/usr/local/bin/apply_nftables_xray.sh", "#!/bin/bash\nnft -f -\n")
	f.write(t, "/etc/systemd/system/xray.service", "[Service]\nExecStart=/usr/local/bin/xray -config /etc/xray/config.json\n")
	f.write(t, "/usr/local/bin/xray", "ELF")
	f.write(t, "/etc/xray/config.json", "{}")
	f.write(t, "/var/log/xray/access.log", "")
	f.write(t, "/etc/systemd/system/hysteria-server.service", "[Service]\nExecStart=/usr/local/bin/hysteria-server server -c /etc/hysteria/config.yaml\n")
	f.write(t, "/usr/local/bin/hysteria-server", "ELF")
	f.write(t, "/etc/hysteria/config.yaml", "auth: {}")
	f.write(t, "/root/.secrets/cloudflare.ini", "dns_cloudflare_api_token = secret\n")
	f.write(t, "/root/.secrets/db.conf", "PG_HOST=\"localhost\"\nPG_USER=\"ray_aio_user\"\nPG_DB_NAME=\"ray_aio_db\"\n")
	f.write(t, "/etc/letsencrypt/live/vpn.example.com/fullchain.pem", "cert")
	f.write(t, "/etc/letsencrypt/renewal-hooks/post/reload_services.sh", "/usr/local/bin/raycontrol regenerate-configs\n")
	f.write(t, "/etc/nftables.conf", "table inet filter {\n\tset knock_stage1 { type ipv4_addr; }\n}\n")
	f.write(t, "/var/log/raycontrol.log", "")
	f.write(t, "/etc/apt/sources.list.d/xanmod-kernel.list", "deb http://deb.xanmod.org releases main\n")
	// Not v0's: they stay.
	f.write(t, "/root/.secrets/other.key", "mine")
	f.write(t, "/etc/letsencrypt/live/blog.example.org/fullchain.pem", "cert")
	f.write(t, "/etc/letsencrypt/renewal-hooks/post/mine.sh", "systemctl reload nginx\n")
	return f
}

func TestNothingOnACleanHost(t *testing.T) {
	f := &fake{root: t.TempDir()}
	// Someone's own Xray and an unrelated db.conf are not v0.
	f.write(t, "/usr/local/bin/xray", "ELF")
	f.write(t, "/etc/systemd/system/xray.service", "[Service]\nExecStart=/usr/local/bin/xray run -c /usr/local/etc/xray/config.json\n")
	f.write(t, "/root/.secrets/db.conf", "PG_DB_NAME=\"shop\"\nPG_USER=\"shop\"\n")
	if found := f.host().Detect(context.Background()); found.Any() {
		t.Fatalf("found %v", found.Items)
	}
}

func TestDetectBackupRemove(t *testing.T) {
	ctx := context.Background()
	f := v0(t)
	h := f.host()
	found := h.Detect(ctx)
	if !found.Any() || found.DB != "ray_aio_db" || found.Role != "ray_aio_user" || found.Domain != "vpn.example.com" ||
		len(found.Kept) != 1 || !strings.Contains(found.Kept[0], "XanMod") {
		t.Fatalf("found %+v", found)
	}
	all := strings.Join(found.Items, "\n")
	for _, want := range []string{"xray.service", "hysteria-server.service", "inet filter", "PostgreSQL database ray_aio_db",
		"certificate vpn.example.com", "/root/.secrets/cloudflare.ini"} {
		if !strings.Contains(all, want) {
			t.Errorf("items lack %q:\n%s", want, all)
		}
	}

	os.MkdirAll(filepath.Join(f.root, "/root"), 0o700)
	name, err := h.Backup(ctx, found, "/root")
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(f.root, name)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup %s: %v %v", name, fi, err)
	}
	names := tarNames(t, filepath.Join(f.root, name))
	for _, want := range []string{"etc/ray-aio/install.conf", "root/.secrets/cloudflare.ini", "etc/xray/config.json", "etc/nftables.conf", "ray-aio-db.sql"} {
		if !slices.Contains(names, want) {
			t.Errorf("backup lacks %s: %v", want, names)
		}
	}
	if slices.Contains(names, "root/.secrets/other.key") {
		t.Error("backup took a file that is not v0's")
	}

	f.dbs = "" // no other database
	if err := h.Remove(ctx, found, true); err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"/etc/ray-aio", "/usr/local/bin/raycontrol", "/usr/local/bin/xray", "/etc/xray", "/var/log/xray",
		"/etc/systemd/system/hysteria-server.service", "/root/.secrets/cloudflare.ini", "/root/.secrets/db.conf",
		"/etc/letsencrypt/renewal-hooks/post/reload_services.sh", "/var/log/raycontrol.log"} {
		if f.exists(gone) {
			t.Errorf("%s stays", gone)
		}
	}
	for _, stays := range []string{"/root/.secrets/other.key", "/etc/letsencrypt/live/blog.example.org/fullchain.pem",
		"/etc/letsencrypt/renewal-hooks/post/mine.sh", "/etc/apt/sources.list.d/xanmod-kernel.list"} {
		if !f.exists(stays) {
			t.Errorf("%s was removed", stays)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(f.root, "/etc/nftables.conf")); strings.Contains(string(b), "knock") || !strings.Contains(string(b), "flush ruleset") {
		t.Errorf("nftables.conf:\n%s", b)
	}
	calls := strings.Join(f.calls, "\n")
	for _, want := range []string{"systemctl disable --now xray.service", "systemctl disable --now hysteria-server.service",
		"nft delete table inet filter", `DROP DATABASE IF EXISTS "ray_aio_db"`, `DROP ROLE IF EXISTS "ray_aio_user"`,
		"certbot delete --non-interactive --cert-name vpn.example.com", "gpasswd -d nobody ssl-cert",
		"purge -y -q postgresql postgresql-17", "purge -y -q qrencode"} {
		if !strings.Contains(calls, want) {
			t.Errorf("no %q in:\n%s", want, calls)
		}
	}
	// Another certificate is there: certbot stays.
	if strings.Contains(calls, "purge -y -q qrencode certbot") || strings.Contains(calls, "-q certbot") {
		t.Errorf("certbot purged next to another certificate:\n%s", calls)
	}
	// Run again: nothing left of v0.
	if again := f.host().Detect(ctx); again.Any() {
		t.Errorf("after removal: %v", again.Items)
	}
}

func TestPostgresWithOtherDatabasesStays(t *testing.T) {
	f := v0(t)
	f.dbs = "shop\n"
	h := f.host()
	if err := h.Remove(context.Background(), h.Detect(context.Background()), true); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(f.calls, "\n")
	if !strings.Contains(calls, `DROP DATABASE IF EXISTS "ray_aio_db"`) || strings.Contains(calls, "postgresql-17") {
		t.Fatalf("calls:\n%s", calls)
	}
}

func tarNames(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, h.Name)
	}
	return names
}
