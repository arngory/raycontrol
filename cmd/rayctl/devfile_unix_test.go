//go:build unix

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arngory/raycontrol/internal/api"
	"github.com/arngory/raycontrol/internal/node"
)

// deviceFile writes an admin device's file as rayctl remote enroll does.
func deviceFile(t *testing.T) remoteIdentity {
	t.Helper()
	cert, err := api.NewClientCertificate()
	if err != nil {
		t.Fatal(err)
	}
	b := node.Bundle{Version: 1, Host: "192.0.2.1", DeviceID: "d-test", DeviceKey: strings.Repeat("00", 32),
		API: &node.BundleSub{Port: 8443, Pin: "pin"}}
	id := remoteIdentity{path: filepath.Join(t.TempDir(), "node-d-test.rcdev"), bundle: b, cert: cert}
	if id.raw, err = b.Encode(); err != nil {
		t.Fatal(err)
	}
	if err := id.save(true); err != nil {
		t.Fatal(err)
	}
	return id
}

// A device file is read only while it is the user's own and closed to
// everyone else; the refusal names the file, its mode and the fix.
func TestDeviceFileMode(t *testing.T) {
	id := deviceFile(t)
	fi, err := os.Stat(id.path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the file as written: %v, %v", fi.Mode(), err)
	}
	got, err := loadIdentity(id.path)
	if err != nil || got.raw != id.raw || got.bundle.DeviceID != "d-test" {
		t.Fatalf("the file as written: %v", err)
	}
	// What remote rotate writes over it stays closed.
	if err := id.save(false); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(id.path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the file as rewritten: %v, %v", fi.Mode(), err)
	}
	for _, mode := range []os.FileMode{0o600, 0o400, 0o700} {
		if err := os.Chmod(id.path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := loadIdentity(id.path); err != nil {
			t.Errorf("mode %v: %v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o620, 0o602, 0o610, 0o601, 0o666, 0o660, 0o444} {
		if err := os.Chmod(id.path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := loadIdentity(id.path)
		if err == nil {
			t.Errorf("mode %v: read", mode)
			continue
		}
		for _, want := range []string{"device file " + id.path, mode.String(), "it holds a private key, make it 0600", "chmod 600 " + id.path} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("mode %v: %q lacks %q", mode, err, want)
			}
		}
		if strings.Contains(err.Error(), "\n") {
			t.Errorf("mode %v: more than a line: %q", mode, err)
		}
	}
	// Through a link it is the file that counts, not the link.
	if err := os.Chmod(id.path, 0o640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link.rcdev")
	if err := os.Symlink(id.path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentity(link); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("an open file through a link: %v", err)
	}
	if err := os.Chmod(id.path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentity(link); err != nil {
		t.Errorf("a closed file through a link: %v", err)
	}
	// A file that is not there is the read's to report, as before.
	if _, err := loadIdentity(filepath.Join(t.TempDir(), "missing.rcdev")); err == nil || !strings.HasPrefix(err.Error(), "open ") {
		t.Errorf("a missing file: %v", err)
	}
}

// Another user's file is refused whatever its mode, but to root: its
// owner can change the node it trusts, and root can anyway (as OpenSSH
// has it for a private key). The mode counts for root too.
func TestDeviceFileOwner(t *testing.T) {
	for _, c := range []struct {
		mode      os.FileMode
		owner, me int
		want      string // "": read
	}{
		{0o600, 1000, 1000, ""},
		{0o600, 0, 0, ""},
		{0o600, -1, 1000, ""}, // the system does not say whose
		{0o644, -1, 1000, "chmod 600"},
		{0o600, 1001, 1000, "belongs to uid 1001, not to you (uid 1000)"},
		{0o644, 1001, 1000, "belongs to uid 1001, not to you (uid 1000)"},
		{0o600, 1000, 0, ""}, // sudo rayctl -remote ~/n.rcdev
		{0o400, 1000, 0, ""},
		{0o644, 1000, 0, "is mode -rw-r--r--"},
		{0o640, 1000, 0, "chmod 600"},
		{0o600, 0, 1000, "belongs to uid 0, not to you (uid 1000)"},
	} {
		err := deviceFileProblem("f.rcdev", c.mode, c.owner, c.me)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%+v: %v", c, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "device file f.rcdev") ||
			strings.Contains(err.Error(), "\n")):
			t.Errorf("%+v: %v", c, err)
		}
	}
	if os.Geteuid() != 0 {
		t.Skip("giving a file away needs root")
	}
	id := deviceFile(t)
	if err := os.Chown(id.path, 65534, -1); err != nil {
		t.Skipf("chown: %v", err)
	}
	if _, err := loadIdentity(id.path); err != nil {
		t.Errorf("root, another user's closed file: %v", err)
	}
	if err := os.Chmod(id.path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentity(id.path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("root, another user's open file: %v", err)
	}
}

// The fix the refusal prints works when pasted into a shell, whatever
// the file's name; a filesystem without modes has its advice too.
func TestDeviceFileFixLine(t *testing.T) {
	for path, want := range map[string]string{
		"n.rcdev":                "n.rcdev",
		"/home/a/node-d_1.rcdev": "/home/a/node-d_1.rcdev",
		"a b/n.rcdev":            "'a b/n.rcdev'",
		"it's.rcdev":             `'it'\''s.rcdev'`,
		"-n.rcdev":               "./-n.rcdev",
		"~/n.rcdev":              "'~/n.rcdev'",
		"$HOME/`x`;*.rcdev":      "'$HOME/`x`;*.rcdev'",
	} {
		if got := shellWord(path); got != want {
			t.Errorf("shellWord(%q) = %s, want %s", path, got, want)
		}
	}
	err := deviceFileProblem("a b/n.rcdev", 0o644, -1, 1000)
	if err == nil || !strings.Contains(err.Error(), "chmod 600 'a b/n.rcdev' (if its filesystem keeps no modes: copy it to your home directory") {
		t.Errorf("the fix: %v", err)
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	for _, name := range []string{"a b.rcdev", "it's.rcdev", "-n.rcdev", "$x `y` \"z\" ;*.rcdev", "~n.rcdev"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(sh, "-c", "chmod 600 "+shellWord(name))
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%q: %v: %s", name, err, out)
		}
		if fi, err := os.Stat(filepath.Join(dir, name)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%q after the fix: %v", name, err)
		}
	}
}

// The check is made on the file that is read, not on its path again: a
// file put in its place after the open counts for nothing, either way.
func TestDeviceFileOpened(t *testing.T) {
	id := deviceFile(t)
	want, err := os.ReadFile(id.path)
	if err != nil {
		t.Fatal(err)
	}
	replace := func(mode os.FileMode, content string) {
		t.Helper()
		other := filepath.Join(filepath.Dir(id.path), "other")
		if err := os.WriteFile(other, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(other, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(other, id.path); err != nil {
			t.Fatal(err)
		}
	}
	// Closed when opened, open in its place afterwards.
	f, err := os.Open(id.path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	replace(0o644, "rcdev1:other\n")
	b, err := readDeviceFile(id.path, f)
	if err != nil || string(b) != string(want) {
		t.Errorf("the opened file: %v; read %q", err, b)
	}
	if got, err := decodeIdentity(id.path, b); err != nil || got.raw != id.raw {
		t.Errorf("the opened file decoded: %v", err)
	}
	if _, err := loadIdentity(id.path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("the file in its place: %v", err)
	}
	// Open when opened, closed in its place afterwards.
	g, err := os.Open(id.path)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	replace(0o600, string(want))
	if _, err := readDeviceFile(id.path, g); err == nil || !strings.Contains(err.Error(), "is mode -rw-r--r--") {
		t.Errorf("an open file, closed after the open: %v", err)
	}
}

// remote export writes the device's certificate and key as a new PEM file,
// closed to others, and says the pin as curl takes it.
func TestRemoteExport(t *testing.T) {
	id := deviceFile(t)
	// A real pin: base64url SHA-256, no padding.
	id.bundle.API.Pin = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
	var err error
	if id.raw, err = id.bundle.Encode(); err != nil {
		t.Fatal(err)
	}
	if err := id.save(false); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "billing.pem")
	var said strings.Builder
	if err := remoteExport([]string{id.path, "-pem", out}, &said); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(out)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the PEM: %v %v", fi, err)
	}
	b, _ := os.ReadFile(out)
	cert, err := api.DecodeClientCertificate(b)
	if err != nil || !cert.Leaf.Equal(id.cert.Leaf) {
		t.Fatalf("the PEM does not read back: %v", err)
	}
	if !strings.Contains(said.String(), "--pinnedpubkey 'sha256//47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='") ||
		!strings.Contains(said.String(), "https://192.0.2.1:8443/raycontrol.device.v1.DeviceService/GetSelf") {
		t.Fatalf("said:\n%s", said.String())
	}
	// Never over a file that is there.
	if err := remoteExport([]string{id.path, "-pem", out}, &said); err == nil {
		t.Fatal("wrote over an existing file")
	}
	if err := remoteExport([]string{id.path}, &said); err == nil {
		t.Fatal("no -pem taken")
	}
}
