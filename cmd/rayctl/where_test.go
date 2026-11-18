package main

import (
	"bytes"
	"errors"
	"flag"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// runCommands reads the commands of (*cli).run from main.go: the cases of
// its switch.
func runCommands(t *testing.T) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var cmds []string
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "run" || fn.Recv == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			if tag, ok := sw.Tag.(*ast.Ident); !ok || tag.Name != "cmd" {
				return true
			}
			for _, c := range sw.Body.List {
				for _, e := range c.(*ast.CaseClause).List {
					lit, ok := e.(*ast.BasicLit)
					if !ok {
						t.Fatalf("a case of run's switch is not a string: %T", e)
					}
					s, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatal(err)
					}
					cmds = append(cmds, s)
				}
			}
			return false
		})
	}
	if len(cmds) < 20 {
		t.Fatalf("run's commands were not read from main.go: %v", cmds)
	}
	return cmds
}

// The table has every command rayctl runs and no other: a new command
// says where it works, or this fails. Its subcommands: TestSubPlaces.
func TestPlaces(t *testing.T) {
	cmds := runCommands(t)
	for _, c := range cmds {
		if _, ok := places[c]; !ok {
			t.Errorf("command %q is not in places (where.go): say where it works", c)
		}
	}
	for key := range places {
		if cmd, _, _ := strings.Cut(key, " "); !slices.Contains(cmds, cmd) {
			t.Errorf("places has %q, which run does not", key)
		}
	}
	// A command with its own place has its command's too: the longer key
	// only narrows.
	for key := range places {
		if cmd, _, sub := strings.Cut(key, " "); sub {
			if _, ok := places[cmd]; !ok {
				t.Errorf("places has %q without %q", key, cmd)
			}
		}
	}
	// What works on the node itself and not through -remote (localOnly)
	// acts on its host.
	for _, c := range localOnly {
		if places[c] != onNode {
			t.Errorf("%s: place %d, want %d (it is in localOnly)", c, places[c], onNode)
		}
	}
}

// subCommands reads the subcommands of each command that (*cli).run
// passes its sub to (return c.service(ctx, sub, rest)): the cases of a
// switch on sub in that method and the strings sub is compared with.
func subCommands(t *testing.T) map[string][]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	methods := map[string]*ast.FuncDecl{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv == nil {
				continue
			}
			if star, ok := fn.Recv.List[0].Type.(*ast.StarExpr); ok {
				if id, ok := star.X.(*ast.Ident); ok && id.Name == "cli" {
					methods[fn.Name.Name] = fn
				}
			}
		}
	}
	isSub := func(e ast.Expr) bool { id, ok := e.(*ast.Ident); return ok && id.Name == "sub" }
	str := func(e ast.Expr) (string, bool) {
		lit, ok := e.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(lit.Value)
		return s, err == nil
	}
	subs := map[string][]string{}
	ast.Inspect(methods["run"].Body, func(n ast.Node) bool {
		cc, ok := n.(*ast.CaseClause)
		if !ok || len(cc.List) != 1 || len(cc.Body) != 1 {
			return true
		}
		cmd, _ := str(cc.List[0])
		ret, ok := cc.Body[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return false
		}
		call, ok := ret.Results[0].(*ast.CallExpr)
		if !ok || !slices.ContainsFunc(call.Args, isSub) {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || methods[sel.Sel.Name] == nil {
			t.Fatalf("run: %s passes sub to %v, which is not a method here", cmd, call.Fun)
		}
		add := func(e ast.Expr) {
			if s, ok := str(e); ok && s != "" && !slices.Contains(subs[cmd], s) {
				subs[cmd] = append(subs[cmd], s)
			}
		}
		ast.Inspect(methods[sel.Sel.Name].Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.SwitchStmt:
				if isSub(n.Tag) {
					for _, c := range n.Body.List {
						for _, e := range c.(*ast.CaseClause).List {
							add(e)
						}
					}
				}
			case *ast.BinaryExpr:
				if n.Op == token.EQL || n.Op == token.NEQ {
					if isSub(n.X) {
						add(n.Y)
					} else if isSub(n.Y) {
						add(n.X)
					}
				}
			}
			return true
		})
		return false
	})
	if len(subs) < 8 || len(subs["service"]) < 5 {
		t.Fatalf("the subcommands were not read: %v", subs)
	}
	return subs
}

// apiSubs are the subcommands that only ask rayd (and read or write the
// files named on their command line, on this machine), and so work where
// their command does: places has no line for them.
var apiSubs = map[string][]string{
	"node":       {"name", "note"},
	"user":       {"add", "del", "disable", "enable", "export", "lan", "limit", "list", "renew", "reset-usage", "services", "usage"},
	"service":    {"add", "del", "disable", "enable", "list", "peer-keys", "rotate", "set"},
	"device":     {"add", "invite", "list", "revoke"},
	"relay":      {"add", "list", "ports", "remove", "set"},
	"dns":        {"check", "cloudflare", "remove", "status", "sync"},
	"summary":    {"api", "off", "on", "show"},
	"app-mirror": {"off", "on", "show"},
	"client":     {"min", "show"},
	"debug":      {"off", "on", "show"},
}

// Every subcommand says where it works too: a line of its own in places
// when it acts on the node's host (as service cert, relay bundle and
// summary db do), or apiSubs when it only asks rayd. A new subcommand of
// an API command that does neither fails here, so that it cannot slip
// through the refusal off Linux. What a subcommand's code does is not
// checked: the list says so for it.
func TestSubPlaces(t *testing.T) {
	subs := subCommands(t)
	for cmd, list := range subs {
		for _, sub := range list {
			_, own := places[cmd+" "+sub]
			switch api := slices.Contains(apiSubs[cmd], sub); {
			case !own && !api:
				t.Errorf("%s %s: neither in places (where.go) nor in apiSubs: say where it works", cmd, sub)
			case own && api:
				t.Errorf("%s %s: both in places and in apiSubs", cmd, sub)
			}
		}
	}
	for cmd, list := range apiSubs {
		for _, sub := range list {
			if !slices.Contains(subs[cmd], sub) {
				t.Errorf("apiSubs has %s %s, which rayctl does not", cmd, sub)
			}
		}
	}
	for key := range places {
		if cmd, sub, ok := strings.Cut(key, " "); ok && !slices.Contains(subs[cmd], sub) {
			t.Errorf("places has %q, which rayctl does not", key)
		}
	}
}

// Off Linux the commands that act on the node's host refuse, in one line
// that says so, whatever the flags; the rest of the table does not.
func TestRefusal(t *testing.T) {
	node := []string{"install", "apply", "update", "uninstall", "backup", "restore", "report", "egress", "conn-limit", "roots",
		"check", "legacy", "relay bundle", "service cert", "summary db"}
	api := []string{"status", "node", "user", "service", "device", "audit", "relay", "admin", "ports", "dns", "summary",
		"app-mirror", "client", "metrics", "remote whoami", "remote rotate", "service rotate", "relay list", "summary show",
		"device invite", "debug", "debug on"}
	free := []string{"knock", "probe", "remote enroll", "version"}
	for _, c := range runCommands(t) {
		if !slices.Contains(node, c) && !slices.Contains(api, c) && !slices.Contains(free, c) && c != "remote" {
			t.Errorf("command %q is in none of this test's lists", c)
		}
	}
	args := func(c string) []string { return append(strings.Fields(c), "x", "-o", "y") }
	for _, goos := range []string{"darwin", "freebsd", "windows"} {
		for _, c := range node {
			for _, flags := range [][2]bool{{false, false}, {true, false}, {false, true}, {true, true}} {
				err := refusal(goos, flags[0], flags[1], args(c))
				if err == nil {
					t.Errorf("%s, %s (remote %v, socket %v): not refused", goos, c, flags[0], flags[1])
					continue
				}
				if s := err.Error(); !strings.HasPrefix(s, c+" works on a Linux node only") || !strings.Contains(s, goos) || strings.Contains(s, "\n") {
					t.Errorf("%s, %s: %q", goos, c, s)
				}
			}
		}
		for _, c := range api {
			err := refusal(goos, false, false, args(c))
			if err == nil {
				t.Errorf("%s, %s without -remote: not refused", goos, c)
			} else if s := err.Error(); !strings.Contains(s, "-remote FILE") || strings.Contains(s, "\n") || strings.Contains(s, "Linux node only") {
				t.Errorf("%s, %s without -remote: %q", goos, c, s)
			}
			if err := refusal(goos, true, false, args(c)); err != nil {
				t.Errorf("%s, -remote F %s: %v", goos, c, err)
			}
			if err := refusal(goos, false, true, args(c)); err != nil {
				t.Errorf("%s, -socket S %s: %v", goos, c, err)
			}
		}
		for _, c := range free {
			for _, remote := range []bool{false, true} {
				if err := refusal(goos, remote, false, args(c)); err != nil {
					t.Errorf("%s, %s (remote %v): %v", goos, c, remote, err)
				}
			}
		}
		// The command alone, as "rayctl status" has it; what run does not
		// know gets its usage, not a refusal.
		if err := refusal(goos, true, false, []string{"status"}); err != nil {
			t.Errorf("%s, -remote F status: %v", goos, err)
		}
		if err := refusal(goos, false, false, []string{"install"}); err == nil {
			t.Errorf("%s, install: not refused", goos)
		}
		for _, a := range [][]string{nil, {"nonsense"}, {"-h"}} {
			if err := refusal(goos, false, false, a); err != nil {
				t.Errorf("%s, %v: %v", goos, a, err)
			}
		}
	}
	// On a node nothing is refused here: the commands check for
	// themselves, as before.
	for _, c := range slices.Concat(node, api, free) {
		for _, flags := range [][2]bool{{false, false}, {true, false}, {false, true}} {
			if err := refusal("linux", flags[0], flags[1], args(c)); err != nil {
				t.Errorf("linux, %s: %v", c, err)
			}
		}
	}
}

// misplaced reads -remote and -socket as main parsed them, for the system
// the test runs on.
func TestMisplaced(t *testing.T) {
	parse := func(args ...string) *flag.FlagSet {
		fs := flag.NewFlagSet("rayctl", flag.ContinueOnError)
		fs.String("socket", "/run/raycontrol/rayd.sock", "")
		fs.Bool("json", false, "")
		fs.String("remote", "", "")
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		return fs
	}
	linux := runtime.GOOS == "linux"
	for _, c := range []struct {
		args    []string
		refused bool // off Linux
	}{
		{[]string{"install", "-host", "192.0.2.1"}, true},
		{[]string{"-remote", "f.rcdev", "install"}, true},
		{[]string{"status"}, true},
		{[]string{"-remote", "", "status"}, true},
		{[]string{"-json", "status"}, true},
		{[]string{"-remote", "f.rcdev", "status"}, false},
		{[]string{"-socket", "/tmp/rayd.sock", "status"}, false},
		{[]string{"-remote", "f.rcdev", "service", "cert", "site", "-chain", "c", "-key", "k"}, true},
		{[]string{"-remote", "f.rcdev", "service", "list"}, false},
		{[]string{"remote", "enroll", "RCINV2:x"}, false},
		{[]string{"knock", "@bundle"}, false},
		{[]string{"probe", "-channel", "-"}, false},
	} {
		err := misplaced(parse(c.args...))
		if want := c.refused && !linux; (err != nil) != want {
			t.Errorf("%v on %s: %v, want refused %v", c.args, runtime.GOOS, err, want)
		}
	}
}

// TestRunMain is rayctl's main as a process, for TestMainRefuses: the
// command line after "--", on the system RAYCTL_TEST_OS names.
func TestRunMain(t *testing.T) {
	goos := os.Getenv("RAYCTL_TEST_OS")
	if goos == "" {
		t.Skip("run by TestMainRefuses")
	}
	thisOS = goos
	os.Args = append([]string{"rayctl"}, flag.Args()...)
	main()
}

// rayctl as it starts off a node: a command of the node's host stops at
// the refusal, before the device file is looked at; one for rayd goes on
// to the device file, which must be closed to others. The commands here
// do no harm where the refusal is missing: they fail on a file or a socket
// that is not there.
func TestMainRefuses(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.rcdev")
	open := filepath.Join(dir, "open.rcdev")
	if err := os.WriteFile(open, []byte("rcdev1:x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	noSocket := filepath.Join(dir, "rayd.sock")
	for _, c := range []struct {
		goos   string
		args   []string
		code   int
		stderr string // a line of standard error starts with it
		lines  int    // of standard error; 0: not counted
	}{
		{"darwin", []string{"-remote", missing, "install", "-host", "192.0.2.1"}, 1, "rayctl: install works on a Linux node only, and this is darwin", 1},
		{"darwin", []string{"-remote", missing, "backup"}, 1, "rayctl: backup works on a Linux node only", 1},
		{"freebsd", []string{"-socket", noSocket, "debug"}, 1, "rayctl: unavailable: ", 1},
		{"freebsd", []string{"debug", "on"}, 1, "rayctl: debug asks a node, and there is none on freebsd: rayctl -remote FILE debug", 1},
		{"darwin", []string{"-remote", missing, "service", "cert", "site", "-chain", missing, "-key", missing}, 1, "rayctl: service cert works on a Linux node only", 1},
		{"darwin", []string{"status"}, 1, "rayctl: status asks a node, and there is none on darwin: rayctl -remote FILE status", 1},
		{"darwin", []string{"-remote", missing, "status"}, 1, "rayctl: open " + missing, 1},
		{"darwin", []string{"-remote", open, "status"}, 1, "rayctl: device file " + open + " is mode -rw-r--r--: it holds a private key, make it 0600: chmod 600 " + open, 1},
		{"darwin", []string{"-socket", noSocket, "status"}, 1, "rayctl: unavailable: ", 1},
		{"darwin", []string{"knock"}, 2, "usage: rayctl", 0},
		{"darwin", []string{"nonsense"}, 2, "rayctl: bad usage", 0},
		// On a node the check is silent: the socket is asked, the device
		// file read, -remote refuses what it always did.
		{"linux", []string{"-socket", noSocket, "status"}, 1, "rayctl: unavailable: ", 1},
		{"linux", []string{"-socket", noSocket, "debug"}, 1, "rayctl: unavailable: ", 1},
		{"linux", []string{"-remote", missing, "backup"}, 1, "rayctl: backup works on the node itself, not through -remote", 1},
		{"linux", []string{"-remote", open, "status"}, 1, "rayctl: device file " + open + " is mode -rw-r--r--", 1},
		// What needs no node here takes no -remote, and what run does not
		// know is its usage: anywhere, before the device file is read.
		{"linux", []string{"-remote", open, "probe", "-channel", "x"}, 1, "rayctl: probe takes no -remote: it works from this machine", 1},
		{"darwin", []string{"-remote", open, "probe", "x"}, 1, "rayctl: probe takes no -remote", 1},
		{"freebsd", []string{"-remote", open, "knock", "x"}, 1, "rayctl: knock takes no -remote", 1},
		{"linux", []string{"-remote", open, "nonsense"}, 2, "rayctl: bad usage", 0},
		{"darwin", []string{"-remote", missing, "nonsense", "x"}, 2, "rayctl: bad usage", 0},
		// version works anywhere; with -remote it asks the node too, so the
		// device file is read.
		{"darwin", []string{"version"}, 0, "", 0},
		{"freebsd", []string{"-json", "version"}, 0, "", 0},
		{"darwin", []string{"-remote", missing, "version"}, 1, "rayctl: open " + missing, 1},
		{"linux", []string{"-remote", open, "version"}, 1, "rayctl: device file " + open + " is mode -rw-r--r--", 1},
		{"darwin", []string{"version", "x"}, 2, "rayctl: bad usage", 0},
	} {
		cmd := exec.Command(os.Args[0], append([]string{"-test.run", "^TestRunMain$", "--"}, c.args...)...)
		cmd.Env = append(os.Environ(), "RAYCTL_TEST_OS="+c.goos)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		err := cmd.Run()
		code := 0
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimRight(stderr.String(), "\n"), "\n")
		if code != c.code || !slices.ContainsFunc(lines, func(l string) bool { return strings.HasPrefix(l, c.stderr) }) ||
			(c.lines != 0 && len(lines) != c.lines) {
			t.Errorf("%s, rayctl %s: exit %d, want %d, and a line %q of %d; standard error:\n%s",
				c.goos, strings.Join(c.args, " "), code, c.code, c.stderr, c.lines, stderr.String())
		}
		if c.code == 2 && strings.Contains(stderr.String(), dir) {
			t.Errorf("%s, rayctl %s: the usage after the device file: %s", c.goos, strings.Join(c.args, " "), stderr.String())
		}
	}
}
