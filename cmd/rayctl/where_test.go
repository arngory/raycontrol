package main

import (
	"flag"
	"go/ast"
	"go/parser"
	"go/token"
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
// says where it works, or this fails.
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
	// acts on its host, but for the probe, which needs no node here at all.
	for _, c := range localOnly {
		want := onNode
		if c == "probe" {
			want = anywhere
		}
		if places[c] != want {
			t.Errorf("%s: place %d, want %d (it is in localOnly)", c, places[c], want)
		}
	}
}

// Off Linux the commands that act on the node's host refuse, in one line
// that says so, whatever the flags; the rest of the table does not.
func TestRefusal(t *testing.T) {
	node := []string{"install", "apply", "update", "uninstall", "backup", "restore", "report", "egress", "conn-limit",
		"check", "legacy", "relay bundle", "service cert", "debug", "summary db"}
	api := []string{"status", "node", "user", "service", "device", "audit", "relay", "admin", "dns", "summary",
		"app-mirror", "metrics", "remote whoami", "remote rotate", "service rotate", "relay list", "summary show",
		"device invite"}
	free := []string{"knock", "probe", "remote enroll"}
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
		for _, a := range [][]string{nil, {"nonsense"}, {"-h"}, {"version"}} {
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
