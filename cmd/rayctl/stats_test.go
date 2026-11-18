package main

import (
	"strings"
	"testing"
)

// The journal's counts: by unit as the report names it, never a message;
// a unit of a service by its kind#n, raycontrol's fixed ones by name, the
// rest "other".
func TestCountJournal(t *testing.T) {
	in := strings.Join([]string{
		`{"_SYSTEMD_UNIT":"rayd.service","PRIORITY":"4","MESSAGE":"secret.example.org"}`,
		`{"_SYSTEMD_UNIT":"rayd.service","PRIORITY":"3"}`,
		`{"_SYSTEMD_UNIT":"rayd.service","PRIORITY":"4"}`,
		`{"_SYSTEMD_UNIT":"niko-my-naive.service","PRIORITY":"3"}`,
		`{"_SYSTEMD_UNIT":"niko-front.service","PRIORITY":"4"}`,
		`{"_SYSTEMD_UNIT":"niko-gone.service","PRIORITY":"2"}`,
		`not json`,
	}, "\n")
	got, err := countJournal(strings.NewReader(in), map[string]string{"rayd.service": "rayd", "niko-my-naive.service": "naive#1"})
	if err != nil {
		t.Fatal(err)
	}
	var s []string
	for _, c := range got {
		s = append(s, c.Unit+"/"+c.Priority+"="+string(rune('0'+c.Entries)))
	}
	if want := "naive#1/err=1 niko-front/warning=1 other/crit=1 rayd/err=1 rayd/warning=2"; strings.Join(s, " ") != want {
		t.Fatalf("%v, want %s", s, want)
	}
}
