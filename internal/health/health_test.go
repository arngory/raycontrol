package health

import (
	"errors"
	"testing"
	"time"
)

func TestBoard(t *testing.T) {
	now := time.Unix(1000, 0)
	b := &Board{Now: func() time.Time { return now }}
	b.Done("apply", nil)
	now = now.Add(time.Minute)
	b.Done("apply", errors.New("service dns: needs inner"))
	b.Done("acme site", nil)
	ls := b.Loops()
	if len(ls) != 2 || ls[0].Name != "acme site" || ls[1].Name != "apply" {
		t.Fatalf("loops %+v", ls)
	}
	a := ls[1]
	if a.Runs != 2 || a.Errors != 1 || a.LastOK.Unix() != 1000 || a.LastErr.Unix() != 1060 || !a.Failing() || a.Err != "service dns: needs inner" {
		t.Fatalf("apply %+v", a)
	}
	now = now.Add(time.Minute)
	b.Done("apply", nil)
	if a := b.Loops()[1]; a.Failing() || a.Err == "" {
		t.Fatalf("apply after recovery %+v: the last error stays, failing is off", a)
	}
	// Within one second the order still counts, and joined errors come on
	// one line.
	b.Done("apply", errors.Join(errors.New("service a: x"), errors.New("service b: y")))
	if a := b.Loops()[1]; !a.Failing() || a.Err != "service a: x ; service b: y" {
		t.Fatalf("failure in the same second %+v", a)
	}
	b.Done("apply", nil)
	if a := b.Loops()[1]; a.Failing() {
		t.Fatalf("success in the same second %+v", a)
	}
	// A deleted site is forgotten; other loops stay.
	b.Done("acme old", errors.New("no"))
	b.Retain("acme ", []string{"site"})
	b.Retain("acme ", []string{"site", "other"})
	if ls := b.Loops(); len(ls) != 2 || ls[0].Name != "acme site" || ls[1].Name != "apply" {
		t.Fatalf("after retain %+v", ls)
	}
	// A check's detail goes with its round, the next round replaces it.
	b.Report("dns-zone dns", "delegated;\n3/3 resolvers", nil)
	if l := b.Loops()[2]; l.Name != "dns-zone dns" || l.Detail != "delegated; ; 3/3 resolvers" || l.Failing() || l.Runs != 1 {
		t.Fatalf("report %+v", l)
	}
	b.Report("dns-zone dns", "not delegated", errors.New("no NS"))
	if l := b.Loops()[2]; l.Detail != "not delegated" || !l.Failing() || l.Err != "no NS" {
		t.Fatalf("failed report %+v", l)
	}
	b.Done("dns-zone dns", nil)
	if l := b.Loops()[2]; l.Detail != "" {
		t.Fatalf("detail after Done %+v", l)
	}
	b.Retain("dns-zone ", nil)
	var nilBoard *Board
	nilBoard.Retain("acme ", nil)
	nilBoard.Done("x", nil)
	nilBoard.Report("x", "y", nil)
	if nilBoard.Loops() != nil {
		t.Fatal("nil board")
	}
}
