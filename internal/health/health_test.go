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
	var nilBoard *Board
	nilBoard.Done("x", nil)
	if nilBoard.Loops() != nil {
		t.Fatal("nil board")
	}
}
