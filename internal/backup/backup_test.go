package backup

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestSealOpen(t *testing.T) {
	data := bytes.Repeat([]byte("SQLite format 3\x00 node state "), 1000)
	sealed, err := Seal(data, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("SQLite")) || len(sealed) >= len(data) {
		t.Fatalf("sealed %d bytes, not compressed or not encrypted", len(sealed))
	}
	got, err := Open(sealed, "correct horse battery")
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("open: %v", err)
	}
	if _, err := Open(sealed, "wrong horse battery"); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	changed := bytes.Clone(sealed)
	changed[len(Magic)+5] ^= 1 // the salt: authenticated as part of the header
	if _, err := Open(changed, "correct horse battery"); err == nil {
		t.Fatal("a changed header opened")
	}
	if _, err := Seal(data, "short"); err == nil {
		t.Fatal("a short passphrase accepted")
	}
	if _, err := Open([]byte("not a backup at all, really not"), "correct horse battery"); err == nil {
		t.Fatal("garbage opened")
	}
}

func TestPackUnpack(t *testing.T) {
	db := append([]byte("SQLite format 3\x00"), bytes.Repeat([]byte{7, 0, 1}, 5000)...)
	meta := Meta{NodeID: "ab12", Version: "v0.3.0", CreatedAt: time.Unix(1_800_000_000, 0).UTC()}
	sealed, err := Pack(meta, db, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("ab12")) || bytes.Contains(sealed, []byte("v0.3.0")) {
		t.Fatal("the description is readable without the passphrase")
	}
	m, got, err := Unpack(sealed, "correct horse battery")
	if err != nil || !bytes.Equal(got, db) || m != meta {
		t.Fatalf("unpack: %+v %v", m, err)
	}
	if _, err := Pack(meta, []byte("not a database"), "correct horse battery"); err == nil {
		t.Fatal("packed something that is not a database")
	}
	other, err := Seal([]byte("{}\nplain text"), "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Unpack(other, "correct horse battery"); err == nil {
		t.Fatal("unpacked something that is not a database")
	}
}
