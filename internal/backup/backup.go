// Package backup seals a snapshot of the node's database with a
// passphrase (docs/08-decisions.md, R4-13): scrypt for the key,
// XChaCha20-Poly1305 for the gzip of the snapshot. The file says nothing
// about the node in the clear; its header is authenticated.
package backup

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

// Magic starts every backup file.
const Magic = "RCBAK1\n"

// Scrypt cost: 2^16 * 8 * 128 bytes = 64 MiB, fine on a small VPS.
const (
	logN = 16
	r    = 8
	p    = 1
)

// MinPassphrase is the shortest passphrase accepted.
const MinPassphrase = 12

// ErrPassphrase means the passphrase is wrong or the file was changed.
var ErrPassphrase = errors.New("backup: wrong passphrase, or the file was changed")

// Seal encrypts data with the passphrase.
func Seal(data []byte, passphrase string) ([]byte, error) {
	if len(passphrase) < MinPassphrase {
		return nil, fmt.Errorf("backup: the passphrase needs %d characters at least", MinPassphrase)
	}
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	header := append([]byte(Magic), logN, r, p)
	header = append(header, salt...)
	header = append(header, nonce...)
	aead, err := key(passphrase, salt, logN, r, p)
	if err != nil {
		return nil, err
	}
	return aead.Seal(header, nonce, z.Bytes(), header), nil
}

// Open decrypts a backup.
func Open(file []byte, passphrase string) ([]byte, error) {
	head := len(Magic) + 3 + 16 + chacha20poly1305.NonceSizeX
	if len(file) < head+chacha20poly1305.Overhead || string(file[:len(Magic)]) != Magic {
		return nil, errors.New("backup: not a raycontrol backup")
	}
	n, rr, pp := file[len(Magic)], file[len(Magic)+1], file[len(Magic)+2]
	if n < 10 || n > 22 || rr == 0 || rr > 32 || pp == 0 || pp > 16 {
		return nil, errors.New("backup: unsupported key parameters")
	}
	salt := file[len(Magic)+3 : len(Magic)+19]
	nonce := file[len(Magic)+19 : head]
	aead, err := key(passphrase, salt, n, rr, pp)
	if err != nil {
		return nil, err
	}
	z, err := aead.Open(nil, nonce, file[head:], file[:head])
	if err != nil {
		return nil, ErrPassphrase
	}
	zr, err := gzip.NewReader(bytes.NewReader(z))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(zr, 1<<30))
}

func key(passphrase string, salt []byte, n, rr, pp byte) (interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}, error) {
	k, err := scrypt.Key([]byte(passphrase), salt, 1<<n, int(rr), int(pp), chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.NewX(k)
}

// Meta describes a backup; it travels inside the sealed part.
type Meta struct {
	NodeID    string    `json:"node_id"`
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

// sqliteMagic starts every SQLite database file.
const sqliteMagic = "SQLite format 3\x00"

// Pack seals a database snapshot and its description.
func Pack(m Meta, db []byte, passphrase string) ([]byte, error) {
	if !bytes.HasPrefix(db, []byte(sqliteMagic)) {
		return nil, errors.New("backup: the snapshot is not an SQLite database")
	}
	head, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return Seal(append(append(head, '\n'), db...), passphrase)
}

// Unpack opens what Pack sealed.
func Unpack(file []byte, passphrase string) (Meta, []byte, error) {
	var m Meta
	plain, err := Open(file, passphrase)
	if err != nil {
		return m, nil, err
	}
	head, db, ok := bytes.Cut(plain, []byte{'\n'})
	if !ok || json.Unmarshal(head, &m) != nil || !bytes.HasPrefix(db, []byte(sqliteMagic)) {
		return m, nil, errors.New("backup: the contents are not a raycontrol database")
	}
	return m, db, nil
}
