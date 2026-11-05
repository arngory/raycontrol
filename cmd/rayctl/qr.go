package main

import (
	"fmt"
	"io"
	"strings"

	"rsc.io/qr"
)

// writeQR draws text as a QR code for a phone to scan off the terminal:
// two modules a character (the upper half block, its foreground the upper
// module, its background the lower), dark on light whatever the terminal's
// theme: black and white of the 256-colour cube (16 and 231), which themes
// leave alone, unlike the 16 colours they repaint; scanners that do not
// try the inverse (zxing as Niko uses it) read it. The quiet zone is the 4
// modules the standard asks for. Level L: a screen shows it clean, and an
// invite (about 650 characters) then takes 93 columns, 105 at M.
func writeQR(w io.Writer, text string) error {
	code, err := qr.Encode(text, qr.L)
	if err != nil {
		return err
	}
	const quiet = 4
	size := code.Size + 2*quiet
	dark := func(x, y int) bool {
		x, y = x-quiet, y-quiet
		return x >= 0 && y >= 0 && x < code.Size && y < code.Size && code.Black(x, y)
	}
	var b strings.Builder
	for y := 0; y < size; y += 2 {
		for x := 0; x < size; x++ {
			fg, bg := "231", "231" // white
			if dark(x, y) {
				fg = "16"
			}
			if dark(x, y+1) {
				bg = "16"
			}
			fmt.Fprintf(&b, "\x1b[38;5;%s;48;5;%sm▀", fg, bg)
		}
		b.WriteString("\x1b[0m\n")
	}
	_, err = io.WriteString(w, b.String())
	return err
}
