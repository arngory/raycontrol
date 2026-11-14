//go:build !linux

package appmirror

import "errors"

// The mirror runs in rayd on a node, and a node is Linux: elsewhere the
// package builds for rayctl, which only asks a node about its mirror.
var errNode = errors.New("appmirror: the mirror keeps and serves releases on a Linux node only")

func statfsFree(string) (uint64, error) { return 0, errNode }

func setLowat(uintptr, int) error { return errNode }
